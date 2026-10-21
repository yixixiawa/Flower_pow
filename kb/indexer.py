"""POC 向量化索引器。

为什么自己实现而不用 Chroma / Qdrant
-------------------------------------
这个工具的POC 库只有几十到几百条量级，引入 Chroma 意味着多一个~100MB 的
依赖树（chromadb → onnxruntime → …），而收益几乎为零。所以这里用
**hashing trick + 稀疏余弦**在纯 Python 里实现：

    文本 → 分词 → hash 到固定维度 → TF-IDF 加权 → L2 归一化 → 落盘 JSON

* 无重依赖，`python -m flower_pow index` 在任何装了 httpx+yaml 的机器上都能跑；
* 索引文件是**可读的 JSON**，出问题能直接打开看；
* 几百条 POC 的全量检索是毫秒级，不需要 FAISS。

若后续 POC 涨到数千条以上，把 :class:`VectorStore` 换成后端实现即可——
检索器（:mod:`kb.retriever`）只依赖 ``search()`` 这一个方法。

分词策略
--------
中文没有空格，按词切分效果差，因此：
* 英文/数字：按 ``[a-z0-9_.-]+`` 切词；
* CJK 连续段：同时产出 1-gram 与 2-gram（bigram 是中文检索的主力特征）；
* 额外产出技术栈别名（``struts2`` → ``struts``），避免用户写一种、库里写另一种。
"""

from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from core.state import POC

# 英文/数字词
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]*")
# CJK 连续段
_CJK_RE = re.compile(r"[\u4e00-\u9fff]+")
# 技术栈别名：把常见写法归一化，提升召回
_TECH_ALIASES: dict[str, str] = {
    "struts2": "struts", "struts-2": "struts", "springboot": "spring",
    "spring-boot": "spring", "spring cloud": "spring", "springcloud": "spring",
    "fastjson2": "fastjson", "shiro": "shiro", "weblogic": "weblogic",
    "swagger2": "swagger", "openapi": "swagger", "thinkphp": "thinkphp",
    "yii2": "yii", "dotnet": "asp.net", "aspnet": "asp.net",
    "log4j2": "log4j", "log4shell": "log4j", "tomcat": "tomcat",
    "jenkins": "jenkins", "nacos": "nacos", "fastapi": "fastapi",
    "django": "django", "laravel": "laravel", "phpinfo": "php",
    "xlsx": "excel", "csv": "excel",
}
# 分词后需要补进词表的技术名词（来自 POC 元数据，通用技术栈）
_EXTRA_TERMS = {
    "cve", "rce", "sqli", "xss", "ssrf", "xxe", "lfi", "rfi", "idor",
    "csrf", "hpp", "ssti", "jwt", "cors", "csp", "hsts", "waf", "cdn",
}


def tokenize(text: str) -> list[str]:
    """把文本切成检索用词袋（英文词 + CJK 1/2-gram + 技术别名）。"""
    if not text:
        return []
    low = text.lower()
    tokens: list[str] = list(_WORD_RE.findall(low))

    for seg in _CJK_RE.findall(low):
        tokens.extend(seg)  # 单字：保证召回
        for i in range(len(seg) - 1):  # 双字：中文检索主力
            tokens.append(seg[i : i + 2])

    expanded = []
    for t in tokens:
        expanded.append(t)
        if t in _TECH_ALIASES:
            expanded.append(_TECH_ALIASES[t])
    return expanded


def _hash_index(token: str, dim: int) -> int:
    """稳定的字符串 hash（Python 内置 hash 有随机盐，跨进程不一致）。"""
    h = 0
    for ch in token:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return h % dim


@dataclass(slots=True)
class IndexedPOC:
    """索引里的一条记录。"""

    poc_id: str
    vector: list[float]
    meta: dict


class VectorStore:
    """混合检索库：稀疏向量余弦 + BM25，纯 Python 实现。

    为什么要混合（这是实测踩出来的坑）
    -----------------------------------
    最初只用 TF-IDF 余弦，结果在 22 条 POC 的小语料上几乎不可用：
    query 向量的非零维度远多于文档向量（目标指纹里都是服务器名、标题、
    各种标识符），稀疏余弦被系统性压到 0.1 以下，``min_score`` 一设就把
    正确结果全过滤了。实测 ``"Apache Tomcat/9.0.65 java tomcat"`` 对
    Struts2 POC 的余弦只有 0.033。

    BM25 在小语料上的表现好得多——它对"精确命中某个词"给予高权重，
    且分数不随词数稀释。所以最终采用：

        hybrid = 0.35 ×归一化余弦 + 0.65 × 归一化 BM25

    余弦负责模糊/语义相近，BM25 负责精确术语命中。两者归一化到 0-1
    后加权，权重偏向 BM25——因为安全测试里技术栈名字精确匹配的价值
    远高于语义相似。

    规模定位是「几千条以内」。超过这个量级请把 :meth:`search` 换成
    FAISS/后端向量库，但 BM25 部分可以原样留着（稀疏检索本来就不贵）。
    """

    # BM25 参数：k1 控制词频饱和，b 控制文档长度归一化
    BM25_K1 = 1.5
    BM25_B = 0.75
    # 余弦与 BM25 的融合权重
    W_COS = 0.35
    W_BM25 = 0.65

    def __init__(self, dim: int = 2048) -> None:
        self.dim = dim
        self.items: dict[str, IndexedPOC] = {}
        # 文档频率，用于 IDF。加权集中在检索侧更灵活，这里只存计数。
        self.df: Counter[str] = Counter()
        self._doc_tokens: dict[str, Counter[str]] = {}
        self._doc_len: dict[str, int] = {}
        self.meta: dict = {"built_at": 0.0, "dim": dim, "version": 3}

    # ── 写入 ──────────────────────────────────────────────────────
    def _unaccount_df(self, doc_id: str) -> None:
        """把某文档之前贡献的 df 计数撤回。

        **增量写入必须先撤回再重新累加**，否则同一 ``doc_id`` 第二次 add 时
        ``df`` 会被重复累加，导致 IDF 偏移、BM25 分数失真。
        这在「全量重建」模式下不会暴露（每次都是全新的 VectorStore），
        但一旦引入「读旧索引 → 加几条 → 存回」的增量路径就会立刻踩到。
        """
        old = self._doc_tokens.get(doc_id)
        if not old:
            return
        for tok in old.keys():
            # Counter 减到 0 就删掉，避免 df 里堆满 0 计数的key
            self.df[tok] -= 1
            if self.df[tok] <= 0:
                del self.df[tok]

    def add(
        self,
        poc: POC | None = None,
        boost_terms: int = 3,
        *,
        doc_id: str | None = None,
        text: str | None = None,
        meta: dict | None = None,
        boost_texts: list[str] | None = None,
    ) -> None:
        """把一条记录加入索引。

        两种用法：

        * **POC 模式**（传 ``poc``）——原有用法，文本取 ``poc.index_document()``，
          加权词取 ``applies_to + tags``。
        * **通用模式**（传 ``doc_id`` + ``text``）——供知识库沉淀扫描发现用，
          不依赖 POC 类型，见 :meth:`add_record`。

        重复 ``doc_id`` 会**覆盖**而非叠加（df 也会正确撤回）。
        """
        if poc is not None:
            doc_id = doc_id or poc.id
            text = text if text is not None else poc.index_document()
            weighty = [t for t in (poc.applies_to + poc.tags) if t]
            meta = meta if meta is not None else poc.to_dict()
        if doc_id is None or text is None:
            raise ValueError("add() 需要 poc，或同时提供 doc_id 与 text")

        toks = list(tokenize(text))
        # 技术栈与标签重复加权
        for t in boost_texts or []:
            if t:
                toks.extend(tokenize(t) * boost_terms)

        # 覆盖前先撤回旧 df（见 _unaccount_df 的注释）
        self._unaccount_df(doc_id)
        tf = Counter(toks)
        self.df.update(tf.keys())
        self._doc_tokens[doc_id] = tf
        self.items[doc_id] = IndexedPOC(poc_id=doc_id, vector=[], meta=dict(meta or {}))

    def add_record(
        self,
        doc_id: str,
        text: str,
        meta: dict | None = None,
        *,
        boost_texts: list[str] | None = None,
        boost_terms: int = 3,
    ) -> None:
        """加入一条**非 POC 来源**的记录（扫描发现、情报、笔记…）。

        独立索引文件（``knowledge_index.json``）走这条路，
        这样自产知识不会混进 POC 索引、破坏 ``index_is_stale`` 的 mtime 判定。
        """
        self.add(
            None,
            boost_terms=boost_terms,
            doc_id=doc_id,
            text=text,
            meta=meta,
            boost_texts=boost_texts,
        )

    def finalize(self) -> None:
        """所有 add 完成后调用：计算 TF-IDF 向量并归一化。"""
        n = max(1, len(self._doc_tokens))
        for poc_id, tf in self._doc_tokens.items():
            vec = [0.0] * self.dim
            for tok, cnt in tf.items():
                idf = math.log((n + 1) / (self.df.get(tok, 0) + 1)) + 1.0
                idx = _hash_index(tok, self.dim)
                vec[idx] += (1.0 + math.log(cnt)) * idf
            norm = math.sqrt(sum(v * v for v in vec))
            if norm > 0:
                vec = [v / norm for v in vec]
            self.items[poc_id].vector = vec
            self._doc_len[poc_id] = sum(tf.values())
        self.meta = {
            "built_at": time.time(),
            "dim": self.dim,
            "version": 3,
            "count": len(self.items),
        }

    # ── BM25 ──────────────────────────────────────────────────────
    def _bm25_scores(self, qtf: Counter[str]) -> dict[str, float]:
        """标准 BM25打分。返回 ``{poc_id: score}``。"""
        n = max(1, len(self._doc_tokens))
        avgdl = (sum(self._doc_len.values()) / n) or 1.0
        k1, b = self.BM25_K1, self.BM25_B

        # 逐 query token 累加，避免为每个文档重复遍历全部 query
        out: dict[str, float] = {}
        for tok, qcnt in qtf.items():
            df = self.df.get(tok, 0)
            if not df:
                continue
            # 加 1 平滑：词越常见，IDF 越接近 0，避免负分
            idf = math.log((n - df + 0.5) / (df + 0.5) + 1.0)
            if idf <= 0:
                continue
            for poc_id, tf in self._doc_tokens.items():
                f = tf.get(tok, 0)
                if not f:
                    continue
                dl = self._doc_len.get(poc_id, 1)
                denom = f + k1 * (1 - b + b * dl / avgdl)
                out[poc_id] = out.get(poc_id, 0.0) + idf * (f * (k1 + 1)) / denom
        return out

    # ── 检索 ──────────────────────────────────────────────────────
    def query_vector(self, text: str) -> list[float]:
        toks = Counter(tokenize(text))
        n = max(1, len(self._doc_tokens))
        vec = [0.0] * self.dim
        for tok, cnt in toks.items():
            idf = math.log((n + 1) / (self.df.get(tok, 0) + 1)) + 1.0
            vec[_hash_index(tok, self.dim)] += (1.0 + math.log(cnt)) * idf
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm > 0 else vec

    def search(
        self, text: str, top_k: int = 10, min_score: float = 0.0
    ) -> list[tuple[str, float]]:
        """混合检索（余弦 + BM25）。返回 ``[(poc_id, score)]``，按分数降序。

        分数已归一化到 0-1，可直接与 ``rag.min_score`` 比较。
        """
        if not self.items:
            return []

        qtf = Counter(tokenize(text))
        if not qtf:
            return []

        # ① 稀疏余弦
        qv = self.query_vector(text)
        cos: dict[str, float] = {}
        for poc_id, item in self.items.items():
            if not item.vector:
                continue
            s = 0.0
            for i, q in enumerate(qv):
                if q:
                    s += q * item.vector[i]
            if s > 0:
                cos[poc_id] = s

        # ② BM25
        bm = self._bm25_scores(qtf)

        # ③ 各自归一化后融合。归一化是必需的：余弦天然偏小、BM25 天然偏大，
        #    不归一的话融合权重就失去意义了。
        cos_max = max(cos.values()) if cos else 0.0
        bm_max = max(bm.values()) if bm else 0.0

        merged: dict[str, float] = {}
        for poc_id in set(cos) | set(bm):
            c = cos.get(poc_id, 0.0) / cos_max if cos_max > 0 else 0.0
            b = bm.get(poc_id, 0.0) / bm_max if bm_max > 0 else 0.0
            merged[poc_id] = self.W_COS * c + self.W_BM25 * b

        scored = [(pid, s) for pid, s in merged.items() if s > min_score]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def debug_search(self, text: str, top_k: int = 8) -> list[dict]:
        """返回两路原始分，供调参时看清"是余弦拖后腿还是 BM25 拖后腿"。"""
        qtf = Counter(tokenize(text))
        qv = self.query_vector(text)
        cos: dict[str, float] = {}
        for pid, item in self.items.items():
            s = sum(q * item.vector[i] for i, q in enumerate(qv) if q)
            cos[pid] = s
        bm = self._bm25_scores(qtf)
        cm = max(cos.values()) or 1.0
        bmv = max(bm.values()) or 1.0
        fused = {
            pid: self.W_COS * (cos.get(pid, 0) / cm) + self.W_BM25 * (bm.get(pid, 0) / bmv)
            for pid in self.items
        }
        top = sorted(fused, key=lambda k: fused[k], reverse=True)[:top_k]
        return [
            {
                "id": pid,
                "cos": round(cos.get(pid, 0.0), 4),
                "bm25": round(bm.get(pid, 0.0), 4),
                "fused": round(fused[pid], 4),
            }
            for pid in top
        ]

    # ── 持久化 ────────────────────────────────────────────────────
    def to_payload(self) -> dict:
        """序列化成可 JSON 化的dict（不含外层包装）。

        抽出来是为了让 :class:`kb.knowledge.KnowledgeStore` 能把它嵌进自己的
        文件里而不必复制一份序列化逻辑。
        """
        return {
            "meta": self.meta,
            "items": [
                {"id": i.poc_id, "v": i.vector, "m": i.meta}
                for i in self.items.values()
            ],
            "df": dict(self.df),
            "tokens": {
                pid: {"tf": dict(tf), "len": self._doc_len.get(pid, 0)}
                for pid, tf in self._doc_tokens.items()
            },
        }

    def save(self, path: str | Path) -> Path:
        """保存索引。

        **必须连BM25 的词频表一起存。** 词频无法从归一化向量反推
        （向量是有损的），而reload_tokens 从 YAML 重算虽然也就几毫秒，
        但会让索引与 POC 目录产生隐式耦合——YAML 改了但索引没重建时
        BM25 用的是新词频、余弦用的是旧向量，两路分数对不上。
        存token 表能让索引自洽，多占的体积在几千条规模下可接受。
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.to_payload(), ensure_ascii=False), encoding="utf-8"
        )
        return p

    @classmethod
    def from_payload(cls, payload: dict) -> "VectorStore | None":
        """从 :meth:`to_payload` 的结构还原。版本不符或缺词频表返回 ``None``。"""
        meta = payload.get("meta") or {}
        if meta.get("version") != 3:
            # 版本不匹配 = 旧版纯余弦索引，没有词频表，必须重建
            return None
        vs = cls(dim=int(meta.get("dim") or 2048))
        vs.meta = meta
        vs.df = Counter(payload.get("df") or {})
        for rec in payload.get("items") or []:
            pid = str(rec.get("id") or "")
            if not pid:
                continue
            vs.items[pid] = IndexedPOC(pid, list(rec.get("v") or []), dict(rec.get("m") or {}))

        tokens = payload.get("tokens") or {}
        if not tokens:
            return None  # 没有词频表 → BM25 不可用，强制重建
        for pid, rec in tokens.items():
            vs._doc_tokens[pid] = Counter(rec.get("tf") or {})
            vs._doc_len[pid] = int(rec.get("len") or 0)
        return vs if vs.items and vs._doc_tokens else None

    @classmethod
    def load(cls, path: str | Path) -> "VectorStore | None":
        p = Path(path)
        if not p.is_file():
            return None
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(payload, dict):
            return None
        return cls.from_payload(payload)

    def __len__(self) -> int:
        return len(self.items)


# ── 索引构建入口 ──────────────────────────────────────────────────


def build_index(
    poc_dir: str | Path,
    db_path: str | Path,
    dim: int = 2048,
    boost_terms: int = 3,
) -> tuple[VectorStore, list[str]]:
    """扫描 ``poc_dir`` 下所有 YAML，构建并保存索引。

    返回 ``(store, errors)``——单个文件坏掉不应该让整次索引失败，
    错误收集起来交给上层打印。
    """
    from detectors.poc_loader import load_poc_dir  # 延迟导入避免循环

    pocs, errors = load_poc_dir(poc_dir)
    store = VectorStore(dim=dim)
    for p in pocs:
        store.add(p, boost_terms=boost_terms)
    store.finalize()
    store.save(db_path)
    return store, errors


def index_is_stale(poc_dir: str | Path, db_path: str | Path) -> bool:
    """索引是否过期——任何一个 YAML 比索引新就需要重建。"""
    db = Path(db_path)
    if not db.is_file():
        return True
    db_mtime = db.stat().st_mtime
    d = Path(poc_dir)
    if not d.is_dir():
        return True
    for f in d.rglob("*.yaml"):
        try:
            if f.stat().st_mtime > db_mtime:
                return True
        except OSError:
            continue
    return False


def dump_index_stats(store: VectorStore) -> str:
    """给 CLI ``index`` 命令用的一行摘要。"""
    if not len(store):
        return "索引为空"
    cats: Counter[str] = Counter()
    for i in store.items.values():
        cats[str(i.meta.get("category") or "?")] += 1
    top = "  ".join(f"{k}={v}" for k, v in cats.most_common(6))
    return f"{len(store)} 条 POC  |  维度={store.dim}  |  {top}"