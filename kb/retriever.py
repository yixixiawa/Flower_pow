"""RAG 检索器：从目标指纹召回最相关的 POC。

流程
----
    指纹 + 资产 → 构造检索 query → 向量召回 top_k → (可选) LLM 重排 → 最终 POC 列表

**为什么召回之后还要 LLM 重排？**
纯向量检索是「词袋相似」，它无法理解"目标是 Spring Boot 2.x，
而这条 POC 针对的是 Spring Boot 1.x 的历史版本"这类关系。重排让模型基于
结构化元数据（技术栈 / 版本 / 路径 / 危害）做一次判别，代价是几十毫秒到几秒，
收益是召回顺序显著更准。

**LLM 不可用时的降级**：直接用向量分排序，并额外做一层**硬性技术栈过滤**
——目标明确是 PHP 就把 ``applies_to: [java]`` 的 POC 降权（保留但排后），
因为这类 POC 100% 是噪音。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.config_loader import RAGConfig
from core.state import Category, POC, ScanResult
from kb.indexer import VectorStore, index_is_stale


@dataclass(slots=True)
class Retrieval:
    """一条召回结果。"""

    poc: POC
    score: float
    reason: str = ""
    # LLM 重排后的分数（None 表示未经 LLM）
    rerank_score: float | None = None

    @property
    def final_score(self) -> float:
        return self.rerank_score if self.rerank_score is not None else self.score


@dataclass(slots=True)
class RetrievalResult:
    """一次检索的完整产出——写进会话快照，便于复盘"为什么跑了这些 POC"。"""

    query: str = ""
    results: list[Retrieval] = field(default_factory=list)
    skipped_low_score: int = 0
    demoted_mismatch: int = 0
    demoted_fingerprint: int = 0
    reranked: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def pocs(self) -> list[POC]:
        return [r.poc for r in self.results]

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "results": [
                {
                    "poc_id": r.poc.id,
                    "score": round(r.score, 4),
                    "rerank_score": (
                        round(r.rerank_score, 4) if r.rerank_score is not None else None
                    ),
                    "reason": r.reason,
                }
                for r in self.results
            ],
            "skipped_low_score": self.skipped_low_score,
            "demoted_mismatch": self.demoted_mismatch,
            "demoted_fingerprint": self.demoted_fingerprint,
            "reranked": self.reranked,
            "notes": self.notes,
        }


# 与向量检索互补的关键词信号：这些是强判别词，直接命中给固定加成
_STRONG_TERMS = {
    "spring": ("spring", "springboot", "spring-boot"),
    "java": ("java", "tomcat", "jsp", "jsessionid", "struts", "shiro", "fastjson"),
    "php": ("php", "phpinfo", "cgi", "thinkphp", "laravel"),
    "python": ("django", "flask", "fastapi", "python"),
    "nodejs": ("node", "express", "nuxt", "next.js"),
    "dotnet": ("asp.net", "aspx", "iis"),
    "go": ("gin", "gofiber"),
}

# 通用基线 POC：与技术栈无关、任何 Web 目标都该查、且单次只读 GET 就能判定。
#
# 为什么需要基线集（这是实测踩出来的坑）
# ----------------------------------------
# RAG 检索的本质是"找相似"，而 `.git/config` 泄露、source map 暴露这些
# 漏洞与技术栈毫无关系——它们在向量空间里与任何 Web 指纹都不相似。
# 实测：Spring Boot 目标上 path-git-config 与 path-source-code 的融合得分
# 都是 0.000，两者都落在 top_k 之外被丢弃。扫描器就此漏掉了最该查的两项。
#
# 解决办法不是调大 top_k（那会牺牲精准度），而是把"必查项"显式声明出来。
# 判据：①与技术栈无关 ②单次只读 GET 就能定论 ③命中即高价值。
# 声明方式：在 YAML 里写 ``always_run: true``。
#
# 下面是已声明者的 ID 索引，_add_baseline() 会按此列表并入执行集。
_BASELINE_IDS: list[str] = [
    "path-git-config",       # .git/config —— 可完整还原源码
    "path-env",              # .env —— 数据库口令 / JWT 密钥
    "path-source-code",      # source map —— 前端源码还原
    "path-config-bak",       # 备份配置文件 —— 数据库凭据
    "hdr-server-disclosure", # 版本号泄露 —— 匹配 CVE 的前提
]


def build_query(result: ScanResult) -> str:
    """从扫描状态里拼出检索 query。

    指纹只是第一层；侦察阶段发现的资产（开放端口、JS 端点、目录）
    往往含更强的技术栈信号，要一并喂给检索器。
    """
    bits: list[str] = []
    for fp in result.fingerprints:
        bits.append(fp.target)
        if fp.title:
            bits.append(fp.title)
        if fp.server:
            bits.append(fp.server)
        bits.extend(fp.tech)
        # 只取有信息量的响应头
        for h in ("x-powered-by", "server", "x-aspnet-version", "x-generator"):
            if v := fp.headers.get(h):
                bits.append(v)
        # Cookie 泄露出的框架痕迹
        if sc := fp.headers.get("set-cookie"):
            bits.append(sc[:120])

    for a in result.assets:
        if a.kind == "port":
            bits.append(f"service {a.value}")
        elif a.kind in {"path", "endpoint"}:
            bits.append(a.value)
        elif a.kind == "js":
            bits.append(a.value)
        elif a.kind == "subdomain":
            # 子域本身是"站点名"，直接进 query 帮助有限；但按前缀拆词
            # （dev/api/admin/staging…）能透出环境与角色线索，
            # 这正是 POC 匹配关心的维度。**拆词而不是整串塞进去**，
            # 否则一串 ``a.b.c.example.com`` 只会稀释语义。
            for lb in str(a.value).split(".")[:-2]:
                if lb and lb not in {"www", "static", "cdn"}:
                    bits.append(lb)

    for t in result.tech():
        bits.append(t)

    return " ".join(str(b) for b in bits if b)[:4000]


class Retriever:
    """向量召回 + LLM 重排。"""

    def __init__(self, cfg: RAGConfig, store: VectorStore, pocs: dict[str, POC]) -> None:
        self.cfg = cfg
        self.store = store
        self.pocs = pocs

    @classmethod
    def from_config(
        cls, cfg: RAGConfig, pocs: dict[str, POC], verbose: bool = False
    ) -> tuple["Retriever | None", list[str]]:
        """加载索引；索引缺失或过期时自动重建。

        返回 ``(retriever, errors)``。索引彻底无法构建时 retriever 为 None，
        上层降级为「全量 POC 按严重度排序」。
        """
        from kb.indexer import build_index

        errors: list[str] = []
        db_path = Path(cfg.db_dir) / "poc_index.json"
        store: VectorStore | None = None

        if not index_is_stale(cfg.poc_dir, db_path):
            store = VectorStore.load(db_path)
            if store is None:
                errors.append(f"索引文件损坏，已重建：{db_path}")

        if store is None:
            if verbose:
                print("[kb] 正在构建 POC 向量索引…")
            try:
                store, errs = build_index(
                    cfg.poc_dir, db_path, dim=cfg.dim, boost_terms=cfg.boost_terms
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"索引构建失败：{type(exc).__name__}: {exc}")
                return None, errors
            errors.extend(errs)
            if verbose:
                from kb.indexer import dump_index_stats

                print(f"[kb] 索引完成：{dump_index_stats(store)}")

        return cls(cfg, store, pocs), errors

    # ── 召回 ──────────────────────────────────────────────────────
    def _mismatch_penalty(self, poc: POC, tech: list[str]) -> float:
        """技术栈明显不匹配时给一个乘性惩罚（不直接丢，避免漏报）。"""
        if not poc.applies_to or not tech:
            return 1.0
        poc_tech = set(poc.applies_to)
        if poc_tech & set(tech):
            return 1.0
        # 目标技术栈在强判别表里，且与 POC 声明的技术栈毫无交集
        for t in tech:
            strong = _STRONG_TERMS.get(t)
            if strong and not (poc_tech & set(strong)):
                return 0.35
        return 0.8

    def retrieve(self, result: ScanResult, top_k: int | None = None) -> RetrievalResult:
        query = build_query(result)
        out = RetrievalResult(query=query[:500])
        if not query.strip():
            out.notes.append("无可用指纹/资产，跳过 RAG 检索")
            return out

        tech = result.tech()
        raw = self.store.search(
            query, top_k=max(top_k or self.cfg.top_k, 10) * 3, min_score=0.0
        )

        # 命中强关键词的额外加成
        for poc_id, score in raw:
            poc = self.pocs.get(poc_id)
            if poc is None:
                continue
            # 指纹类不进召回列表——它们是建立目标画像用的工具，
            # 不是漏洞验证项。放进 top_k 会挤掉真正的漏洞 POC
            # （实测：Spring 目标上 fp-backend 排到第4，占掉一个名额）。
            if poc.category is Category.FINGERPRINT:
                out.demoted_fingerprint += 1
                continue
            hay = f"{poc.name} {' '.join(poc.tags)} {' '.join(poc.applies_to)}".lower()
            bonus = 0.0
            for t in tech:
                for term in _STRONG_TERMS.get(t, ()):
                    if term in hay:
                        bonus += 0.06
            penalty = self._mismatch_penalty(poc, tech)
            final = (score + bonus) * penalty
            if penalty < 1.0:
                out.demoted_mismatch += 1
            reason = f"向量相似度 {score:.3f}"
            if bonus:
                reason += f" + 技术栈关键词 +{bonus:.2f}"
            if penalty < 1.0:
                reason += f" × 技术栈不匹配 {penalty:.2f}"
            if final >= self.cfg.min_score:
                out.results.append(Retrieval(poc=poc, score=final, reason=reason))
            else:
                out.skipped_low_score += 1

        out.results.sort(key=lambda r: r.final_score, reverse=True)
        limit = top_k or self.cfg.top_k
        out.results = out.results[:limit]

        # ── 基线集兜底 ───────────────────────────────────────────
        # 纯 RAG 的固有盲区：`.git/config` 泄露、source map 暴露这类漏洞
        # **与技术栈无关**。任何检索都召不回它们（实测在 Spring 目标上
        # 得分为 0，落在 top_k 之外），但它们恰恰是最该查的。
        # 所以：标记了 always_run 的 POC 无条件并入，不占 top_k 名额。
        baseline = self._add_baseline(out, tech, limit)
        if baseline:
            out.notes.append(f"并入 {len(baseline)} 条通用基线 POC（与技术栈无关的必查项）")

        return out

    def _add_baseline(
        self, out: RetrievalResult, tech: list[str], limit: int
    ) -> list[POC]:
        """把基线 POC 并入结果。

        判定``always_run`` 声明或命中 ID 索引——两者取或，
        这样新增基线 POC 时既可以改 YAML（推荐），也可以临时加 ID。
        """
        chosen: list[POC] = []
        existing = {r.poc.id for r in out.results}
        for poc_id, poc in self.pocs.items():
            if poc_id in existing:
                continue
            is_header_check = poc.category is Category.HEADER_CHECK
            if not (poc.always_run or poc_id in _BASELINE_IDS or is_header_check):
                continue
            if poc.category is Category.FINGERPRINT or poc.intrusive:
                continue
            # 基线 POC 若明确声明了技术栈且与目标完全不匹配，跳过
            if poc.applies_to and tech and self._mismatch_penalty(poc, tech) < 0.5:
                continue
            reason = (
                "通用基线（与技术栈无关的必查项）"
                if poc_id in _BASELINE_IDS or poc.always_run
                # 响应头检查类永远必查：判断"CSP 是否缺失"与目标是什么技术栈
                # 毫无关系，它问的是"这个头在不在"，任何 Web 目标都该查。
                # 实测：这类 POC 在向量空间的得分是 0.000（name/description
                # 里根本没有 set-cookie / httponly 这类响应头关键词），
                # 靠检索永远召不回来。
                else f"响应头检查类（{poc.category.value}，无条件必查）"
            )
            out.results.append(
                Retrieval(
                    poc=poc,
                    score=self.cfg.min_score,  # 恰好卡在阈值上，排在召回结果之后
                    reason=reason,
                )
            )
            chosen.append(poc)
        return chosen

    # ── LLM 重排 ──────────────────────────────────────────────────
    def rerank_with_llm(
        self,
        retr: RetrievalResult,
        target: str,
        profile: str,
        llm_client: object | None,
    ) -> RetrievalResult:
        """让LLM 基于结构化元数据重排。

        ``llm_client`` 为 None 或不可用时直接返回原排序（静默降级）。
        """
        client = llm_client
        if client is None or not getattr(client, "available", False):
            retr.notes.append("LLM 未配置，重排跳过（沿用向量排序）")
            return retr
        if not self.cfg.rerank_with_llm or not retr.results:
            return retr
        try:
            ranked = client.rerank_pocs(target, profile, retr.results)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            retr.notes.append(f"LLM 重排失败，回退向量排序：{type(exc).__name__}")
            return retr

        if not ranked:
            retr.notes.append("LLM 重排返回空结果，回退向量排序")
            return retr

        by_id = {r.poc.id: r for r in retr.results}
        new: list[Retrieval] = []
        for poc_id, score in ranked.items():
            r = by_id.get(poc_id)
            if r is None:
                continue
            r.rerank_score = max(0.0, min(1.0, float(score)))
            r.reason += f" | LLM 重排 {r.rerank_score:.2f}"
            new.append(r)
        if not new:
            return retr
        new.sort(key=lambda r: r.final_score, reverse=True)
        retr.results = new
        retr.reranked = True
        return retr