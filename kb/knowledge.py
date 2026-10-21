"""知识库沉淀：把扫描发现回灌成可检索的知识。

为什么需要这一层
----------------
``kb/indexer.py`` 原本是**单向**的：人写 ``poc/*.yaml`` → 建索引 → 检索。
扫描结果只流向 ``output/`` 和 ``data/sessions/``，终点是文件，不是知识。
这意味着：

* 同一个站反复测，每次都要从头踩一遍坑；
* 花了代价得到的真实证据（"这个站 Actuator 没开"）留不下来。

这一层补上「扫描发现 → 知识」的回写，形成闭环。

三条硬约束（都是为了不把知识库喂脏）
------------------------------------
1. **只沉淀确认过的**：``confirmed=True`` 且``verdict != false_positive``。
   未经研判的原始命中里false positive 占比很高，直接入库等于负样本污染召回。
2. **独立索引文件**：``knowledge_index.json``，与 ``poc_index.json`` 分开。
   混在一起会破坏 ``index_is_stale`` 基于 YAML mtime 的过期判定。
3. **去重靠指纹**：同一站同一类型同一路径的发现只留一条，
   重复测试不会把库撑爆，也不会让同一条知识霸占 top_k。

与TF-IDF 的兼容性
-----------------
索引的 IDF 依赖全局文档数与全局 df，所以**任何写入后都必须整体重算**
（``finalize()``）。几千条规模下这是毫秒级，不需要增量倒排索引。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from core.state import Finding, Severity
from kb.indexer import VectorStore

KNOWLEDGE_VERSION = 1

# 只有这些等级值得沉淀。INFO 是「观察」不是「漏洞」，沉淀它只会稀释召回。
DEFAULT_MIN_SEVERITY = Severity.MEDIUM
# 默认要求 LLM 研判确认过（confidence >= 0.6），否则标记为待人工复核
DEFAULT_MIN_CONFIDENCE = 0.6
# 单库容量上限：超了按时间淘汰最旧的（避免无限膨胀）
DEFAULT_MAX_ENTRIES = 2000


def _fingerprint(f: Finding, target: str = "") -> str:
    """知识指纹：同一站 + 同一类型 + 同一位置 → 同一个指纹。

    刻意**不含** severity 与 matched_at：同一个洞在不同时间扫出来应当
    合并成一条，而不是每次都新增。
    """
    loc = (f.matched_at or "").split("?")[0].rstrip("/")
    raw = f"{target}|{f.poc_id}|{f.category.value if hasattr(f.category, 'value') else f.category}|{loc}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def finding_to_record(
    f: Finding,
    target: str = "",
    *,
    min_severity: Severity = DEFAULT_MIN_SEVERITY,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    require_triage: bool = False,
) -> dict[str, Any] | None:
    """把一条发现转成知识记录；不合格返回 ``None``。

    门控条件（任一不满足即拒绝）：
    * ``confirmed`` 为真
    * ``verdict`` 不是 ``false_positive``
    * 等级不低于 ``min_severity``
    * 有证据（``matched_at`` 非空）——没有位置的「知识」检索时毫无用处

    ``require_triage=True`` 时额外要求 ``confidence >= min_confidence``
    （**不做 falsy 豁免**）。用于「本次没跑研判」的场景：此时所有
    ``confidence`` 都是 0，若按默认规则会被``if f.confidence and ...`` 的
    falsy 判断整体放过，等于把未过滤的原始命中全灌进知识库。
    """
    sev = f.severity if isinstance(f.severity, Severity) else Severity.parse(str(f.severity))
    if sev.rank < min_severity.rank:
        return None
    # 人工排除为误报的一律不沉淀。**必须显式判 dismissed**：人工排除刻意
    # 不改 verdict/confirmed（那两个是探针与 LLM 的客观结论，改了撤销就有损），
    # 所以只靠下面两条是拦不住人工排除项的。
    if getattr(f, "dismissed", False):
        return None
    if not f.confirmed:
        return None
    if (f.verdict or "").strip().lower() == "false_positive":
        return None
    if not (f.matched_at or "").strip():
        return None
    if require_triage:
        # 严格：0 也算不达标
        if f.confidence < min_confidence:
            return None
    elif f.confidence and f.confidence < min_confidence:
        # 宽松：有研判结果时才校验门槛；confidence=0 视为「未研判」，
        # 此时靠等级+证据位置把关（调用方若不能接受，应开require_triage）
        return None

    cat = f.category.value if hasattr(f.category, "value") else str(f.category)
    parts = [
        f"{f.name}（{sev.label}）",
        f"分类 {cat}",
        f"位置 {f.matched_at}",
        f.description or "",
        f.rationale or "",
        f"检测器 {f.detector}",
        " ".join(f.tags or []),
    ]
    if target:
        parts.insert(0, f"目标 {target}")
    if f.cve:
        parts.append("CVE " + " ".join(f.cve))
    if f.remediation:
        parts.append(f"修复建议 {f.remediation}")

    return {
        "id": _fingerprint(f, target),
        "text": "\n".join(p for p in parts if p),
        "meta": {
            "kind": "finding",
            "poc_id": f.poc_id,
            "name": f.name,
            "severity": sev.value,
            "category": cat,
            "detector": f.detector,
            "target": target,
            "matched_at": f.matched_at,
            "verdict": f.verdict or "",
            "confidence": f.confidence,
            "tags": list(f.tags or []),
            "cve": list(f.cve or []),
            "ingested_at": time.time(),
        },
        # 技术栈与分类是最强匹配信号，参考 POC 的加权做法
        "boost_texts": [cat, *(f.tags or []), *(f.cve or [])],
    }


@dataclass
class IngestReport:
    """一次沉淀的结果统计。"""

    scanned: int = 0
    accepted: int = 0
    rejected_low_severity: int = 0
    rejected_unconfirmed: int = 0
    rejected_false_positive: int = 0
    rejected_dismissed: int = 0   # 人工排除为误报（与 LLM 判误报分开统计）
    rejected_no_evidence: int = 0
    rejected_low_confidence: int = 0
    updated: int = 0# 已存在→更新的条数
    evicted: int = 0          # 因超容量被淘汰的条数

    def line(self) -> str:
        parts = [f"扫描 {self.scanned} 条，入库 {self.accepted} 条"]
        if self.updated:
            parts.append(f"（其中更新 {self.updated} 条）")
        bits = [
            ("等级不足", self.rejected_low_severity),
            ("未确认", self.rejected_unconfirmed),
            ("误报", self.rejected_false_positive),
            ("人工排除", self.rejected_dismissed),
            ("无证据", self.rejected_no_evidence),
            ("置信度低", self.rejected_low_confidence),
        ]
        detail = "、".join(f"{k} {v}" for k, v in bits if v)
        if detail:
            parts.append(f"，过滤 {detail}")
        if self.evicted:
            parts.append(f"，淘汰 {self.evicted} 条")
        return " ".join(parts)


class KnowledgeStore:
    """扫描发现沉淀库（独立索引文件，不与 POC 混用）。"""

    def __init__(
        self,
        db_path: str | Path,
        dim: int = 2048,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self.db_path = Path(db_path)
        self.dim = dim
        self.max_entries = max_entries
        self.store = VectorStore(dim=dim)   # 空store，待载入或首次写入
        self.records: dict[str, dict] = {}   # id -> 知识正文（供展示/导出）
        self._loaded = False

    # ── 载入 / 保存 ───────────────────────────────────────────────
    @classmethod
    def open(
        cls,
        db_path: str | Path,
        dim: int = 2048,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> "KnowledgeStore":
        ks = cls(db_path, dim, max_entries=max_entries)
        ks._load()
        return ks

    def _load(self) -> None:
        self._loaded = True
        if not self.db_path.is_file():
            return
        try:
            payload = json.loads(self.db_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if int(payload.get("version") or 0) != KNOWLEDGE_VERSION:
            return# 版本不符直接当空库，避免读坏数据
        self.records = dict(payload.get("records") or {})
        vs = VectorStore.from_payload(payload.get("index") or {})
        if vs is not None:
            self.store = vs

    def save(self) -> Path:
        vs = self.store
        vs.finalize()
        p = self.db_path
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": KNOWLEDGE_VERSION,
            "meta": {
                "saved_at": time.time(),
                "dim": self.dim,
                "count": len(self.records),
            },
            "records": self.records,
            "index": vs.to_payload(),
        }
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return p

    # ── 写入 ──────────────────────────────────────────────────────
    def ingest_findings(
        self,
        findings: Iterable[Finding],
        target: str = "",
        *,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        boost_terms: int = 3,
        require_triage: bool = False,
    ) -> IngestReport:
        """把一批发现沉淀进库。返回统计报告。

        ``require_triage=True`` 用于未跑研判的场景（见
        :func:`finding_to_record` 同名参数的说明）。
        """
        if not self._loaded:
            self._load()
        rep = IngestReport()
        pending: list[dict] = []

        for f in findings or []:
            rep.scanned += 1
            sev = f.severity if isinstance(f.severity, Severity) else Severity.parse(str(f.severity))
            # 先做归因统计，便于用户看清「为什么没入库」
            if sev.rank < min_severity.rank:
                rep.rejected_low_severity += 1
                continue
            if getattr(f, "dismissed", False):
                # 人工排除为误报：既不算"未确认"也不算"LLM 判误报"，
                # 单列一档，否则用户会以为是自己研判出的误报。
                rep.rejected_dismissed += 1
                continue
            if not f.confirmed:
                rep.rejected_unconfirmed += 1
                continue
            if (f.verdict or "").strip().lower() == "false_positive":
                rep.rejected_false_positive += 1
                continue
            if not (f.matched_at or "").strip():
                rep.rejected_no_evidence += 1
                continue
            if require_triage:
                if f.confidence < min_confidence:
                    rep.rejected_low_confidence += 1
                    continue
            elif f.confidence and f.confidence < min_confidence:
                rep.rejected_low_confidence += 1
                continue

            rec = finding_to_record(
                f, target,
                min_severity=min_severity,
                min_confidence=min_confidence,
                require_triage=require_triage,
            )
            if rec is None:
                continue
            pending.append(rec)

        # 先全部收集完再写入，避免边遍历边改
        for rec in pending:
            rid = rec["id"]
            existed = rid in self.records
            if existed:
                # 保留首次发现时间，更新最新证据
                old_at = (self.records[rid].get("meta") or {}).get("ingested_at")
                rec["meta"]["ingested_at"] = old_at or rec["meta"]["ingested_at"]
                rec["meta"]["updated_at"] = time.time()
                rep.updated += 1
            self.records[rid] = {"text": rec["text"], "meta": rec["meta"]}
            self.store.add_record(
                rid, rec["text"], rec["meta"],
                boost_texts=rec["boost_texts"], boost_terms=boost_terms,
            )
            rep.accepted += 1

        rep.evicted = self._evict()
        return rep

    def _evict(self) -> int:
        """超容量时按「最近更新」淘汰最旧的。"""
        if self.max_entries <= 0 or len(self.records) <= self.max_entries:
            return 0
        # 每条都可能被更新过，用 updated_at 兜底其次用 ingested_at
        def key(rid: str) -> float:
            m = self.records[rid].get("meta") or {}
            return float(m.get("updated_at") or m.get("ingested_at") or 0.0)

        ordered = sorted(self.records.keys(), key=key)          # 最旧在前
        drop = ordered[: len(self.records) - self.max_entries]
        for rid in drop:
            self.records.pop(rid, None)
            self.store.items.pop(rid, None)
            self.store._doc_tokens.pop(rid, None)
            self.store._doc_len.pop(rid, None)
            # df 必须同步撤回，否则 IDF 残留
            self.store._unaccount_df(rid)
        return len(drop)

    # ── 检索 / 视图 ───────────────────────────────────────────────
    def search(self, text: str, top_k: int = 5, min_score: float = 0.0) -> list[tuple[str, float]]:
        if not self._loaded:
            self._load()
        return self.store.search(text, top_k=top_k, min_score=min_score)

    def recent(self, n: int = 10) -> list[dict]:
        if not self._loaded:
            self._load()
        items = [
            {"id": rid, **rec.get("meta", {})}
            for rid, rec in self.records.items()
        ]
        items.sort(key=lambda d: d.get("updated_at") or d.get("ingested_at") or 0.0, reverse=True)
        return items[:n]

    def __len__(self) -> int:
        return len(self.records)

    def summary(self) -> str:
        if not len(self):
            return "知识库为空（还没有沉淀过扫描发现）"
        cats: dict[str, int] = {}
        sevs: dict[str, int] = {}
        targets: set[str] = set()
        for rec in self.records.values():
            m = rec.get("meta") or {}
            cats[str(m.get("category") or "?")] = cats.get(str(m.get("category") or "?"), 0) + 1
            sevs[str(m.get("severity") or "?")] = sevs.get(str(m.get("severity") or "?"), 0) + 1
            if m.get("target"):
                targets.add(str(m["target"]))
        top_c = " ".join(f"{k}={v}" for k, v in sorted(cats.items(), key=lambda x: -x[1])[:6])
        top_s = " ".join(f"{k}={v}" for k, v in sorted(sevs.items(), key=lambda x: -x[1]))
        return (
            f"{len(self)} 条知识 | {len(targets)} 个目标 | "
            f"等级 {top_s} | 分类 {top_c}"
        )


__all__ = [
    "KnowledgeStore",
    "IngestReport",
    "finding_to_record",
    "KNOWLEDGE_VERSION",
    "DEFAULT_MIN_SEVERITY",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_MAX_ENTRIES",
]
