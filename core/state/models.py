"""运行时对象：证据 / 指纹 / 资产 / 发现 / 扫描结果。

原 :mod:`core.state` 的「运行时对象」段。设计约束（证据优先 / 可快照 /
零重依赖）写在门面 :mod:`core.state` 的 docstring 里。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.state.enums import Category, Severity
from core.state.poc import POC
from core.state.util import safe_name


# ── 运行时对象 ────────────────────────────────────────────────────


@dataclass(slots=True)
class Evidence:
    """原始 HTTP 证据——AI 研判与人工复核的唯一依据。"""

    url: str
    method: str = "GET"
    request_line: str = ""
    status_code: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    body_size: int = 0
    elapsed_ms: int = 0
    error: str = ""
    # 证据落盘后的相对路径
    artifact: str = ""
    # ── POC 执行过程（报告里的「怎么执行的」就靠这三个字段）──
    # 触发的 POC 定义 id（manual_ 前缀的表示手工登记）
    poc_id: str = ""
    poc_name: str = ""
    # **实际发出的 payload**：GET 的 query、POST 的 body 都在这里。
    # 报告里必须原样给出，否则对方无法复现。
    payload_sent: str = ""
    # 判定「成立」的依据：命中的规则描述 + 模式
    expected: str = ""
    matched_pattern: str = ""
    # 命中的是第几条规则（多规则时定位用）
    rule_index: int = 0
    # **完整响应体**（运行期专用）：比 body_excerpt 大得多，只用于
    # 命中时落盘完整报文（见 detectors/base.py 的 _persist_evidence）。
    # 刻意**不进 to_dict/from_dict**——会话快照与 JSON 报告不该背着
    # 每条证据几十 KB 的全文；落盘后靠 artifact 路径回读。
    full_body: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "request_line": self.request_line,
            "status_code": self.status_code,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "body_excerpt": self.body_excerpt,
            "body_size": self.body_size,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "artifact": self.artifact,
            "poc_id": self.poc_id,
            "poc_name": self.poc_name,
            "payload_sent": self.payload_sent,
            "expected": self.expected,
            "matched_pattern": self.matched_pattern,
            "rule_index": self.rule_index,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "Evidence | None":
        if not d:
            return None
        return cls(
            url=str(d.get("url") or ""),
            method=str(d.get("method") or "GET"),
            request_line=str(d.get("request_line") or ""),
            status_code=d.get("status_code"),
            request_headers=dict(d.get("request_headers") or {}),
            response_headers=dict(d.get("response_headers") or {}),
            body_excerpt=str(d.get("body_excerpt") or ""),
            body_size=int(d.get("body_size") or 0),
            elapsed_ms=int(d.get("elapsed_ms") or 0),
            error=str(d.get("error") or ""),
            artifact=str(d.get("artifact") or ""),
            poc_id=str(d.get("poc_id") or ""),
            poc_name=str(d.get("poc_name") or ""),
            payload_sent=str(d.get("payload_sent") or ""),
            expected=str(d.get("expected") or ""),
            matched_pattern=str(d.get("matched_pattern") or ""),
            rule_index=int(d.get("rule_index") or 0),
        )

    def fingerprint(self) -> str:
        raw = f"{self.method}|{self.status_code}|{self.body_excerpt[:512]}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]


@dataclass(slots=True)
class Fingerprint:
    """目标指纹——RAG 检索 query 的主要来源。"""

    target: str
    http_status: int | None = None
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        bits = [f"HTTP {self.http_status}"] if self.http_status else []
        if self.title:
            bits.append(f"title={self.title!r}")
        if self.server:
            bits.append(f"server={self.server!r}")
        if self.tech:
            bits.append(f"tech={','.join(self.tech)}")
        return " | ".join(bits) or "no fingerprint"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "http_status": self.http_status,
            "title": self.title,
            "server": self.server,
            "tech": self.tech,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Fingerprint":
        return cls(
            target=str(d.get("target") or ""),
            http_status=d.get("http_status"),
            title=str(d.get("title") or ""),
            server=str(d.get("server") or ""),
            tech=[str(x) for x in (d.get("tech") or [])],
            headers=dict(d.get("headers") or {}),
        )


@dataclass(slots=True)
class Asset:
    """侦察阶段发现的资产（端口 / 目录 / JS / 端点 / 密钥）。"""

    kind: str                # port | path | js | endpoint | secret
    value: str
    meta: dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "meta": self.meta, "source": self.source}


@dataclass(slots=True)
class AttackStep:
    """一个可复核的攻击链步骤：前置条件、动作、证据与结果。"""

    action: str
    finding_id: str = ""
    evidence: str = ""
    result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "finding_id": self.finding_id,
            "evidence": self.evidence,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "AttackStep":
        d = d or {}
        return cls(
            action=str(d.get("action") or ""),
            finding_id=str(d.get("finding_id") or ""),
            evidence=str(d.get("evidence") or ""),
            result=str(d.get("result") or ""),
        )


@dataclass(slots=True)
class AttackChain:
    """多条发现串联后的、可直接放进报告的攻击链。"""

    chain_id: str
    title: str
    entry_point: str
    final_impact: str
    severity: Severity
    steps: list[AttackStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "severity": self.severity.value,
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "AttackChain":
        d = d or {}
        return cls(
            chain_id=str(d.get("chain_id") or ""),
            title=str(d.get("title") or ""),
            entry_point=str(d.get("entry_point") or ""),
            final_impact=str(d.get("final_impact") or ""),
            severity=Severity.parse(d.get("severity") or "info"),
            steps=[AttackStep.from_dict(x) for x in (d.get("steps") or [])],
        )


@dataclass(slots=True)
class Finding:
    """一条漏洞发现。"""

    poc_id: str
    name: str
    severity: Severity
    category: Category
    description: str = ""
    remediation: str = ""
    matched_at: str = ""
    evidence: Evidence | None = None
    references: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    detector: str = "http"
    # RAG 检索得分（用于解释「为什么跑了这条 POC」）
    rag_score: float = 0.0
    # LLM 研判结果
    verdict: str = ""# true_positive | false_positive | needs_manual
    confidence: float = 0.0
    rationale: str = ""
    confirmed: bool = True
    tags: list[str] = field(default_factory=list)
    # ── 人工误报排除 ──────────────────────────────────────────────
    # 为什么不直接 ``del``：报告必须能解释"这条为什么没列出来"。硬删会连
    # "谁在什么时候因为什么判的误报"一起丢掉——复核记录本身就是交付物的一部分。
    # 所以默认是**标记排除**（可 undo），``purge`` 才是物理删除。
    #
    # 公开演示站（如 demo.ikuai8.com 这类"演示用、内容本就公开"的站点）挂出
    # 的所谓"敏感信息"是典型误报，自动探针没法自己判断，只能人工排除。
    dismissed: bool = False
    dismiss_reason: str = ""
    dismissed_at: float = 0.0
    # ── 攻击链关联 ──────────────────────────────────────────────
    chain_id: str = ""
    step_index: int = 0
    exploit_payload: str = ""

    @property
    def active(self) -> bool:
        """是否仍计入有效发现（未被排除为误报）。"""
        return not self.dismissed

    def to_dict(self) -> dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "name": self.name,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "remediation": self.remediation,
            "matched_at": self.matched_at,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "references": self.references,
            "cve": self.cve,
            "detector": self.detector,
            "rag_score": round(self.rag_score, 4),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "confirmed": self.confirmed,
            "tags": self.tags,
            "dismissed": self.dismissed,
            "dismiss_reason": self.dismiss_reason,
            "dismissed_at": self.dismissed_at,
            "chain_id": self.chain_id,
            "step_index": self.step_index,
            "exploit_payload": self.exploit_payload,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            poc_id=str(d.get("poc_id") or ""),
            name=str(d.get("name") or ""),
            severity=Severity.parse(d.get("severity") or "info"),
            category=Category(str(d.get("category") or "content_match")),
            description=str(d.get("description") or ""),
            remediation=str(d.get("remediation") or ""),
            matched_at=str(d.get("matched_at") or ""),
            evidence=Evidence.from_dict(d.get("evidence")),
            references=[str(x) for x in (d.get("references") or [])],
            cve=[str(x) for x in (d.get("cve") or [])],
            detector=str(d.get("detector") or "http"),
            rag_score=float(d.get("rag_score") or 0.0),
            verdict=str(d.get("verdict") or ""),
            confidence=float(d.get("confidence") or 0.0),
            rationale=str(d.get("rationale") or ""),
            confirmed=bool(d.get("confirmed", True)),
            tags=[str(x) for x in (d.get("tags") or [])],
            # 旧快照没有这三个字段——缺省即"未排除"，向后兼容
            dismissed=bool(d.get("dismissed", False)),
            dismiss_reason=str(d.get("dismiss_reason") or ""),
            dismissed_at=float(d.get("dismissed_at") or 0.0),
            chain_id=str(d.get("chain_id") or ""),
            step_index=int(d.get("step_index") or 0),
            exploit_payload=str(d.get("exploit_payload") or ""),
        )


def dismiss_finding(f: Finding, reason: str) -> None:
    """把一条发现标记为误报（可撤销）。

    **不动 verdict / confirmed**：那两个字段是探针与 LLM 研判的客观结论；
    "人工判定为误报"是另一层信息（谁、何时、为什么），单独记在 dismissed
    三件套里。混着写会让撤销变成有损操作——原来研判出的 true_positive
    一旦被覆盖就找不回来了。
    """
    f.dismissed = True
    f.dismiss_reason = (reason or "").strip() or "误报"
    f.dismissed_at = time.time()
    if "dismissed" not in f.tags:
        f.tags.append("dismissed")


def restore_finding(f: Finding) -> None:
    """撤销误报排除，让它重新计入有效发现。"""
    f.dismissed = False
    f.dismiss_reason = ""
    f.dismissed_at = 0.0
    f.tags = [t for t in f.tags if t != "dismissed"]


def _mark_if_excluded(target: str, f: Finding) -> bool:
    """发现入库前套用"历史误报排除清单"，命中就顺手标成已排除。

    为什么在**入库时**标记、而不是在报告层过滤：报告层过滤只能让报告干净，
    会话里这条发现依旧是"有效发现"——``/findings``、状态行、下一轮研判都会
    继续把它当真，用户会以为排除没生效。入库时标记则一次生效、处处一致。

    排除清单读不出来（文件损坏 / 无权限）绝不能让扫描崩掉，所以整段兜底。
    """
    if f.dismissed:
        return True
    try:
        from core.exclusions import match_reason

        reason = match_reason(target, f.poc_id, f.matched_at)
    except Exception:  # noqa: BLE001
        return False
    if reason is None:
        return False
    dismiss_finding(f, reason or "历史误报排除（自动套用）")
    return True


@dataclass(slots=True)
class ScanResult:
    """一次扫描的完整状态快照——会话文件就是它的序列化。"""

    target: str
    session_id: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    fingerprints: list[Fingerprint] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Agent 主动提取并复用的上下文变量，如 jobNumber / authCode / tmpToken。
    context_vars: dict[str, Any] = field(default_factory=dict)
    attack_chains: list[AttackChain] = field(default_factory=list)
    # 调度阶段耗时，用于报告里的"时间都花在哪"
    phases: dict[str, float] = field(default_factory=dict)
    pocs_loaded: int = 0
    pocs_selected: int = 0
    pocs_executed: int = 0
    pocs_skipped: int = 0
    llm_enabled: bool = False
    # 实际使用的模型与调用统计（由 LLMClient.stats() 填充）。
    # 报告里必须留痕：配了 pro 却因拼错名走了 flash 时，这是唯一线索。
    llm_stats: dict[str, Any] = field(default_factory=dict)
    rag_enabled: bool = False
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    # ── 有效发现 vs 已排除（误报）─────────────────────────────────
    #
    # ``counts()`` / ``by_severity()`` 一律**只算有效发现**，报告概览、风险
    # 概览表、状态行都从这里取数——所以排除一条误报后，所有下游自动跟着变，
    # 不需要在各处零散地加过滤条件（加漏一处就会"报告里删了、概览里还在"）。
    # 已排除的发现仍留在 ``findings`` 里，供报告的"误报复核"附录使用。
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.active]

    def dismissed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.dismissed]

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.dismissed:
                continue
            c[f.severity.value] += 1
        return c

    def by_severity(self) -> dict[str, list[Finding]]:
        """按严重度分组，**只含有效发现**（已排除的误报不进报告详情）。"""
        out: dict[str, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda x: x.severity.rank, reverse=True):
            if f.dismissed:
                continue
            out.setdefault(f.severity.value, []).append(f)
        return out

    def add_findings(self, incoming: list[Finding]) -> int:
        """发现进入会话的**唯一收口**：去重 → 套用误报排除 → 重排。

        为什么要有这个收口：以前各处直接 ``result.findings.extend(...)``
        （planner 6 处、scheduler、repl 各一处），于是任何"入库策略"都只能
        逐个调用点去打补丁，漏一处就漏一处。误报排除就是被这个坑到的第一个
        策略——本该在第一轮就自动挂上"历史误报"标记的发现，从 planner 那条
        路径进来时会被当成新发现重新报出来。

        返回真正新增的条数。
        """
        seen = {(f.poc_id, f.matched_at) for f in self.findings}
        added = 0
        for f in incoming:
            k = (f.poc_id, f.matched_at)
            if k in seen:
                continue
            seen.add(k)
            _mark_if_excluded(self.target, f)
            self.findings.append(f)
            added += 1
        self.findings.sort(
            key=lambda x: (x.severity.rank, x.rag_score), reverse=True
        )
        return added

    def tech(self) -> list[str]:
        seen: list[str] = []
        for fp in self.fingerprints:
            for t in fp.tech:
                if t not in seen:
                    seen.append(t)
        return seen

    def assets_of(self, kind: str) -> list[Asset]:
        return [a for a in self.assets if a.kind == kind]

    def add_attack_chain(self, chain: AttackChain) -> AttackChain:
        """新增或替换同 ID 的攻击链，避免模型重复调用造成重复报告。"""
        for index, existing in enumerate(self.attack_chains):
            if existing.chain_id == chain.chain_id:
                self.attack_chains[index] = chain
                return chain
        self.attack_chains.append(chain)
        return chain

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 2),
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "assets": [a.to_dict() for a in self.assets],
            "counts": self.counts(),
            "pocs_loaded": self.pocs_loaded,
            "pocs_selected": self.pocs_selected,
            "pocs_executed": self.pocs_executed,
            "pocs_skipped": self.pocs_skipped,
            "llm_enabled": self.llm_enabled,
            "llm": self.llm_stats,
            "rag_enabled": self.rag_enabled,
            "phases": {k: round(v, 2) for k, v in self.phases.items()},
            "findings": [f.to_dict() for f in self.findings],
            "context_vars": self.context_vars,
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "errors": self.errors,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        r = cls(
            target=str(d.get("target") or ""),
            session_id=str(d.get("session_id") or ""),
            started_at=float(d.get("started_at") or time.time()),
            finished_at=float(d.get("finished_at") or 0.0),
            fingerprints=[Fingerprint.from_dict(x) for x in (d.get("fingerprints") or [])],
            assets=[Asset(**x) for x in (d.get("assets") or []) if isinstance(x, dict)],
            findings=[Finding.from_dict(x) for x in (d.get("findings") or [])],
            context_vars=dict(d.get("context_vars") or {}),
            attack_chains=[AttackChain.from_dict(x) for x in (d.get("attack_chains") or [])],
            phases={str(k): float(v) for k, v in (d.get("phases") or {}).items()},
            pocs_loaded=int(d.get("pocs_loaded") or 0),
            pocs_selected=int(d.get("pocs_selected") or 0),
            pocs_executed=int(d.get("pocs_executed") or 0),
            pocs_skipped=int(d.get("pocs_skipped") or 0),
            llm_enabled=bool(d.get("llm_enabled")),
            llm_stats=dict(d.get("llm") or {}),
            rag_enabled=bool(d.get("rag_enabled")),
            errors=[str(x) for x in (d.get("errors") or [])],
            notes=[str(x) for x in (d.get("notes") or [])],
        )
        return r

    # ── 会话快照 ──────────────────────────────────────────────
    def save(self, sessions_dir: str | Path) -> Path:
        d = Path(sessions_dir)
        d.mkdir(parents=True, exist_ok=True)
        sid = self.session_id or f"{int(self.started_at)}"
        path = d / f"session_{safe_name(self.target)}_{sid}.json"
        path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    @classmethod
    def load(cls, path: str | Path) -> "ScanResult":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


