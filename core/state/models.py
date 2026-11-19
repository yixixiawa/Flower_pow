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

from core.state.enums import Category, FindingStatus, Severity
from core.state.poc import POC
from core.state.quality import EvidenceQuality, decide_status
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
    # ── 三层隔离（Target → ScanRun → Finding）────────────────────
    # 证据必须继承**产生它时的扫描轮次**：换目标或新开一轮扫描后，
    # 旧证据不能再被当成新目标的 PoC 贴进报告（串台事故的真实路径）。
    # 没有显式指定时由 ``ScanResult.add_findings`` 按当前作用域统一打标。
    run_id: str = ""
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
            "run_id": self.run_id,
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
            run_id=str(d.get("run_id") or ""),
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


def _status_from_dict(d: dict[str, Any]) -> FindingStatus:
    """从快照恢复定级，兼容没有 ``status`` 字段的旧快照。

    旧快照里 ``confirmed=False`` 的语义是「模型判了误报、已从正式列表剔除」，
    映射到 ``REJECTED`` 才能保持"口径不变"；缺字段则说明它当时就在正式列表里。
    """
    raw = d.get("status")
    if raw:
        return FindingStatus.parse(raw)
    if "confirmed" in d:
        return FindingStatus.CONFIRMED if d.get("confirmed") else FindingStatus.REJECTED
    return FindingStatus.CONFIRMED


@dataclass(slots=True)
class PendingClue:
    """一条**待验证线索**——被 Finding Validator 拦下的提交。

    为什么不能直接丢掉：模型看到的"可疑现象"往往是真的，只是还没验证到
    能写进报告的程度。丢掉等于让下一轮从头再找；留着并写清缺什么，人工
    或模型补一次就能升级成正式发现。

    为什么不能塞进 ``findings`` 只把 status 设成待复核：两者的**生命周期
    不同**。正式发现要出现在漏洞列表、报告章节、知识库与数量统计里；
    线索只活在会话里，供复核与补填。混在一起，下游任何一处忘了过滤就会
    把线索当成漏洞（"待复核"那一档至少还有证据与定级，线索可能连响应都
    没有）。
    """

    clue_id: str
    created_at: float
    vuln_type: str = ""
    name: str = ""
    severity: str = ""
    url: str = ""
    trigger: str = ""
    raw_request: str = ""
    raw_response: str = ""
    basis: str = ""
    impact: str = ""
    # 拦截原因：缺失/模糊的字段标签 + 逐条明细（报告外可查，便于补填）
    missing: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    # agent = 提交时被拦；report-audit = 导出前复核被拦
    source: str = "agent"
    # pending 待补填 / promoted 已升级为正式发现
    status: str = "pending"
    promoted_to: str = ""

    @property
    def label(self) -> str:
        return f"{self.vuln_type or self.name or '未命名线索'} @ {self.url or '-'}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "clue_id": self.clue_id,
            "created_at": self.created_at,
            "vuln_type": self.vuln_type,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "trigger": self.trigger,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "basis": self.basis,
            "impact": self.impact,
            "missing": list(self.missing),
            "reasons": list(self.reasons),
            "source": self.source,
            "status": self.status,
            "promoted_to": self.promoted_to,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PendingClue":
        return cls(
            clue_id=str(d.get("clue_id") or "clue_unknown"),
            created_at=float(d.get("created_at") or 0.0),
            vuln_type=str(d.get("vuln_type") or ""),
            name=str(d.get("name") or ""),
            severity=str(d.get("severity") or ""),
            url=str(d.get("url") or ""),
            trigger=str(d.get("trigger") or ""),
            raw_request=str(d.get("raw_request") or ""),
            raw_response=str(d.get("raw_response") or ""),
            basis=str(d.get("basis") or ""),
            impact=str(d.get("impact") or ""),
            missing=[str(x) for x in (d.get("missing") or [])],
            reasons=[str(x) for x in (d.get("reasons") or [])],
            source=str(d.get("source") or "agent"),
            status=str(d.get("status") or "pending"),
            promoted_to=str(d.get("promoted_to") or ""),
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
    # ── 三层隔离：Target → ScanRun → Finding ─────────────────────
    # ``target_id`` 目标归属、``run_id`` 扫描归属。为什么不放在 evidence
    # 上就够了：定级、统计、报告过滤都要按作用域算，逐条查 evidence 太脆。
    # 两个都留空 = 旧快照（历史数据），报告过滤时视为属于当前作用域，
    # 不然老会话一恢复就什么都导不出来。
    target_id: str = ""
    run_id: str = ""
    evidence: Evidence | None = None
    references: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    detector: str = "http"
    # RAG 检索得分（用于解释「为什么跑了这条 POC」）
    rag_score: float = 0.0
    # LLM 研判结果
    verdict: str = ""# true_positive | false_positive | needs_manual
    # **模型对自己判断的信心，不是"漏洞为真的概率"**。0.95 只说明模型
    # 对这段证据有把握，和真实的真阳性率没有换算关系——最终定级看 status。
    confidence: float = 0.0
    rationale: str = ""
    # ── 三档定级 + 客观证据质量（见 core/state/quality.py）──────────
    # status 是**唯一权威**：只有 CONFIRMED 进正式报告、计入数量、沉淀知识库。
    # 旧字段 ``confirmed`` 保留为只读属性（= status is CONFIRMED），
    # 免得历史快照与外部脚本读取时炸掉。
    status: FindingStatus = FindingStatus.CONFIRMED
    # 为什么定到这一档（报告附录里逐条列出，复核时可追溯）
    status_reason: str = ""
    # 客观证据分（0~1），由六维加权算出；llm 置信度不参与这个分数
    evidence_score: float = 0.0
    # 六维明细（没跑二次验证的旧快照为 None）
    quality: EvidenceQuality | None = None
    # 二次验证的过程记录：完整性检查/反向验证/复测各自的结论
    verify_notes: list[str] = field(default_factory=list)
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
    # 排除前的定级——撤销时原样恢复（"撤销"就该是撤销，不是重新判一遍）。
    # 旧快照没有这个字段，restore 时退回"按证据重算"。
    status_before_dismiss: str = ""
    # ── 攻击链关联 ──────────────────────────────────────────────
    chain_id: str = ""
    step_index: int = 0
    exploit_payload: str = ""
    # ── 七字段契约里"必须由人/模型判断"的两项 ────────────────────
    # 其余五项能从证据推（URL / 请求 / 响应 / 依据），这两项推不出来：
    # 触发前提与真实影响是结论，不是数据。报告正文会原样展示它们。
    trigger: str = ""
    impact: str = ""
    # ── 准入检查结论 ─────────────────────────────────────────────
    # ``validated`` = 已通过**其适用的**准入检查：手工发现过七字段闸门
    # （core/validation），自动探针过二次验证的证据评分（core/state/quality）。
    # 它只说明"报告所需的信息/证据到位"，**不代表漏洞一定为真**。
    # 旧快照没有这个字段，默认 False：导出前复核会重新判定，不靠一个
    # 可能过期的标记放行。
    validated: bool = False
    validation_note: str = ""

    @property
    def active(self) -> bool:
        """是否仍计入有效发现（未被排除为误报）。"""
        return not self.dismissed

    @property
    def confirmed(self) -> bool:
        """兼容旧字段：是否已确认。**唯一判据是 status**。

        以前这是可写字段，模型判误报就把它置 False，等于让 LLM 直接决定
        "这条不算漏洞"。现在它只读——定级走 :mod:`core.state.quality` 的
        证据评分，模型结论只是其中一个（降级用）输入。
        """
        return self.status is FindingStatus.CONFIRMED

    @property
    def needs_review(self) -> bool:
        return self.status is FindingStatus.NEEDS_REVIEW

    @property
    def rejected(self) -> bool:
        return self.status is FindingStatus.REJECTED

    @property
    def llm_confidence(self) -> float:
        """模型自评信心（语义见 :attr:`confidence`）。"""
        return self.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "name": self.name,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "remediation": self.remediation,
            "matched_at": self.matched_at,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "references": self.references,
            "cve": self.cve,
            "detector": self.detector,
            "rag_score": round(self.rag_score, 4),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rationale": self.rationale,
            # 新三档定级 + 客观证据评分（老消费方读 "confirmed" 仍然可用）
            "status": self.status.value,
            "status_reason": self.status_reason,
            "evidence_score": round(self.evidence_score, 4),
            "quality": self.quality.to_dict() if self.quality else None,
            "verify_notes": self.verify_notes,
            "confirmed": self.confirmed,
            "tags": self.tags,
            "dismissed": self.dismissed,
            "dismiss_reason": self.dismiss_reason,
            "dismissed_at": self.dismissed_at,
            "status_before_dismiss": self.status_before_dismiss,
            "chain_id": self.chain_id,
            "step_index": self.step_index,
            "exploit_payload": self.exploit_payload,
            "trigger": self.trigger,
            "impact": self.impact,
            "validated": self.validated,
            "validation_note": self.validation_note,
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
            target_id=str(d.get("target_id") or ""),
            run_id=str(d.get("run_id") or ""),
            evidence=Evidence.from_dict(d.get("evidence")),
            references=[str(x) for x in (d.get("references") or [])],
            cve=[str(x) for x in (d.get("cve") or [])],
            detector=str(d.get("detector") or "http"),
            rag_score=float(d.get("rag_score") or 0.0),
            verdict=str(d.get("verdict") or ""),
            confidence=float(d.get("confidence") or 0.0),
            rationale=str(d.get("rationale") or ""),
            status=_status_from_dict(d),
            status_reason=str(d.get("status_reason") or ""),
            evidence_score=float(d.get("evidence_score") or 0.0),
            quality=EvidenceQuality.from_dict(d.get("quality")),
            verify_notes=[str(x) for x in (d.get("verify_notes") or [])],
            tags=[str(x) for x in (d.get("tags") or [])],
            # 旧快照没有这三个字段——缺省即"未排除"，向后兼容
            dismissed=bool(d.get("dismissed", False)),
            dismiss_reason=str(d.get("dismiss_reason") or ""),
            dismissed_at=float(d.get("dismissed_at") or 0.0),
            status_before_dismiss=str(d.get("status_before_dismiss") or ""),
            chain_id=str(d.get("chain_id") or ""),
            step_index=int(d.get("step_index") or 0),
            exploit_payload=str(d.get("exploit_payload") or ""),
            trigger=str(d.get("trigger") or ""),
            impact=str(d.get("impact") or ""),
            # 旧快照没有这两项：validated 按 False 处理，导出前会重新校验
            validated=bool(d.get("validated", False)),
            validation_note=str(d.get("validation_note") or ""),
        )


def dismiss_finding(f: Finding, reason: str) -> None:
    """把一条发现标记为误报（可撤销）——同时落到 ``REJECTED`` 档。

    **不动 verdict / confidence**：那两个字段是探针与 LLM 研判的客观结论；
    "人工判定为误报"是另一层信息（谁、何时、为什么），单独记在 dismissed
    三件套里。混着写会让撤销变成有损操作——原来研判出的 true_positive
    一旦被覆盖就找不回来了。

    **要动 status**：三档状态是"这条算不算正式漏洞"的权威口径，
    人工判误报后它必须离开正式列表（否则报告正文还会列出来）。
    撤销时按证据重新算，而不是记住旧值——证据更新后旧值会变陈旧。
    """
    f.dismissed = True
    f.dismiss_reason = (reason or "").strip() or "误报"
    f.dismissed_at = time.time()
    if not f.status_before_dismiss:
        f.status_before_dismiss = f.status.value
    f.status = FindingStatus.REJECTED
    f.status_reason = f"人工判定误报：{f.dismiss_reason}"
    if "dismissed" not in f.tags:
        f.tags.append("dismissed")


def restore_finding(f: Finding) -> None:
    """撤销误报排除，让它重新计入有效发现。

    优先恢复到**排除前记录的档位**（"撤销"的语义就是撤销）；老快照没记过
    那一档时，按当前证据重新算一遍（:func:`core.state.quality.decide_status`），
    而不是硬塞一个 ``CONFIRMED``——那等于绕过证据门槛。
    """
    prev = (f.status_before_dismiss or "").strip()
    f.dismissed = False
    f.dismiss_reason = ""
    f.dismissed_at = 0.0
    f.status_before_dismiss = ""
    f.tags = [t for t in f.tags if t != "dismissed"]
    if prev:
        f.status = FindingStatus.parse(prev)
        f.status_reason = f"撤销人工排除，恢复为排除前的档位：{f.status.label}"
        return
    f.status, f.status_reason = decide_status(
        f.quality,
        verdict=f.verdict,
        llm_confidence=f.confidence,
        evidence_score=f.evidence_score,
    )
    f.status_reason = f"撤销人工排除后按证据重算：{f.status_reason}"


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
class ScanRun:
    """一次扫描任务（三层隔离的第二层：Target → ScanRun → Finding）。

    每次**执行扫描**都开一个新的 run：工具调用、证据、漏洞发现都继承
    当前 run_id。它的价值在于把"这批发现是哪一次扫描跑出来的"变成
    结构化事实，而不是靠"会话没换过目标"这种约定——约定总有被忘记的
    时候（``/target`` 串台事故就是这么来的）。
    """

    run_id: str
    target_id: str
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    # running | done | aborted
    status: str = "running"
    # 人可读的标签（"目标 <url>"、"第 3 轮剧本"……），只用于展示
    label: str = ""

    def finish(self, status: str = "done") -> None:
        self.finished_at = time.time()
        self.status = status

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanRun":
        d = d or {}
        return cls(
            run_id=str(d.get("run_id") or ""),
            target_id=str(d.get("target_id") or ""),
            started_at=float(d.get("started_at") or 0.0),
            finished_at=float(d.get("finished_at") or 0.0),
            status=str(d.get("status") or "done"),
            label=str(d.get("label") or ""),
        )


@dataclass(slots=True)
class ScanResult:
    """一次扫描的完整状态快照——会话文件就是它的序列化。"""

    target: str
    session_id: str = ""
    # ── 三层隔离的作用域字段 ─────────────────────────────────────
    # ``target_id`` 归一后的当前目标；``current_run_id`` 当前扫描轮次。
    # ``runs`` 保存本会话所有扫描任务的台账（含历史轮次，供追溯）。
    # 旧快照没有这些字段——缺省为空，报告过滤按"历史数据放行"处理。
    target_id: str = ""
    current_run_id: str = ""
    runs: list[ScanRun] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    fingerprints: list[Fingerprint] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # ── 待验证线索（被 Finding Validator 拦下的提交）─────────────────
    # **刻意不写进 ``to_dict()``**：那份字典同时是 JSON 报告的正文，
    # 线索按设计不得进入正式报告。快照另走 ``clues_dict()``
    # （见 core/session/session.py），保证"看得到、但不算漏洞"。
    pending_clues: list[PendingClue] = field(default_factory=list)
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

    # ── 三层隔离：Target → ScanRun → Finding ─────────────────────
    def _scope_target(self) -> str:
        return self.target_id or self.target

    def current_run(self) -> ScanRun | None:
        for r in self.runs:
            if r.run_id == self.current_run_id:
                return r
        return None

    def new_run(self, label: str = "") -> ScanRun:
        """开一个新的扫描轮次：之后所有工具调用、证据与发现都归它。

        为什么要 uuid 而不是时间戳：同一秒内可能连开两轮（自动轮询、
        连续切换目标），秒级 id 会撞车，隔离就成了摆设。
        """
        import uuid

        run = ScanRun(
            run_id=uuid.uuid4().hex[:12],
            target_id=self._scope_target(),
            label=label or f"扫描 {self._scope_target()}",
        )
        # 上一轮还没收尾就开新一轮：如实标记为中止，而不是留个假"running"
        prev = self.current_run()
        if prev is not None and prev.status == "running":
            prev.finish(status="aborted")
        self.runs.append(run)
        self.current_run_id = run.run_id
        return run

    def scoped_findings(self) -> list[Finding]:
        """**报告导出的唯一取数口**：只留 target 与 run 都对得上当前
        作用域的发现。

        过滤规则（宽容旧数据）：

        * 发现带 ``target_id`` 且与当前目标不同 → 剔除（串台的主体路径）；
        * 发现带 ``run_id`` 且不是当前轮次 → 剔除（上一轮扫描的残留）；
        * 两个都为空 = 旧快照 / 未打标的历史数据 → 放行，否则老会话
          一恢复就什么都导不出来。

        新数据走 ``add_findings`` 时必然被打上完整标记，所以对新会话
        这等价于严格等值过滤（``target_id == 当前 and run_id == 当前``）。
        """
        cur_t = self._scope_target()
        cur_r = self.current_run_id
        out: list[Finding] = []
        for f in self.findings:
            if f.target_id and cur_t and f.target_id != cur_t:
                continue
            if f.run_id and cur_r and f.run_id != cur_r:
                continue
            out.append(f)
        return out

    def scoped_view(self) -> "ScanResult":
        """报告 writer 专用的浅拷贝视图：findings 过滤到当前作用域。

        浅拷贝意味着 Finding 对象本身是共享的——writer 里的导出前复核
        （改状态、登记线索）仍然写回原对象，会话快照能如实记录；而
        ``counts()`` / ``by_severity()`` / ``to_dict()`` 这些全部基于
        过滤后的列表运算，报告不会再把别的目标/别的轮次算进来。
        """
        import copy

        view = copy.copy(self)
        view.findings = self.scoped_findings()
        return view

    # ── 三档状态：正式列表 vs 待复核 vs 误报 ─────────────────────
    #
    # 口径（与需求一致）：
    #   * ``confirmed_findings()`` —— **唯一**进正式报告、计入漏洞数量、
    #     沉淀知识库的一档；
    #   * ``needs_review_findings()`` —— 有可疑现象但证据不足，单列附录，
    #     **不计入**已确认漏洞数量；
    #   * ``rejected_findings()`` —— 误报/无效命中，保留复核记录（含人工排除项）。
    #
    # ``counts()`` / ``by_severity()`` 只算已确认，报告概览、风险表、状态行
    # 都从这里取数——所以定级一变，所有下游自动跟着变，不需要各处零散过滤。
    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.confirmed and not f.dismissed]

    def needs_review_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.needs_review and not f.dismissed]

    def rejected_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.rejected or f.dismissed]

    def active_findings(self) -> list[Finding]:
        """仍计入有效发现的——即已确认且未被人工排除。"""
        return self.confirmed_findings()

    def dismissed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.dismissed]

    def status_counts(self) -> dict[str, int]:
        """三档计数（dismissed 一律归到 rejected）。"""
        c = {s.value: 0 for s in FindingStatus}
        for f in self.findings:
            if f.dismissed:
                c[FindingStatus.REJECTED.value] += 1
            else:
                c[f.status.value] += 1
        return c

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.confirmed_findings():
            c[f.severity.value] += 1
        return c

    # ── 待验证线索 ────────────────────────────────────────────────
    def active_clues(self) -> list[PendingClue]:
        """仍未升级的线索（已升级的保留记录，但不再需要补填）。"""
        return [c for c in self.pending_clues if c.status != "promoted"]

    def add_clue(self, clue: PendingClue) -> PendingClue:
        """登记线索：同一 ID 覆盖而不是追加。

        为什么覆盖：同一条线索通常会被反复提交（模型补一次、又不全、再补），
        每次追加会在清单里堆出一串同名条目，复核时根本分不清哪条是最新的。
        ``created_at`` 保留**第一次**看到它的时间——那才是"这条线索多久没
        查清"的真实起点。
        """
        for i, old in enumerate(self.pending_clues):
            if old.clue_id == clue.clue_id:
                clue.created_at = old.created_at or clue.created_at
                self.pending_clues[i] = clue
                return clue
        self.pending_clues.append(clue)
        return clue

    def resolve_clue(self, clue_id: str, poc_id: str) -> bool:
        """线索升级为正式发现：打上 promoted，保留原始记录备查。"""
        for c in self.pending_clues:
            if c.clue_id == clue_id:
                c.status = "promoted"
                c.promoted_to = poc_id
                return True
        return False

    def clues_dict(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.pending_clues]

    def by_severity(self) -> dict[str, list[Finding]]:
        """按严重度分组，**只含已确认漏洞**（待复核/误报另有附录）。"""
        out: dict[str, list[Finding]] = {}
        for f in sorted(
            self.confirmed_findings(), key=lambda x: x.severity.rank, reverse=True
        ):
            out.setdefault(f.severity.value, []).append(f)
        return out

    def add_findings(self, incoming: list[Finding], *, restamp: bool = False) -> int:
        """发现进入会话的**唯一收口**：去重 → 打标 → 套用误报排除 → 重排。

        为什么要有这个收口：以前各处直接 ``result.findings.extend(...)``
        （planner 6 处、scheduler、repl 各一处），于是任何"入库策略"都只能
        逐个调用点去打补丁，漏一处就漏一处。误报排除就是被这个坑到的第一个
        策略——本该在第一轮就自动挂上"历史误报"标记的发现，从 planner 那条
        路径进来时会被当成新发现重新报出来。

        ``restamp=True`` 用于**并入外部扫描结果**（如 /auto 把 Scheduler.scan
        的结果并回会话）：那次扫描是代表当前会话执行的，发现归属必须改判到
        当前作用域，否则它们带着扫描任务的 run_id 进来，报告按 run 过滤时
        会被当成"别的轮次"整体漏掉。默认 False——带异构标记进来的发现视为
        串台数据，保留原标记，由报告过滤剔除。

        返回真正新增的条数。
        """
        cur_t = self._scope_target()
        cur_r = self.current_run_id
        seen = {(f.poc_id, f.matched_at) for f in self.findings}
        added = 0
        for f in incoming:
            k = (f.poc_id, f.matched_at)
            if k in seen:
                continue
            seen.add(k)
            # ── 三层隔离打标：发现的归属在**入库时**固定下来 ─────────
            # 这是发现进会话的唯一收口，在这里打标才能保证"漏一处就串台"
            # 不可能发生。已有标记的（显式带作用域进来的）默认不覆盖——
            # 带着别的目标/轮次标记进来的发现，会在报告过滤时被剔除，
            # 而不是被改写归属后混进当前报告；restamp 场景例外（见上）。
            if restamp or not f.target_id:
                f.target_id = cur_t
            if restamp or not f.run_id:
                f.run_id = cur_r
            # 证据同样继承扫描轮次：报告里的报文必须能回答"哪一轮跑出来的"
            if f.evidence is not None and (restamp or not f.evidence.run_id):
                f.evidence.run_id = f.run_id
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
            "target_id": self._scope_target(),
            "current_run_id": self.current_run_id,
            "runs": [r.to_dict() for r in self.runs],
            "session_id": self.session_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 2),
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "assets": [a.to_dict() for a in self.assets],
            "counts": self.counts(),
            "status_counts": self.status_counts(),
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
            target_id=str(d.get("target_id") or ""),
            current_run_id=str(d.get("current_run_id") or ""),
            runs=[ScanRun.from_dict(x) for x in (d.get("runs") or []) if isinstance(x, dict)],
            started_at=float(d.get("started_at") or time.time()),
            finished_at=float(d.get("finished_at") or 0.0),
            fingerprints=[Fingerprint.from_dict(x) for x in (d.get("fingerprints") or [])],
            assets=[Asset(**x) for x in (d.get("assets") or []) if isinstance(x, dict)],
            findings=[Finding.from_dict(x) for x in (d.get("findings") or [])],
            # 线索只来自会话快照（报告 JSON 不含这个键）
            pending_clues=[
                PendingClue.from_dict(x)
                for x in (d.get("pending_clues") or [])
                if isinstance(x, dict)
            ],
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


