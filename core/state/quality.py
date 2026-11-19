"""证据质量（EvidenceQuality）：把「命中」和「漏洞」分开算。

为什么需要它
------------
原来的判定只有两路输入：POC 规则命中（一次请求）+ LLM 研判置信度。
两者都不可靠——规则命中可能只是软 404 / 通用响应，而 LLM 的 0.95
**是"我对这段证据有把握"的自评，不是"该漏洞为真的概率 95%"**。
把后者当概率用，等于把模型的口气当成证据，这正是误报的主要来源。

所以这里单独拆出一个客观评分器：六个维度、各自独立取证、加权成
``evidence_score``（0~1）。LLM 的置信度只作为**一个降级输入**参与
最终定级，永远不能单独把一条发现抬成已确认。

六个维度与强度分档
------------------
=====================  ======  ================================================
维度                    分值    含义
=====================  ======  ================================================
``response_valid``        5    请求成功、有状态码，不是超时/连接失败
``evidence_complete``    10    状态行/响应头/响应体/URL/长度齐备，可落盘复现
``baseline_different``   20    与随机不存在路径、站点首页基线显著不同（排除通用响应）
``signature_specific``   25    命中的是该 POC 的专属特征，而不是"HTTP 200"这种通用条件
``reproducible``         20    独立复测一次，结论一致
``impact_proven``        20    响应里有能证明实际影响的内容（密钥、passwd、版本回显…）
=====================  ======  ================================================

分档（对应需求里的强度表）：

===========  ========  ==================================================
分档          分数      典型组合
===========  ========  ==================================================
很弱           < 20     只有 HTTP 200
弱             20~39    命中关键词 / 与基线可区分，但无专属特征
中等           40~64    命中专属响应特征
强             65~84    以上 + 独立复测一致
很强           ≥ 85     以上 + 能证明实际安全影响
===========  ========  ==================================================

定级规则（:func:`decide_status`）
--------------------------------
按顺序短路，**顺序本身就是策略**：

1. 响应无效（无状态码 / 请求失败）→ ``REJECTED``
2. 与基线一致（软 404 / 通用页面）→ ``REJECTED``
3. 尝试过复测但没复现 → ``NEEDS_REVIEW``（一次性异常不等于误报）
4. 证据不完整（缺状态行/响应头/正文）→ ``NEEDS_REVIEW``
5. 模型判误报且证据分 < 0.85 → ``NEEDS_REVIEW``（模型只能降级，不能独断）
6. 证据分 ≥ 0.70 且（复测一致 或 影响可证）→ ``CONFIRMED``
7. 证据分 ≥ 0.85 → ``CONFIRMED``
8. 其余 → ``NEEDS_REVIEW``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.state.enums import FindingStatus

# ── 维度定义 ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Dimension:
    """一个证据维度：字段名 / 权重 / 中文标签。"""

    key: str
    points: int
    label: str


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension("response_valid", 5, "响应有效"),
    Dimension("evidence_complete", 10, "证据完整"),
    Dimension("baseline_different", 20, "基线可区分"),
    Dimension("signature_specific", 25, "专属特征"),
    Dimension("reproducible", 20, "独立复测"),
    Dimension("impact_proven", 20, "影响可证"),
)

MAX_POINTS = sum(d.points for d in DIMENSIONS)  # 100

# 分档门槛（含下限）
STRENGTH_BANDS: tuple[tuple[int, str, str], ...] = (
    (85, "very_strong", "很强"),
    (65, "strong", "强"),
    (40, "medium", "中等"),
    (20, "weak", "弱"),
    (0, "very_weak", "很弱"),
)

# 定级门槛
CONFIRM_SCORE = 0.70          # 足以确认的证据分
CONFIRM_WITH_LLM_SCORE = 0.85  # 模型反对时仍要确认所需的更高证据分


@dataclass(slots=True)
class EvidenceQuality:
    """一条发现的客观证据质量。**与 LLM 置信度完全解耦。**

    六个布尔维度即需求里的评估表；``retest_attempted`` 只是记账字段
    （区分"复测失败"和"按非破坏性原则没复测"），不参与打分。
    """

    response_valid: bool = False
    baseline_different: bool = False
    signature_specific: bool = False
    evidence_complete: bool = False
    reproducible: bool = False
    impact_proven: bool = False
    # 记账：是否真的尝试过独立复测。False + reproducible=False = 跳过（如 POST 类）
    retest_attempted: bool = False
    # 反向验证时与基线的相似度（0~1），用于报告里解释"为什么算通用响应"
    baseline_similarity: float = 1.0
    # 复测得到的状态码（-1 表示未复测）
    retest_status: int = -1

    # ── 打分 ──────────────────────────────────────────────────────
    @property
    def points(self) -> int:
        return sum(
            d.points for d in DIMENSIONS if bool(getattr(self, d.key, False))
        )

    @property
    def score(self) -> float:
        """``evidence_score``：0~1 的客观证据质量。"""
        return round(self.points / MAX_POINTS, 4)

    @property
    def strength(self) -> str:
        """档位键：very_weak / weak / medium / strong / very_strong。"""
        p = self.points
        for floor, key, _ in STRENGTH_BANDS:
            if p >= floor:
                return key
        return "very_weak"

    @property
    def strength_label(self) -> str:
        p = self.points
        for floor, _, label in STRENGTH_BANDS:
            if p >= floor:
                return label
        return "很弱"

    # ── 可读化 ────────────────────────────────────────────────────
    def passed(self) -> list[str]:
        return [d.label for d in DIMENSIONS if bool(getattr(self, d.key, False))]

    def gaps(self) -> list[str]:
        """缺哪些维度——报告里"为什么没确认"就靠它。"""
        out: list[str] = []
        for d in DIMENSIONS:
            if bool(getattr(self, d.key, False)):
                continue
            if d.key == "reproducible" and not self.retest_attempted:
                out.append("独立复测（非幂等方法，按非破坏性原则跳过）")
            else:
                out.append(d.label)
        return out

    def summary(self) -> str:
        return f"{self.strength_label}（{self.points}/{MAX_POINTS}）"

    def line(self) -> str:
        """一行六维明细，报告详情段直接贴。"""
        marks = []
        for d in DIMENSIONS:
            ok = bool(getattr(self, d.key, False))
            marks.append(f"{d.label} {'✓' if ok else '✗'}")
        return " · ".join(marks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "response_valid": self.response_valid,
            "baseline_different": self.baseline_different,
            "signature_specific": self.signature_specific,
            "evidence_complete": self.evidence_complete,
            "reproducible": self.reproducible,
            "impact_proven": self.impact_proven,
            "retest_attempted": self.retest_attempted,
            "baseline_similarity": round(self.baseline_similarity, 4),
            "retest_status": self.retest_status,
            # 派生字段一并落盘：报告/JSON 消费方不必自己再实现一遍打分
            "points": self.points,
            "score": self.score,
            "strength": self.strength,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "EvidenceQuality | None":
        if not d or not isinstance(d, dict):
            return None
        return cls(
            response_valid=bool(d.get("response_valid")),
            baseline_different=bool(d.get("baseline_different")),
            signature_specific=bool(d.get("signature_specific")),
            evidence_complete=bool(d.get("evidence_complete")),
            reproducible=bool(d.get("reproducible")),
            impact_proven=bool(d.get("impact_proven")),
            retest_attempted=bool(d.get("retest_attempted")),
            baseline_similarity=float(d.get("baseline_similarity") or 1.0),
            retest_status=int(d.get("retest_status", -1) or -1),
        )


# ── 定级 ──────────────────────────────────────────────────────────


def decide_status(
    quality: "EvidenceQuality | None",
    *,
    verdict: str = "",
    llm_confidence: float = 0.0,
    evidence_score: float | None = None,
) -> tuple[FindingStatus, str]:
    """按证据评分 + 模型结论定级，返回 ``(状态, 理由)``。

    ``quality`` 为 ``None``（例如二次验证被关掉、或旧会话补算）时退回
    ``evidence_score`` 单值判断；连分数都没有时按模型结论保守处理：
    只有 ``true_positive`` 才给 ``CONFIRMED``，其余一律 ``NEEDS_REVIEW``——
    **宁可疑，不轻视**。
    """
    v = (verdict or "").strip().lower()
    score = (
        quality.score if quality is not None
        else max(0.0, min(1.0, float(evidence_score or 0.0)))
    )

    # 1) 响应无效：连 HTTP 都没成功，不存在"证据"
    if quality is not None and not quality.response_valid:
        return FindingStatus.REJECTED, "无效证据：请求失败或没有拿到状态码，无法构成漏洞证据"

    # 2) 反向验证失败：与随机路径/首页基线一致，属于通用响应（软 404 一类）
    if quality is not None and not quality.baseline_different:
        sim = f"{quality.baseline_similarity:.0%}" if quality.baseline_similarity <= 1 else "-"
        return (
            FindingStatus.REJECTED,
            f"反向验证未通过：响应与基线相似度 {sim}，属站点通用响应而非该路径的证据",
        )

    # 3) 复测未复现：可能是抖动/一次性异常，不是"没有漏洞"
    if quality is not None and quality.retest_attempted and not quality.reproducible:
        return (
            FindingStatus.NEEDS_REVIEW,
            "独立复测未复现：首次命中无法在第二次请求中重现，需人工确认",
        )

    # 4) 证据缺项：缺状态行/响应头/正文，复核时无法判断
    if quality is not None and not quality.evidence_complete:
        return (
            FindingStatus.NEEDS_REVIEW,
            "证据不完整：" + "、".join(quality.gaps()[:3]) + "，不足以下结论",
        )

    # 5) 模型判误报：只能把结论压到"待复核"，除非客观证据极强
    if v == "false_positive" and score < CONFIRM_WITH_LLM_SCORE:
        return (
            FindingStatus.NEEDS_REVIEW,
            f"模型判为误报（自评信心 {llm_confidence:.0%}，不是漏洞为真的概率），"
            f"但客观证据分 {score:.2f} 尚未达到可反驳程度，转人工复核",
        )

    # 6) 证据足以确认：高分 + （复测一致 或 影响可证）
    if quality is not None and score >= CONFIRM_SCORE and (
        quality.reproducible or quality.impact_proven
    ):
        why = "独立复测一致" if quality.reproducible else "响应中可证实际影响"
        return FindingStatus.CONFIRMED, f"证据分 {score:.2f}，{why}"

    # 7) 极高证据分可单独确认
    if score >= CONFIRM_WITH_LLM_SCORE:
        return FindingStatus.CONFIRMED, f"证据分 {score:.2f}，达到直接确认门槛"

    # 8) 其余：可疑但不足
    if score <= 0.0 and v not in ("true_positive", "needs_manual", ""):
        return FindingStatus.NEEDS_REVIEW, "证据未评估且模型结论不明确，转人工复核"
    return (
        FindingStatus.NEEDS_REVIEW,
        f"证据分 {score:.2f} 未达确认门槛（{CONFIRM_SCORE:.2f}），"
        f"缺：" + ("、".join(quality.gaps()[:3]) if quality is not None else "证据评估"),
    )


def status_from_evidence(
    quality: "EvidenceQuality | None",
    *,
    verdict: str = "",
    llm_confidence: float = 0.0,
    evidence_score: float | None = None,
) -> FindingStatus:
    """只要状态不要理由（撤销误报时按证据重算用）。"""
    return decide_status(
        quality,
        verdict=verdict,
        llm_confidence=llm_confidence,
        evidence_score=evidence_score,
    )[0]
