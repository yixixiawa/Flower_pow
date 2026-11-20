"""安全验收的数据模型：需求、用例规格、观测结果、六类状态。

六类状态（用户验收规则第一节，不得互相自动转换）::

    UNIT_PASS         单元逻辑测试通过
    INTEGRATION_PASS  跨模块集成测试通过
    SECURITY_PASS     安全边界与绕过测试通过（最高档）
    FAIL              至少一项必要测试失败
    NOT_TESTED        没有执行必要测试
    INCONCLUSIVE      测试结果不足以判断

**NOT_TESTED / INCONCLUSIVE 永远不会被升级成 PASS**——判定函数
:func:`evaluate_case` 里它们是显式的终止分支，不是"没失败就算过"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

UNIT_PASS = "UNIT_PASS"
INTEGRATION_PASS = "INTEGRATION_PASS"
SECURITY_PASS = "SECURITY_PASS"
FAIL = "FAIL"
NOT_TESTED = "NOT_TESTED"
INCONCLUSIVE = "INCONCLUSIVE"

PASS_STATES = (UNIT_PASS, INTEGRATION_PASS, SECURITY_PASS)
ALL_STATES = (UNIT_PASS, INTEGRATION_PASS, SECURITY_PASS, FAIL, NOT_TESTED, INCONCLUSIVE)

# 用例类型 → 全过时对应的状态
KIND_STATUS = {
    "unit": UNIT_PASS,
    "integration": INTEGRATION_PASS,
    "security": SECURITY_PASS,
}


@dataclass(frozen=True)
class Requirement:
    """一条安全需求。severity=P0 时任何非 SECURITY_PASS 都否决整体验收。"""

    id: str
    title: str
    severity: str                 # P0 | P1
    boundary: str                 # 需求要守住的边界（报告"预期结果"用）
    sources: tuple[str, ...]      # 对应源代码文件
    must_be_negative: bool = True  # 是否必须有负向用例


@dataclass(frozen=True)
class CaseSpec:
    """一个测试用例的**规格**。注意预期在这里，不在用例函数里。

    ``expect`` 是结构化预期（点路径 → 值），由 harness 对照观测结果：
    ``values.decision`` / ``http_sent`` / ``network.count`` /
    ``audit.any`` 等。用例函数就算把 assert 全删了，观测不符预期照样 FAIL。
    """

    id: str
    req: str
    name: str
    kind: str                      # unit | integration | security
    fn: str                        # ``模块:函数名``
    expect: dict[str, Any] = field(default_factory=dict)
    negative: bool = False
    min_assertions: int = 1
    sources: tuple[str, ...] = ()
    note: str = ""


@dataclass
class CaseResult:
    """一次真实执行后采集到的**事实**。"""

    spec: CaseSpec
    executed: bool = False
    assertions_total: int = 0
    assertions_passed: int = 0
    failed_labels: list[str] = field(default_factory=list)
    values: dict[str, Any] = field(default_factory=dict)

    # 网络事实（由 gateway 追踪器 / mock server 采集，不是用例自报）
    http_sent: bool = False
    http_hops: list[str] = field(default_factory=list)
    network_hits: list[str] = field(default_factory=list)
    network_hosts: list[str] = field(default_factory=list)
    gateway_ok: bool = True
    ungoverned_sends: list[str] = field(default_factory=list)

    # 审计事实（从落盘 JSONL 增量读取）
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    audit_file_ok: bool = True

    error: str = ""                # 用例执行异常（→ INCONCLUSIVE）
    status: str = NOT_TESTED
    reason: str = ""
    risk: str = ""                 # 尚未覆盖的风险（写进报告）


def grade_requirement(kinds: list[str], statuses: list[str]) -> str:
    """需求级状态。

    **SECURITY_PASS 的语义是"这条需求的安全边界与绕过测试通过了"**，
    不是"这条需求下每条用例都必须是 security 类型"。一条需求通常同时
    有单元、集成、安全三类用例：只要全部通过，且其中至少一条是
    security 类型（安全边界真被验证过），就记 SECURITY_PASS。
    """
    if not statuses:
        return NOT_TESTED
    if FAIL in statuses:
        return FAIL
    if INCONCLUSIVE in statuses:
        return INCONCLUSIVE
    if NOT_TESTED in statuses:
        return NOT_TESTED
    if "security" in kinds and all(s in PASS_STATES for s in statuses):
        # 安全边界用例存在且全部通过 —— 这才是 SECURITY_PASS
        return SECURITY_PASS
    if any(k in ("integration", "security") for k in kinds) and all(
        s in PASS_STATES for s in statuses
    ):
        return INTEGRATION_PASS
    if all(s in PASS_STATES for s in statuses):
        return UNIT_PASS
    return INCONCLUSIVE


def worst_requirement_status(statuses: list[str]) -> str:
    """兼容旧名：只看状态、不看类型的最低档判定。"""
    if not statuses:
        return NOT_TESTED
    if FAIL in statuses:
        return FAIL
    if INCONCLUSIVE in statuses:
        return INCONCLUSIVE
    if NOT_TESTED in statuses:
        return NOT_TESTED
    if all(s == SECURITY_PASS for s in statuses):
        return SECURITY_PASS
    if all(s in (SECURITY_PASS, INTEGRATION_PASS) for s in statuses):
        return INTEGRATION_PASS
    if all(s in PASS_STATES for s in statuses):
        return UNIT_PASS
    return INCONCLUSIVE


__all__ = [
    "UNIT_PASS", "INTEGRATION_PASS", "SECURITY_PASS", "FAIL",
    "NOT_TESTED", "INCONCLUSIVE", "PASS_STATES", "ALL_STATES",
    "KIND_STATUS", "Requirement", "CaseSpec", "CaseResult",
    "worst_requirement_status", "grade_requirement",
]
