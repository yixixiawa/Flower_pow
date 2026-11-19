"""接口测试生命周期权限控制（111.md）。

四个模块的分工：

===================  ==========================================================
``api_policy``       定义命令权限矩阵和默认决策（十条规则 × 六字段）
``request_guard``    执行请求前的权限检查和拒绝控制（七维度识别 + Hybrid 决策）
``test_transaction`` 约束测试对象生命周期（台账按 run_id 分桶）
``audit_logger``     记录允许、拒绝和审批相关事件（JSONL，旁路不阻断）
===================  ==========================================================

对外接口：``from policy import RequestGuard, PolicyAudit, TestLedger``。
"""

from policy.api_policy import (
    COMMAND_FOR_CATEGORY,
    ApiCategory,
    Decision,
    Environment,
    PermissionLevel,
    PolicyDecision,
    PolicyRule,
    RULES,
    decide,
    rule_for_command,
    rules_table_markdown,
)
from policy.audit_logger import PolicyAudit
from policy.request_guard import ClassifiedRequest, GuardContext, RequestGuard, classify_request
from policy.test_transaction import TestLedger, TrackedObject

__all__ = [
    # api_policy
    "RULES", "PolicyRule", "PolicyDecision", "decide", "rule_for_command",
    "rules_table_markdown", "COMMAND_FOR_CATEGORY",
    "ApiCategory", "Decision", "Environment", "PermissionLevel",
    # request_guard
    "RequestGuard", "GuardContext", "classify_request", "ClassifiedRequest",
    # test_transaction
    "TestLedger", "TrackedObject",
    # audit_logger
    "PolicyAudit",
]
