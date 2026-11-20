"""Plan / Work 工作流（对话式文件分析的二、三阶段）。

分工与边界：

* :mod:`core.workflow.plan` —— 只读分析 → 结构化计划；步骤校验（禁本地写、
  禁 L3、禁未知工具）；受控状态机
* :mod:`core.workflow.approval` —— **一次性 + 绑定内容摘要 + 绑定会话**的
  计划确认票据（它不是 L0-L3 的权限授权）
* :mod:`core.workflow.work` —— 执行已确认计划；每步仍走原有权限矩阵与
  统一 Gateway；每步落审计；失败按依赖传播
"""

from core.workflow.approval import (
    PLAN_APPROVAL_TTL,
    PlanApproval,
    PlanApprovalLedger,
)
from core.workflow.plan import (
    PLAN_FORBIDDEN_TOOLS,
    PLAN_TTL,
    Plan,
    PlanBuilder,
    PlanError,
    PlanStateError,
    PlanStep,
    WorkflowState,
)
from core.workflow.work import StepResult, WorkDenied, WorkReport, WorkRunner

__all__ = [
    "PLAN_FORBIDDEN_TOOLS", "PLAN_TTL", "PLAN_APPROVAL_TTL",
    "Plan", "PlanStep", "PlanBuilder", "PlanError", "PlanStateError", "WorkflowState",
    "PlanApproval", "PlanApprovalLedger",
    "WorkRunner", "WorkDenied", "WorkReport", "StepResult",
]
