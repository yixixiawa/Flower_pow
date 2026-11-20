"""计划审批——**一次性的、绑定内容摘要的**确认票据。

和 :class:`policy.test_transaction.ApprovalLedger`（请求级审批）刻意分开：
两者管的不是一件事。

* 请求级审批（``ApprovalLedger``）：**这一次 HTTP 请求**能不能发。
* 计划审批（本模块）：**这份计划**能不能开始执行。它不解锁任何请求——
  Work 里每一步仍然要各自过权限矩阵与统一 Gateway。

所以本票据**不是** L0-L3 的授权，也不该被当成"用户已同意所有操作"的
通行证。三条纪律：

1. **绑定内容摘要**：票面记 ``plan_digest``；计划改了（步骤/目标/文件
   sha256 任一变化）摘要就变，旧票对不上 → 拒绝消费。
2. **单次消费**：消费即作废，重放拒绝（保留票根以便审计区分"重放"与"伪造"）。
3. **绑定会话**：``session_id`` 对不上不消费——A 会话批准的计划不能被
   B 会话拿去执行（并发/多窗口场景）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import uuid4

from core.workflow.plan import Plan, PlanStateError, WorkflowState

PLAN_APPROVAL_TTL = 600.0


@dataclass(slots=True)
class PlanApproval:
    token: str
    plan_id: str
    plan_digest: str
    session_id: str
    approver: str = ""
    authenticated: bool = False
    issued_at: float = 0.0
    expires_at: float = 0.0
    consumed_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "token": self.token, "plan_id": self.plan_id,
            "plan_digest": self.plan_digest, "session_id": self.session_id,
            "approver": self.approver, "authenticated": self.authenticated,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
        }


class PlanApprovalLedger:
    """计划审批票据台账。签发与消费都 fail-closed。"""

    def __init__(self, ttl: float = PLAN_APPROVAL_TTL) -> None:
        self.ttl = ttl
        self._issued: dict[str, PlanApproval] = {}

    def issue(
        self, plan: Plan, *, approver: str = "", authenticated: bool = False,
        ttl: float | None = None,
    ) -> PlanApproval:
        """为人已确认的计划签票。**只接受待确认状态的计划。**"""
        if plan.state is not WorkflowState.AWAITING_APPROVAL:
            raise PlanStateError(
                f"计划当前是 {plan.state.value}，只有 AWAITING_APPROVAL 才能签发票据"
            )
        if not plan.digest():
            raise PlanStateError("计划没有内容摘要，无法签发绑定票据")
        self._purge()
        now = time.monotonic()
        ap = PlanApproval(
            token=uuid4().hex[:16],
            plan_id=plan.plan_id,
            plan_digest=plan.digest(),
            session_id=plan.session_id,
            approver=approver or "",
            authenticated=bool(authenticated and approver),
            issued_at=now,
            expires_at=now + (self.ttl if ttl is None else ttl),
        )
        self._issued[ap.token] = ap
        return ap

    def consume(
        self, token: str, *, plan_id: str, plan_digest: str, session_id: str,
    ) -> tuple[bool, str]:
        """消费一张票。返回 (成功?, 理由)——理由要进审计，可对账。"""
        ap = self._issued.get(token or "")
        if ap is None:
            return False, "计划审批票据不存在（从未签发，或已消费/已清除）"
        if ap.consumed_at:
            return False, "计划审批票据已被消费（一次性，不得重放）"
        now = time.monotonic()
        if now >= ap.expires_at:
            self._issued.pop(token, None)
            return False, "计划审批票据已过期（签发后未及时确认执行）"
        if ap.plan_id != (plan_id or ""):
            return False, f"票据与计划不符：票面 {ap.plan_id} ≠ 计划 {plan_id}"
        if ap.session_id != (session_id or ""):
            return False, (
                f"票据与当前会话不符：票面会话 {ap.session_id} ≠ 当前 {session_id}"
                "（跨会话的计划不能拿来执行）"
            )
        if ap.plan_digest != (plan_digest or ""):
            return False, (
                "计划内容已变更：票据绑定的摘要与当前计划不符"
                "（步骤/目标/文件 sha256 任一变化都会导致重新确认）"
            )
        ap.consumed_at = now
        who = f"{ap.approver}{'（已认证）' if ap.authenticated else '（未认证）'}" if ap.approver else "未记录审批人"
        return True, f"计划审批票据 {ap.token} 消费成功（审批人 {who}）"

    def outstanding(self) -> int:
        self._purge()
        return sum(1 for ap in self._issued.values() if not ap.consumed_at)

    def _purge(self) -> int:
        now = time.monotonic()
        stale = [
            t for t, ap in self._issued.items()
            if now >= ap.expires_at or (ap.consumed_at and now - ap.consumed_at > self.ttl)
        ]
        for t in stale:
            self._issued.pop(t, None)
        return len(stale)
