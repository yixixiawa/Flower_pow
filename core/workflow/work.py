"""Work 阶段：执行**已被确认**的计划，每一步仍然过原有闸门。

这里最容易犯的错，是把"用户确认了计划"当成"所有操作都放行"。所以本模块
每次执行只做三件事：**核对（计划/文件/票据）→ 逐步调用 → 记账**，
从不修改任何权限状态，也不给 Runner 传任何"已批准"的标记：

* 计划里的 ``http_request`` 步骤照旧过 ``RequestGuard`` 与统一 Gateway：
  L3 照样拒、UNKNOWN 照样拒、生产环境照样拒、删除照样查台账；
* 计划里的本地工具只认**本会话已授权**的 ``file_id``；
* 每步一条 ``work_step`` 审计事件，另加 ``work_start`` / ``work_end``，
  被拦的步骤连"拒绝原因"一起落盘。

失败语义按依赖走：某步被拦/失败，**只有依赖它的步骤**跳过并标记原因，
不相关步骤继续——一次性把整份计划全废掉，会让"第 5 步失败"这种局部问题
退化成"什么都没测"。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.files.tools import LOCAL_TOOLS, run_local_tool
from core.workflow.approval import PlanApprovalLedger
from core.workflow.plan import Plan, WorkflowState

# Runner 用这些前缀表达"没执行/执行失败"，Work 据此判定步骤状态
_BLOCKED_PREFIXES = ("【已拦截】", "【未知工具】", "【不可用】")
_FAILED_PREFIXES = ("【执行失败】", "【参数不合法】", "【解析失败】")


class WorkDenied(Exception):
    """计划不能执行（未确认/变更/文件变化/过期/跨会话）。"""


@dataclass(slots=True)
class StepResult:
    no: int
    title: str
    tool: str
    status: str          # ok | blocked | failed | skipped
    output: str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "no": self.no, "title": self.title, "tool": self.tool,
            "status": self.status,
            # 输出截断后再落报告：审计文件是长期留存的，不该被长正文撑爆
            "output": self.output[:2000], "elapsed": round(self.elapsed, 3),
        }


@dataclass(slots=True)
class WorkReport:
    plan_id: str
    session_id: str
    state: WorkflowState
    steps: list[StepResult] = field(default_factory=list)
    reason: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def ok(self) -> bool:
        return self.state is WorkflowState.COMPLETED

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for st in self.steps:
            out[st.status] = out.get(st.status, 0) + 1
        return out

    def audit_summary(self) -> str:
        c = self.counts()
        parts = [f"{k} {v}" for k, v in sorted(c.items())]
        head = f"计划 {self.plan_id} → {self.state.value}"
        body = "、".join(parts) if parts else "无步骤"
        tail = f"；原因：{self.reason}" if self.reason else ""
        return f"{head}（{body}）{tail}"

    def render(self) -> str:
        lines = [f"执行结果：{self.state.value}"]
        for st in self.steps:
            lines.append(f"  {st.no}. [{st.status}] {st.title}（{st.tool}，{st.elapsed:.2f}s）")
            first = (st.output or "").strip().splitlines()
            if first:
                lines.append(f"       {first[0][:180]}")
        if self.reason:
            lines.append(f"  说明：{self.reason}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id, "session_id": self.session_id,
            "state": self.state.value, "reason": self.reason,
            "steps": [st.to_dict() for st in self.steps],
            "counts": self.counts(),
            "started_at": self.started_at, "finished_at": self.finished_at,
        }


class WorkRunner:
    """执行一份已确认的计划。**并发安全**：状态全在参数与实例里。"""

    def __init__(
        self, session, runner, *, approvals: PlanApprovalLedger, audit,
        now=None,
    ) -> None:
        self.session = session
        self.runner = runner
        self.approvals = approvals
        self.audit = audit
        self._now = now or time.time

    # ── 入口 ──────────────────────────────────────────────────────
    async def run(self, plan: Plan, token: str) -> WorkReport:
        self._verify(plan, token)
        return await self._execute(plan)

    # ── 执行前核对 ────────────────────────────────────────────────
    def _verify(self, plan: Plan, token: str) -> None:
        if plan.session_id != self.session.session_id:
            raise WorkDenied(
                f"计划属于会话 {plan.session_id}，当前会话是 {self.session.session_id}："
                "跨会话的计划不能执行"
            )
        if plan.state is not WorkflowState.AWAITING_APPROVAL:
            raise WorkDenied(
                f"计划当前状态是 {plan.state.value}，不是待确认状态："
                "只能执行已确认（AWAITING_APPROVAL → APPROVED）的计划"
            )
        if plan.is_expired(now=self._now()):
            plan.transition(WorkflowState.EXPIRED)
            self._audit_plan("deny", plan, "计划已过期（超过有效期，需重新分析并确认）")
            raise WorkDenied(
                f"计划已过期（有效期至 {time.strftime('%H:%M:%S', time.localtime(plan.expires_at))}）："
                "请重新生成并确认"
            )

        # 文件内容必须与计划冻结的一致——否则分析结论已经不成立了
        changed: list[str] = []
        for f in plan.files:
            fid = f.get("file_id", "")
            ok, why = self.session.files.access.verify(fid)
            if not ok:
                changed.append(why)
        if changed:
            plan.transition(WorkflowState.EXPIRED)
            self._audit_plan("deny", plan, "输入文件已变化：" + "；".join(changed))
            raise WorkDenied(
                "输入文件内容已变化，旧计划失效（需重新分析后再确认）："
                + "；".join(changed)
            )

        ok, why = self.approvals.consume(
            token, plan_id=plan.plan_id, plan_digest=plan.digest(),
            session_id=self.session.session_id,
        )
        if not ok:
            self._audit_plan("deny", plan, why)
            raise WorkDenied(f"计划未获有效确认：{why}")

    # ── 执行 ──────────────────────────────────────────────────────
    async def _execute(self, plan: Plan) -> WorkReport:
        plan.transition(WorkflowState.APPROVED)
        plan.transition(WorkflowState.EXECUTING)
        report = WorkReport(
            plan_id=plan.plan_id, session_id=plan.session_id, state=WorkflowState.EXECUTING,
        )
        self._audit_plan("allow", plan, f"开始执行（{len(plan.steps)} 步）", event="work_start")

        bad: set[int] = set()
        for step in plan.steps:
            blocked_by = [d for d in step.depends_on if d in bad]
            if blocked_by:
                res = StepResult(
                    no=step.no, title=step.title, tool=step.tool, status="skipped",
                    output=f"依赖的步骤 {blocked_by} 未成功，跳过本步（未发出任何请求）",
                )
                report.steps.append(res)
                self._audit_step(plan, res)
                bad.add(step.no)
                continue

            started = time.perf_counter()
            try:
                out = await self._run_step(step)
            except Exception as exc:  # noqa: BLE001 - 单步异常不能炸掉整份计划
                out = f"【执行失败】{type(exc).__name__}: {exc}"
            elapsed = time.perf_counter() - started
            status = _status_of(out)
            res = StepResult(
                no=step.no, title=step.title, tool=step.tool, status=status,
                output=out or "", elapsed=elapsed,
            )
            report.steps.append(res)
            self._audit_step(plan, res)
            if status != "ok":
                bad.add(step.no)
                if not report.reason:
                    report.reason = f"第 {step.no} 步「{step.title}」{_why_label(status)}：{_first_line(out)}"

        report.finished_at = self._now()
        final = WorkflowState.FAILED if any(
            st.status in ("blocked", "failed") for st in report.steps
        ) else WorkflowState.COMPLETED
        plan.transition(final)
        report.state = final
        self._audit_plan(
            "allow" if final is WorkflowState.COMPLETED else "deny",
            plan,
            f"执行结束：{report.audit_summary()}", event="work_end",
        )
        return report

    async def _run_step(self, step) -> str:
        if step.tool in LOCAL_TOOLS:
            # 本地只读：不经目标策略矩阵（它没有"目标"），但只认已授权 file_id
            return run_local_tool(step.tool, dict(step.args), self.session)
        # 面向目标的工具：一律走 Runner 的统一入口（策略矩阵 + 统一 Gateway）
        return await self.runner.execute(step.tool, dict(step.args), self.session)

    # ── 审计 ──────────────────────────────────────────────────────
    def _audit_plan(self, decision: str, plan: Plan, reason: str, *, event: str = "work") -> None:
        self._log(
            event, plan, reason=reason, decision=decision,
            extra={"plan_id": plan.plan_id},
        )

    def _audit_step(self, plan: Plan, res: StepResult) -> None:
        self._log(
            "work_step",
            plan,
            reason=f"步骤 {res.no} {res.status}：{_first_line(res.output)}",
            command=res.tool,
            decision=res.status,
            extra={"plan_id": plan.plan_id, "step": res.no, "tool": res.tool},
        )

    def _log(self, event: str, plan: Plan, *, reason: str, command: str = "",
             decision: str = "", extra: dict | None = None) -> None:
        """审计是旁路：写失败也不许把执行链炸断（但会被 ``writable`` 反映）。"""
        try:
            result = self.session.result
            self.audit.log(
                event,
                command=command or "计划执行",
                decision=decision,
                target_id=getattr(result, "target_id", "") or "",
                run_id=getattr(result, "current_run_id", "") or "",
                reason=reason,
                extra={"session_id": plan.session_id, **(extra or {})},
            )
        except Exception:  # noqa: BLE001
            pass


def _status_of(output: str) -> str:
    text = (output or "").lstrip()
    if text.startswith(_BLOCKED_PREFIXES):
        return "blocked"
    if text.startswith(_FAILED_PREFIXES):
        return "failed"
    return "ok"


def _why_label(status: str) -> str:
    return {"blocked": "被策略拦截", "failed": "执行失败", "skipped": "被跳过"}.get(status, status)


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:300]
    return ""
