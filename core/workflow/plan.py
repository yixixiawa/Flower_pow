"""Plan 阶段：只读分析 → 结构化计划 → 等待确认。

**Plan 阶段的只读是结构性的，不是靠提示词。** 三条硬约束：

1. :class:`PlanBuilder` 只读``session.files``里**已授权**的文件，
   全程不调用任何 Runner 工具（不发请求、不写盘、不跑命令）。
   这一点有测试盯着（``spy`` 掉 ``runner.execute`` 断言零调用）。
2. 计划步骤里**不许出现本地写操作**（``write_file`` / ``edit_file`` /
   ``delete_file``）。本工具是扫描器，不是编辑器——"分析完顺手改代码"
   不在它的职责里，禁掉比"允许但要审批"更安全。
3. 步骤里的 L3 工具与未知工具**在构建期就拒**。L3 是永久拒绝，
   把它写进计划等于给用户一个永远执行不了的计划，属于误导。

计划的状态机在 :class:`Plan` 里：``transition()`` 是唯一改状态的方式，
``state`` 是只读 property。所以"跳过审批直接 EXECUTING"在代码层面做不到，
不是"约定不要这么做"。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from uuid import uuid4
from dataclasses import dataclass, field
from enum import Enum

from core.files.tools import LOCAL_TOOLS

# 计划步骤里禁止出现的工具：**本地写操作**。
# 理由见模块文档第 2 条。放在这里而不是散在 builder 里，是为了让
# 测试和文档都引用同一份清单。
PLAN_FORBIDDEN_TOOLS: frozenset[str] = frozenset(
    {"write_file", "edit_file", "delete_file", "report_export"}
)

_RISK_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}
PLAN_TTL = 1800.0  # 计划默认 30 分钟内有效


class PlanError(Exception):
    """计划内容不合法（构建期拒绝）。"""


class PlanStateError(PlanError):
    """非法的状态转换。"""


class WorkflowState(str, Enum):
    CREATED = "CREATED"
    READING = "READING"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


# 允许的边。**没有"任何状态 → EXECUTING"这种捷径**：
# 进 EXECUTING 的唯一路径是 AWAITING_APPROVAL → APPROVED → EXECUTING，
# 而 APPROVED 只能由 WorkRunner 在消费掉审批票据之后打。
_ALLOWED: dict[WorkflowState, frozenset[WorkflowState]] = {
    WorkflowState.CREATED: frozenset({
        WorkflowState.READING, WorkflowState.REJECTED, WorkflowState.EXPIRED,
    }),
    WorkflowState.READING: frozenset({
        WorkflowState.PLANNING, WorkflowState.FAILED,
        WorkflowState.REJECTED, WorkflowState.EXPIRED,
    }),
    WorkflowState.PLANNING: frozenset({
        WorkflowState.AWAITING_APPROVAL, WorkflowState.FAILED,
        WorkflowState.REJECTED, WorkflowState.EXPIRED,
    }),
    WorkflowState.AWAITING_APPROVAL: frozenset({
        WorkflowState.APPROVED, WorkflowState.REJECTED, WorkflowState.EXPIRED,
    }),
    WorkflowState.APPROVED: frozenset({
        WorkflowState.EXECUTING, WorkflowState.EXPIRED,
    }),
    WorkflowState.EXECUTING: frozenset({
        WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.EXPIRED,
    }),
    WorkflowState.COMPLETED: frozenset(),
    WorkflowState.FAILED: frozenset(),
    WorkflowState.REJECTED: frozenset(),
    WorkflowState.EXPIRED: frozenset(),
}


@dataclass(slots=True)
class PlanStep:
    """计划里的一步。``depends_on`` 是步骤编号（失败后依赖它的步骤跳过）。"""

    no: int
    title: str
    tool: str
    args: dict = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    risk: str = "L0"
    needs_extra_auth: bool = False
    depends_on: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "no": self.no, "title": self.title, "tool": self.tool,
            "args": dict(self.args), "files": list(self.files),
            "risk": self.risk, "needs_extra_auth": self.needs_extra_auth,
            "depends_on": list(self.depends_on),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PlanStep":
        return cls(
            no=int(d.get("no") or 0),
            title=str(d.get("title") or ""),
            tool=str(d.get("tool") or ""),
            args=dict(d.get("args") or {}),
            files=[str(x) for x in (d.get("files") or [])],
            risk=str(d.get("risk") or "L0"),
            needs_extra_auth=bool(d.get("needs_extra_auth")),
            depends_on=[int(x) for x in (d.get("depends_on") or [])],
        )


class Plan:
    """一份待确认/已确认的执行计划。

    ``state`` 是只读 property：只能通过 :meth:`transition` 改，
    且只能在 :data:`_ALLOWED` 允许的边上改。
    """

    def __init__(
        self,
        plan_id: str,
        session_id: str,
        goal: str,
        *,
        steps: list[PlanStep] | None = None,
        files: list[dict] | None = None,
        analysis: str = "",
        risks: list[str] | None = None,
        side_effects: list[str] | None = None,
        extra_auth: list[str] | None = None,
        expected: str = "",
        open_questions: list[str] | None = None,
        created_at: float | None = None,
        expires_at: float | None = None,
        state: WorkflowState = WorkflowState.CREATED,
    ) -> None:
        self.plan_id = plan_id
        self.session_id = session_id
        self.goal = goal
        self.steps = list(steps or [])
        self.files = list(files or [])
        self.analysis = analysis
        self.risks = list(risks or [])
        self.side_effects = list(side_effects or [])
        self.extra_auth = list(extra_auth or [])
        self.expected = expected
        self.open_questions = list(open_questions or [])
        self.created_at = created_at or time.time()
        self.expires_at = expires_at or (self.created_at + PLAN_TTL)
        self._state = state

    # ── 状态 ──────────────────────────────────────────────────────
    @property
    def state(self) -> WorkflowState:
        return self._state

    def transition(self, target: WorkflowState) -> WorkflowState:
        """受控状态转换。非法边一律抛 :class:`PlanStateError`。"""
        target = WorkflowState(target)
        allowed = _ALLOWED.get(self._state, frozenset())
        if target not in allowed:
            raise PlanStateError(
                f"非法状态转换：{self._state.value} → {target.value}"
                + ("" if allowed else "（终态不可再转换）")
                + (
                    "；进入 EXECUTING 必须先经审批（AWAITING_APPROVAL → APPROVED）"
                    if target is WorkflowState.EXECUTING
                    else ""
                )
            )
        self._state = target
        return self._state

    def is_expired(self, *, now: float | None = None) -> bool:
        if self._state is WorkflowState.EXPIRED:
            return True
        return (now if now is not None else time.time()) >= self.expires_at

    # ── 派生 ──────────────────────────────────────────────────────
    @property
    def risk_level(self) -> str:
        worst = "L0"
        for st in self.steps:
            if _RISK_ORDER.get(st.risk, 0) > _RISK_ORDER.get(worst, 0):
                worst = st.risk
        return worst

    def digest(self) -> str:
        """内容摘要——**审批绑定的是它**（步骤/目标/文件 sha256 任一变化即变）。"""
        payload = {
            "session_id": self.session_id,
            "goal": self.goal,
            "files": [
                {"file_id": f.get("file_id", ""), "sha256": f.get("sha256", "")}
                for f in self.files
            ],
            "steps": [
                {
                    "no": st.no, "title": st.title, "tool": st.tool,
                    "args": st.args, "risk": st.risk,
                    "depends_on": st.depends_on,
                }
                for st in self.steps
            ],
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    @classmethod
    def new(cls, session_id: str, goal: str, **kw) -> "Plan":
        return cls(plan_id=f"plan-{uuid4().hex[:12]}", session_id=session_id, goal=goal, **kw)

    # ── 序列化 ────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id, "session_id": self.session_id, "goal": self.goal,
            "state": self._state.value, "analysis": self.analysis,
            "steps": [st.to_dict() for st in self.steps],
            "files": [dict(f) for f in self.files],
            "risks": list(self.risks), "side_effects": list(self.side_effects),
            "extra_auth": list(self.extra_auth), "expected": self.expected,
            "open_questions": list(self.open_questions),
            "created_at": self.created_at, "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Plan":
        return cls(
            plan_id=str(d.get("plan_id") or ""),
            session_id=str(d.get("session_id") or ""),
            goal=str(d.get("goal") or ""),
            steps=[PlanStep.from_dict(s) for s in (d.get("steps") or []) if isinstance(s, dict)],
            files=[dict(f) for f in (d.get("files") or []) if isinstance(f, dict)],
            analysis=str(d.get("analysis") or ""),
            risks=[str(x) for x in (d.get("risks") or [])],
            side_effects=[str(x) for x in (d.get("side_effects") or [])],
            extra_auth=[str(x) for x in (d.get("extra_auth") or [])],
            expected=str(d.get("expected") or ""),
            open_questions=[str(x) for x in (d.get("open_questions") or [])],
            created_at=float(d.get("created_at") or time.time()),
            expires_at=float(d.get("expires_at") or 0) or None,
            state=_as_state(d.get("state")),
        )

    # ── 展示 ──────────────────────────────────────────────────────
    def render(self) -> str:
        """终端展示：目标/文件/步骤/风险/待授权/预期/未决。"""
        lines = [
            f"计划 {self.plan_id}（{self.state.value}）",
            f"  目标：{self.goal}",
        ]
        if self.files:
            lines.append("  输入文件：")
            for f in self.files:
                lines.append(
                    f"    - {f.get('name', '?')} [{f.get('file_id', '?')}] "
                    f"sha256 {str(f.get('sha256', ''))[:12]}…"
                )
        if self.analysis:
            lines.append(f"  分析：{self.analysis.strip().splitlines()[0][:200]}")
        lines.append(f"  风险等级：{self.risk_level}")
        if self.steps:
            lines.append("  步骤：")
            for st in self.steps:
                extra = f"（→ 依赖 {st.depends_on}）" if st.depends_on else ""
                flag = "  ⚠额外授权" if st.needs_extra_auth else ""
                lines.append(f"    {st.no}. [{st.risk}] {st.title} · {st.tool}{flag}{extra}")
        for label, items in (
            ("可能的副作用", self.side_effects),
            ("需要的额外授权", self.extra_auth),
            ("尚未解决", self.open_questions),
        ):
            if items:
                lines.append(f"  {label}：")
                lines.extend(f"    - {x}" for x in items)
        if self.risks:
            lines.append("  风险：")
            lines.extend(f"    - {x}" for x in self.risks)
        if self.expected:
            lines.append(f"  预期结果：{self.expected}")
        return "\n".join(lines)


def _int_list(value, *, step_no: int = 0) -> list[int]:
    """把 ``depends_on`` 归一成 int 列表。**非数字直接报错，不猜。**

    模型经常把依赖写成工具名（"depends_on": ["list_session_files"]）。
    猜成 0 或忽略会让"依赖关系"静默失效——那正是"失败了还继续往下跑"
    的根源，所以这里宁可拒绝整份计划。
    """
    if value in (None, "", []):
        return []
    items = value if isinstance(value, list) else [value]
    out: list[int] = []
    for raw in items:
        try:
            out.append(int(raw))
            continue
        except (TypeError, ValueError):
            pass
        # 模型常把依赖写成 "step2" / "#2" / "s2"——语义唯一，归一即可；
        # 但写成工具名（"list_session_files"）时无法确定指向哪一步，
        # 这种必须拒绝，否则"依赖"会静默失效。
        m = re.fullmatch(r"\s*(?:step|#|s)?\s*(\d{1,3})\s*", str(raw), re.I)
        if m:
            out.append(int(m.group(1)))
            continue
        raise PlanError(
            f"第 {step_no} 步的 depends_on 必须是步骤编号（如 2 / \"step2\"），"
            f"收到 {raw!r}；依赖关系写错会让失败传播失效"
        )
    return out


def _as_state(value) -> WorkflowState:
    try:
        return WorkflowState(str(value))
    except ValueError:
        return WorkflowState.CREATED


class PlanBuilder:
    """把"用户目标 + 已授权文件 + 模型提案"变成一份受校验的 :class:`Plan`。"""

    def __init__(self, session, *, runner=None, llm=None) -> None:
        self.session = session
        self.runner = runner
        self.llm = llm

    # ── 只读阶段 ──────────────────────────────────────────────────
    def read_phase(self, goal: str) -> list[dict]:
        """Plan 阶段的**全部动作**：读已授权文件，产出事实。

        ``goal`` 只用于日志/展示——本方法不解析它、不发请求、不写盘。
        """
        self._goal = goal
        return self.session.files.facts()

    # ── 构建 ──────────────────────────────────────────────────────
    def build(self, goal: str, proposal: dict | None = None) -> Plan:
        proposal = proposal or {}
        facts = self.read_phase(goal)
        plan = Plan.new(
            self.session.session_id,
            goal,
            files=[
                {"file_id": f["file_id"], "name": f["name"], "sha256": f["sha256"],
                 "lines": f.get("lines", 0), "ok": f.get("ok", True)}
                for f in facts
            ],
        )
        plan.transition(WorkflowState.READING)
        plan.transition(WorkflowState.PLANNING)
        plan.analysis = str(proposal.get("analysis") or "").strip()
        plan.steps = self.validate_steps(proposal.get("steps") or [])
        plan.risks = [str(x) for x in (proposal.get("risks") or [])]
        plan.expected = str(proposal.get("expected") or "")
        plan.open_questions = [str(x) for x in (proposal.get("open_questions") or [])]
        plan.extra_auth = [
            f"第 {st.no} 步「{st.title}」需要单独审批（{st.risk}）"
            for st in plan.steps if st.needs_extra_auth
        ]
        plan.side_effects = self._side_effects(plan.steps)
        plan.transition(WorkflowState.AWAITING_APPROVAL)
        return plan

    # ── 步骤校验 ──────────────────────────────────────────────────
    def validate_steps(self, raw_steps: list) -> list[PlanStep]:
        """逐条校验并把步骤**归一**成 :class:`PlanStep`。非法即抛。"""
        if not isinstance(raw_steps, list):
            raise PlanError("steps 必须是数组")
        out: list[PlanStep] = []
        for i, item in enumerate(raw_steps, 1):
            if not isinstance(item, dict):
                raise PlanError(f"第 {i} 步不是对象")
            tool = str(item.get("tool") or "").strip()
            args = dict(item.get("args") or {}) if isinstance(item.get("args"), dict) else {}
            args = self._fill_url(args)
            if not tool:
                raise PlanError(f"第 {i} 步缺少 tool")
            level, command, why = self._classify(tool, args)
            if tool in PLAN_FORBIDDEN_TOOLS:
                raise PlanError(
                    f"第 {i} 步「{item.get('title') or tool}」是本地写操作（{tool}）："
                    f"本工作流不修改本地文件，Plan 阶段与 Work 阶段都不允许"
                )
            if level == "L3":
                raise PlanError(
                    f"第 {i} 步「{item.get('title') or tool}」命中 L3（{command}）："
                    f"L3 命令永久拒绝，不得写入计划"
                )
            if level == "?":
                raise PlanError(
                    f"第 {i} 步「{item.get('title') or tool}」无法授权："
                    f"{why or '工具未知或权限矩阵无授权行'}——默认拒绝执行，不得写入计划"
                )
            out.append(PlanStep(
                no=i,
                title=str(item.get("title") or f"第 {i} 步"),
                tool=tool,
                args=dict(args),
                files=[str(x) for x in (item.get("files") or [])],
                risk=level,
                needs_extra_auth=level in ("L2", "L3") or bool(item.get("needs_extra_auth")),
                depends_on=_int_list(item.get("depends_on"), step_no=i),
            ))
        # 依赖只能指向**前面**的步骤（指向后面/自己 → 计划无法执行）
        for st in out:
            for dep in st.depends_on:
                if dep >= st.no or dep < 1:
                    raise PlanError(
                        f"第 {st.no} 步的依赖 {dep} 不合法：只能依赖编号更小的步骤"
                    )
        return out

    def _fill_url(self, args: dict) -> dict:
        """补全 ``http_request`` 的 url：模型常只写 path，目标由会话给定。

        只在**两者都在**时拼接（会话有目标 + 步骤给了 path/endpoint）；
        缺一个就保持原样，让校验如实报"缺少 url"，不做猜测。
        """
        if str(args.get("url") or "").strip():
            return args
        path = str(args.get("path") or args.get("endpoint") or "").strip()
        target = str(getattr(self.session, "target", "") or "").rstrip("/")
        if target and path:
            args["url"] = f"{target}/{path.lstrip('/')}"
        return args

    def _classify(self, tool: str, args: dict) -> tuple[str, str, str]:
        """工具 → (风险等级, 矩阵命令, 判定说明)。``?`` 表示未知/无授权行。

        第三个返回值是给用户看的**原因**：同为"拒绝"，"工具名打错了"、
        "这个探针类别没有授权行"、"这是 L3" 三种情况该说三句不同的话。
        """
        from policy.api_policy import PermissionLevel, rule_for_command
        from policy.request_guard import (
            _BUILTIN_TOOL_COMMAND,
            PROBE_KIND_COMMAND,
            classify_request,
        )

        if tool in LOCAL_TOOLS:
            # 本地只读：不涉及目标，按 L0 处理（仍受"仅授权文件"约束）
            return "L0", "查询详情", ""
        if tool == "http_request":
            url = str(args.get("url") or "")
            method = str(args.get("method") or "GET")
            body = str(args.get("body") or "")
            if not url:
                return "?", "", "http_request 缺少 url"
            c = classify_request(url, method, body=body, params=args.get("params")
                                 if isinstance(args.get("params"), dict) else None)
            command = c.command or ""
        elif tool == "exploit_probe":
            kinds = str(args.get("kinds") or "rce,fileread")
            commands = [PROBE_KIND_COMMAND.get(k.strip().lower(), "")
                        for k in kinds.split(",")]
            if not commands or any(not c for c in commands):
                bad = [k for k, c in zip(
                    [x.strip() for x in kinds.split(",")], commands) if not c]
                return "?", "", (
                    f"探针类别 {'/'.join(bad) or kinds} 没有权限矩阵授权行"
                    f"（UNKNOWN 默认拒绝；已知类别：{'、'.join(sorted(PROBE_KIND_COMMAND))}）"
                )
            command = max(commands, key=lambda c: _RISK_ORDER.get(
                (rule_for_command(c).level if rule_for_command(c) else "L3"), 0))
        else:
            if self.runner is not None and getattr(self.runner, f"_h_{tool}", None) is None:
                return "?", "", f"工具「{tool}」不存在（本机没有这个工具）"
            command = _BUILTIN_TOOL_COMMAND.get(tool, "")
            if not command:
                return "?", "", f"工具「{tool}」没有权限矩阵授权行（AUTH 类不映射 L0）"
        rule = rule_for_command(command)
        if rule is None:
            return "?", command, f"命令「{command}」不在权限矩阵里"
        level = {
            PermissionLevel.L0: "L0", PermissionLevel.L1: "L1",
            PermissionLevel.L2: "L2", PermissionLevel.L3: "L3",
        }.get(rule.level, "?")
        return level, command, ""

    @staticmethod
    def _side_effects(steps: list[PlanStep]) -> list[str]:
        out: list[str] = []
        for st in steps:
            if st.risk == "L2":
                out.append(f"第 {st.no} 步可能改变目标状态（{st.risk}）：{st.title}")
            elif st.risk == "L1":
                out.append(f"第 {st.no} 步会在目标上创建/修改测试数据（L1）：{st.title}")
        return out
