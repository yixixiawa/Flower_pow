"""``_WorkflowMixin``：对话式文件访问 + Plan/Work 命令。

命令都在这里落地，**不新建 UI**：复用现有 REPL 的输入/补全/打印。

* ``/read <路径>`` —— 用户点名一个本地文件（显式授权），读进来并显示摘要
* ``/files [--drop <id>]`` —— 已授权文件清单 / 移除
* ``/plan <目标>`` —— 只读分析已授权文件 → 生成计划 → 等待确认
* ``/approve [y|n]`` —— 确认（或拒绝）当前计划，签发一次性票据
* ``/work`` —— 执行已确认的计划（每步仍过策略矩阵与统一 Gateway）
* ``/reject`` —— 明确拒绝当前计划（终态）

安全相关的两个约定：

1. **``/plan`` 没有副作用**：它只读已授权文件，不调用 Runner 工具；
2. **确认不等于放权**：``/approve`` 只签计划票据，不解锁任何 L0-L3 判定。
   执行时该拒的照样拒（命令里看到 ``【已拦截】`` 就是它在生效）。
"""

from __future__ import annotations

import asyncio
import getpass
import json

from core.files import FileAccessDenied
from core.workflow import (
    Plan,
    PlanApprovalLedger,
    PlanBuilder,
    PlanError,
    WorkDenied,
    WorkflowState,
    WorkRunner,
)

# 计划展示时最多显示多少行预览（完整内容用 /read 或 /files 看）
_PREVIEW_LINES = 12


class _WorkflowMixin:
    """文件与工作流命令。状态挂 self 上，随会话走。"""

    # ── 惰性状态 ──────────────────────────────────────────────────
    @property
    def active_plan(self) -> Plan | None:
        plan = getattr(self, "_active_plan", None)
        if plan is None:
            return None
        if plan.state in (WorkflowState.REJECTED, WorkflowState.EXPIRED,
                          WorkflowState.COMPLETED, WorkflowState.FAILED):
            return None
        return plan

    @active_plan.setter
    def active_plan(self, plan: Plan | None) -> None:
        self._active_plan = plan
        try:
            self._refresh_completer()
        except Exception:  # noqa: BLE001
            pass

    @property
    def plan_approvals(self) -> PlanApprovalLedger:
        led = getattr(self, "_plan_approvals", None)
        if led is None:
            led = PlanApprovalLedger()
            self._plan_approvals = led
        return led

    @staticmethod
    def _approver_label() -> str:
        """真实审批人：交互式会话的登录用户名（与请求级审批同源口径）。"""
        try:
            return f"interactive:{getpass.getuser()}"
        except Exception:  # noqa: BLE001 - 拿不到用户名也不能凭空造身份
            return ""

    def _pending_token(self) -> str:
        return getattr(self, "_plan_token", "") or ""

    # ── /read ────────────────────────────────────────────────────
    def _read_file(self, arg: str) -> None:
        raw = (arg or "").strip()
        if not raw:
            print("用法：/read <文件路径>（如 /read ./docs/api.md）")
            return
        try:
            rec = self.session.files.ingest(raw)
        except FileAccessDenied as exc:
            print(f"【已拒绝】{exc}")
            return
        parsed = self.session.files.read(rec.file_id)
        print(f"已授权：{rec.name}  [{rec.file_id}]")
        print(f"  路径：{rec.path}")
        print(f"  大小：{rec.size} 字节   MIME：{rec.mime}")
        print(f"  SHA256：{rec.sha256}")
        if not parsed.ok:
            print(f"  ⚠ 解析失败：{parsed.error}")
            print("  （原文仍可看，但不要把它当作已正确解析的内容）")
        else:
            notes = "；".join(parsed.notes)
            print(f"  解析：{parsed.kind}，{parsed.lines} 行" + (f"（{notes}）" if notes else ""))
        preview = parsed.numbered(limit=_PREVIEW_LINES)
        if preview:
            print(f"  ── 前 {min(_PREVIEW_LINES, parsed.lines)} 行 ──")
            print(preview)
        self._save()

    # ── /files ───────────────────────────────────────────────────
    def _files(self, arg: str = "") -> None:
        text = (arg or "").strip()
        if text.startswith("--drop"):
            fid = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
            if not fid:
                print("用法：/files --drop <file_id>")
                return
            if self.session.files.forget(fid):
                print(f"已移除 {fid}（之后的分析与计划不再引用它）")
                self._save()
            else:
                print(f"未找到 file_id={fid}（用 /files 看现有清单）")
            return
        if text.startswith("--clear"):
            n = self.session.files.clear()
            print(f"已清空 {n} 个文件授权")
            self._save()
            return
        print(self.session.files.summary_table())

    # ── /plan ────────────────────────────────────────────────────
    def _plan(self, arg: str) -> None:
        goal = (arg or "").strip()
        if not goal:
            print("用法：/plan <你想达成什么>")
            print("  例：/plan 分析这些接口文档里的权限控制问题，先给整改计划")
            return
        if not self.session.files.records():
            print("还没有授权任何文件：先 /read <路径>，再 /plan")
            return
        llm = self.llm if getattr(self, "llm", None) is not None else None
        if llm is None or not getattr(self.cfg.llm, "enabled", False) or not self.cfg.llm.api_key:
            print("【需要模型】/plan 要用模型读文件并给出分析，当前没有可用的 API Key。")
            print("  1) /key 配置 API Key 后重试；或")
            print("  2) 直接用 /files 与 /read 看事实，自己判断（本工作流不代替你分析）")
            return
        proposal = self._ask_plan(goal, llm)
        if proposal is None:
            return
        self._plan_from_proposal(goal, proposal)

    def _ask_plan(self, goal: str, llm) -> dict | None:
        """请模型产出提案（analysis + steps）。**JSON 解析失败就说失败**。"""
        ctx = self.session.files.prompt_block()
        system = (
            "你是渗透测试助手。只读分析用户提供的文件，产出执行计划。"
            "严格输出 JSON：{\"analysis\": \"...\", \"steps\": [{\"title\", \"tool\", \"args\", "
            "\"depends_on\"}], \"risks\": [], \"expected\": \"\", \"open_questions\": []}。"
            "可用工具：http_request（对目标的一次请求）、list_session_files、"
            "read_local_file、grep_local_file。"
            "禁止把本地写操作（write_file/edit_file/delete_file）写进步骤；"
            "探针类（exploit_probe / sqli_probe）与其它 L3 操作"
            "（SQL 注入/命令执行/批量删除）一律不得写入——它们在本工具里永久拒绝。"
        )
        user = f"用户目标：{goal}\n\n{ctx}"
        try:
            raw = llm.ask(system, user)
        except Exception as exc:  # noqa: BLE001 - 模型层异常不该炸 REPL
            print(f"【模型调用失败】{type(exc).__name__}: {exc}")
            return None
        text = (raw or "").strip()
        if "```" in text:
            start = text.find("{")
            end = text.rfind("}")
            text = text[start:end + 1] if start >= 0 and end > start else text
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            print(f"【计划解析失败】模型返回的不是合法 JSON（{exc}）；未执行任何操作。")
            print("  可以重试，或缩小目标范围。")
            return None
        if not isinstance(data, dict):
            print("【计划解析失败】模型返回的 JSON 不是对象")
            return None
        return data

    def _plan_from_proposal(self, goal: str, proposal: dict) -> None:
        """构建并展示计划（测试与 ``/plan`` 共用这条路）。"""
        builder = PlanBuilder(self.session, runner=getattr(self, "runner", None),
                             llm=getattr(self, "llm", None))
        try:
            plan = builder.build(goal, proposal)
        except PlanError as exc:
            print(f"【计划被拒绝】{exc}")
            print("  未执行任何操作；请调整目标或步骤后重试。")
            return
        except Exception as exc:  # noqa: BLE001 - 模型给的提案什么形状都可能
            print(f"【计划构建失败】{type(exc).__name__}: {exc}")
            print("  未执行任何操作。")
            return
        self.active_plan = plan
        print()
        print(plan.render())
        print()
        print("状态：待确认。风险与副作用请先看清楚。")
        print("  /approve y   确认并允许执行（只签这份计划，不解锁任何权限）")
        print("  /approve n   或 /reject   拒绝（终态，不会执行）")
        self._save()

    # ── /approve ─────────────────────────────────────────────────
    # 名字必须避开 ``_approve``：那是**请求级**上传审批回调（history.py），
    # 撞名会让 ``runner.approver = self._approve`` 绑到本方法上（签名不同），
    # 上传审批直接失效。
    def _approve_plan(self, arg: str) -> None:
        plan = self.active_plan
        if plan is None:
            print("当前没有待确认的计划（先 /plan <目标>）")
            return
        want = (arg or "").strip().lower()
        if want in ("n", "no", "reject", "拒绝"):
            self._reject_plan()
            return
        if want not in ("y", "yes", "ok", "确认", ""):
            print("用法：/approve [y|n]")
            return
        try:
            ap = self.plan_approvals.issue(
                plan, approver=self._approver_label(), authenticated=True,
            )
        except PlanError as exc:
            print(f"【无法确认】{exc}")
            return
        self._plan_token = ap.token
        print(f"已确认计划 {plan.plan_id}（票据 {ap.token}，一次性）。")
        print("  下一步：/work 执行。注意：确认的是**这份计划**，"
              "每一步仍会各自过权限矩阵——被拦的步骤会如实报告。")
        self._save()

    def _reject_plan(self) -> None:
        plan = self.active_plan
        if plan is None:
            print("当前没有待确认的计划")
            return
        try:
            plan.transition(WorkflowState.REJECTED)
        except PlanError as exc:
            print(f"【无法拒绝】{exc}")
            return
        print(f"已拒绝计划 {plan.plan_id}（终态，不会执行）")
        self._plan_token = ""
        self._save()

    # ── /work ────────────────────────────────────────────────────
    def _work(self, arg: str) -> None:
        plan = self.active_plan
        if plan is None:
            print("当前没有可执行的计划（先 /plan 再 /approve y）")
            return
        token = self._pending_token()
        if not token:
            print("这份计划还没有被确认：先 /approve y（或 /reject 拒绝）")
            return
        if getattr(self, "runner", None) is None:
            print("当前没有可用的工具运行期（Agent 未启动）。切换 /agent on 后重试。")
            return
        audit = getattr(self.runner, "policy_audit", None)
        w = WorkRunner(self.session, self.runner,
                       approvals=self.plan_approvals, audit=audit)
        try:
            report = asyncio.run(w.run(plan, token))
        except WorkDenied as exc:
            print(f"【未执行】{exc}")
            self._plan_token = ""
            self._save()
            return
        print(report.render())
        print(f"\n审计摘要：{report.audit_summary()}")
        print(f"审计文件：{getattr(audit, 'path', '（不可用）')}")
        self._plan_token = ""
        if report.state is not WorkflowState.COMPLETED:
            print("  提示：失败/被拦的步骤没有执行任何请求；依赖它们的步骤已跳过。")
        self._save()

    # ── 给 Agent 系统提示用的一段事实 ────────────────────────────
    def _files_brief(self) -> str:
        recs = self.session.files.records()
        if not recs:
            return ""
        names = "、".join(f"{r.name}[{r.file_id}]" for r in recs[:8])
        more = f" 等 {len(recs)} 个" if len(recs) > 8 else ""
        return f"本会话已授权的本地文件：{names}{more}（用 read_local_file 读取，禁止访问其它路径）"

