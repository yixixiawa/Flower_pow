"""对话式 Plan / Work 工作流 —— 第二、三阶段回归测试。

**先有测试再有实现**。断言按 plan2file.md 四/五/六/八节逐条落：

Plan 阶段（只读）
  1. 状态机：CREATED→READING→PLANNING→AWAITING_APPROVAL，任何"跳过审批"
     的转换被拒；直接改 state 属性也被拒（property 无 setter）
  2. Plan 阶段**不产生任何工具调用**（不写文件、不发请求、不跑命令）
  3. 计划里不能出现本地写操作（write/edit/delete_file）——本工作流不改用户文件
  4. 计划里不能出现 L3 工具（永久拒绝）与未知工具
  5. 风险等级取步骤最高级；需要额外授权的步骤被标记

审批
  6. 未审批的 Plan 无法进入 Work
  7. 计划内容（步骤/目标/文件 sha256）变化 → 旧审批失效
  8. 审批一次性消费；过期失效；换 session 失效
  9. Plan Approval **不是** L0-L3 授权（审批通过后策略照旧）

文件
 10. 文件内容变化 → 旧 Plan 失效且拒绝执行（不触网）

Work 执行（第三阶段）
 11. 每个工具调用走原有统一 Gateway（mock 双端口计数：该发的发了、被拒的没发）
 12. L3 在所有环境被拒（含"绕过构建校验强行塞进去"的情形）
 13. UNKNOWN 工具被拒
 14. 生产环境不能通过 Work 确认解锁写操作
 15. 每步写审计事件（work_start/work_step/work_end）
 16. 某步失败/被拦 → 依赖它的后续步骤 skipped，报告原因

对话界面
 17. /read /files /plan /reject /work 在 REPL 里可用；无模型时 /plan 明确提示

运行：.venv/Scripts/python.exe scripts/workflow_test.py
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "scripts"))

from acceptance.mocknet import MockNet  # noqa: E402
from core.config_loader import Config  # noqa: E402
from core.session import Session  # noqa: E402
from core.tools.runner import ToolRunner  # noqa: E402
from core.workflow import (  # noqa: E402
    PLAN_FORBIDDEN_TOOLS,
    Plan,
    PlanApprovalLedger,
    PlanBuilder,
    PlanError,
    PlanStateError,
    PlanStep,
    WorkDenied,
    WorkflowState,
    WorkRunner,
)
from policy.api_policy import Environment  # noqa: E402

OK = 0
FAIL = 0


def check(cond: bool, msg: str) -> None:
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  ok   {msg}")
    else:
        FAIL += 1
        print(f"  FAIL {msg}")


def cfg_for(env: str = Environment.ISOLATED_TEST, data_dir: str = "./data") -> Config:
    cfg = Config()
    cfg.data_dir = data_dir
    cfg.policy.environments = {"127.0.0.*": env}
    return cfg


def new_session(net: MockNet | None = None, cfg: Config | None = None) -> Session:
    s = Session(target=net.target if net else "http://127.0.0.1:9")
    s.attach_files(__import__("core.files", fromlist=["FileAccess"]).FileAccess(s.session_id))
    return s


# ── 场景1 状态机 ────────────────────────────────────────────────────


def scenario_state_machine() -> None:
    print("\n场景1 状态机受控（不能绕过审批）")
    plan = Plan.new(session_id="s1", goal="分析接口文档的权限问题")
    check(plan.state is WorkflowState.CREATED, "新建 → CREATED")
    plan.transition(WorkflowState.READING)
    plan.transition(WorkflowState.PLANNING)
    plan.transition(WorkflowState.AWAITING_APPROVAL)
    check(plan.state is WorkflowState.AWAITING_APPROVAL, "READING → PLANNING → AWAITING_APPROVAL")

    for bad in (WorkflowState.EXECUTING, WorkflowState.COMPLETED, WorkflowState.FAILED):
        try:
            plan.transition(bad)
            check(False, f"AWAITING_APPROVAL → {bad.value} 应被拒绝（必须先审批）")
        except PlanStateError:
            check(True, f"AWAITING_APPROVAL → {bad.value} 被拒绝")
    # APPROVED 是"审批通过"的唯一入口，且只能经由 transition 到达；
    # 真正的闸门在 WorkRunner：它必须在消费掉票据后才打这个状态。
    plan.transition(WorkflowState.APPROVED)
    check(plan.state is WorkflowState.APPROVED, "AWAITING_APPROVAL → APPROVED 是允许的（审批通过）")
    plan.transition(WorkflowState.EXECUTING)
    check(plan.state is WorkflowState.EXECUTING, "APPROVED → EXECUTING 允许（执行阶段）")
    try:
        plan.transition(WorkflowState.APPROVED)
        check(False, "EXECUTING 不能倒回 APPROVED")
    except PlanStateError:
        check(True, "EXECUTING 不能倒回 APPROVED（状态只进不退）")

    try:
        plan.state = WorkflowState.EXECUTING  # type: ignore[misc]
        check(False, "直接给 state 赋值应被拒绝")
    except AttributeError:
        check(True, "直接改 state 属性被拒（只能走 transition）")

    rej = Plan.new(session_id="s1", goal="g2")
    rej.transition(WorkflowState.READING)
    rej.transition(WorkflowState.PLANNING)
    rej.transition(WorkflowState.AWAITING_APPROVAL)
    rej.transition(WorkflowState.REJECTED)
    check(rej.state is WorkflowState.REJECTED, "可显式拒绝")
    try:
        rej.transition(WorkflowState.APPROVED)
        check(False, "REJECTED 不能再被批准")
    except PlanStateError:
        check(True, "REJECTED 是终态：不能再批准")

    p2 = Plan.new(session_id="s1", goal="g")
    p2.transition(WorkflowState.EXPIRED)
    check(p2.state is WorkflowState.EXPIRED, "任何阶段可过期")
    check(p2.is_expired(now=p2.created_at), "EXPIRED 视为已过期")


# ── 场景2 Plan 只读 ─────────────────────────────────────────────────


def scenario_plan_readonly(tmp: Path, net: MockNet) -> None:
    print("\n场景2 Plan 阶段只读：不发请求、不写文件")
    doc = tmp / "api.md"
    doc.write_text("GET /api/users 需要登录\nDELETE /api/users/1 需要管理员\n", encoding="utf-8")
    cfg = cfg_for(data_dir=str(tmp / "d1"))
    s = new_session(net, cfg)
    rec = s.files.ingest(doc)
    runner = ToolRunner(cfg, root=str(tmp))
    called: list[str] = []
    orig = runner.execute

    async def spy(name, args, session):  # noqa: ANN001
        called.append(name)
        return await orig(name, args, session)

    runner.execute = spy  # type: ignore[method-assign]

    builder = PlanBuilder(s, runner=runner)
    snapshot = net.snapshot()

    @contextlib.contextmanager
    def boom(*a, **kw):  # 任何写盘/请求都算违规
        raise AssertionError("Plan 阶段发生了副作用")
        yield

    facts = builder.read_phase("分析接口文档的鉴权问题")
    check(bool(facts) and facts[0]["file_id"] == rec.file_id, "Plan 阶段能读到已授权文件的事实")
    check("GET /api/users" in str(facts[0].get("preview") or "") or facts[0]["lines"] > 0,
          "事实里带正文/行数（引用位置可落地）")
    check(not called, f"Plan 阶段没有调用任何工具（实={called}）")
    check(net.delta(snapshot) == [], "Plan 阶段没有发出任何网络请求")

    # 计划里不许出现本地写操作
    proposal = {
        "analysis": "文档显示删除接口只校验登录态",
        "steps": [
            {"title": "改一下源码加鉴权", "tool": "write_file",
             "args": {"path": "api.md", "content": "x"}},
        ],
    }
    try:
        builder.build("分析接口文档的鉴权问题", proposal)
        check(False, "本地写操作步骤应被拒绝")
    except PlanError as exc:
        check("不修改本地文件" in str(exc) or "写" in str(exc), f"拒绝本地写步骤：{exc}")
    check(set(PLAN_FORBIDDEN_TOOLS) >= {"write_file", "edit_file", "delete_file"},
          "禁止清单覆盖本地写/改/删三种工具")

    # L3 与未知工具
    for tool, kw in (("exploit_probe", {"kinds": "sqli"}), ("sqli_probe", {}), ("no_such_tool", {})):
        try:
            builder.build("x", {"analysis": "a", "steps": [
                {"title": "t", "tool": tool, "args": kw}]})
            check(False, f"{tool} 作为计划步骤应被拒绝")
        except PlanError as exc:
            check(True, f"{tool} 作为计划步骤被拒绝：{exc}")


# ── 场景3 计划构建与风险 ────────────────────────────────────────────


def scenario_build(tmp: Path, net: MockNet) -> None:
    print("\n场景3 计划结构、风险与待授权标记")
    doc = tmp / "perm.md"
    doc.write_text("DELETE /api/users/1\n", encoding="utf-8")
    cfg = cfg_for(data_dir=str(tmp / "d2"))
    s = new_session(net, cfg)
    s.files.ingest(doc)
    builder = PlanBuilder(s, runner=ToolRunner(cfg, root=str(tmp)))
    plan = builder.build("验证删除接口鉴权", {
        "analysis": "接口只校验登录态，未校验属主",
        "steps": [
            {"title": "读取列表确认存在", "tool": "http_request",
             "args": {"url": f"{net.target}/api/users", "method": "GET"}},
            {"title": "创建测试用户", "tool": "http_request",
             "args": {"url": f"{net.target}/api/users", "method": "POST",
                      "body": '{"name":"t"}'}},
            {"title": "删除越权对象", "tool": "http_request",
             "args": {"url": f"{net.target}/api/users/9999", "method": "DELETE"},
             "depends_on": [2]},
        ],
        "risks": ["删除越权对象可能误删他人数据"],
        "expected": "确认 403/401 是否返回",
        "open_questions": ["对象 9999 是否属于其他用户"],
    })
    check(plan.plan_id and plan.session_id == s.session_id, "plan_id 与 session_id 绑定")
    check(plan.state is WorkflowState.AWAITING_APPROVAL, "构建完成即等待确认")
    check([st.no for st in plan.steps] == [1, 2, 3], "步骤编号连续")
    check(plan.risk_level == "L2", f"风险取最高级，实={plan.risk_level}")
    check(plan.extra_auth and any("删除" in x for x in plan.extra_auth),
          f"需要额外授权的步骤被标记，实={plan.extra_auth}")
    check(plan.files and plan.files[0]["file_id"] and len(plan.files[0]["sha256"]) == 64,
          "计划里冻结输入文件的 sha256")
    check(plan.digest() and len(plan.digest()) == 64, "计划有内容摘要（审批绑定它）")
    check(plan.expected and plan.risks and plan.open_questions, "预期/风险/未决问题齐全")
    # 依赖写成 "step2" 这种口语形式要能被归一（语义唯一），写成工具名则拒绝
    p_dep = builder.build("依赖归一", {"analysis": "a", "steps": [
        {"title": "第一步", "tool": "list_session_files"},
        {"title": "第二步", "tool": "list_session_files", "depends_on": ["step1"]},
    ]})
    check(p_dep.steps[1].depends_on == [1], f"\"step1\" 归一成 1，实={p_dep.steps[1].depends_on}")
    try:
        builder.build("依赖写错", {"analysis": "a", "steps": [
            {"title": "第一步", "tool": "list_session_files"},
            {"title": "第二步", "tool": "list_session_files",
             "depends_on": ["list_session_files"]}]})
        check(False, "depends_on 写成工具名应被拒绝")
    except PlanError as exc:
        check("depends_on" in str(exc), f"depends_on 写成工具名被拒绝：{exc}")

    d1 = plan.digest()
    plan.steps.append(PlanStep(no=4, title="多一步", tool="list_session_files"))
    check(plan.digest() != d1, "改步骤 → 摘要变化（旧审批自然失效）")


# ── 场景4 审批 ──────────────────────────────────────────────────────


def scenario_approval(tmp: Path, net: MockNet) -> None:
    print("\n场景4 审批绑定 / 一次性 / 过期 / 换会话")
    cfg = cfg_for(data_dir=str(tmp / "d3"))
    s = new_session(net, cfg)
    doc = tmp / "a.md"
    doc.write_text("hello\n", encoding="utf-8")
    s.files.ingest(doc)
    builder = PlanBuilder(s, runner=ToolRunner(cfg, root=str(tmp)))
    plan = builder.build("看文档", {"analysis": "a", "steps": [
        {"title": "列文件", "tool": "list_session_files", "args": {}}]})

    led = PlanApprovalLedger()
    ap = led.issue(plan, approver="ops-zhang", authenticated=True)
    check(ap.token and ap.plan_digest == plan.digest(), "票据绑定计划摘要")
    check(led.consume(ap.token, plan_id=plan.plan_id, plan_digest=plan.digest(),
                      session_id=s.session_id)[0], "首次消费成功")
    ok2, why = led.consume(ap.token, plan_id=plan.plan_id, plan_digest=plan.digest(),
                           session_id=s.session_id)
    check(not ok2 and "消费" in why, f"票据一次性：二次消费被拒（{why}）")

    ap2 = led.issue(plan)
    ok3, why3 = led.consume(ap2.token, plan_id=plan.plan_id, plan_digest="deadbeef",
                            session_id=s.session_id)
    check(not ok3 and ("不符" in why3 or "摘要" in why3), f"摘要不符 → 拒绝（{why3}）")
    ok4, why4 = led.consume(ap2.token, plan_id=plan.plan_id, plan_digest=plan.digest(),
                            session_id="other-session")
    check(not ok4 and "会话" in why4, f"换会话 → 拒绝（{why4}）")

    led0 = PlanApprovalLedger(ttl=0.0)
    ap3 = led0.issue(plan)
    ok5, why5 = led0.consume(ap3.token, plan_id=plan.plan_id,
                             plan_digest=plan.digest(), session_id=s.session_id)
    check(not ok5 and "过期" in why5, f"过期票据被拒（{why5}）")

    # 审批不是权限授权：批了删除，仍然过不了台账
    from policy.request_guard import GuardContext, RequestGuard

    guard = RequestGuard(cfg)
    ctx = guard.check_request(
        f"{net.target}/api/users/9999", "DELETE",
        ctx=GuardContext(
            target_id=s.result.target_id,
            run_id=s.result.current_run_id,
            bound_target=net.target,
            identity="anonymous@127.0.0.1",
            identity_bound=True,
            environment=Environment.ISOLATED_TEST,
        ),
    )
    check(ctx.decision in ("REVIEW", "DENY"), f"审批不改变策略判定（仍 {ctx.decision}）")


# ── 场景5 未审批 / 文件变化 → 不能执行 ──────────────────────────────


def scenario_work_refuses(tmp: Path, net: MockNet) -> None:
    print("\n场景5 未审批 / 计划被改 / 文件已变 / 已过期 → 拒绝执行")
    cfg = cfg_for(data_dir=str(tmp / "d4"))
    s = new_session(net, cfg)
    doc = tmp / "b.md"
    doc.write_text("v1\n", encoding="utf-8")
    s.files.ingest(doc)
    builder = PlanBuilder(s, runner=ToolRunner(cfg, root=str(tmp)))

    def build() -> Plan:
        return builder.build("看文档", {"analysis": "a", "steps": [
            {"title": "列文件", "tool": "list_session_files", "args": {}}]})

    runner = ToolRunner(cfg, root=str(tmp))
    w = WorkRunner(s, runner, approvals=PlanApprovalLedger(), audit=runner.policy_audit)

    plan = build()
    try:
        asyncio.run(w.run(plan, ""))
        check(False, "未审批应拒绝执行")
    except WorkDenied as exc:
        check("确认" in str(exc) or "审批" in str(exc), f"未审批 → 拒绝：{exc}")

    plan = build()
    ap = w.approvals.issue(plan)
    plan.steps.append(PlanStep(no=2, title="多一步", tool="list_session_files"))
    try:
        asyncio.run(w.run(plan, ap.token))
        check(False, "计划被改后应拒绝执行")
    except WorkDenied as exc:
        check("不符" in str(exc) or "变更" in str(exc), f"计划被改 → 旧审批失效：{exc}")

    plan = build()
    ap = w.approvals.issue(plan)
    doc.write_text("v2 被改过了\n", encoding="utf-8")
    snap = net.snapshot()
    try:
        asyncio.run(w.run(plan, ap.token))
        check(False, "文件变化后应拒绝执行")
    except WorkDenied as exc:
        check("变化" in str(exc), f"文件变化 → 旧计划失效：{exc}")
    check(net.delta(snap) == [], "文件变化被拒时没有任何网络请求")

    # 过期
    doc.write_text("v1\n", encoding="utf-8")
    s.files.forget(s.files.records()[0].file_id)
    s.files.ingest(doc)
    plan = builder.build("看文档", {"analysis": "a", "steps": [
        {"title": "列文件", "tool": "list_session_files", "args": {}}]})
    ap = w.approvals.issue(plan)
    w2 = WorkRunner(s, runner, approvals=w.approvals, audit=runner.policy_audit,
                    now=lambda: plan.expires_at + 10)
    try:
        asyncio.run(w2.run(plan, ap.token))
        check(False, "过期计划应拒绝执行")
    except WorkDenied as exc:
        check("过期" in str(exc), f"过期 → 拒绝：{exc}")


# ── 场景6 Work 执行：统一 Gateway / L3 / UNKNOWN / 生产 ─────────────


def scenario_work_execute(tmp: Path, net: MockNet) -> None:
    print("\n场景6 Work 执行走统一 Gateway，策略照旧生效")
    cfg = cfg_for(data_dir=str(tmp / "d5"))
    s = new_session(net, cfg)
    doc = tmp / "c.md"
    doc.write_text("接口说明\n", encoding="utf-8")
    s.files.ingest(doc)
    runner = ToolRunner(cfg, root=str(tmp))
    audit_dir = Path(cfg.data_dir) / "policy" / "audit.jsonl"
    builder = PlanBuilder(s, runner=runner)

    plan = builder.build("跑两个只读步骤", {"analysis": "a", "steps": [
        {"title": "列会话文件", "tool": "list_session_files", "args": {}},
        {"title": "GET 列表", "tool": "http_request",
         "args": {"url": f"{net.target}/api/users", "method": "GET"}},
    ]})
    ap = PlanApprovalLedger().issue(plan, approver="ops-zhang")
    w = WorkRunner(s, runner, approvals=PlanApprovalLedger(), audit=runner.policy_audit)
    ap = w.approvals.issue(plan, approver="ops-zhang")
    snap = net.snapshot()
    report = asyncio.run(w.run(plan, ap.token))
    check(report.state is WorkflowState.COMPLETED, f"正常计划执行完成，实={report.state}")
    check(len(report.steps) == 2 and all(st.status == "ok" for st in report.steps),
          f"两步都成功，实={[(st.no, st.status) for st in report.steps]}")
    hit = [r.path for r in net.delta(snap)]
    check("/api/users" in hit, f"该发的请求确实发出去了（经统一 Gateway），实={hit}")
    check(audit_dir.is_file(), "审计文件已落盘")
    txt = audit_dir.read_text(encoding="utf-8")
    check(txt.count('"work_step"') >= 2, "每步都有 work_step 审计事件")
    check('"work_start"' in txt and '"work_end"' in txt, "执行开始/结束都有审计")
    check(report.state is WorkflowState.COMPLETED and plan.state is WorkflowState.COMPLETED,
          "报告与计划状态一致")

    # L3：即使绕过构建校验强行塞进计划，执行时仍被拦且不触网
    plan2 = builder.build("强塞 L3", {"analysis": "a", "steps": [
        {"title": "列文件", "tool": "list_session_files", "args": {}}]})
    plan2.steps.append(PlanStep(no=2, title="SQL 注入", tool="exploit_probe",
                                args={"url": net.target, "kinds": "sqli"}, risk="L3"))
    w2 = WorkRunner(s, runner, approvals=PlanApprovalLedger(), audit=runner.policy_audit)
    ap2 = w2.approvals.issue(plan2)
    snap = net.snapshot()
    rep2 = asyncio.run(w2.run(plan2, ap2.token))
    check(rep2.state is WorkflowState.FAILED, f"含 L3 步骤 → 整体 FAILED，实={rep2.state}")
    check(rep2.steps[-1].status == "blocked", f"L3 步骤被拦，实={rep2.steps[-1].status}")
    check(net.delta(snap) == [], "L3 被拦时零网络请求（没打目标）")
    check("SQL 注入" in rep2.steps[-1].output or "拒绝" in rep2.steps[-1].output,
          "拒绝原因可读（回灌给用户，不是静默失败）")

    # UNKNOWN 工具
    plan3 = builder.build("未知工具", {"analysis": "a", "steps": [
        {"title": "列文件", "tool": "list_session_files", "args": {}}]})
    plan3.steps.append(PlanStep(no=2, title="未知", tool="no_such_tool"))
    w3 = WorkRunner(s, runner, approvals=PlanApprovalLedger(), audit=runner.policy_audit)
    rep3 = asyncio.run(w3.run(plan3, w3.approvals.issue(plan3).token))
    check(rep3.steps[-1].status in ("blocked", "failed"), f"未知工具被拒，实={rep3.steps[-1].status}")

    # 依赖失败 → 后续 skipped
    # 用"删除未登记对象"制造失败：构建期合法（L2），执行期被台账拦下
    plan4 = builder.build("依赖停止", {"analysis": "a", "steps": [
        {"title": "删除未登记对象", "tool": "http_request",
         "args": {"url": f"{net.target}/api/users/9999", "method": "DELETE"}},
        {"title": "依赖它", "tool": "http_request",
         "args": {"url": f"{net.target}/api/users", "method": "GET"}, "depends_on": [1]},
    ]})
    w4 = WorkRunner(s, runner, approvals=PlanApprovalLedger(), audit=runner.policy_audit)
    snap = net.snapshot()
    rep4 = asyncio.run(w4.run(plan4, w4.approvals.issue(plan4).token))
    check(rep4.steps[1].status == "skipped", f"依赖失败的步骤被跳过，实={rep4.steps[1].status}")
    check(net.delta(snap) == [], "跳过的步骤没有偷偷发请求")
    check(bool(rep4.reason) and ("拦截" in rep4.reason or "台账" in rep4.reason),
          f"报告里说明失败原因，实={rep4.reason!r}")

    # 生产环境：确认也解锁不了写操作
    cfg_p = cfg_for(env=Environment.PRODUCTION, data_dir=str(tmp / "d6"))
    s_p = new_session(net, cfg_p)
    s_p.files.ingest(doc)
    runner_p = ToolRunner(cfg_p, root=str(tmp))
    builder_p = PlanBuilder(s_p, runner=runner_p)
    plan_p = builder_p.build("生产写操作", {"analysis": "a", "steps": [
        {"title": "列文件", "tool": "list_session_files", "args": {}}]})
    plan_p.steps.append(PlanStep(no=2, title="生产删除", tool="http_request",
                                 args={"url": f"{net.target}/api/users/1",
                                       "method": "DELETE"}, risk="L2"))
    w_p = WorkRunner(s_p, runner_p, approvals=PlanApprovalLedger(), audit=runner_p.policy_audit)
    snap = net.snapshot()
    rep_p = asyncio.run(w_p.run(plan_p, w_p.approvals.issue(plan_p).token))
    check(rep_p.steps[-1].status == "blocked", f"生产环境写操作被拦，实={rep_p.steps[-1].status}")
    check(net.delta(snap) == [], "生产环境被拦时零请求（确认不是解锁器）")


# ── 场景7 REPL 分发 ─────────────────────────────────────────────────


def scenario_repl(tmp: Path, net: MockNet) -> None:
    print("\n场景7 对话界面：/read /files /plan /reject /work")
    from core.repl import Repl

    cfg = cfg_for(data_dir=str(tmp / "d7"))
    cfg.llm.enabled = False
    cfg.llm.api_key = ""
    s = new_session(net, cfg)
    repl = Repl(cfg, s, agent=False, probes=[])
    doc = tmp / "chat.md"
    doc.write_text("POST /api/users\n", encoding="utf-8")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle(f"/read {doc}"))
    out = buf.getvalue()
    check("chat.md" in out, f"/read 输出文件名，实={out[:80]!r}")
    check(not s.files.records() == [] and s.files.records()[0].name == "chat.md",
          "/read 之后文件进了会话台账")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle("/files"))
    check("chat.md" in buf.getvalue(), "/files 列出已授权文件")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle("/plan 看下这个接口"))
    out = buf.getvalue()
    check("模型" in out or "API Key" in out, f"无模型时 /plan 明确提示，实={out[:80]!r}")

    # 有提案时（内部入口，测试用）：走同一套构建 + 展示
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._plan_from_proposal("看下这个接口", {
            "analysis": "接口未鉴权", "steps": [
                {"title": "GET 列表", "tool": "http_request",
                 "args": {"url": f"{net.target}/api/users", "method": "GET"}}]})
    out = buf.getvalue()
    check("待确认" in out or "AWAITING" in out or "确认" in out, f"计划展示后要求确认，实={out[:120]!r}")
    check(repl.active_plan is not None, "当前会话持有待确认计划")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle("/work"))
    check("确认" in buf.getvalue() or "审批" in buf.getvalue(),
          f"未确认就 /work → 提示先确认，实={buf.getvalue()[:80]!r}")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle("/reject"))
    check(repl.active_plan is None and "拒绝" in buf.getvalue(),
          f"/reject 关闭计划，实={buf.getvalue()[:60]!r}")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(repl._handle("/files --drop nope"))
    check("未找到" in buf.getvalue(), f"/files --drop 未知 id 明确提示，实={buf.getvalue()[:60]!r}")


def scenario_local_tools(tmp: Path, net: MockNet) -> None:
    print("\n场景8 本地文件工具（Agent 可读、越权必拒）")
    cfg = cfg_for(data_dir=str(tmp / "d8"))
    s = new_session(net, cfg)
    doc = tmp / "tool.md"
    doc.write_text("第一行 GET /api/users\n第二行 POST /api/users\n", encoding="utf-8")
    rec = s.files.ingest(doc)
    runner = ToolRunner(cfg, root=str(tmp))

    out = asyncio.run(runner.execute("list_session_files", {}, s))
    check("tool.md" in out and rec.file_id in out, f"清单工具列出已授权文件，实={out[:60]!r}")
    out = asyncio.run(runner.execute("read_local_file", {"file_id": rec.file_id}, s))
    check("GET /api/users" in out and "1|" in out.replace(" ", ""),
          f"读取工具带行号返回正文，实={out[:60]!r}")
    out = asyncio.run(runner.execute(
        "grep_local_file", {"file_id": rec.file_id, "pattern": "POST"}, s))
    check("第二行" in out and out.strip().startswith("2"), f"检索工具返回命中行号，实={out[:40]!r}")
    out = asyncio.run(runner.execute("read_local_file", {"file_id": "deadbeef"}, s))
    check(out.startswith("【已拦截】"), f"未授权 file_id 被拒，实={out[:60]!r}")
    out = asyncio.run(runner.execute(
        "read_local_file", {"file_id": rec.file_id, "start": 2, "lines": 1}, s))
    check("第二行" in out and "第一行" not in out, f"分页读取按行区间，实={out[:40]!r}")

    note = s.files.prompt_note()
    check("tool.md" in note and "GET /api/users" not in note,
          f"系统提示只放清单、不放正文，实={note[:80]!r}")


def scenario_static_exit() -> None:
    print("\n场景9 出口纪律（Work 不自己发请求）")
    work_src = (PROJECT / "core" / "workflow" / "work.py").read_text(encoding="utf-8")
    check("httpx" not in work_src and "aiohttp" not in work_src,
          "work.py 不直接持有 HTTP 客户端（只能通过 Runner 的统一出口）")
    check("runner.execute" in work_src, "面向目标的步骤统一走 runner.execute")
    files_src = (PROJECT / "core" / "files" / "tools.py").read_text(encoding="utf-8")
    check("httpx" not in files_src and "requests" not in files_src,
          "本地文件工具不发任何网络请求")


def main() -> int:
    net = MockNet()
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            tmp = Path(td)
            scenario_state_machine()
            scenario_plan_readonly(tmp, net)
            scenario_build(tmp, net)
            scenario_approval(tmp, net)
            scenario_work_refuses(tmp, net)
            scenario_work_execute(tmp, net)
            scenario_repl(tmp, net)
            scenario_local_tools(tmp, net)
            scenario_static_exit()
    finally:
        net.close()
    total = OK + FAIL
    print(f"\n{OK}/{total} 通过")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
