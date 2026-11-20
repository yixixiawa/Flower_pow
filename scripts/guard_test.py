"""``/guard`` 分级权限管理命令测试（guardschedule.md §7 全部 12 条）。

先于实现编写（schedule 要求"先新增失败测试，再实现功能"）。所有断言
对照 guardschedule.md 原文条款，不放松、不跳过。

运行：``python scripts/guard_test.py``（退出码 0 = 全过）。
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import Config
from core.session.session import Session
from core.tools.runner import ToolRunner
from policy.api_policy import Environment, decide
from policy.guard_registry import get_registry

PASS = 0
FAIL: list[str] = []


def check(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


def cfg_for(env: str = Environment.ISOLATED_TEST, data_dir: str = "./data") -> Config:
    cfg = Config()
    cfg.data_dir = data_dir
    cfg.policy.environments = {"127.0.0.*": env}
    return cfg


def new_session(target: str = "http://127.0.0.1:8080") -> Session:
    s = Session(target=target)
    return s


# ── 场景1 /guard status 正确显示等级状态 ────────────────────────────


def scenario_status(tmp: Path) -> None:
    print("\n场景1 /guard status 显示等级状态")
    cfg = cfg_for(data_dir=str(tmp / "d1"))
    s = new_session()
    from core.repl import Repl

    repl = Repl(cfg, s, agent=False, probes=[])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard("status")
    out = buf.getvalue()
    check("L0" in out and "L1" in out and "L2" in out and "L3" in out,
          "status 输出包含 L0..L3 各级状态")
    check("UNKNOWN" in out, "status 输出包含 UNKNOWN 默认拒绝")
    check("readonly" in out, "status 显示只读模式状态")
    check(s.session_id in out, "status 显示当前会话标识")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard("")
    out = buf.getvalue()
    check("L0" in out and "L3" in out, "裸 /guard 默认展示各级规则")


# ── 场景2 L0..L3 只能查看规则，不改变权限 ──────────────────────────


def scenario_levels_viewonly(tmp: Path) -> None:
    print("\n场景2 等级命令只查看、不改权限")
    cfg = cfg_for(data_dir=str(tmp / "d2"))
    s = new_session()

    before_del = decide("删除测试数据", environment=Environment.ISOLATED_TEST)
    before_sqli = decide("SQL 注入验证", environment=Environment.ISOLATED_TEST)

    from core.repl import Repl

    repl = Repl(cfg, s, agent=False, probes=[])
    for arg in ("L0", "L1", "L2", "L3"):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            repl._guard(arg)
        out = buf.getvalue()
        check(bool(out.strip()), f"/guard {arg} 有输出")

    after_del = decide("删除测试数据", environment=Environment.ISOLATED_TEST)
    after_sqli = decide("SQL 注入验证", environment=Environment.ISOLATED_TEST)
    check(before_del.decision == after_del.decision and before_sqli.decision == after_sqli.decision,
          "查看等级规则前后矩阵判定不变（不是解锁开关）")
    check(bool(getattr(cfg.scan, "readonly", True)) is True,
          "/guard L0..L3 不改变只读模式")

    # /guard L3 展示最高风险警告，且明确"仅用于提醒"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard("L3")
    out = buf.getvalue()
    check("你知道你在干什么了" in out, "L3 视图展示最高风险警告")
    check("永久" in out or "PERMANENT" in out.upper(), "L3 视图声明永久拒绝")


# ── 场景3/4 L3 与 UNKNOWN 无法人工审批解锁 ─────────────────────────


def scenario_l3_unknown_no_ticket(tmp: Path) -> None:
    print("\n场景3+4 L3 / UNKNOWN 拿不到审批票据")
    reg = get_registry(str(tmp / "d3"))

    req3, why3 = reg.register(
        session_id="s3", target_id="t3", run_id="r3",
        url="http://127.0.0.1:8080/api/users/1", method="GET",
        fingerprint="fp-l3", level="L3", command="SQL 注入验证",
        environment=Environment.ISOLATED_TEST, identity="anonymous@127.0.0.1",
        kind="sqli", reason="L3",
    )
    check(req3 is None, "L3 请求不进入可审批队列")
    check("L3" in (why3 or ""), f"L3 注册被拒且说明原因，实={why3!r}")

    req4, why4 = reg.register(
        session_id="s3", target_id="t3", run_id="r3",
        url="http://127.0.0.1:8080/api/x", method="PROPFIND",
        fingerprint="fp-unk", level="UNKNOWN", command="未知命令",
        environment=Environment.ISOLATED_TEST, identity="anonymous@127.0.0.1",
        kind="", reason="UNKNOWN",
    )
    check(req4 is None, "UNKNOWN 请求不进入可审批队列")

    # 即使绕过注册直接造一个 L3 票据请求，approve 也必须拒绝
    ok, msg, _tok = reg.approve(
        "GRD-fake", session_id="s3", target_id="t3",
        environment=Environment.ISOLATED_TEST, approver="interactive:x",
    )
    check(not ok, "不存在的请求编号无法审批")


# ── 场景5 L1 在非隔离测试环境被拒绝 ────────────────────────────────


def scenario_l1_env(tmp: Path) -> None:
    print("\n场景5 L1 仅隔离测试环境")
    reg = get_registry(str(tmp / "d5"))
    req, _ = reg.register(
        session_id="s5", target_id="t5", run_id="r5",
        url="http://127.0.0.1:8080/api/users", method="POST",
        fingerprint="fp-l1", level="L1", command="创建测试数据",
        environment=Environment.ISOLATED_TEST, identity="anonymous@127.0.0.1",
        kind="create", reason="测试数据操作",
    )
    check(req is not None, "隔离测试环境内 L1 可登记待审批")

    for env, label in (
        (Environment.DEDICATED_TEST, "专门测试环境"),
        (Environment.PRODUCTION, "生产环境"),
        (Environment.UNKNOWN, "环境未知"),
    ):
        ok, msg, _ = reg.approve(
            req.request_id, session_id="s5", target_id="t5",
            environment=env, approver="interactive:x",
        )
        check(not ok, f"L1 在 {label} 被拒绝审批")

    ok, msg, tok = reg.approve(
        req.request_id, session_id="s5", target_id="t5",
        environment=Environment.ISOLATED_TEST, approver="interactive:yixixiawa",
    )
    check(ok, "L1 在隔离测试环境允许审批")


# ── 场景6 L2 审批绑定具体请求（一次性）────────────────────────────


def scenario_l2_binding(tmp: Path) -> None:
    print("\n场景6 L2 票据绑定具体请求")
    reg = get_registry(str(tmp / "d6"))
    fp = "fp-l2-delete"
    req, _ = reg.register(
        session_id="s6", target_id="t6", run_id="r6",
        url="http://127.0.0.1:8080/api/users/4321", method="DELETE",
        fingerprint=fp, level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST, identity="anonymous@127.0.0.1",
        kind="delete", reason="删除预置测试数据",
    )
    check(req is not None, "L2 删除可登记待审批")
    ok, msg, tok = reg.approve(
        req.request_id, session_id="s6", target_id="t6",
        environment=Environment.ISOLATED_TEST, approver="interactive:yixixiawa",
    )
    check(ok and tok, "审批通过并签发票据")

    ok1, _ = reg.consume(
        tok, session_id="s6", target_id="t6", run_id="r6",
        url=req.url, method="DELETE", fingerprint=fp,
        identity="anonymous@127.0.0.1",
    )
    check(ok1, "同指纹首次消费成功")
    ok2, _ = reg.consume(
        tok, session_id="s6", target_id="t6", run_id="r6",
        url=req.url, method="DELETE", fingerprint=fp,
        identity="anonymous@127.0.0.1",
    )
    check(not ok2, "同指纹二次消费被拒（一次性）")

    # 匿名审批人 = 未认证审批，必须拒绝签发
    req2, _ = reg.register(
        session_id="s6", target_id="t6", run_id="r6",
        url="http://127.0.0.1:8080/api/users/4322", method="DELETE",
        fingerprint="fp-2", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST, identity="anonymous@127.0.0.1",
        kind="delete", reason="",
    )
    ok, _msg, _t = reg.approve(
        req2.request_id, session_id="s6", target_id="t6",
        environment=Environment.ISOLATED_TEST, approver="",
    )
    check(not ok, "无真实审批主体 → 拒绝签发")


# ── 场景7-10 内容/目标/会话变化 → 票据失效 ─────────────────────────


def scenario_ticket_invalidation(tmp: Path) -> None:
    print("\n场景7-10 票据绑定失效矩阵")
    reg = get_registry(str(tmp / "d7"))

    def make(fp: str, url: str, sid: str = "s7", tid: str = "t7"):
        req, _ = reg.register(
            session_id=sid, target_id=tid, run_id="r7",
            url=url, method="DELETE", fingerprint=fp, level="L2",
            command="删除测试数据", environment=Environment.ISOLATED_TEST,
            identity="anonymous@127.0.0.1", kind="delete", reason="",
        )
        ok, _m, tok = reg.approve(
            req.request_id, session_id=sid, target_id=tid,
            environment=Environment.ISOLATED_TEST, approver="interactive:x",
        )
        return tok, req

    # 7 URL 变化
    tok, req = make("fp7a", "http://127.0.0.1:8080/api/users/1")
    ok, why = reg.consume(tok, session_id="s7", target_id="t7", run_id="r7",
                          url="http://127.0.0.1:8080/api/users/2",
                          method="DELETE", fingerprint="fp7b",
                          identity="anonymous@127.0.0.1")
    check(not ok, "URL 变化 → 票据失效")

    # 8 请求体变化（指纹含 body）
    tok, req = make("fp8a", "http://127.0.0.1:8080/api/items")
    ok, _ = reg.consume(tok, session_id="s7", target_id="t7", run_id="r7",
                        url=req.url, method="POST", fingerprint="fp8b",
                        identity="anonymous@127.0.0.1")
    check(not ok, "请求体/指纹变化 → 票据失效")

    # 9 切换 target
    tok, req = make("fp9", "http://127.0.0.1:8080/api/users/3")
    ok, _ = reg.consume(tok, session_id="s7", target_id="t9x", run_id="r7",
                        url=req.url, method="DELETE", fingerprint="fp9",
                        identity="anonymous@127.0.0.1")
    check(not ok, "切换 target → 票据失效")

    # 10 切换 session
    tok, req = make("fp10", "http://127.0.0.1:8080/api/users/4", sid="s10")
    ok, _ = reg.consume(tok, session_id="s10-other", target_id="t7", run_id="r7",
                        url=req.url, method="DELETE", fingerprint="fp10",
                        identity="anonymous@127.0.0.1")
    check(not ok, "切换 session → 票据失效")

    # 跨会话审批被拒（schedule §3.2/3.3）
    req, _ = reg.register(
        session_id="sA", target_id="tA", run_id="rA",
        url="http://127.0.0.1:8080/api/users/9", method="DELETE",
        fingerprint="fp-x", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    ok, _m, _t = reg.approve(req.request_id, session_id="sB", target_id="tA",
                             environment=Environment.ISOLATED_TEST,
                             approver="interactive:x")
    check(not ok, "他人会话的请求不可审批（session 隔离）")
    ok, _m, _t = reg.approve(req.request_id, session_id="sA", target_id="tB",
                             environment=Environment.ISOLATED_TEST,
                             approver="interactive:x")
    check(not ok, "跨 target 的请求不可审批")


# ── 场景11 readonly off 不绕过策略 ─────────────────────────────────


def scenario_readonly_no_bypass(tmp: Path) -> None:
    print("\n场景11 readonly off 不绕过 Policy")
    cfg = cfg_for(data_dir=str(tmp / "d11"))
    s = new_session()
    from core.repl import Repl

    repl = Repl(cfg, s, agent=False, probes=[])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard("readonly off")
    out = buf.getvalue()
    check("矩阵" in out or "权限" in out, "readonly off 提示不放松矩阵")
    check(getattr(cfg.scan, "readonly", True) is False, "只读确实退出")

    before = decide("SQL 注入验证", environment=Environment.ISOLATED_TEST)
    check(before.decision == "DENY", "readonly off 后 L3 仍 DENY")

    runner = ToolRunner(cfg, root=str(tmp))
    blocked = asyncio.run(runner._policy_gate(
        "sqli_probe", {"url": "http://127.0.0.1:8080/api/x"}, s,
    ))
    check(blocked is not None, "readonly off 后 L3 工具仍被 Runner 拦截")

    blocked2 = asyncio.run(runner._policy_gate(
        "http_request", {"url": "http://10.9.9.9/x", "method": "GET"}, s,
    ))
    check(blocked2 is not None, "readonly off 后范围外目标仍被拦截")


# ── 场景12 审批/拒绝/撤销全部落持久化审计；审计坏 → 拒绝 ───────────


def scenario_audit(tmp: Path) -> None:
    print("\n场景12 审计持久化与失败拒绝")
    d = tmp / "d12"
    reg = get_registry(str(d))
    req, _ = reg.register(
        session_id="s12", target_id="t12", run_id="r12",
        url="http://127.0.0.1:8080/api/users/5", method="DELETE",
        fingerprint="fp12", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    ok, _m, tok = reg.approve(req.request_id, session_id="s12", target_id="t12",
                              environment=Environment.ISOLATED_TEST,
                              approver="interactive:yixixiawa")
    check(ok, "审批成功")
    reg.consume(tok, session_id="s12", target_id="t12", run_id="r12",
                url=req.url, method="DELETE", fingerprint="fp12",
                identity="anonymous@127.0.0.1")

    req2, _ = reg.register(
        session_id="s12", target_id="t12", run_id="r12",
        url="http://127.0.0.1:8080/api/users/6", method="DELETE",
        fingerprint="fp12b", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    reg.deny(req2.request_id, session_id="s12", approver="interactive:yixixiawa")
    req3, _ = reg.register(
        session_id="s12", target_id="t12", run_id="r12",
        url="http://127.0.0.1:8080/api/users/7", method="DELETE",
        fingerprint="fp12c", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    ok3, _m, tok3 = reg.approve(req3.request_id, session_id="s12",
                                target_id="t12",
                                environment=Environment.ISOLATED_TEST,
                                approver="interactive:yixixiawa")
    reg.revoke(req3.request_id, session_id="s12", approver="interactive:yixixiawa")

    audit_path = d / "policy" / "audit.jsonl"
    check(audit_path.exists(), "审计文件已持久化")
    events = [json.loads(x)["event"] for x in audit_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    check("guard_issue" in events, "审批签发有审计")
    check("guard_consume" in events, "票据消费有审计")
    check("guard_deny" in events, "拒绝有审计")
    check("guard_revoke" in events, "撤销有审计")
    raw = audit_path.read_text(encoding="utf-8")
    check("yixixiawa" in raw, "审计记录真实审批主体")
    check("s12" in raw and "t12" in raw, "审计含 session_id / target_id")

    # 审计不可持久化 → 敏感操作（审批）必须拒绝
    reg_off = get_registry(str(tmp / "d12-off"), audit_enabled=False)
    req4, _ = reg_off.register(
        session_id="s12x", target_id="t12x", run_id="r12x",
        url="http://127.0.0.1:8080/api/users/8", method="DELETE",
        fingerprint="fp12x", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    ok, _m, _t = reg_off.approve(req4.request_id, session_id="s12x",
                                 target_id="t12x",
                                 environment=Environment.ISOLATED_TEST,
                                 approver="interactive:x")
    check(not ok, "审计持久化失败 → 审批必须拒绝")


# ── 场景13 Runner 集成：L2 被拦 → pending → /guard 审批 → 放行 ─────


def scenario_runner_integration(tmp: Path) -> None:
    print("\n场景13 Runner 与 /guard 审批闭环（上传）")
    d = tmp / "d13"
    # 上传需要专门测试环境（DEDICATED_TEST）才进入 REVIEW 审批通道
    cfg = cfg_for(env=Environment.DEDICATED_TEST, data_dir=str(d))
    s = new_session()
    runner = ToolRunner(cfg, root=str(tmp))

    url = "http://127.0.0.1:8080/upload"
    blocked = asyncio.run(runner._policy_gate(
        "http_request", {"url": url, "method": "POST", "body": "data=x"}, s,
    ))
    check(blocked is not None, "L2 上传无审批 → 拦截")
    check("GRD-" in (blocked or ""), f"拒绝文本给出 GUARD 请求编号，实={blocked[:80]!r}")

    reg = get_registry(str(d))
    pend = reg.pending(s.session_id)
    check(len(pend) == 1, "拦截时自动登记待审批请求")
    rid = pend[0].request_id

    # 重复触发同一请求：去重，不无限堆 pending
    asyncio.run(runner._policy_gate(
        "http_request", {"url": url, "method": "POST", "body": "data=x"}, s,
    ))
    check(len(reg.pending(s.session_id)) == 1, "同指纹重复拦截只登记一次")

    ok, _m, tok = reg.approve(
        rid, session_id=s.session_id,
        target_id=s.result.target_id or s.target,
        environment=Environment.DEDICATED_TEST,
        approver="interactive:yixixiawa",
    )
    check(ok, "/guard approve 语义（经 registry）审批通过")

    allowed = asyncio.run(runner._policy_gate(
        "http_request", {"url": url, "method": "POST", "body": "data=x"}, s,
    ))
    check(allowed is None, "票据消费后同一请求放行")
    check(len(reg.pending(s.session_id)) == 0, "消费后退出 pending")

    # 内容变化 → 需要重新审批
    blocked2 = asyncio.run(runner._policy_gate(
        "http_request", {"url": url, "method": "POST", "body": "data=y"}, s,
    ))
    check(blocked2 is not None, "请求体变化 → 重新进入待审批")

    # L3 触发 → 警告登记 + 拒绝文本含警告
    blocked3 = asyncio.run(runner._policy_gate(
        "sqli_probe", {"url": url}, s,
    ))
    check(blocked3 is not None and "你知道你在干什么了" in blocked3,
          "L3 拒绝文本展示最高风险警告")
    sight = reg.last_l3_sighting(s.session_id)
    check(sight is not None and sight.get("operation") and sight.get("target"),
          "L3 识别信息（操作/目标/来源/等级/原因）已登记")


# ── 场景14 REPL /guard pending / approve / deny / revoke ───────────


def scenario_repl_pending(tmp: Path) -> None:
    print("\n场景14 REPL 审批命令闭环")
    d = tmp / "d14"
    cfg = cfg_for(env=Environment.DEDICATED_TEST, data_dir=str(d))
    s = new_session()
    from core.repl import Repl

    runner = ToolRunner(cfg, root=str(tmp))
    asyncio.run(runner._policy_gate(
        "http_request",
        {"url": "http://127.0.0.1:8080/upload", "method": "POST", "body": "a=1"}, s,
    ))

    repl = Repl(cfg, s, agent=False, probes=[])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard("pending")
    out = buf.getvalue()
    check("GRD-" in out, "pending 列出请求编号")
    check("upload" in out.lower() or "上传" in out, "pending 显示操作")

    rid = get_registry(str(d)).pending(s.session_id)[0].request_id
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard(f"approve {rid}")
    out = buf.getvalue()
    check("一次性" in out or "票据" in out, "approve 输出票据说明")

    # deny / revoke 路径
    runner2 = ToolRunner(cfg, root=str(tmp))
    s2 = Session(target="http://127.0.0.1:8080")
    asyncio.run(runner2._policy_gate(
        "http_request",
        {"url": "http://127.0.0.1:8080/upload", "method": "POST", "body": "b=2"}, s2,
    ))
    rid2 = get_registry(str(d)).pending(s2.session_id)[0].request_id
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard(f"deny {rid2}")
    check("拒绝" in buf.getvalue(), "deny 有确认输出")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._guard(f"revoke {rid2}")
    check("撤销" in buf.getvalue() or "不存在" in buf.getvalue(),
          "revoke 有确认输出（已拒绝的请求报不存在/已处理）")

    # 补全候选
    from core.repl.context import _ContextMixin  # noqa: F401  确保可导入
    args = repl._completer_args("guard")
    check("status" in args and "pending" in args and "approve" in args,
          "/guard 参数 Tab 可补全")


# ── 场景15 过期票据失效 ────────────────────────────────────────────


def scenario_expiry(tmp: Path) -> None:
    print("\n场景15 票据过期")
    reg = get_registry(str(tmp / "d15"))
    reg._ttl = -1  # 立即过期（测试注入）
    req, _ = reg.register(
        session_id="s15", target_id="t15", run_id="r15",
        url="http://127.0.0.1:8080/api/users/5", method="DELETE",
        fingerprint="fp15", level="L2", command="删除测试数据",
        environment=Environment.ISOLATED_TEST,
        identity="anonymous@127.0.0.1", kind="delete", reason="",
    )
    ok, _m, tok = reg.approve(req.request_id, session_id="s15", target_id="t15",
                              environment=Environment.ISOLATED_TEST,
                              approver="interactive:x")
    check(ok, "签发成功（过期参数为负仅测试用）")
    ok2, why = reg.consume(tok, session_id="s15", target_id="t15", run_id="r15",
                           url=req.url, method="DELETE", fingerprint="fp15",
                           identity="anonymous@127.0.0.1")
    check(not ok2 and "过期" in (why or ""), f"过期票据消费被拒，实={why!r}")
    reg._ttl = 300


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scenario_status(tmp)
        scenario_levels_viewonly(tmp)
        scenario_l3_unknown_no_ticket(tmp)
        scenario_l1_env(tmp)
        scenario_l2_binding(tmp)
        scenario_ticket_invalidation(tmp)
        scenario_readonly_no_bypass(tmp)
        scenario_audit(tmp)
        scenario_runner_integration(tmp)
        scenario_repl_pending(tmp)
        scenario_expiry(tmp)
    print(f"\n{PASS}/{PASS + len(FAIL)} 项通过")
    if FAIL:
        print("失败：")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
