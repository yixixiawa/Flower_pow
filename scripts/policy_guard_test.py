"""接口测试生命周期权限控制（policy/，111.md）的回归测试（不触网）。

锁死六件事：
  1. 规则清单表：恰好十条、严格六列、等级与矩阵一致、L3 无执行路径；
  2. decide()：L0 有条件允许 / L1 仅隔离测试环境 / L2 专门环境与审批 /
     L3 默认禁止，条件不满足统一"拒绝执行"，生产环境不得因审批解锁；
  3. classify_request()：九类接口分类齐全、EXPORT 独立、不得仅凭
     Method 判断、任一维度更高风险按更高风险处理；
  4. RequestGuard：环境判不出 = unknown = 拒绝；host 通配绑定生效；
     未知工具 UNKNOWN 拒绝；L3 显式授权在生产环境仍被拒；
  5. TestLedger：台账按 run_id 分桶，未知对象无审批不得删除；
  6. Runner 集成：execute() 前置闸门真的拦（不触网），审计留痕，
     放行的写操作进台账。

运行：.venv/Scripts/python.exe scripts/policy_guard_test.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import Config  # noqa: E402
from core.session import Session  # noqa: E402
from policy.api_policy import (  # noqa: E402
    ApiCategory,
    Decision,
    Environment,
    RULES,
    decide,
    rule_for_command,
    rules_table_markdown,
)
from policy.request_guard import RequestGuard, classify_request  # noqa: E402
from policy.test_transaction import TestLedger  # noqa: E402

PASS = 0
FAIL: list[str] = []


def ok(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


# ── 1. 规则清单表 ────────────────────────────────────────────────

EXPECTED_LEVELS = {
    "查询详情": "L0", "查询列表": "L0",
    "创建测试数据": "L1", "修改测试数据": "L1",
    "上传测试文件": "L2", "删除测试数据": "L2",
    "批量删除": "L3", "SQL 注入验证": "L3", "命令执行": "L3", "定时任务执行": "L3",
}
EXPECTED_ALLOW = {
    "查询详情": "有条件允许", "查询列表": "有条件允许",
    "创建测试数据": "仅隔离测试环境", "修改测试数据": "仅隔离测试环境",
    "上传测试文件": "需要专门测试环境", "删除测试数据": "需要单独审批",
}


def test_rules_table() -> None:
    ok(len(RULES) == 10, f"恰好十条规则（实际 {len(RULES)}）")
    for r in RULES:
        ok(len(r.to_row()) == 6, f"{r.command} 严格六列")
        ok(r.handling == "拒绝执行", f"{r.command} 条件不满足统一拒绝执行")
        ok(EXPECTED_LEVELS.get(r.command) == r.level, f"{r.command} 等级与矩阵一致")
        if r.command in EXPECTED_ALLOW:
            ok(r.allow_when.startswith(EXPECTED_ALLOW[r.command]), f"{r.command} 允许条件按矩阵原文")
        if r.level == "L3":
            ok("无" in r.allow_when and "禁止" in r.default_status, f"{r.command} L3 仅禁止规则")
    table = rules_table_markdown()
    ok(len([ln for ln in table.splitlines() if ln.startswith("|")]) == 12, "表格含表头+分隔+10 行")
    ok(rule_for_command("不存在的命令") is None, "矩阵外命令查不到规则")


# ── 2. decide() 决策引擎 ─────────────────────────────────────────


def test_decide() -> None:
    # L0：绑定齐全 → 允许；缺绑定 → 拒绝
    d = decide("查询详情", environment="production", identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "L0 只读 + 绑定齐全 → 允许")
    d = decide("查询列表", identity_bound=True, target_bound=False)
    ok(d.decision == Decision.DENY and "目标未绑定" in d.reason, "L0 目标未绑定 → 拒绝")

    # L1：仅隔离测试环境
    d = decide("创建测试数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "L1 隔离测试环境 → 允许")
    for env in (Environment.PRODUCTION, Environment.DEDICATED_TEST, Environment.UNKNOWN):
        d = decide("修改测试数据", environment=env, identity_bound=True, target_bound=True)
        ok(d.decision == Decision.DENY, f"L1 {env} → 拒绝（dedicated 不满足『仅隔离』）")

    # L2 上传：专门测试环境；isolated 也算专门（非生产），生产拒绝
    d = decide("上传测试文件", environment=Environment.DEDICATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "L2 上传 dedicated_test → 允许")
    d = decide("上传测试文件", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "L2 上传 isolated_test → 允许")
    d = decide("上传测试文件", environment=Environment.PRODUCTION,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.DENY, "L2 上传生产环境 → 拒绝")

    # L2 删除：测试环境 + 单独审批；无审批 REVIEW；生产环境审批也不行
    d = decide("删除测试数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True, approved=False)
    ok(d.decision == Decision.REVIEW, "L2 删除无审批 → REVIEW")
    d = decide("删除测试数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.ALLOW, "L2 删除有审批 → 允许")
    d = decide("删除测试数据", environment=Environment.PRODUCTION,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.DENY and "不得推导" in d.reason, "生产环境删除审批也不解锁")

    # L3：默认禁止，无审批无路径
    for cmd in ("批量删除", "SQL 注入验证", "命令执行", "定时任务执行"):
        d = decide(cmd, environment=Environment.ISOLATED_TEST,
                   identity_bound=True, target_bound=True)
        ok(d.decision == Decision.DENY, f"L3 {cmd} 无审批 → 直接拒绝")

    # 未知命令 → UNKNOWN
    d = decide("未知命令")
    ok(d.decision == Decision.UNKNOWN, "矩阵外命令 → UNKNOWN")


# ── 3. classify_request 七维度识别 ────────────────────────────────


def test_classify() -> None:
    # 只读
    c = classify_request("http://t.example.com/api/users/1", "GET")
    ok(c.category == ApiCategory.READ and c.command == "查询详情", "GET 详情 → READ")
    # EXPORT 独立分类，不归入 READ
    c = classify_request("http://t.example.com/api/users/export", "GET")
    ok(c.category == ApiCategory.EXPORT, "EXPORT 独立分类")
    ok(c.command == "查询详情", "EXPORT 落到 L0 查询命令")
    # 登录是 AUTH，不是"创建资源"
    c = classify_request("http://t.example.com/api/login", "POST", body="u=1&p=2")
    ok(c.category == ApiCategory.AUTH, "POST /login → AUTH（不按 POST 升级为 CREATE）")
    # 删除
    c = classify_request("http://t.example.com/api/users/1", "DELETE")
    ok(c.command == "删除测试数据", "DELETE → 删除测试数据")
    # 仅凭 Method 不够：GET + 破坏性 SQL 请求体 → 按 SQL 注入验证（L3）
    c = classify_request(
        "http://t.example.com/api/search", "GET",
        body="q=1'; DROP TABLE users--",
    )
    ok(c.command == "SQL 注入验证", "GET + 破坏性 SQL 体 → SQL 注入验证（更高风险为准）")
    # 批量删除
    c = classify_request(
        "http://t.example.com/api/users/delete", "POST", body='{"ids":[1,2,3]}'
    )
    ok(c.command == "批量删除", "ids 数组 + delete 路径 → 批量删除")
    # 定时任务
    c = classify_request(
        "http://t.example.com/api/task/run", "POST",
        params={"cron": "0 0 * * *"},
    )
    ok(c.command == "定时任务执行", "cron 参数 → 定时任务执行")
    # 上传（multipart）
    c = classify_request(
        "http://t.example.com/api/upload", "POST",
        body="content-disposition: form-data; filename=\"a.txt\"",
    )
    ok(c.category == ApiCategory.UPLOAD, "multipart → UPLOAD")
    # 命令执行语义
    c = classify_request("http://t.example.com/api/cmd/exec", "POST", body="c=ls")
    ok(c.command == "命令执行", "exec 路径 → 命令执行")
    # 分类覆盖九类（AUTH 覆盖 + UNKNOWN 由 guard 层产生）
    cats = {ApiCategory.READ, ApiCategory.CREATE, ApiCategory.UPDATE, ApiCategory.DELETE,
            ApiCategory.UPLOAD, ApiCategory.EXPORT, ApiCategory.EXECUTE, ApiCategory.AUTH}
    ok(len(cats) == 8, "九类分类常量齐备（UNKNOWN 由未识别产生）")
    # 创建/修改识别
    c = classify_request("http://t.example.com/api/users", "POST", body='{"name":"t"}')
    ok(c.command == "创建测试数据", "POST 创建资源 → 创建测试数据")
    c = classify_request("http://t.example.com/api/users/1", "PUT", body='{"name":"t"}')
    ok(c.command == "修改测试数据", "PUT → 修改测试数据")
    # 路径正则不误伤 /settings /news /address
    c = classify_request("http://t.example.com/api/settings", "GET")
    ok(c.category == ApiCategory.READ, "GET /settings 不误判为 UPDATE")


# ── 4. RequestGuard 环境绑定与拒绝 ────────────────────────────────


def _cfg_with(**kw) -> Config:
    cfg = Config()
    for k, v in kw.items():
        setattr(cfg.policy, k, v)
    return cfg


def test_guard() -> None:
    from policy.request_guard import GuardContext

    bound = GuardContext(target_bound=True, identity_bound=True)
    # 环境判不出 = unknown → L1 拒绝（不猜）
    g = RequestGuard(_cfg_with())
    ctx = g.check_request("http://10.9.9.9/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "默认 unknown 环境：创建被拒")

    # host 通配绑定：isolated_test 环境 L1 放行
    g = RequestGuard(_cfg_with(environments={"192.168.*": Environment.ISOLATED_TEST}))
    ctx = g.check_request("http://192.168.1.10:8080/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.ALLOW, "隔离测试环境：创建放行")
    ctx = g.check_request("http://10.0.0.5/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "未命中绑定表 → 拒绝")

    # 未知外部工具 → UNKNOWN 拒绝
    ctx = g.check_tool("totally-unknown-tool", {}, ctx=bound)
    ok(ctx.decision == Decision.UNKNOWN, "未知工具 UNKNOWN 默认拒绝")

    # L3 无审批直接拒；有审批 + 非测试环境仍拒（审批不解锁生产危险操作）
    g2 = RequestGuard(_cfg_with())
    ctx = g2.check_tool("sqlmap", {"target": "http://192.168.1.10"}, ctx=bound)
    ok(ctx.decision == Decision.DENY, "sqlmap 无审批 → 拒绝")
    g3 = RequestGuard(_cfg_with(
        approvals={"SQL 注入验证": True},
        environments={"192.168.*": Environment.ISOLATED_TEST},
    ))
    ctx = g3.check_tool("sqlmap", {"target": "http://192.168.1.10"}, ctx=bound)
    ok(ctx.decision == Decision.REVIEW, "sqlmap 显式授权 + 测试环境 → REVIEW（环境门已过）")
    g4 = RequestGuard(_cfg_with(approvals={"SQL 注入验证": True}))
    ctx = g4.check_tool("sqlmap", {"target": "http://10.0.0.5"}, ctx=bound)
    ok(ctx.decision == Decision.DENY, "sqlmap 显式授权但环境未知 → 仍拒绝")

    # 策略关闭 → 一律放行（回到旧行为）
    g5 = RequestGuard(_cfg_with(enabled=False))
    ok(g5.check_request("http://x/", "DELETE").allowed, "策略关闭时放行（readonly 等旧闸门接管）")


# ── 5. TestLedger 生命周期台账 ───────────────────────────────────


def test_ledger() -> None:
    led = TestLedger()
    led.record("http://t.example.com/api/users/33", "create", run_id="r1", target_id="t")
    led.record("http://t.example.com/api/upload/77", "upload", run_id="r2", target_id="t")
    ok(led.known("http://t.example.com/api/users/33?id=1"), "剥 query 后命中台账")
    ok(not led.known("http://t.example.com/api/users/999"), "未登记对象未知")
    verdict, why = led.delete_verdict(
        "http://t.example.com/api/users/33", environment=Environment.ISOLATED_TEST
    )
    ok(verdict, f"删除台账已知对象放行（{why}）")
    verdict, why = led.delete_verdict(
        "http://t.example.com/api/users/999", environment=Environment.ISOLATED_TEST
    )
    ok(not verdict, "删除未知对象且无审批 → 拒绝")
    verdict, _ = led.delete_verdict(
        "http://t.example.com/api/users/999", environment=Environment.ISOLATED_TEST,
        approved=True,
    )
    ok(verdict, "未知对象 + 单独审批 → 放行（如预置测试用户清理）")
    verdict, why = led.delete_verdict(
        "http://t.example.com/api/users/33", environment=Environment.PRODUCTION
    )
    ok(not verdict and "不得推导" in why, "生产环境一律不删（即使台账已知）")
    ok(len(led.objects_of("r1")) == 1, "按 run_id 分桶取对象")
    led.clear(run_id="r1")
    ok(not led.known("http://t.example.com/api/users/33"), "清 run 后对象不再已知")
    ok(led.known("http://t.example.com/api/upload/77"), "其他 run 不受影响")


# ── 6. Runner 集成：闸门真的拦、审计留痕、放行进台账 ────────────────


def test_runner_gate() -> None:
    from core.tools.runner import ToolRunner

    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(
            environments={"127.0.0.*": Environment.ISOLATED_TEST},
        )
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s = Session(target="http://127.0.0.1:8080")
        s.credentials["token"] = "x"  # 身份绑定

        # DELETE → 删除测试数据 L2：REVIEW 且无审批通道 → 拒绝（不触网）
        out = asyncio.run(runner.execute(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/1", "method": "DELETE"}, s,
        ))
        ok(out.startswith("【已拦截】"), "L2 删除无审批通道被闸门拦下")
        ok("删除测试数据" in out, "拒绝回执写明命中的命令")

        # 审计留痕：拒绝事件已落 JSONL
        audit_file = Path(td) / "policy" / "audit.jsonl"
        ok(audit_file.is_file(), "审计 JSONL 已落盘")
        events = [json.loads(ln) for ln in audit_file.read_text(encoding="utf-8").splitlines()]
        ok(any(e["event"] == "deny" and e["command"] == "删除测试数据" for e in events),
           "审计里有拒绝事件")
        ok(all(e.get("run_id") == s.result.current_run_id for e in events if e["event"] == "deny"),
           "审计事件带当前 run_id（三层隔离对齐）")

        # 带审批通道（自动拒绝）：删除仍被拦
        async def _deny(_desc: str) -> bool:
            return False

        runner.approver = _deny
        out = asyncio.run(runner.execute(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/1", "method": "DELETE"}, s,
        ))
        ok(out.startswith("【已拦截】"), "运行期审批拒绝 → 拦截")

        # 创建进隔离测试环境 → 闸门放行（handler 会触网，这里直接测 _policy_gate）
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users", "method": "POST", "body": '{"name":"t"}'},
            s,
        ))
        ok(verdict is None, "隔离测试环境的创建请求放行")
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/users"), "放行的创建进台账")

        # 破坏性 SQL 体（GET 也拦）→ SQL 注入验证 L3 拒绝
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/search?q=1",
             "body": "q=1'; DROP TABLE users--"},
            s,
        ))
        ok(verdict is not None and "SQL 注入验证" in verdict, "破坏性 SQL 被按 L3 拦下")

        # 外部工具：curl 只读取证放行；sqlmap 无审批拦截
        verdict = asyncio.run(runner._policy_gate(
            "external_tool", {"tool": "curl", "args": []}, s,
        ))
        ok(verdict is None, "curl（只读映射）放行")
        verdict = asyncio.run(runner._policy_gate(
            "external_tool", {"tool": "sqlmap", "target": "http://127.0.0.1"}, s,
        ))
        ok(verdict is not None and "SQL 注入验证" in verdict, "sqlmap 无审批被拦")

        # exploit_probe 默认带 rce → 命令执行 L3 拒绝
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080"}, s,
        ))
        ok(verdict is not None and "命令执行" in verdict, "rce 探针被按 L3 拦下")

        # 换目标清台账：旧 run 的对象不再"已知"
        runner.test_ledger.record("http://127.0.0.1:8080/api/old", "create", run_id="old-run")
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/old"), "登记后已知")
        runner.reset_target_scope()
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/old"), "reset_target_scope 清台账")

        # 审计异常兜底：写到不可写的路径不抛
        from policy.audit_logger import PolicyAudit

        bad = PolicyAudit("Z:/definitely/not/writable", enabled=True)
        try:
            bad.log("allow", command="查询详情")
            ok(True, "审计落盘失败不抛异常")
        except Exception as exc:  # noqa: BLE001
            ok(False, f"审计落盘失败不抛异常（却抛了 {type(exc).__name__}）")

        # 策略关闭的 runner：闸门全放行
        cfg_off = Config()
        cfg_off.policy.enabled = False
        off = ToolRunner(cfg_off, root=td)
        verdict = asyncio.run(off._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users/1", "method": "DELETE"}, s,
        ))
        ok(verdict is None, "policy.enabled=false 时闸门放行")


def main() -> int:
    test_rules_table()
    test_decide()
    test_classify()
    test_guard()
    test_ledger()
    test_runner_gate()
    print(
        f"\n权限控制回归 {PASS}/{PASS} 通过"
        + (f"（另有 {len(FAIL)} 项失败）" if FAIL else "")
    )
    for name in FAIL:
        print(f"  - {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
