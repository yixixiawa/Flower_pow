"""接口测试生命周期权限控制（policy/，111.md）的回归测试（不触网）。

锁死八件事：
  1. 规则清单表：十条矩阵规则 + EXPORT/AUTH 显式化两条 = 12 条、
     严格六列、等级与矩阵一致、L3 无执行路径；
  2. decide()：L0 有条件允许 / L1 仅隔离测试环境（含导出数据）/
     L2 上传仅 dedicated_test 且逐请求审批 / L2 删除单独审批 /
     L3 一律拒绝；AUTH 显式落「认证操作」L0；
  3. classify_request()：九类接口分类齐全、EXPORT 独立、更高风险为准；
  4. 目标范围统一校验 in_scope：scheme+hostname+port 规范化比较、
     路径前缀授权；所有工具走同一把尺子；目标 URL 合法性校验
     （非法目标/协议/端口明确拒绝）；
  5. 审批只在运行期逐请求发生——配置级审批整体无效；审批 =
     一次性票据（精确匹配、单次消费、带过期时间）；
  6. 台账四元组（目标/run/身份/对象标识）**严格**匹配（维度缺失
     即未知；跨端点按 id 命中须同主机且在登记路径前缀下），创建
     真实请求成功（2xx/3xx）并取得对象标识才登记；
  7. 审计持久化是写操作与审批的先决条件；只读放行但告警；
     写操作放行留痕本身必须落盘成功；
  8. Runner 集成：exploit_probe 与其他工具同一 _policy_ctx / in_scope，
     放行 ≠ 登记（pending → 执行成功后落账）。

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
    COMMAND_FOR_CATEGORY,
    Decision,
    Environment,
    RULES,
    decide,
    rule_for_command,
    rules_table_markdown,
)
from policy.request_guard import RequestGuard, classify_request, in_scope  # noqa: E402
from policy.test_transaction import TestLedger, extract_object_id  # noqa: E402

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
    "导出数据": "L1", "认证操作": "L0",
}
EXPECTED_ALLOW = {
    "查询详情": "有条件允许", "查询列表": "有条件允许",
    "创建测试数据": "仅隔离测试环境", "修改测试数据": "仅隔离测试环境",
    "上传测试文件": "需要专门测试环境", "删除测试数据": "需要单独审批",
    "导出数据": "仅隔离测试环境", "认证操作": "有条件允许",
}


def test_rules_table() -> None:
    ok(len(RULES) == 12, f"10 条矩阵规则 + EXPORT/AUTH 显式 2 条（实际 {len(RULES)}）")
    for r in RULES:
        ok(len(r.to_row()) == 6, f"{r.command} 严格六列")
        ok(r.handling == "拒绝执行", f"{r.command} 条件不满足统一拒绝执行")
        ok(EXPECTED_LEVELS.get(r.command) == r.level, f"{r.command} 等级与矩阵一致")
        if r.command in EXPECTED_ALLOW:
            ok(r.allow_when.startswith(EXPECTED_ALLOW[r.command]), f"{r.command} 允许条件按矩阵原文")
    ok("逐请求审批" in rule_for_command("上传测试文件").allow_when, "上传规则明示逐请求审批")
    if r_level := rule_for_command("上传测试文件"):
        ok("隔离测试环境亦不满足" in r_level.deny_when, "上传规则明示隔离测试环境不满足")
    if r_level := rule_for_command("删除测试数据"):
        ok(r_level.level == "L2", "删除保持 L2")
    table = rules_table_markdown()
    ok(len([ln for ln in table.splitlines() if ln.startswith("|")]) == 14, "表格含表头+分隔+12 行")
    ok(rule_for_command("不存在的命令") is None, "矩阵外命令查不到规则")
    # 第三轮整改 #3：EXPORT/AUTH 显式独立映射，L0 查询命令只留给 READ——
    # 不得为通过分类器而把新类别映射到 L0。
    ok(COMMAND_FOR_CATEGORY[ApiCategory.EXPORT] == "导出数据",
       "EXPORT 显式映射「导出数据」（L1，无隐式 L0 授权）")
    ok(COMMAND_FOR_CATEGORY[ApiCategory.AUTH] == "认证操作",
       "AUTH 显式映射「认证操作」（不自动归入普通 READ）")
    l0_mapped = {k for k, v in COMMAND_FOR_CATEGORY.items() if v in ("查询详情", "查询列表")}
    ok(l0_mapped == {ApiCategory.READ}, f"仅 READ 映射 L0 查询命令（实际 {l0_mapped}）")


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

    # L2 上传（P1-③）：**仅 dedicated_test**，且逐请求审批
    d = decide("上传测试文件", environment=Environment.DEDICATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.REVIEW, "L2 上传 dedicated_test → REVIEW（逐请求审批）")
    d = decide("上传测试文件", environment=Environment.DEDICATED_TEST,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.ALLOW, "L2 上传 dedicated_test + 逐请求审批 → 允许")
    d = decide("上传测试文件", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.DENY, "L2 上传 isolated_test → 拒绝（TEST_ENVS 不再放行上传）")
    d = decide("上传测试文件", environment=Environment.PRODUCTION,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.DENY, "L2 上传生产环境 → 拒绝")

    # L2 删除：测试环境 + 单独审批（运行期逐请求）；生产环境审批也不行
    d = decide("删除测试数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True, approved=False)
    ok(d.decision == Decision.REVIEW, "L2 删除无审批 → REVIEW")
    d = decide("删除测试数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.ALLOW, "L2 删除有审批 → 允许")
    d = decide("删除测试数据", environment=Environment.PRODUCTION,
               identity_bound=True, target_bound=True, approved=True)
    ok(d.decision == Decision.DENY and "不得推导" in d.reason, "生产环境删除审批也不解锁")

    # L3：默认禁止，审批无出路
    for cmd in ("批量删除", "SQL 注入验证", "命令执行", "定时任务执行"):
        d = decide(cmd, environment=Environment.ISOLATED_TEST,
                   identity_bound=True, target_bound=True)
        ok(d.decision == Decision.DENY, f"L3 {cmd} 无审批 → 直接拒绝")
        d = decide(cmd, environment=Environment.ISOLATED_TEST,
                   identity_bound=True, target_bound=True, approved=True)
        ok(d.decision == Decision.DENY, f"L3 {cmd} 显式审批 → 仍然拒绝（无出路）")

    # 未知命令 → UNKNOWN
    d = decide("未知命令")
    ok(d.decision == Decision.UNKNOWN, "矩阵外命令 → UNKNOWN")

    # 第二轮整改 #2：EXPORT/AUTH 显式化——不再隐式 L0
    d = decide("导出数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "导出数据（L1）隔离测试环境 → 允许")
    for env in (Environment.PRODUCTION, Environment.DEDICATED_TEST, Environment.UNKNOWN):
        d = decide("导出数据", environment=env, identity_bound=True, target_bound=True)
        ok(d.decision == Decision.DENY, f"导出数据 {env} → 拒绝（不再隐式 L0 放行）")
    d = decide("认证操作", environment=Environment.PRODUCTION,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.ALLOW, "认证操作（L0）绑定齐全 → 允许（显式规则行）")
    d = decide("认证操作", identity_bound=True, target_bound=False)
    ok(d.decision == Decision.DENY, "认证操作目标未绑定 → 拒绝")


# ── 3. classify_request 七维度识别 ────────────────────────────────


def test_classify() -> None:
    c = classify_request("http://t.example.com/api/users/1", "GET")
    ok(c.category == ApiCategory.READ and c.command == "查询详情", "GET 详情 → READ")
    c = classify_request("http://t.example.com/api/users/export", "GET")
    ok(c.category == ApiCategory.EXPORT, "EXPORT 独立分类")
    ok(c.command == "导出数据", "EXPORT → 导出数据（L1，不再隐式落 L0 查询）")
    c = classify_request("http://t.example.com/api/login", "POST", body="u=1&p=2")
    ok(c.category == ApiCategory.AUTH, "POST /login → AUTH（不按 POST 升级为 CREATE）")
    ok(c.command == "认证操作", "AUTH → 认证操作（显式 L0 规则行）")
    c = classify_request("http://t.example.com/api/users/1", "DELETE")
    ok(c.command == "删除测试数据", "DELETE → 删除测试数据")
    c = classify_request(
        "http://t.example.com/api/search", "GET",
        body="q=1'; DROP TABLE users--",
    )
    ok(c.command == "SQL 注入验证", "GET + 破坏性 SQL 体 → SQL 注入验证（更高风险为准）")
    c = classify_request(
        "http://t.example.com/api/users/delete", "POST", body='{"ids":[1,2,3]}'
    )
    ok(c.command == "批量删除", "ids 数组 + delete 路径 → 批量删除")
    c = classify_request(
        "http://t.example.com/api/task/run", "POST",
        params={"cron": "0 0 * * *"},
    )
    ok(c.command == "定时任务执行", "cron 参数 → 定时任务执行")
    c = classify_request(
        "http://t.example.com/api/upload", "POST",
        body="content-disposition: form-data; filename=\"a.txt\"",
    )
    ok(c.category == ApiCategory.UPLOAD, "multipart → UPLOAD")
    c = classify_request("http://t.example.com/api/cmd/exec", "POST", body="c=ls")
    ok(c.command == "命令执行", "exec 路径 → 命令执行")
    c = classify_request("http://t.example.com/api/users", "POST", body='{"name":"t"}')
    ok(c.command == "创建测试数据", "POST 创建资源 → 创建测试数据")
    c = classify_request("http://t.example.com/api/users/1", "PUT", body='{"name":"t"}')
    ok(c.command == "修改测试数据", "PUT → 修改测试数据")
    c = classify_request("http://t.example.com/api/settings", "GET")
    ok(c.category == ApiCategory.READ, "GET /settings 不误判为 UPDATE")


# ── 4. 目标范围统一校验（P0-①）+ RequestGuard ─────────────────────


def _cfg_with(**kw) -> Config:
    cfg = Config()
    for k, v in kw.items():
        setattr(cfg.policy, k, v)
    return cfg


def test_scope() -> None:
    # scheme + hostname + port 规范化比较（P0-①：修掉只比 hostname 的洞）
    ok(in_scope("http://h:8080/api/users", "http://h:8080"), "同 scheme+host+port → 在范围内")
    ok(not in_scope("http://h:9999/api/users", "http://h:8080"), "端口不同 → 出界")
    ok(in_scope("http://h/api/users", "http://h:80"), "默认端口归一（省略 80）")
    ok(in_scope("http://h:80/api", "http://h"), "默认端口归一（显式 80）")
    ok(in_scope("https://h/api", "https://h"), "https 默认端口归一（443）")
    ok(not in_scope("https://h/api", "http://h"), "scheme 不同 → 出界")
    ok(in_scope("http://H:8080/api", "http://h:8080"), "hostname 大小写不敏感")
    ok(not in_scope("http://user@h:8080/api", "http://h:8080") is not True or
       in_scope("http://user@h:8080/api", "http://h:8080"), "userinfo 不影响范围判定")

    # 路径按授权范围处理
    ok(in_scope("http://h:8080/app/users/1", "http://h:8080/app"), "绑定路径前缀内 → 在范围内")
    ok(not in_scope("http://h:8080/other", "http://h:8080/app"), "绑定路径前缀外 → 出界")
    ok(not in_scope("http://h:8080/application", "http://h:8080/app"), "前缀撞车（/application ≠ /app/）→ 出界")
    ok(in_scope("http://h:8080/app", "http://h:8080/app"), "恰好等于前缀 → 在范围内")
    ok(in_scope("http://h:8080/anything", "http://h:8080"), "根绑定 → 全路径在范围内")
    ok(not in_scope("not-a-url", "http://h:8080"), "请求 URL 解析失败 → 不在范围内（fail-closed）")
    ok(not in_scope("http://h:8080/", ""), "绑定目标为空 → 不在范围内（fail-closed）")


def test_guard() -> None:
    from policy.request_guard import GuardContext

    bound = GuardContext(bound_target="http://192.168.1.10:8080", identity_bound=True)
    # 环境判不出 = unknown → L1 拒绝（不猜）
    g = RequestGuard(_cfg_with())
    ctx = g.check_request("http://10.9.9.9/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "默认 unknown 环境：创建被拒")

    # host 通配绑定：isolated_test 环境 L1 放行（同主机）
    g = RequestGuard(_cfg_with(environments={"192.168.*": Environment.ISOLATED_TEST}))
    ctx = g.check_request("http://192.168.1.10:8080/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.ALLOW, "隔离测试环境 + 同主机：创建放行")
    ctx = g.check_request("http://10.0.0.5/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "未命中绑定表 → 拒绝")

    # P0-①：同环境但**端口不同** → 出界拒绝（旧实现只比 hostname，放行了）
    ctx = g.check_request("http://192.168.1.10:9999/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "同主机不同端口（出界）→ 拒绝")
    ctx = g.check_request("http://192.168.1.99/api/users", "POST", body="{}", ctx=bound)
    ok(ctx.decision == Decision.DENY, "同环境但跨主机（出界）→ 拒绝")
    ctx = g.check_request(
        "http://192.168.1.10/api/users", "POST", body="{}",
        ctx=GuardContext(identity_bound=True),
    )
    ok(ctx.decision == Decision.DENY, "无绑定目标 → 拒绝（不能只看环境）")

    # 未知外部工具 → UNKNOWN 拒绝
    ctx = g.check_tool("totally-unknown-tool", {}, ctx=bound)
    ok(ctx.decision == Decision.UNKNOWN, "未知工具 UNKNOWN 默认拒绝")

    # P0-②：配置级审批**整体无效**（L3 写进去无效，L2 删除写进去也无效）
    g3 = RequestGuard(_cfg_with(
        approvals={"SQL 注入验证": True, "命令执行": True, "删除测试数据": True},
        environments={"192.168.*": Environment.ISOLATED_TEST},
    ))
    ok(getattr(g3, "approved", None) is None, "配置级审批属性已移除")
    ctx = g3.check_tool("sqlmap", {"target": "http://192.168.1.10"}, ctx=bound)
    ok(ctx.decision == Decision.DENY, "sqlmap（L3）配置审批也无效")
    ctx = g3.check_tool("hydra", {"target": "http://192.168.1.10"}, ctx=bound)
    ok(ctx.decision == Decision.DENY, "hydra（命令执行 L3）配置审批也无效")
    # 删除（L2）恒 REVIEW：审批只存在于运行期逐请求通道
    ctx = g3.check_request("http://192.168.1.10:8080/api/users/1", "DELETE", ctx=bound)
    ok(ctx.decision == Decision.REVIEW, "删除配置审批写 true 也只给 REVIEW（审批逐请求）")

    # P0-2：策略强制执行——enabled=False 不再是旁路
    g5 = RequestGuard(_cfg_with(enabled=False))
    ctx = g5.check_request("http://192.168.1.10/api/users", "POST", body="{}", ctx=bound)
    ok(not ctx.allowed, "enabled=false 时策略仍强制执行（创建仍走判定）")
    ctx = g5.check_tool("sqlmap", {"target": "http://192.168.1.10"}, ctx=bound)
    ok(ctx.decision == Decision.DENY, "enabled=false 时 sqlmap 仍拒绝")


# ── 4b. P0/P1/P2 整改专项 ─────────────────────────────────────────


def test_hardening() -> None:
    from policy.audit_logger import PolicyAudit
    from policy.enforcer import active_scan_check, scoped_scan_config

    # P0-4：sqli 探针映射 L3（命令映射表）
    from core.tools.runner.base import _ToolRunnerBase

    m = _ToolRunnerBase._PROBE_KIND_COMMAND
    ok(m.get("sqli") == "SQL 注入验证", "sqli 探针 → SQL 注入验证（L3）")
    ok(m.get("rce") == "命令执行", "rce 探针 → 命令执行（L3）")
    ok(m.get("fileread") == "查询详情", "fileread 探针 → 查询详情（L0）")

    # P1-6：params / POC 声明 / 历史行为真正进分类器
    c = classify_request(
        "http://t.example.com/api/task", "GET", params={"cron": "0 0 * * *"},
    )
    ok(c.command == "定时任务执行", "params 里的 cron 进分类（定时任务 L3）")
    c = classify_request("http://t.example.com/api/list", "GET", poc_hint="sqli blind injection")
    ok(c.command == "SQL 注入验证", "POC 声明 sqli 进分类（L3，更高风险为准）")
    c = classify_request("http://t.example.com/api/list", "GET", history_hint="批量删除")
    ok(c.command == "批量删除", "历史行为批量删除进分类（更高风险为准）")

    # P0-②：对象标识提取——创建/上传集合端点响应优先，资源端点 URL 优先
    ok(extract_object_id("http://t/api/users", '{"id":"u-1001"}', url_first=False) == "u-1001",
       "创建（集合端点）从响应体提取对象标识")
    ok(extract_object_id("http://t/api/users", '{"data":{"user_id":"abc-9"}}', url_first=False) == "abc-9",
       "嵌套 user_id 也能提取")
    ok(extract_object_id("http://t/api/users/33", "", url_first=True) == "33",
       "资源型端点从 URL 尾段提取")
    ok(extract_object_id("http://t/api/users", '{"msg":"ok"}', url_first=False) == "",
       "响应无标识 → 提取为空（不得登记）")

    # P1-10：MCP/CLI/后台任务统一入口
    cfg = _cfg_with(environments={"10.0.0.*": Environment.PRODUCTION})
    allowed, msg = active_scan_check(cfg, "http://10.0.0.5/")
    ok(not allowed, "生产环境：主动扫描拒绝")
    ok("生产环境" in msg, "拒绝文本写明生产环境")
    allowed, msg = active_scan_check(_cfg_with(), "http://10.9.9.9/")
    ok(allowed, "未绑定环境：放行但降级")
    cfg2, note = scoped_scan_config(_cfg_with(), "http://10.9.9.9/")
    ok(not cfg2.scan.sqli_probe_enabled and not cfg2.scan.rce_probe_enabled,
       "未绑定环境：SQLi/RCE 探针强制关闭")
    cfg3, note3 = scoped_scan_config(
        _cfg_with(environments={"192.168.*": Environment.ISOLATED_TEST}), "http://192.168.1.1/",
    )
    ok(cfg3.scan.sqli_probe_enabled, "隔离测试环境：探针按配置执行")
    ok(note3 == "", "测试环境无降级提示")

    # P2-11 + P1-⑤：审计落盘失败的明确策略
    a = PolicyAudit("./data", enabled=True)
    a._flush = lambda entries: False  # 模拟磁盘持续不可写
    for i in range(10):
        a.log("allow", command="查询详情", run_id=f"r{i}")
    ok(a.pending_count == 10, f"落盘失败事件进待写队列（{a.pending_count}）")
    ok("未落盘 10" in a.summary_line(), "状态行可见审计缺口")
    a._flush = lambda entries: True
    ok(a.log("deny", command="命令执行") is True, "log 返回 True = 已持久化")
    ok(a.pending_count == 0, "恢复可写后欠账全部补写")
    ok("⚠" not in a.summary_line(), "缺口清零后状态行不再告警")
    # writable 探针（P1-⑤）
    bad = PolicyAudit("Z:/definitely/not/writable", enabled=True)
    ok(bad.writable is False, "不可写路径 → writable False")
    off = PolicyAudit("./data", enabled=False)
    ok(off.writable is False, "audit.enabled=false → writable False（无持久化审计）")
    good = PolicyAudit("./data", enabled=True)
    ok(good.writable is True, "可写路径 → writable True")


# ── 5. TestLedger 四元组台账（P0-②）───────────────────────────────


def test_ledger() -> None:
    led = TestLedger()
    # P0-②：创建/上传没有对象标识 → 不登记
    ok(led.record("http://t.example.com/api/users", "create", run_id="r1", target_id="t") is None,
       "创建无对象标识 → 不登记")
    led.record("http://t.example.com/api/users", "create", run_id="r1", target_id="t",
               identity="anon", object_id="33")
    led.record("http://t.example.com/api/upload/77", "upload", run_id="r2", target_id="t",
               identity="anon", object_id="77")
    # 四元组：目标
    ok(not led.known("http://t.example.com/api/users/33", target_id="other",
                     run_id="r1", identity="anon"),
       "跨目标不命中（对象标识相同也不行）")
    ok(led.known("http://t.example.com/api/users/33", target_id="t",
                 run_id="r1", identity="anon"),
       "同目标按对象标识命中（集合端点创建 → 资源端点删除）")
    # 四元组：run
    ok(not led.known("http://t.example.com/api/users/33", target_id="t",
                     run_id="r9", identity="anon"),
       "跨 run 不命中（旧轮次登记对新 run 不可复用）")
    # 四元组：身份
    ok(not led.known("http://t.example.com/api/users/33", target_id="t",
                     run_id="r1", identity="cred:x:1234"),
       "跨身份不命中（换凭证/换账号不可复用）")
    # 第二轮整改：维度缺失 = 无法确认归属 = 未知（fail-closed，空参数不再当通配符）
    ok(not led.known("http://t.example.com/api/users/33"),
       "四元组全缺 → 不命中（不再隐式命中整个台账）")
    ok(not led.known("http://t.example.com/api/users/33", target_id="t"),
       "缺 run/身份 → 不命中")
    ok(not led.known("http://t.example.com/api/users/33", target_id="t", run_id="r1"),
       "缺身份 → 不命中")
    # URL key 精确命中（上传资源端点）
    ok(led.known("http://t.example.com/api/upload/77?id=1", target_id="t",
                 run_id="r2", identity="anon"),
       "剥 query 后命中台账")
    ok(not led.known("http://t.example.com/api/users/999", target_id="t",
                     run_id="r1", identity="anon"),
       "未登记对象未知")
    # 第二轮整改：跨端点按 id 命中必须同主机且在登记路径前缀之下
    led.record("http://t.example.com/api/other/33", "update", run_id="r1",
               target_id="t", identity="anon", object_id="33")
    ok(led.known("http://t.example.com/api/other/33", target_id="t",
                 run_id="r1", identity="anon"),
       "同键命中（update 资源端点）")
    # 注意：/api/other/33 与 /api/users 登记的 33 是不同端点——严格前缀
    # 约束下，other 的同名 id 不得串到 users 端点。用独立台账逐条验证：
    led2 = TestLedger()
    led2.record("http://t.example.com/api/other/33", "update", run_id="r1",
                target_id="t", identity="anon", object_id="33")
    ok(not led2.known("http://t.example.com/api/users/33", target_id="t",
                      run_id="r1", identity="anon"),
       "跨端点同名 id 不命中（/api/other/33 ≠ /api/users 前缀）")
    led3 = TestLedger()
    led3.record("http://other.example.com/api/users/33", "update", run_id="r1",
                target_id="t", identity="anon", object_id="33")
    ok(not led3.known("http://t.example.com/api/users/33", target_id="t",
                      run_id="r1", identity="anon"),
       "跨主机同名 id 不命中")
    # 删除判定
    verdict, why = led.delete_verdict(
        "http://t.example.com/api/users/33", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST,
    )
    ok(verdict, f"四元组匹配的删除放行（{why}）")
    verdict, _ = led.delete_verdict(
        "http://t.example.com/api/users/33", target_id="t", run_id="r9",
        identity="anon", environment=Environment.ISOLATED_TEST,
    )
    ok(not verdict, "run 不匹配的删除 → 未知对象")
    verdict, _ = led.delete_verdict(
        "http://t.example.com/api/users/999", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST,
    )
    ok(not verdict, "删除未知对象且无审批 → 拒绝")
    verdict, _ = led.delete_verdict(
        "http://t.example.com/api/users/999", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST,
        approved=True,
    )
    ok(verdict, "未知对象 + 绑定本次请求的审批 → 放行")
    verdict, why = led.delete_verdict(
        "http://t.example.com/api/users/33", target_id="t", run_id="r1",
        identity="anon", environment=Environment.PRODUCTION,
    )
    ok(not verdict and "不得推导" in why, "生产环境一律不删（即使台账已知）")
    ok(len(led.objects_of("r1")) == 2, "按 run_id 分桶取对象")
    led.clear(run_id="r1")
    ok(not led.known("http://t.example.com/api/users/33", target_id="t",
                     run_id="r1", identity="anon"),
       "清 run 后对象不再已知")
    ok(led.known("http://t.example.com/api/upload/77", target_id="t",
                 run_id="r2", identity="anon"),
       "其他 run 不受影响")


# ── 6. Runner 集成：闸门、逐请求审批、pending 台账、审计前置 ────────


def test_runner_gate() -> None:
    from core.tools.runner import ToolRunner

    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST})
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s = Session(target="http://127.0.0.1:8080")

        # ── P1-④：真实账号身份（凭证值指纹，可区分多账号）──────────
        runner._observe_identity({"Authorization": "Bearer token-A"}, "http://127.0.0.1:8080/", session=s)
        id_a = runner._identity
        ok(id_a.startswith("cred:authorization:") and len(id_a) > len("cred:authorization:"),
           f"凭证 → cred:<头名>:<指纹>（{id_a}）")
        ok("token" not in id_a and "Bearer" not in id_a, "凭证值不进身份标签")
        runner._observe_identity({"Authorization": "Bearer token-B"}, "http://127.0.0.1:8080/", session=s)
        ok(runner._identity != id_a, "不同凭证值 = 不同身份（管理员/普通用户可区分）")
        s2 = Session(target="http://127.0.0.1:8080")
        s2.credentials["role"] = "admin"
        runner._observe_identity({"Authorization": "Bearer token-C"}, "http://127.0.0.1:8080/", session=s2)
        ok(runner._identity.endswith("@admin"), "显式角色声明进身份标签")
        runner.reset_target_scope()
        ok(runner._identity == "", "reset_target_scope 重置身份上下文")
        ok(runner._current_identity(s).startswith("anonymous@"), "无凭证 → 显式匿名身份")

        # ── DELETE → L2 删除：REVIEW 且无审批通道 → 拒（不触网）────
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

        # ── P0-②：审批逐请求绑定对象 URL，参数变化不可复用 ─────────
        calls: list[str] = []

        async def _approve(desc: str) -> bool:
            calls.append(desc)
            return True

        runner.approver = _approve
        v1 = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/42", "method": "DELETE"}, s,
        ))
        ok(v1 is None, "未知对象 + 绑定本次请求的逐请求审批 → 放行")
        v2 = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/43", "method": "DELETE"}, s,
        ))
        ok(v2 is None, "第二个对象触发第二次逐请求审批 → 放行")
        ok(len(calls) == 2 and "/users/42" in calls[0] and "/users/43" in calls[1],
           "审批绑定具体对象 URL（参数变化 → 重新审批，不可复用）")

        # 无审批通道：未知对象删不掉
        runner.approver = None
        v3 = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/99", "method": "DELETE"}, s,
        ))
        ok(v3 is not None and "删除测试数据" in v3, "无审批通道 → 未知对象拒绝删除")

        # ── P0-②：放行 ≠ 登记（pending → 执行成功且取得标识才落账）──
        v = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users", "method": "POST", "body": '{"name":"t"}'},
            s,
        ))
        ok(v is None, "隔离测试环境的创建放行")
        tid, rid = runner._policy_scope(s)
        ident = runner._current_identity(s)
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/users",
                                        target_id=tid, run_id=rid, identity=ident),
           "放行未执行 → 尚未登记（放行 ≠ 登记）")
        pend = runner._pending_ledger
        ok(pend is not None and pend["action"] == "create", "放行的创建挂 pending 台账")
        # 执行成功但响应没有对象标识 → 不登记
        runner._commit_pending_ledger(pend, '{"ok":true}')
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/users",
                                        target_id=tid, run_id=rid, identity=ident),
           "创建成功但无对象标识 → 不登记")
        ok(runner._pending_ledger is None, "pending 已消费")
        # 第二轮整改 #4：请求失败（http_request 无状态码行）/4xx/5xx → 不登记
        runner._pending_ledger = dict(pend)
        runner._commit_pending_ledger(runner._pending_ledger,
                                      "请求失败：connection refused", tool="http_request")
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/users",
                                        target_id=tid, run_id=rid, identity=ident),
           "请求失败（无状态码行）→ 不登记")
        runner._pending_ledger = dict(pend)
        runner._commit_pending_ledger(runner._pending_ledger,
                                      'POST http://127.0.0.1:8080/api/users\n'
                                      '状态码：500  耗时：10ms  正文大小：9B\n'
                                      '正文（2 字符）：\n{}', tool="http_request")
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/users",
                                        target_id=tid, run_id=rid, identity=ident),
           "服务端 500（对象未建立）→ 不登记")
        # 执行成功且取得对象标识 → 登记；删除端点靠标识匹配
        runner._pending_ledger = dict(pend)
        runner._commit_pending_ledger(runner._pending_ledger,
                                      'POST http://127.0.0.1:8080/api/users\n'
                                      '状态码：201  耗时：10ms  正文大小：33B\n'
                                      '正文（33 字符）：\n{"ok":true,"data":{"id":"u-1001"}}',
                                      tool="http_request")
        ok(runner.test_ledger.known(
            "http://127.0.0.1:8080/api/users/u-1001",
            target_id=tid, run_id=rid, identity=pend["identity"],
        ), "请求成功（2xx）且取得对象标识 → 登记")
        ok(not runner.test_ledger.known(
            "http://127.0.0.1:8080/api/users/u-1001",
            target_id=tid, run_id=rid, identity="cred:x:aaaa",
        ), "身份不同 → 台账不认（四元组）")
        ok(not runner.test_ledger.known(
            "http://127.0.0.1:8080/api/users/u-1001",
            target_id=tid, run_id="other-run", identity=pend["identity"],
        ), "run 不同 → 台账不认（四元组）")

        # ── P0-①：exploit_probe 与其他工具同一 _policy_ctx / in_scope ──
        # 同主机不同端口 → 出界
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:9999/api/users", "method": "GET"}, s,
        ))
        ok(verdict is not None and "已拦截" in verdict, "同主机不同端口 → 出界拒绝")
        # 跨主机
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.2/api/users", "method": "POST", "body": "{}"},
            s,
        ))
        ok(verdict is not None and "目标未绑定" in verdict, "跨主机请求按未绑定拒绝")
        # exploit_probe 走统一范围校验：出界 URL 同样拒
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.2/", "kinds": "fileread"}, s,
        ))
        ok(verdict is not None and "已拦截" in verdict, "exploit_probe 出界（P0-① 统一校验）拒绝")
        # exploit_probe 范围内 fileread（L0）放行
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080/", "kinds": "fileread"}, s,
        ))
        ok(verdict is None, "exploit_probe 范围内只读探针放行")
        # 破坏性 SQL 体 → SQL 注入验证 L3 拒绝
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/search?q=1",
             "body": "q=1'; DROP TABLE users--"},
            s,
        ))
        ok(verdict is not None and "SQL 注入验证" in verdict, "破坏性 SQL 被按 L3 拦下")
        # exploit_probe sqli → L3
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080", "kinds": "sqli"}, s,
        ))
        ok(verdict is not None and "SQL 注入验证" in verdict, "sqli 探针被按 L3 拦下")
        # 未知探针类别 → 拒绝（不猜）
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080", "kinds": "wormhole"}, s,
        ))
        ok(verdict is not None and "未识别" in verdict, "未知探针类别拒绝")

        # ── 外部工具：curl 只读放行；sqlmap L3 拒 ────────────────────
        verdict = asyncio.run(runner._policy_gate(
            "external_tool", {"tool": "curl", "args": []}, s,
        ))
        ok(verdict is None, "curl（只读映射）放行")
        verdict = asyncio.run(runner._policy_gate(
            "external_tool", {"tool": "sqlmap", "target": "http://127.0.0.1"}, s,
        ))
        ok(verdict is not None and "SQL 注入验证" in verdict, "sqlmap（L3）被拦")

        # ── P1-⑤：审计持久化是写操作与审批的先决条件 ────────────────
        runner.policy_audit.path = Path("Z:/definitely/not/writable/policy/audit.jsonl")
        runner.policy_audit._probe_ok = None  # 失效探针缓存
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users2", "method": "POST", "body": "{}"},
            s,
        ))
        ok(verdict is not None and "无法持久化" in verdict, "审计不可持久化 → 写操作拒绝执行")
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/items/1", "method": "GET"}, s,
        ))
        ok(verdict is None, "审计不可持久化 → 只读操作放行")
        ok(any(e["event"] == "warn" for e in runner.policy_audit.recent()),
           "只读放行留 warn 告警（内存可见）")
        ok("warn" in runner.policy_audit.summary_line() or "⚠" in runner.policy_audit.summary_line(),
           "状态行可见审计告警")
        runner.policy_audit.enabled = False
        runner.policy_audit._probe_ok = None
        verdict = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users3", "method": "POST", "body": "{}"},
            s,
        ))
        ok(verdict is not None and "无法持久化" in verdict,
           "audit.enabled=false → 写操作拒绝（不能用内存记录替代持久化审计）")
        runner.policy_audit.enabled = True
        runner.policy_audit._probe_ok = None

        # ── 换目标清台账 ──────────────────────────────────────────────
        runner.test_ledger.record(
            "http://127.0.0.1:8080/api/old", "update", run_id="old-run",
            target_id="old", identity="anon", object_id="old",
        )
        ok(runner.test_ledger.known(
            "http://127.0.0.1:8080/api/old", target_id="old", run_id="old-run",
            identity="anon",
        ), "登记后已知")
        runner.reset_target_scope()
        ok(not runner.test_ledger.known(
            "http://127.0.0.1:8080/api/old", target_id="old", run_id="old-run",
            identity="anon",
        ), "reset_target_scope 清台账")

        # ── P0-2：policy.enabled=false 时闸门仍拦截 ──────────────────
        cfg_off = Config()
        cfg_off.policy.enabled = False
        off_runner = ToolRunner(cfg_off, root=td)
        verdict = asyncio.run(off_runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/users/1", "method": "DELETE"}, s,
        ))
        ok(verdict is not None and verdict.startswith("【已拦截】"),
           "policy.enabled=false 时闸门仍拦截（强制执行）")


# ── 7. 第二轮整改专项：目标校验 / 审批票据 / 留痕收口 ───────────────


def test_remediation2() -> None:
    from core.tools.runner import ToolRunner
    from policy.api_policy import PolicyDecision
    from policy.test_transaction import ApprovalLedger

    # ── #1：目标 URL 合法性校验（非法目标/协议/端口明确拒绝）────────
    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST})
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s = Session(target="http://127.0.0.1:8080")

        cases = [
            ({"url": "ftp://127.0.0.1:8080/etc/passwd", "kinds": "fileread"},
             "协议", "exploit_probe 非法协议（ftp://）明确拒绝"),
            ({"url": "http://127.0.0.1:70000/", "kinds": "fileread"},
             "端口", "exploit_probe 端口越界（:70000）明确拒绝"),
            ({"url": "http://127.0.0.1:8080/a b", "kinds": "fileread"},
             "非法", "exploit_probe URL 含空白明确拒绝"),
            ({"url": "file:///etc/passwd", "kinds": "fileread"},
             "协议", "exploit_probe file:// 协议拒绝"),
        ]
        for args, kw, name in cases:
            verdict = asyncio.run(runner._policy_gate("exploit_probe", args, s))
            ok(verdict is not None and kw in verdict and "已拦截" in verdict, name)

        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "ftp://127.0.0.1:8080/x", "method": "GET"}, s,
        ))
        ok(verdict is not None and "协议" in verdict, "http_request 非法协议同样拒绝")
        # 合法目标不受影响（L0 探针照常放行）
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080/", "kinds": "fileread"}, s,
        ))
        ok(verdict is None, "合法目标 + 范围内只读探针仍放行")

        # ── #2：EXPORT 显式 L1——unknown 环境下导出被拒（旧行为是隐式放行）
        cfg_u = _cfg_with()  # 不绑定环境表 → 环境判不出 = unknown
        cfg_u.data_dir = td
        runner_u = ToolRunner(cfg_u, root=td)
        verdict = asyncio.run(runner_u._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/export", "method": "GET"},
            s,
        ))
        ok(verdict is not None and "导出数据" in verdict and "已拦截" in verdict,
           "EXPORT（导出数据 L1）unknown 环境 → 拒绝（无隐式 L0 授权）")
        # 隔离测试环境下导出按 L1 显式放行
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/export", "method": "GET"},
            s,
        ))
        ok(verdict is None, "EXPORT（导出数据 L1）隔离测试环境 → 显式放行")
        # AUTH 显式 L0——登录放行，且审计里有「认证操作」命令名
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/login",
                             "method": "POST", "body": "u=1&p=2"}, s,
        ))
        ok(verdict is None, "AUTH（认证操作 L0）绑定齐全 → 放行")
        ok(any(e["command"] == "认证操作" and e["event"] == "allow"
               for e in runner.policy_audit.recent()),
           "AUTH 授权以显式命令名「认证操作」进审计（可追踪）")

        # ── #5：审批票据——精确匹配、单次消费、带过期时间、绑定请求指纹 ──
        led = ApprovalLedger(ttl=60.0)
        ap = led.issue(url="http://h/api/users/42", command="删除测试数据",
                       target_id="t", run_id="r1", identity="anon",
                       method="DELETE", request_digest="fp-abc", level="L2",
                       approver="human")
        # 票面不符 → 拒绝消费
        c, why = led.consume(ap.token, url="http://h/api/users/43", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "不符" in why, "审批票据对象 URL 不符 → 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="上传测试文件",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "不符" in why, "审批票据命令不符 → 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="POST", request_digest="fp-abc", level="L2")
        ok(not c and "方法" in why, "审批票据方法不符 → 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-other", level="L2")
        ok(not c and "请求内容" in why, "审批票据请求指纹不符（参数/体/POC 变更）→ 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L1")
        ok(not c and "风险等级" in why, "审批票据风险等级不符 → 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="other", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "不符" in why, "审批票据目标不符（切目标须重批）→ 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r9", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "不符" in why, "审批票据轮次不符 → 拒绝消费")
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r1", identity="cred:x:1",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "不符" in why, "审批票据身份不符 → 拒绝消费")
        # 票面全对 → 消费成功；票面绑定信息完整可追踪
        ok(ap.method == "DELETE" and ap.request_digest == "fp-abc"
           and ap.level == "L2" and ap.approver == "human",
           "票据票面绑定 方法/请求指纹/风险等级/审批人")
        c, why = led.consume(ap.token, url="http://h/api/users/42?id=x", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(c, f"审批票据精确匹配 → 消费成功（{why}）")
        # 单次消费：重放拒绝
        c, why = led.consume(ap.token, url="http://h/api/users/42", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c and "单次" in why, "审批票据重放 → 拒绝（单次消费）")
        c, _ = led.consume("never-issued", url="http://h/", command="删除测试数据",
                           target_id="t", run_id="r1", identity="anon",
                           method="DELETE", request_digest="fp-abc", level="L2")
        ok(not c, "不存在的票据 → 拒绝")
        # 过期：ttl=0 即签发即过期
        ap2 = led.issue(url="http://h/api/x", command="删除测试数据",
                        target_id="t", run_id="r1", identity="anon",
                        method="DELETE", request_digest="fp-x", level="L2", ttl=0.0)
        c, why = led.consume(ap2.token, url="http://h/api/x", command="删除测试数据",
                             target_id="t", run_id="r1", identity="anon",
                             method="DELETE", request_digest="fp-x", level="L2")
        ok(not c and "过期" in why, "过期票据 → 拒绝消费")
        ok(led.outstanding() == 0, "过期票据被清除（outstanding 归零）")
        # 第三轮整改 #5：L3 命令不得签发审批票据（结构性兜底）
        try:
            led.issue(url="http://h/", command="SQL 注入验证", target_id="t",
                      run_id="r1", identity="anon", level="L3")
            ok(False, "L3 命令签发审批票据被拒绝")
        except ValueError:
            ok(True, "L3 命令签发审批票据被拒绝（审批无出路）")
        # 请求内容指纹：任一项变更指纹即变更
        from policy.test_transaction import request_fingerprint as _rf
        base_fp = _rf(method="POST", url="http://h/api", params={"a": 1}, body="x", poc_id="p")
        ok(_rf(method="GET", url="http://h/api", params={"a": 1}, body="x", poc_id="p") != base_fp,
           "方法变更 → 请求指纹变更")
        ok(_rf(method="POST", url="http://h/api", params={"a": 2}, body="x", poc_id="p") != base_fp,
           "参数变更 → 请求指纹变更")
        ok(_rf(method="POST", url="http://h/api", params={"a": 1}, body="x", poc_id="p") == base_fp,
           "同内容键序无关 → 指纹稳定")

        # runner 通道：人审批通过 → 票据签发并当场消费（审计带 token）
        async def _approve(desc: str) -> bool:
            return True

        runner.approver = _approve
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/77", "method": "DELETE"}, s,
        ))
        ok(v is None, "逐请求审批通过 → 放行（票据在通道内签发并消费）")
        approvals = [e for e in runner.policy_audit.recent() if e["event"] == "approval"]
        ok(approvals and approvals[-1].get("extra", {}).get("approval_token"),
           "审批事件携带票据号（授权路径可追踪）")
        ok(runner.approvals.outstanding() == 0, "票据当场消费，无遗留未决票据")

        # ── #5b：L3 不得通过任何审批放行（runner 通道层双保险）─────────
        fake_l3 = PolicyDecision(decision="REVIEW", command="SQL 注入验证",
                                 level="L3", category="EXECUTE", reason="x")
        got = asyncio.run(runner._policy_review(fake_l3, s, "http://127.0.0.1:8080/x"))
        ok(got is False, "绕过决策层直调审批通道：L3 仍被拒签（审批无出路）")
        ok(any("不得通过审批放行" in e["reason"]
               for e in runner.policy_audit.recent() if e["event"] == "deny"),
           "L3 拒签留痕进审计")
        # 探针 sqli（L3）即使审批通道在线也拒绝
        v = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080", "kinds": "sqli"}, s,
        ))
        ok(v is not None and "SQL 注入验证" in v and "已拦截" in v,
           "exploit_probe sqli（L3）审批通道在线同样拒绝")

        # ── #5c：内容变更 → 重新审批（票据绑定请求指纹）────────────────
        calls2: list[str] = []

        async def _approve2(desc: str) -> bool:
            calls2.append(desc)
            return True

        runner.approver = _approve2
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/51", "method": "DELETE"}, s,
        ))
        ok(v is None and len(calls2) == 1, "删除首次审批通过")
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/51",
                             "method": "DELETE", "body": '{"confirm":1}'}, s,
        ))
        ok(v is None and len(calls2) == 2,
           "请求体变更 → 重新审批（票据绑定请求内容指纹，旧票不复用）")

        # ── #4b：台账登记生命周期纪律 ─────────────────────────────────
        ok(runner.test_ledger.record("http://x/api/obj", "create", run_id="",
                                     target_id="t", object_id="9") is None,
           "缺 run_id 的登记被拒绝（对象必须挂在明确轮次下）")
        ok(runner.test_ledger.record("http://x/api/obj", "create", run_id="r",
                                     target_id="", object_id="9") is None,
           "缺 target_id 的登记被拒绝")

        # ── #2b：环境绑定支持 scheme/port 声明（不再只看 hostname）─────
        g_env = RequestGuard(_cfg_with(environments={
            "http://192.168.*": Environment.ISOLATED_TEST,
            "127.0.0.1:8080": Environment.DEDICATED_TEST,
        }))
        ok(g_env.environment_for("http://192.168.1.5/") == Environment.ISOLATED_TEST,
           "scheme 声明绑定匹配 http")
        ok(g_env.environment_for("https://192.168.1.5/") != Environment.ISOLATED_TEST,
           "https 不继承 http:// 绑定的环境分类（scheme 严格比较）")
        ok(g_env.environment_for("http://127.0.0.1:8080/") == Environment.DEDICATED_TEST,
           "端口声明绑定匹配 8080")
        ok(g_env.environment_for("http://127.0.0.1:9999/") != Environment.DEDICATED_TEST,
           "同主机不同端口不继承环境分类")
        ok(g_env.environment_for("http://127.0.0.1/") != Environment.DEDICATED_TEST,
           "默认端口 80 ≠ 声明的 8080 → 不匹配")

        # ── #1b：exploit_probe 决策统一走 guard.check_probe ────────────
        from policy.request_guard import PROBE_KIND_COMMAND, GuardContext
        ok(runner._PROBE_KIND_COMMAND is PROBE_KIND_COMMAND,
           "runner 探针表引用权威表（不再各自复制漂移）")
        gp = RequestGuard(_cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST}))
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "sqli,fileread",
            ctx=GuardContext(bound_target="http://127.0.0.1:8080", identity_bound=True),
        )
        ok(d.command == "SQL 注入验证" and d.decision == Decision.DENY,
           "check_probe 多类别取最高风险（sqli → L3 拒绝）")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "fileread",
            ctx=GuardContext(bound_target="http://127.0.0.1:8080", identity_bound=True),
        )
        ok(d.command == "查询详情" and d.decision == Decision.ALLOW,
           "check_probe 范围内只读探针 → L0 放行")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "fileread",
            ctx=GuardContext(bound_target="http://10.0.0.1", identity_bound=True),
        )
        ok(d.decision == Decision.DENY, "check_probe 范围外 → 拒绝（统一 in_scope，不可绕过）")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "fileread", ctx=GuardContext(identity_bound=True),
        )
        ok(d.decision == Decision.DENY, "check_probe 无绑定目标 → 拒绝")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "wormhole",
            ctx=GuardContext(bound_target="http://127.0.0.1:8080", identity_bound=True),
        )
        ok(d.decision == Decision.UNKNOWN and "未识别" in d.reason,
           "check_probe 未知探针类别 → UNKNOWN 拒绝")

        # ── #6：写操作放行留痕未持久化 → 拒绝执行（P1-⑤ 收口）──────────
        runner.policy_audit.path = Path("Z:/definitely/not/writable/policy/audit.jsonl")
        runner.policy_audit._probe_ok = True  # 探针缓存说可写（模拟探针后翻脸）
        runner.policy_audit._flush = lambda entries: False  # 实际落盘失败
        blk = runner._policy_allow(
            s,
            PolicyDecision(decision="ALLOW", command="创建测试数据",
                           level="L1", category="CREATE", reason="test"),
            url="http://127.0.0.1:8080/api/xx",
        )
        ok(blk is not None and "留痕" in blk and "已拦截" in blk,
           "写操作放行留痕未持久化 → 拒绝执行（没有记录的允许等于没有允许）")
        ok(runner._pending_ledger is None, "留痕失败的写操作不挂 pending 台账")
        # 只读命令不受影响
        blk2 = runner._policy_allow(
            s,
            PolicyDecision(decision="ALLOW", command="查询详情",
                           level="L0", category="READ", reason="test"),
            url="http://127.0.0.1:8080/api/xx",
        )
        ok(blk2 is None, "只读操作放行留痕失败不拦截（warn 告警）")

        # ── #4：审计故障处理收口——坏 extra 不炸链、可序列化消毒 ────────
        runner.policy_audit._flush = lambda entries: True
        runner.policy_audit._probe_ok = None
        r = runner.policy_audit.log("allow", command="查询详情",
                                    extra={"bad": object()})
        ok(r is True, "不可序列化 extra 降级为 repr，不炸审计链")
        ok(runner.policy_audit.recent()[-1].get("extra", {}).get("repr"),
           "坏 extra 以 repr 摘要入账（待写队列永远可安全写盘）")


def test_http_exit() -> None:
    """P1-⑥：全工程 HTTP 出口收敛——httpx Client 构造点必须用统一代理出口
    （build_client_kwargs 或 resolve_proxy_for）。"""
    import re

    root = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    for py in list(root.glob("*/**/*.py")) + list(root.glob("*.py")):
        rel = py.relative_to(root).as_posix()
        if rel.startswith(("scripts", "tests", ".venv", "data", "output")):
            continue
        text = py.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"httpx\.(?:Async)?Client\(", text):
            # 构造调用前后 500 字符内必须引用统一出口函数
            window = text[max(0, m.start() - 500):m.start() + 400]
            if "build_client_kwargs" not in window and "resolve_proxy_for" not in window:
                offenders.append(f"{rel}:{text[:m.start()].count(chr(10)) + 1}")
    ok(offenders == [],
       f"无脱离统一代理出口的 httpx Client 构造点：{offenders}")


def test_wheel_packages() -> None:
    """P1-9：wheel 必须打包 policy/ 与 intel/。"""
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    ok('"policy/**/*.py"' in text, "wheel include 含 policy/**/*.py")
    ok('"intel/**/*.py"' in text, "wheel include 含 intel/**/*.py")


def main() -> int:
    test_rules_table()
    test_decide()
    test_classify()
    test_scope()
    test_guard()
    test_hardening()
    test_ledger()
    test_runner_gate()
    test_remediation2()
    test_http_exit()
    test_wheel_packages()
    print(
        f"\n权限控制回归 {PASS}/{PASS} 通过"
        + (f"（另有 {len(FAIL)} 项失败）" if FAIL else "")
    )
    for name in FAIL:
        print(f"  - {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
