"""接口测试生命周期权限控制（policy/，111.md）的回归测试（不触网）。

锁死十件事：
  1. 规则清单表：**恰好十条矩阵命令**（第四轮整改：删除 EXPORT/AUTH
     的自造规则行）、严格六列、等级与矩阵一致、L3 无执行路径；
  2. decide()：L0 有条件允许 / L1 仅隔离测试环境 /
     L2 上传仅 dedicated_test 且逐请求审批 / L2 删除单独审批 /
     L3 一律拒绝；矩阵外命令（含 EXPORT/AUTH 类别映射出的空命令）
     → UNKNOWN 默认拒绝；
  3. classify_request()：九类接口分类齐全、EXPORT/AUTH 独立分类且
     保留风险信号、更高风险为准；
  4. 目标范围统一校验 in_scope：scheme+hostname+port 规范化比较、
     路径前缀授权 + **路径规范化防绕过**（编码点段/双斜杠/反斜杠/
     尾斜杠在比对前摊平）；目标 URL 合法性校验；
  5. 审批只在运行期逐请求发生——配置级审批整体无效；审批 =
     一次性票据（精确匹配、单次消费、带过期时间、绑定请求指纹与
     **真实审批人身份**）；
  6. 台账四元组（目标/run/身份/对象标识）**严格**匹配（维度缺失
     即未知；跨端点按 id 命中须同主机且在登记路径前缀下），创建
     真实请求成功（2xx/3xx）并取得对象标识才登记；**删除判定只认
     本次创建/上传的对象——仅修改过的既有对象一律走单独审批**；
  7. 审计持久化是写操作与审批的先决条件；只读放行但告警；
     写操作放行留痕本身必须落盘成功；审批审计带真实审批人；
  8. Runner 集成：exploit_probe 与其他工具同一 _policy_ctx / in_scope，
     放行 ≠ 登记（pending → 执行成功后落账）；
  9. 身份逐请求解析：无凭证明确匿名、不继承前次实名身份；
 10. 并发状态隔离：pending 台账与身份挂 ContextVar，并发工具调用
     互不污染。

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
}
EXPECTED_ALLOW = {
    "查询详情": "有条件允许", "查询列表": "有条件允许",
    "创建测试数据": "仅隔离测试环境", "修改测试数据": "仅隔离测试环境",
    "上传测试文件": "需要专门测试环境", "删除测试数据": "需要单独审批",
}


def test_rules_table() -> None:
    ok(len(RULES) == 10, f"恰好十条矩阵命令（第四轮整改：EXPORT/AUTH 自造规则已删，实际 {len(RULES)}）")
    ok(rule_for_command("导出数据") is None, "「导出数据」规则已删除（EXPORT 无矩阵授权行）")
    ok(rule_for_command("认证操作") is None, "「认证操作」规则已删除（AUTH 无矩阵授权行）")
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
    ok(len([ln for ln in table.splitlines() if ln.startswith("|")]) == 12, "表格含表头+分隔+10 行")
    ok(rule_for_command("不存在的命令") is None, "矩阵外命令查不到规则")
    # 第四轮整改 #1：EXPORT/AUTH 保持独立分类与风险信号，但**没有矩阵
    # 授权行**——命令映射为空串，decide() 判 UNKNOWN 默认拒绝。不得为
    # 通过分类器而把新类别映射进任何矩阵命令。
    ok(COMMAND_FOR_CATEGORY[ApiCategory.EXPORT] == "",
       "EXPORT 命令映射为空（无授权依据 → UNKNOWN，不映射 L0/L1）")
    ok(COMMAND_FOR_CATEGORY[ApiCategory.AUTH] == "",
       "AUTH 命令映射为空（无授权依据 → UNKNOWN，不映射 L0）")
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
    # 第四轮整改 #1：自造的「导出数据」「认证操作」规则已删除——
    # 矩阵外命令一律 UNKNOWN，不存在任何 L0/L1 旁路
    d = decide("导出数据", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.UNKNOWN, "导出数据（规则已删）→ UNKNOWN 默认拒绝")
    d = decide("认证操作", environment=Environment.ISOLATED_TEST,
               identity_bound=True, target_bound=True)
    ok(d.decision == Decision.UNKNOWN, "认证操作（规则已删）→ UNKNOWN 默认拒绝")


# ── 3. classify_request 七维度识别 ────────────────────────────────


def test_classify() -> None:
    c = classify_request("http://t.example.com/api/users/1", "GET")
    ok(c.category == ApiCategory.READ and c.command == "查询详情", "GET 详情 → READ")
    c = classify_request("http://t.example.com/api/users/export", "GET")
    ok(c.category == ApiCategory.EXPORT, "EXPORT 独立分类（保留）")
    ok(c.command == "", "EXPORT 命令映射为空 → 决策 UNKNOWN（第四轮整改）")
    ok(c.risk_level == "L0" or c.signals, "EXPORT 保留识别信号（审计可见识别出了导出）")
    c = classify_request("http://t.example.com/api/login", "POST", body="u=1&p=2")
    ok(c.category == ApiCategory.AUTH, "POST /login → AUTH（不按 POST 升级为 CREATE）")
    ok(c.command == "", "AUTH 命令映射为空 → 决策 UNKNOWN（第四轮整改）")
    # 路径规范化：编码变体不得逃过分类信号（第四轮整改 #5）
    c = classify_request("http://t.example.com/api/users/%65xport", "GET")
    ok(c.category == ApiCategory.EXPORT, "编码路径（%65xport）仍识别为 EXPORT")
    c = classify_request("http://t.example.com/api/users/export/", "GET")
    ok(c.category == ApiCategory.EXPORT, "尾斜杠不影响分类")
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

    # ── 第四轮整改 #5：路径规范化防前缀绕过 ──────────────────────────
    # 编码点段：字面量前缀比对会把它们误判"在 /app 内"
    ok(not in_scope("http://h:8080/app/%2e%2e/other", "http://h:8080/app"),
       "编码点段（%2e%2e）→ 规范化后出界")
    ok(not in_scope("http://h:8080/app/%252e%252e/secret", "http://h:8080/app"),
       "多层编码点段（%252e%252e）→ 逐层解码后出界")
    ok(not in_scope("http://h:8080/app/%2e%2e%2fother", "http://h:8080/app"),
       "编码点段+编码斜杠混合 → 出界")
    ok(not in_scope("http://h:8080/app/../other", "http://h:8080/app"),
       "明文点段（..）→ 出界")
    # 冗余形态：规范化后仍是同一路径 → 不影响正常访问
    ok(in_scope("http://h:8080/app//sub", "http://h:8080/app"), "双斜杠折叠 → 仍在前缀内")
    ok(in_scope("http://h:8080/app/./sub", "http://h:8080/app"), "点段冗余（.）→ 仍在前缀内")
    ok(in_scope("http://h:8080/app/sub/", "http://h:8080/app"), "尾斜杠 → 仍在前缀内")
    ok(in_scope("http://h:8080/app/%2Fsub", "http://h:8080/app"),
       "编码斜杠解码为路径分隔 → 仍在前缀内（语义路径）")


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
    # P0-4（第六轮整改）：fileread 是主动利用（路径穿越取文件），矩阵没有
    # 它的授权行 → 移出映射 → UNKNOWN 默认拒绝，不得映射查询详情 L0。
    ok("fileread" not in m, "fileread 探针移出命令映射（无矩阵授权 → UNKNOWN/DENY）")

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
    cfg_in = _cfg_with(environments={"192.168.*": Environment.ISOLATED_TEST})
    cfg_in.scan.sqli_probe_enabled = True
    cfg3, note3 = scoped_scan_config(cfg_in, "http://192.168.1.1/")
    # P0-3（第六轮整改）：批量流水线在测试环境也**不得自动放行 L3**——
    # SQLi/RCE 探针一律关闭（矩阵 L3 默认禁止，审批无出路，测试环境
    # 不构成授权依据）；且返回配置副本，绝不改共享 cfg。
    ok(not cfg3.scan.sqli_probe_enabled and not cfg3.scan.rce_probe_enabled,
       "隔离测试环境：L3 探针（SQLi/RCE）强制关闭（P0-3）")
    ok(cfg3 is not cfg_in and cfg_in.scan.sqli_probe_enabled,
       "scoped_scan_config 返回配置副本（不污染共享配置）")
    ok("L3" in note3, "测试环境提示 L3 探针已按矩阵关闭")

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
    # ── 第四轮整改 #3：删除判定只认本次创建/上传的对象 ──────────────
    # 仅修改过的既有对象（update 条目）不得认定为本次创建
    led4 = TestLedger()
    led4.record("http://t.example.com/api/preset/7", "update", run_id="r1",
                target_id="t", identity="anon", object_id="7")
    ok(led4.known("http://t.example.com/api/preset/7", target_id="t",
                  run_id="r1", identity="anon"),
       "update 条目在 known() 里可见（修改过 ≠ 不是本次动过）")
    verdict, why = led4.delete_verdict(
        "http://t.example.com/api/preset/7", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST,
    )
    ok(not verdict and "台账" in why,
       "仅修改过的既有对象 → 删除不放行（修改 ≠ 本次创建，第四轮整改 #3）")
    verdict, _ = led4.delete_verdict(
        "http://t.example.com/api/preset/7", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST, approved=True,
    )
    ok(verdict, "仅修改过的既有对象 + 绑定本次请求的单独审批 → 放行")
    # create/upload 条目照常进删除判定（led 的 users/33 是 create 登记）
    verdict, _ = led.delete_verdict(
        "http://t.example.com/api/users/33", target_id="t", run_id="r1",
        identity="anon", environment=Environment.ISOLATED_TEST,
    )
    ok(verdict, "本次创建并取得标识的对象 → 删除判定照常放行")
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

        # ── 第四轮整改 #2：身份逐请求解析，不继承前次实名身份 ─────────
        id_d = runner._observe_identity(
            {"Authorization": "Bearer token-D"}, "http://127.0.0.1:8080/", session=s,
        )
        ok(id_d.startswith("cred:"), "带凭证请求 → 实名身份（逐请求解析）")
        id_anon = runner._observe_identity({}, "http://127.0.0.1:8080/", session=s)
        ok(id_anon.startswith("anonymous@127.0.0.1") and runner._identity == "",
           "无凭证请求 → 明确回到匿名（不继承前次实名身份，第四轮整改 #2）")
        ok(runner._observe_identity(
            {"Authorization": "Bearer token-E"}, "http://127.0.0.1:8080/", session=s,
        ).startswith("cred:"), "恢复凭证 → 实名身份重新解析")
        # 头部工具（exploit_probe/external_tool）不继承实名身份：gate 内显式重置。
        # 注意 ContextVar 语义：asyncio.run 的任务拷贝上下文，任务内的赋值
        # 不回传外层——所以把"设残留身份 → 过 gate → 读身份"放进同一协程。
        async def _probe_identity() -> str:
            runner._identity = "cred:authorization:abcd1234ef"  # 模拟前次实名残留
            await runner._policy_gate(
                "exploit_probe", {"url": "http://127.0.0.1:8080/", "kinds": "fileread"}, s,
            )
            return runner._identity

        ok(asyncio.run(_probe_identity()) == "",
           "exploit_probe gate 不继承前次实名身份（匿名解析）")

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
        # ContextVar 语义：pending 挂在当前协程上下文，gate 与 pending
        # 读取放同一协程内（与真实 agent 循环的 await 语义一致）。
        async def _gate_create():
            v = await runner._policy_gate(
                "http_request",
                {"url": "http://127.0.0.1:8080/api/users", "method": "POST", "body": '{"name":"t"}'},
                s,
            )
            return v, runner._pending_ledger

        v, pend = asyncio.run(_gate_create())
        ok(v is None, "隔离测试环境的创建放行")
        tid, rid = runner._policy_scope(s)
        ident = (pend or {}).get("identity", "")
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/users",
                                        target_id=tid, run_id=rid, identity=ident),
           "放行未执行 → 尚未登记（放行 ≠ 登记）")
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
        # P0-4（第六轮整改）：fileread 无矩阵授权 → UNKNOWN 拒绝（范围内也一样）
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080/", "kinds": "fileread"}, s,
        ))
        ok(verdict is not None and "已拦截" in verdict and "未识别" in verdict,
           "exploit_probe fileread（无矩阵授权行）→ UNKNOWN 默认拒绝")
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
        # 合法目标 + 范围内 fileread 探针 → UNKNOWN 拒绝（P0-4：无矩阵授权）
        verdict = asyncio.run(runner._policy_gate(
            "exploit_probe", {"url": "http://127.0.0.1:8080/", "kinds": "fileread"}, s,
        ))
        ok(verdict is not None and "已拦截" in verdict,
           "合法目标 + fileread 探针仍拒绝（P0-4：fileread 无授权行）")

        # ── #1（第四轮整改）：EXPORT/AUTH 无矩阵授权 → UNKNOWN 默认拒绝 ──
        # 矩阵恰好十条命令；EXPORT/AUTH 只有独立分类与风险信号，
        # 没有授权依据时必须映射为 UNKNOWN/DENY，任何环境都不放行。
        cfg_u = _cfg_with()  # 不绑定环境表 → 环境判不出 = unknown
        cfg_u.data_dir = td
        runner_u = ToolRunner(cfg_u, root=td)
        verdict = asyncio.run(runner_u._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/export", "method": "GET"},
            s,
        ))
        ok(verdict is not None and "已拦截" in verdict,
           "EXPORT（无矩阵授权行）unknown 环境 → UNKNOWN 默认拒绝")
        # 隔离测试环境下导出**同样拒绝**——EXPORT 没有任何授权出路
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/export", "method": "GET"},
            s,
        ))
        ok(verdict is not None and "已拦截" in verdict,
           "EXPORT 隔离测试环境同样拒绝（无授权依据即 UNKNOWN/DENY）")
        # AUTH 同样无矩阵授权行 → 登录请求 UNKNOWN 拒绝（不得映射 L0）
        verdict = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/login",
                             "method": "POST", "body": "u=1&p=2"}, s,
        ))
        ok(verdict is not None and "已拦截" in verdict,
           "AUTH（无矩阵授权行）→ UNKNOWN 默认拒绝（不映射 L0）")

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

        # ── #4（第四轮整改）：审批人真实身份进审批审计 ──────────────────
        runner.approver_identity = "ops-zhangsan"
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/users/88", "method": "DELETE"}, s,
        ))
        ok(v is None, "显式审批人身份：删除审批通过放行")
        aprs = [e for e in runner.policy_audit.recent() if e["event"] == "approval"]
        ok(aprs and aprs[-1].get("extra", {}).get("approver") == "ops-zhangsan",
           "审批审计 extra.approver = 显式声明的真实审批人（第四轮整改 #4）")
        ok("ops-zhangsan" in aprs[-1]["reason"], "审批理由行也带审批人（可追责到人）")
        ok(aprs[-1].get("extra", {}).get("identity"), "审批审计带请求身份（谁在什么身份下获批）")
        runner.approver_identity = ""
        # P1-4（第六轮整改）：函数名兜底**禁用**——裸函数通道拿不到真实
        # 身份就返回空串，审批按"未认证审批人"留痕。
        ok(runner._approver_label() == "",
           "未显式声明且通道无身份属性 → 不再用函数名充当审批人（P1-4）")
        _chan = type("Chan", (), {"approver_id": "alice@corp"})()
        runner.approver = _chan
        ok(runner._approver_label() == "alice@corp", "通道对象自带身份属性 → 用真实身份")
        runner.approver = _approve2

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
        # P0-4（第六轮整改）：混合类别里有未识别项 → 整体 UNKNOWN（fail-closed，
        # 不"去掉未知类别继续判"）
        ok(d.decision == Decision.UNKNOWN and d.command == "",
           "check_probe 多类别含未识别项 → 整体 UNKNOWN 拒绝")
        # P0-4（第六轮整改）：fileread 单独执行 → UNKNOWN 拒绝（无矩阵授权行）
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "fileread",
            ctx=GuardContext(bound_target="http://127.0.0.1:8080", identity_bound=True),
        )
        ok(d.decision == Decision.UNKNOWN and d.command == "",
           "check_probe fileread → UNKNOWN 默认拒绝（不映射查询详情 L0）")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "fileread",
            ctx=GuardContext(bound_target="http://10.0.0.1", identity_bound=True),
        )
        ok(d.decision == Decision.UNKNOWN, "check_probe fileread（无论范围）→ UNKNOWN 拒绝")
        d = gp.check_probe(
            "http://127.0.0.1:8080/", "upload",
            ctx=GuardContext(bound_target="http://127.0.0.1:8080", identity_bound=True),
        )
        ok(d.command == "上传测试文件" and d.decision == Decision.DENY,
           "check_probe upload → L2 上传（隔离环境不满足专门条件 → 拒绝）")
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


def test_concurrency_isolation() -> None:
    """第四轮整改 #6：Runner 并发状态污染——pending 台账与身份挂 ContextVar。"""
    from core.tools.runner import ToolRunner

    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST})
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s = Session(target="http://127.0.0.1:8080")

        async def _fake_http(session, **kwargs):  # noqa: ANN001, ANN202
            url = str(kwargs.get("url") or "")
            tail = url.rstrip("/").split("/")[-1]
            return (
                f"POST {url}\n状态码：201  耗时：1ms  正文大小：46B\n"
                f'正文（46 字符）：\n{{"ok":true,"data":{{"id":"{tail}-obj"}}}}'
            )

        runner._h_http_request = _fake_http

        async def _two():
            return await asyncio.gather(
                runner.execute("http_request", {
                    "url": "http://127.0.0.1:8080/api/alpha",
                    "method": "POST", "body": "{}",
                }, s),
                runner.execute("http_request", {
                    "url": "http://127.0.0.1:8080/api/beta",
                    "method": "POST", "body": "{}",
                }, s),
            )

        outs = asyncio.run(_two())
        ok(all("状态码：201" in o for o in outs), "并发创建两次都执行成功")
        tid, rid = runner._policy_scope(s)
        ident = runner._current_identity(s)
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/alpha/alpha-obj",
                                    target_id=tid, run_id=rid, identity=ident),
           "并发 A 的 pending 未被 B 覆盖（alpha-obj 已登记，第四轮整改 #6）")
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/beta/beta-obj",
                                    target_id=tid, run_id=rid, identity=ident),
           "并发 B 的 pending 未被 A 覆盖（beta-obj 已登记，第四轮整改 #6）")
        ok(runner._pending_ledger is None, "并发执行后无遗留 pending 条目")


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


def test_round6() -> None:
    """第六轮整改专项：P0（全工具入闸/Detector 统一入口/流水线 L3/fileread/
    批量 POC 约束）+ P1（L0 环境绑定/身份三元组/候选空拒绝/审批真实身份/
    解码歧义）+ P2（HTTP 出口覆盖/入口一致性/并发隔离）。"""
    from core.tools.runner import ToolRunner
    from policy.api_policy import PolicyDecision
    from policy.request_guard import (
        GuardContext,
        RequestGuard,
        in_scope,
        over_decode_limit,
    )

    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST})
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s = Session(target="http://127.0.0.1:8080")

        # ── P1-1：L0 加环境绑定——unknown 环境仅明确只读操作 ──────────
        d = decide("查询详情", environment=Environment.UNKNOWN,
                   identity_bound=True, target_bound=True, clearly_read_only=False)
        ok(d.decision == Decision.DENY,
           "L0 unknown 环境 + 非明确只读 → 拒绝（P1-1 环境绑定）")
        d = decide("查询详情", environment=Environment.UNKNOWN,
                   identity_bound=True, target_bound=True, clearly_read_only=True)
        ok(d.decision == Decision.ALLOW,
           "L0 unknown 环境 + 明确只读（GET 无高危信号）→ 放行")
        d = decide("查询详情", environment=Environment.ISOLATED_TEST,
                   identity_bound=True, target_bound=True, clearly_read_only=False)
        ok(d.decision == Decision.ALLOW, "L0 已绑定环境（隔离测试）→ 放行")
        # unknown 环境的 http_request：GET 只读放行，POST 写语义拒绝
        cfg_u = _cfg_with()
        cfg_u.data_dir = td
        runner_u = ToolRunner(cfg_u, root=td)
        v = asyncio.run(runner_u._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/items/1", "method": "GET"}, s,
        ))
        ok(v is None, "unknown 环境：GET 明确只读 → 放行")
        v = asyncio.run(runner_u._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/items", "method": "POST", "body": "{}"}, s,
        ))
        ok(v is not None and "已拦截" in v, "unknown 环境：POST 写语义 → 拒绝")
        v = asyncio.run(runner_u._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/items/1", "method": "DELETE"}, s,
        ))
        ok(v is not None and "已拦截" in v, "unknown 环境：DELETE → 拒绝")

        # ── P0-1：sqli_probe / login / authz_probe / recon_* 全部入闸 ──
        from policy.request_guard import BUILTIN_POLICY_TOOLS

        ok("sqli_probe" in BUILTIN_POLICY_TOOLS and "login" in BUILTIN_POLICY_TOOLS
           and "authz_probe" in BUILTIN_POLICY_TOOLS and "recon_paths" in BUILTIN_POLICY_TOOLS,
           "内置目标请求工具全部纳入 BUILTIN_POLICY_TOOLS（P0-1）")
        ok(runner._BUILTIN_POLICY_TOOLS is BUILTIN_POLICY_TOOLS,
           "runner 引用权威工具集合（不各自漂移）")
        v = asyncio.run(runner._policy_gate(
            "sqli_probe", {"url": "http://127.0.0.1:8080/", "limit": 5}, s,
        ))
        ok(v is not None and "SQL 注入验证" in v and "已拦截" in v,
           "sqli_probe 工具 → L3 一律拒绝（验收：sqli_probe L3 拒绝）")
        v = asyncio.run(runner._policy_gate(
            "login", {"url": "http://127.0.0.1:8080/api/login",
                      "username": "u", "password": "p"}, s,
        ))
        ok(v is not None and "已拦截" in v,
           "login 工具 → AUTH 无矩阵授权行 → UNKNOWN 拒绝")
        # authz_probe：只读 GET 对比 → L0，隔离测试环境放行
        v = asyncio.run(runner._policy_gate(
            "authz_probe", {"url": "http://127.0.0.1:8080/", "limit": 5}, s,
        ))
        ok(v is None, "authz_probe（L0 只读对比）绑定齐全 → 放行")
        # recon_paths：L0 侦察 → 放行
        v = asyncio.run(runner._policy_gate(
            "recon_paths", {"url": "http://127.0.0.1:8080/"}, s,
        ))
        ok(v is None, "recon_paths（L0 侦察）→ 放行")
        # recon_ports 用 host 参数 → 同样入闸
        v = asyncio.run(runner._policy_gate(
            "recon_ports", {"host": "127.0.0.1"}, s,
        ))
        ok(v is None, "recon_ports（host 参数）→ 放行")
        # unknown 环境：authz_probe 的请求是只读 GET → 放行；出界 → 拒
        v = asyncio.run(runner_u._policy_gate(
            "authz_probe", {"url": "http://127.0.0.1:8080/"}, s,
        ))
        ok(v is None, "unknown 环境：authz_probe 只读 → 放行（unknown 仅明确只读）")
        v = asyncio.run(runner._policy_gate(
            "recon_paths", {"url": "http://10.9.9.9/"}, s,
        ))
        ok(v is not None and "已拦截" in v, "recon_paths 出界 → 拒绝（统一范围校验）")

        # ── P1-2：身份绑定 session_id / target_id / 凭证指纹 ──────────
        s_a = Session(target="http://127.0.0.1:8080")
        s_a.session_id = "sess-A"
        s_b = Session(target="http://127.0.0.1:8080")
        s_b.session_id = "sess-B"
        runner._observe_identity(
            {"Authorization": "Bearer same-token"}, "http://127.0.0.1:8080/", session=s_a,
        )
        ida = runner._current_identity(s_a, url="http://127.0.0.1:8080/")
        runner._identity = ""
        runner._observe_identity(
            {"Authorization": "Bearer same-token"}, "http://127.0.0.1:8080/", session=s_b,
        )
        idb = runner._current_identity(s_b, url="http://127.0.0.1:8080/")
        ok(ida != idb, "同 Token 不同 Session → 身份不同（P1-2 会话隔离）")
        ok("|sess=sess-A|" in ida and "|sess=sess-B|" in idb,
           "身份串绑定 session_id（可对账）")
        ok("|tgt=127.0.0.1:8080" in ida, "身份串绑定 target（目标维度可对账）")
        # 匿名请求紧接管理员请求仍匿名（同一会话内来回切换）
        runner._identity = ""
        runner._observe_identity(
            {"Authorization": "Bearer admin-tok"}, "http://127.0.0.1:8080/", session=s_a,
        )
        id_admin = runner._current_identity(s_a, url="http://127.0.0.1:8080/")
        runner._identity = ""
        id_anon1 = runner._observe_identity({}, "http://127.0.0.1:8080/", session=s_a)
        runner._identity = ""
        runner._observe_identity(
            {"Authorization": "Bearer admin-tok"}, "http://127.0.0.1:8080/", session=s_a,
        )
        id_admin2 = runner._current_identity(s_a, url="http://127.0.0.1:8080/")
        ok(id_anon1.startswith("anonymous@") and "|sess=sess-A|" in id_anon1,
           "匿名请求 → 显式匿名身份（绑定会话/目标）")
        ok(id_admin == id_admin2 and id_admin != id_anon1,
           "管理员身份恢复解析且与匿名身份不同")

        # ── P1-3：对象 ID 候选集为空不得放行走台账 ────────────────────
        led = TestLedger()
        led.record("http://h/api/users", "create", run_id="r", target_id="t",
                   identity="i", object_id="33")
        ok(not led.known("http://h/", run_id="r", target_id="t", identity="i"),
           "删除 URL 提不出任何候选 id → 不放行（P1-3）")
        verdict, why = led.delete_verdict(
            "http://h/", run_id="r", target_id="t", identity="i",
            environment=Environment.ISOLATED_TEST,
        )
        ok(not verdict, "候选集为空的删除 → 台账拒绝（P1-3）")
        verdict, _ = led.delete_verdict(
            "http://h/api/users/33", run_id="r", target_id="t", identity="i",
            environment=Environment.ISOLATED_TEST,
        )
        ok(verdict, "候选 id 命中登记对象 → 正常放行（行为不回归）")

        # ── P1-5：路径解码达上限仍歧义 → 拒绝 ────────────────────────
        ok(not over_decode_limit("/app/%2e%2e/other"), "单层编码可解码 → 非歧义")
        ok(not over_decode_limit("/app/x%20y"), "常规 %20 编码 → 非歧义")
        ok(not over_decode_limit("/app/%252e%252e"), "双层编码（限内）→ 非歧义，摊平解析")
        ok(over_decode_limit("/app/%2525252e%2525252e"), "四层以上嵌套编码 → 歧义（P1-5）")
        ok(in_scope("http://127.0.0.1:8080/app/%2e/sub", "http://127.0.0.1:8080/app"),
           "限内编码摊平后按真实语义比对（/app/./sub → /app/sub 在前缀内）")
        ok(not in_scope("http://127.0.0.1:8080/app/%2e%2e/other", "http://127.0.0.1:8080/app"),
           "编码 .. 摊平后逃出前缀 → 拒绝（路径穿越）")
        ok(not in_scope("http://127.0.0.1:8080/app/%2525252e%2525252e", "http://127.0.0.1:8080/app"),
           "多层编码歧义路径 → fail-closed 拒绝（验收：多层编码路径穿越拒绝）")
        v = asyncio.run(runner._policy_gate(
            "http_request",
            {"url": "http://127.0.0.1:8080/api/%2525252e%2525252e", "method": "GET"}, s,
        ))
        ok(v is not None and "已拦截" in v, "多层编码歧义路径的请求 → 闸门拒绝")

        # ── P1-4：审批回调返回真实身份；无身份不得记为已认证审批人 ──────
        async def _approve_bool(desc: str) -> bool:
            return True

        async def _approve_id(desc: str) -> str:
            return "ops-lisi"

        runner.approver = _approve_bool
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/u/1", "method": "DELETE"}, s,
        ))
        ok(v is None, "裸布尔审批通道：操作放行")
        apr = [e for e in runner.policy_audit.recent() if e["event"] == "approval"][-1]
        ok(apr.get("extra", {}).get("authenticated_approver") is False
           and "未认证" in apr.get("extra", {}).get("approver", ""),
           "无真实身份的审批 → 记为未认证审批人（不得冒充已认证）")
        runner.approver = _approve_id
        v = asyncio.run(runner._policy_gate(
            "http_request", {"url": "http://127.0.0.1:8080/api/u/2", "method": "DELETE"}, s,
        ))
        ok(v is None, "回调返回真实身份 → 放行")
        apr = [e for e in runner.policy_audit.recent() if e["event"] == "approval"][-1]
        ok(apr.get("extra", {}).get("approver") == "ops-lisi"
           and apr.get("extra", {}).get("authenticated_approver") is True,
           "回调返回的真实身份进审批审计（authenticated_approver=True）")

        # ── P0-2：Detector.send_request 统一安全入口（不靠 Runner 工具名）─
        from detectors.http_detector import HttpDetector

        class _FakeResp:
            def __init__(self) -> None:
                self.status_code = 200
                self.headers = {"content-type": "text/html"}
                self.content = b"hello"

        class _FakeClient:
            async def request(self, method, url, headers=None, content=None):  # noqa: ANN001
                return _FakeResp()

        det = HttpDetector(cfg.scan)
        det.client = lambda url="": _FakeClient()  # type: ignore[method-assign]
        # 绑定范围 = 首个请求；正常 GET 放行且真实发出
        ev = asyncio.run(det.send_request("http://127.0.0.1:8080/api/list"))
        ok(not ev.error and ev.status_code == 200, "Detector 正常只读 GET → 放行并发出")
        # sqli 类别（_current_kind）→ L3 → 拦截，不触网
        det._current_kind = "sqli"
        ev = asyncio.run(det.send_request("http://127.0.0.1:8080/api/list?id=1"))
        ok(ev.error and ev.error.startswith("【策略拦截】") and "SQL 注入验证" in ev.error,
           "Detector sqli 探针请求 → L3 拦截（统一安全入口，不靠工具名）")
        ok(det.policy_blocked == 1 and det.policy_notes, "拦截计数与原因可观测")
        # 跨主机出界 → 拦截
        det._current_kind = ""
        ev = asyncio.run(det.send_request("http://10.9.9.9/api/list"))
        ok(ev.error and "超出" in ev.error, "Detector 跨主机请求 → 范围拦截")
        # 非法协议 → 拦截
        ev = asyncio.run(det.send_request("ftp://127.0.0.1/x"))
        ok(ev.error and "非法" in ev.error, "Detector ftp:// 目标 → 拦截")
        # unknown 环境：POST 写语义 → 拦截
        det_u = HttpDetector(cfg_u.scan)
        det_u.client = lambda url="": _FakeClient()  # type: ignore[method-assign]
        ev = asyncio.run(det_u.send_request("http://127.0.0.1:8080/api/items",
                                            method="POST", body="a=1"))
        ok(ev.error and "【策略拦截】" in ev.error,
           "Detector unknown 环境 POST → 拦截（unknown 仅明确只读）")
        # 上传类：dedicated 环境 + 探测器审批通道 → policy_approved 通路
        det_d = HttpDetector(_cfg_with(environments={"127.0.0.*": Environment.DEDICATED_TEST}).scan)
        det_d.client = lambda url="": _FakeClient()  # type: ignore[method-assign]
        ev = asyncio.run(det_d.send_request("http://127.0.0.1:8080/upload", method="POST",
                                            body="--b\r\ncontent-disposition: form-data"))
        ok(ev.error and "【策略拦截】" in ev.error,
           "Detector 上传（L2 REVIEW）无逐请求审批 → 拦截")
        ev = asyncio.run(det_d.send_request("http://127.0.0.1:8080/upload", method="POST",
                                            body="--b\r\ncontent-disposition: form-data",
                                            policy_approved=True))
        ok(not ev.error, "Detector 上传（L2 REVIEW）+ 逐请求审批标记 → 放行")

        # ── P2：CLI / MCP / Agent / 后台任务的策略入口一致性（静态回归）──
        root = Path(__file__).resolve().parent.parent
        entry_checks = [
            ("cli/scan.py", "active_scan_check"),
            ("mcp_server/jobs.py", "active_scan_check"),
            ("core/repl/auto.py", "active_scan_check"),
            ("core/tools/runner/verify.py", "active_scan_check"),
            ("core/subdomain.py", "active_scan_check"),
        ]
        missing = [
            rel for rel, kw in entry_checks
            if kw not in (root / rel).read_text(encoding="utf-8", errors="ignore")
        ]
        ok(not missing, f"CLI/MCP/Agent/子域入口全部走 active_scan_check：{missing}")
        ok("build_client_kwargs" in (root / "detectors/base.py").read_text(encoding="utf-8"),
           "Detector HTTP 客户端走统一代理出口（覆盖率）")
        # 内置工具闸门接线（Agent 路径）：_POLICY_TOOLS 覆盖全部目标请求工具
        from core.tools.runner.base import _ToolRunnerBase

        for t in ("sqli_probe", "login", "authz_probe", "recon_fingerprint",
                  "recon_ports", "recon_ports_bg", "recon_paths", "recon_js",
                  "js_audit", "recon_openapi", "recon_subdomains"):
            ok(t in _ToolRunnerBase._POLICY_TOOLS, f"Agent 闸门覆盖 {t}")


def test_round6_concurrency() -> None:
    """第六轮验收：后台并发无身份/台账串线——同一 Token 在两个会话里
    并发创建，台账条目身份互不串（P1-2 三元组 + ContextVar 隔离）。"""
    from core.tools.runner import ToolRunner

    with tempfile.TemporaryDirectory() as td:
        cfg = _cfg_with(environments={"127.0.0.*": Environment.ISOLATED_TEST})
        cfg.data_dir = td
        runner = ToolRunner(cfg, root=td)
        s_a = Session(target="http://127.0.0.1:8080")
        s_a.session_id = "sess-A"
        s_b = Session(target="http://127.0.0.1:8080")
        s_b.session_id = "sess-B"

        async def _fake_http(session, **kwargs):  # noqa: ANN001, ANN202
            url = str(kwargs.get("url") or "")
            tail = url.rstrip("/").split("/")[-1]
            return (
                f"POST {url}\n状态码：201  耗时：1ms  正文大小：46B\n"
                f'正文（46 字符）：\n{{"ok":true,"data":{{"id":"{tail}-obj"}}}}'
            )

        runner._h_http_request = _fake_http
        # 两个会话用同一个 Token 并发创建
        s_a.credentials["token"] = "same-token"
        s_b.credentials["token"] = "same-token"

        async def _two():
            return await asyncio.gather(
                runner.execute("http_request", {
                    "url": "http://127.0.0.1:8080/api/alpha",
                    "method": "POST", "body": "{}",
                }, s_a),
                runner.execute("http_request", {
                    "url": "http://127.0.0.1:8080/api/beta",
                    "method": "POST", "body": "{}",
                }, s_b),
            )

        outs = asyncio.run(_two())
        ok(all("状态码：201" in o for o in outs), "并发创建两次都执行成功")
        tid, rid = runner._policy_scope(s_a)
        # 两个会话的台账身份必须不同（同 Token/同目标、仅 session 不同）
        obj_a = next(o for o in runner.test_ledger.objects_of() if "alpha" in o.url)
        obj_b = next(o for o in runner.test_ledger.objects_of() if "beta" in o.url)
        id_a, id_b = obj_a.identity, obj_b.identity
        ok(id_a != id_b, "同 Token 不同 Session → 台账身份不同（P1-2）")
        ok("sess=sess-A" in id_a and "sess=sess-B" in id_b,
           "台账身份绑定 session_id（可对账）")
        tid_a, rid_a = runner._policy_scope(s_a)
        tid_b, rid_b = runner._policy_scope(s_b)
        ok(rid_a != rid_b, "不同会话 → 各自独立的扫描轮次（run 隔离）")
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/alpha/alpha-obj",
                                    target_id=tid_a, run_id=rid_a, identity=id_a),
           "会话 A 的对象以 A 的身份落账（不被 B 串线）")
        ok(runner.test_ledger.known("http://127.0.0.1:8080/api/beta/beta-obj",
                                    target_id=tid_b, run_id=rid_b, identity=id_b),
           "会话 B 的对象以 B 的身份落账（不被 A 串线）")
        ok(not runner.test_ledger.known("http://127.0.0.1:8080/api/alpha/alpha-obj",
                                        target_id=tid_b, run_id=rid_b, identity=id_b),
           "A 的对象对 B 的会话/身份不可见（台账不串线）")
        ok(runner._pending_ledger is None, "并发执行后无遗留 pending 条目")
        # 审计隔离：allow 事件各带各的身份
        events = [e for e in runner.policy_audit.recent()
                  if e["event"] == "allow" and e.get("command") == "创建测试数据"]
        idents = {e.get("target_id") and e.get("run_id") and e.get("url") for e in events}
        ok(len(events) == 2 and len(idents) == 2,
           "并发创建的两条放行留痕互相独立")


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
    test_concurrency_isolation()
    test_round6()
    test_round6_concurrency()
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
