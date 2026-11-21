"""需求级单元用例：策略矩阵、范围校验、台账、审批票据。

这些用例**不触网**，只验证决策逻辑本身。它们只能拿到 UNIT_PASS——
每条需求还必须有一条 SECURITY 类型的用例，单靠本文件不能交差
（目录里对此有强制检查）。
"""

from __future__ import annotations

from policy.api_policy import (
    COMMAND_FOR_CATEGORY,
    RULES,
    ApiCategory,
    Decision,
    Environment,
    decide,
    rule_for_command,
)
from policy.request_guard import (
    HOST_SCOPED_TOOLS,
    PROBE_KIND_COMMAND,
    GuardContext,
    RequestGuard,
    classify_request,
    host_in_scope,
    in_scope,
)
from policy.test_transaction import ApprovalLedger, TestLedger


# ── L3 ────────────────────────────────────────────────────────────

L3_COMMANDS = ("批量删除", "SQL 注入验证", "命令执行", "定时任务执行")
ALL_ENVS = (
    Environment.PRODUCTION,
    Environment.DEDICATED_TEST,
    Environment.ISOLATED_TEST,
    Environment.UNKNOWN,
)


def l3_decide_all_envs(ctx) -> None:
    """4 命令 × 4 环境 × 审批开/关 = 32 种组合，全部不得 ALLOW。"""
    deny = 0
    allow = 0
    total = 0
    for cmd in L3_COMMANDS:
        for env in ALL_ENVS:
            for approved in (False, True):
                d = decide(
                    cmd, environment=env,
                    identity_bound=True, target_bound=True, approved=approved,
                )
                total += 1
                if d.decision == Decision.DENY:
                    deny += 1
                if d.decision == Decision.ALLOW:
                    allow += 1
                ctx.check(
                    d.decision != Decision.ALLOW,
                    f"{cmd} 在 {env}（approved={approved}）不得 ALLOW，实际 {d.decision}",
                )
                ctx.check(
                    d.level == "L3",
                    f"{cmd} 的风险等级应为 L3，实际 {d.level}",
                )
    ctx.set("total", total)
    ctx.set("deny_count", deny)
    ctx.set("allow_count", allow)


def approval_refuses_l3(ctx) -> None:
    led = ApprovalLedger()
    raised = 0
    for cmd in L3_COMMANDS:
        try:
            led.issue(
                url="http://h/x", command=cmd, target_id="t", run_id="r",
                identity="i", level="L3", approver="alice",
            )
        except ValueError as exc:
            raised += 1
            ctx.check(
                cmd in str(exc) or "L3" in str(exc),
                f"{cmd} 的拒签理由应点名命令或 L3",
            )
    ctx.set("raised", raised)
    ctx.set("issued", led.outstanding())
    ctx.check(raised == len(L3_COMMANDS), f"四个 L3 命令都必须拒签，实际 {raised}")
    ctx.check(led.outstanding() == 0, "L3 不得留下任何有效票据")


# ── UNKNOWN ───────────────────────────────────────────────────────

def unknown_command_denied(ctx) -> None:
    d = decide("不存在的命令", identity_bound=True, target_bound=True)
    ctx.check(d.decision == Decision.UNKNOWN, f"应为 UNKNOWN，实际 {d.decision}")
    ctx.check(d.denied, "UNKNOWN 必须视为拒绝（denied=True）")
    ctx.check(d.command == "", "未识别的命令不得回填任何矩阵命令")
    ctx.set("decision", d.decision)
    ctx.set("denied", bool(d.denied))


def unknown_method_denied(ctx) -> None:
    url = "http://h:8080/api/thing"
    cls = classify_request(url, method="PROPFIND")
    ctx.check(cls.category == ApiCategory.UNKNOWN, f"分类应为 UNKNOWN，实际 {cls.category}")
    ctx.check(cls.command == "", f"未识别方法不得映射命令，实际 {cls.command!r}")
    guard = RequestGuard(ctx.cfg(env=""))
    d = guard.check_request(
        url, method="PROPFIND",
        ctx=GuardContext(
            target_id="http://h:8080", bound_target="http://h:8080",
            # 环境给成测试环境，才能把判定推进到"认证入口是否登记"这一步：
            # 这条用例考的是"AUTH 没有授权依据"，不是"环境未知"。
            environment="isolated_test", identity_bound=True,
        ),
    )
    ctx.check(d.decision == Decision.UNKNOWN, f"决策应为 UNKNOWN，实际 {d.decision}")
    ctx.check(d.denied, "UNKNOWN 必须视为拒绝")
    ctx.set("decision", d.decision)
    ctx.set("command", cls.command)


# ── EXPORT / AUTH ─────────────────────────────────────────────────

def export_denied(ctx) -> None:
    url = "http://h:8080/export/users"
    cls = classify_request(url, method="GET")
    ctx.check(cls.category == ApiCategory.EXPORT, f"分类应为 EXPORT，实际 {cls.category}")
    ctx.check(cls.command == "", "EXPORT 没有矩阵授权行 → 命令必须为空")
    guard = RequestGuard(ctx.cfg(env=""))
    d = guard.check_request(
        url, method="GET",
        ctx=GuardContext(
            target_id="http://h:8080", bound_target="http://h:8080",
            # 环境给成测试环境，才能把判定推进到"认证入口是否登记"这一步：
            # 这条用例考的是"AUTH 没有授权依据"，不是"环境未知"。
            environment="isolated_test", identity_bound=True,
        ),
    )
    ctx.check(d.decision == Decision.UNKNOWN, f"决策应为 UNKNOWN（默认拒绝），实际 {d.decision}")
    ctx.check(d.category == ApiCategory.EXPORT, "审计里应保留 EXPORT 识别信号")
    ctx.set("category", d.category)
    ctx.set("decision", d.decision)
    ctx.set("command", cls.command)


def auth_denied(ctx) -> None:
    """AUTH 没有矩阵授权行，但仍必须被拒——且不走 L0/L1。

    第七轮整改后 AUTH 走 **AUTH_BOOTSTRAP 受限通道**：没有已登记认证入口
    的登录请求会被 DENY（而不是静默 UNKNOWN）。安全性质不变（拒绝），
    口径更严格：DENY 比 UNKNOWN 更明确，且 level 一定是 AUTH_BOOTSTRAP，
    证明它没有被映射进任何矩阵等级。
    """
    url = "http://h:8080/login"
    cls = classify_request(url, method="POST")
    ctx.check(cls.category == ApiCategory.AUTH, f"分类应为 AUTH，实际 {cls.category}")
    ctx.check(cls.command == "", "AUTH 没有矩阵授权行 → 命令必须为空")
    guard = RequestGuard(ctx.cfg(env=""))
    d = guard.check_request(
        url, method="POST",
        ctx=GuardContext(
            target_id="http://h:8080", bound_target="http://h:8080",
            # 环境给成测试环境，才能把判定推进到"认证入口是否登记"这一步：
            # 这条用例考的是"AUTH 没有授权依据"，不是"环境未知"。
            environment="isolated_test", identity_bound=True,
        ),
    )
    ctx.check(d.decision == Decision.DENY, f"决策应为 DENY（受限通道拒绝），实际 {d.decision}")
    ctx.check(d.denied, "DENY 必须视为拒绝")
    ctx.check(not d.allowed, "AUTH 请求不得被放行")
    ctx.check(d.level == "AUTH_BOOTSTRAP",
              f"AUTH 必须走受限通道而不是矩阵等级，实际 level={d.level!r}")
    # 空 body 的 POST /login：路径自证认出它是登录入口，但**缺凭证字段**，
    # 依然拒绝（"像登录入口"不等于"就是一次登录"）。理由必须说清是哪一条。
    ctx.check(
        ("凭证" in d.reason) or ("未登记" in d.reason) or ("结构" in d.reason),
        f"拒绝理由应说明未通过哪条认证条件：{d.reason[:120]}",
    )
    ctx.check(any(("PARAMS_INVALID" in s) or ("ENDPOINT_UNREGISTERED" in s)
                  for s in d.signals),
              f"判定码应是 PARAMS_INVALID / ENDPOINT_UNREGISTERED：{d.signals}")

    # 反向加强：**参数是合法凭证**、但路径不是认证入口 → 认证通道仍然拒绝。
    # 这条证明放宽的只是"入口识别"，没有变成"任意 URL 都能提交凭证"。
    # （直接调 check_auth：这里考的是 AUTH_BOOTSTRAP 通道本身，不牵扯分类器。）
    d2 = guard.check_auth(
        "http://h:8080/api/users/export", method="POST",
        body='{"username": "u", "password": "p"}',
        ctx=GuardContext(
            target_id="http://h:8080", bound_target="http://h:8080",
            environment="isolated_test", identity_bound=True,
        ),
        count_rate=False,
    )
    ctx.check(d2.decision == Decision.DENY,
              f"非认证路径即使带凭证也必须拒绝，实际 {d2.decision}")
    ctx.check("未登记" in d2.reason or "不是认证入口" in d2.reason,
              f"拒绝理由应说明该路径不是认证入口：{d2.reason[:120]}")
    ctx.set("category", d.category)
    ctx.set("decision", d.decision)
    ctx.set("level", d.level)
    ctx.set("command", cls.command)


def no_export_auth_rows(ctx) -> None:
    ctx.check(len(RULES) == 10, f"矩阵必须恰好十条，实际 {len(RULES)}")
    ctx.check(rule_for_command("导出数据") is None, "不得存在「导出数据」授权行")
    ctx.check(rule_for_command("认证操作") is None, "不得存在「认证操作」授权行")
    ctx.check(COMMAND_FOR_CATEGORY.get(ApiCategory.EXPORT) == "",
              "EXPORT 不得映射进任何矩阵命令")
    ctx.check(COMMAND_FOR_CATEGORY.get(ApiCategory.AUTH) == "",
              "AUTH 不得映射进任何矩阵命令")
    ctx.set("rules", len(RULES))
    ctx.set("export_row", rule_for_command("导出数据") is not None)
    ctx.set("auth_row", rule_for_command("认证操作") is not None)


# ── fileread ──────────────────────────────────────────────────────

def fileread_unmapped(ctx) -> None:
    ctx.check("fileread" not in PROBE_KIND_COMMAND,
              "fileread 不得出现在探针映射表（无矩阵授权）")
    guard = RequestGuard(ctx.cfg(env=""))
    d = guard.check_probe(
        "http://h:8080/x", "fileread",
        ctx=GuardContext(
            target_id="http://h:8080", bound_target="http://h:8080",
            # 环境给成测试环境，才能把判定推进到"认证入口是否登记"这一步：
            # 这条用例考的是"AUTH 没有授权依据"，不是"环境未知"。
            environment="isolated_test", identity_bound=True,
        ),
    )
    ctx.check(d.decision == Decision.UNKNOWN, f"应 UNKNOWN 拒绝，实际 {d.decision}")
    ctx.check(d.denied, "UNKNOWN 必须视为拒绝")
    ctx.set("mapped", "fileread" in PROBE_KIND_COMMAND)
    ctx.set("decision", d.decision)


def sqli_maps_l3(ctx) -> None:
    cmd = PROBE_KIND_COMMAND.get("sqli")
    ctx.check(cmd == "SQL 注入验证", f"sqli 应映射 SQL 注入验证，实际 {cmd!r}")
    r = rule_for_command(cmd or "")
    ctx.check(r is not None and r.level == "L3", "SQL 注入验证必须是 L3")
    ctx.check(rule_for_command("查询详情").level == "L0", "对照项：查询详情是 L0")
    ctx.set("sqli_command", cmd or "")
    ctx.set("sqli_level", r.level if r else "")
    ctx.set("read_level", rule_for_command("查询详情").level)


# ── 范围 ──────────────────────────────────────────────────────────

def scope_matrix(ctx) -> None:
    bound = "http://h:8080/app"
    checks = [
        ("http://h:8080/app/users/1", True, "前缀内 → 在范围内"),
        ("http://h:8080/app", True, "恰好等于前缀 → 在范围内"),
        ("http://h:8080/application", False, "前缀撞车 → 出界"),
        ("http://h:9999/app/users", False, "端口不同 → 出界"),
        ("https://h:8080/app/users", False, "scheme 不同 → 出界"),
        ("http://h:80/", True, "默认端口归一（另绑 http://h）"),
        ("http://h:8080/app/%2e%2e/other", False, "编码点段 → 摊平后出界"),
        ("http://h:8080/app//../other", False, "双斜杠+点段 → 出界"),
        ("http://h:8080/app\\..\\other", False, "反斜杠 → 归一后出界"),
        ("http://h:8080/app/%252525252e%252525252e/other", False,
         "解码达上限仍歧义 → fail-closed"),
        ("http://h:8080/app/./users", True, "点段冗余 → 同一路径"),
        ("not-a-url", False, "解析失败 → 出界"),
        ("http://h:8080/other", False, "前缀外 → 出界"),
        ("http://H:8080/app/users", True, "hostname 大小写不敏感"),
    ]
    failures = 0
    for url, want, why in checks:
        b = "http://h" if url == "http://h:80/" else bound
        got = in_scope(url, b)
        if got != want:
            failures += 1
        ctx.check(got == want, f"{why}：in_scope({url!r}, {b!r}) 期望 {want}，实际 {got}")
    ctx.set("checks", len(checks))
    ctx.set("failures", failures)


def host_scope_only_for_host_tools(ctx) -> None:
    host_ok = host_in_scope("http://h:9999/x", "http://h:8080")
    strict_ok = in_scope("http://h:9999/x", "http://h:8080")
    ctx.check(host_ok is True, "主机级授权应允许同主机换端口")
    ctx.check(strict_ok is False, "严格范围必须比较端口")
    ctx.check("recon_ports" in HOST_SCOPED_TOOLS, "recon_ports 属于主机级工具")
    ctx.check("http_request" not in HOST_SCOPED_TOOLS,
              "http_request 不得按主机级授权（路径工具必须严格）")
    ctx.set("host_ok", host_ok)
    ctx.set("strict_ok", strict_ok)
    ctx.set("port_tool_listed", "recon_ports" in HOST_SCOPED_TOOLS)


# ── 台账 ──────────────────────────────────────────────────────────

def ledger_strict_id(ctx) -> None:
    led = TestLedger()
    created = led.record(
        "http://h:8080/api/users", "create",
        run_id="r1", target_id="t1", identity="i1", object_id="4321",
    )
    led.record(
        "http://h:8080/api/preset/7", "update",
        run_id="r1", target_id="t1", identity="i1", object_id="7",
    )
    no_id = led.record(
        "http://h:8080/api/things", "create",
        run_id="r1", target_id="t1", identity="i1", object_id="",
    )
    created_ok, _ = led.delete_verdict(
        "http://h:8080/api/users/4321", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    other_ok, _ = led.delete_verdict(
        "http://h:8080/api/users/9999", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    update_ok, _ = led.delete_verdict(
        "http://h:8080/api/preset/7", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    root_ok, _ = led.delete_verdict(
        "http://h:8080/", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    ctx.check(created is not None, "本次创建且带对象 ID → 应登记")
    ctx.check(no_id is None, "创建但取不到对象 ID → 不得登记")
    ctx.check(created_ok is True, "删除本次创建的具体对象 ID → 放行")
    ctx.check(other_ok is False, "删除同端点其它 ID → 拒绝")
    ctx.check(update_ok is False, "仅修改过的既有对象 → 不得删除（审批不能替代身份验证）")
    ctx.check(root_ok is False, "删除 URL 提不出对象 ID → 拒绝（fail-closed）")
    ctx.set("created_ok", created_ok)
    ctx.set("other_id_ok", other_ok)
    ctx.set("update_only_ok", update_ok)
    ctx.set("root_ok", root_ok)


def ledger_approval_cannot_replace_identity(ctx) -> None:
    led = TestLedger()
    led.record(
        "http://h:8080/api/users", "create",
        run_id="r1", target_id="t1", identity="i1", object_id="4321",
    )
    known_ok, _ = led.delete_verdict(
        "http://h:8080/api/users/4321", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    unknown_approved_ok, why = led.delete_verdict(
        "http://h:8080/api/users/9999", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST, approved=True,
    )
    unknown_ok, _ = led.delete_verdict(
        "http://h:8080/api/users/9999", run_id="r1", target_id="t1",
        identity="i1", environment=Environment.ISOLATED_TEST,
    )
    ctx.check(known_ok is True, "台账内对象 → 放行")
    ctx.check(unknown_approved_ok is False,
              "对象身份未验证时，单独审批也不得放行（需求：必须验证具体对象 ID）")
    ctx.check(unknown_ok is False, "未知对象无审批 → 拒绝")
    ctx.set("known_ok", known_ok)
    ctx.set("unknown_approved_ok", unknown_approved_ok)
    ctx.set("unknown_no_approval_ok", unknown_ok)
    if unknown_approved_ok:
        ctx.note_risk(f"审批仍可替代对象身份验证：{why}")


# ── 审批票据 ──────────────────────────────────────────────────────

def ticket_binding(ctx) -> None:
    led = ApprovalLedger(ttl=60)
    issue_kw = dict(
        url="http://h:8080/api/users/1", command="删除测试数据",
        target_id="t1", run_id="r1", identity="i1",
        method="DELETE", request_digest="digest-1", level="L2", approver="alice",
    )
    consume_kw = {k: v for k, v in issue_kw.items() if k != "approver"}
    ap = led.issue(**issue_kw)
    wrong_url, _ = led.consume(
        ap.token, **{**consume_kw, "url": "http://h:8080/api/users/2"},
    )
    wrong_method, _ = led.consume(ap.token, **{**consume_kw, "method": "GET"})
    wrong_digest, _ = led.consume(
        ap.token, **{**consume_kw, "request_digest": "digest-2"},
    )
    wrong_level, _ = led.consume(ap.token, **{**consume_kw, "level": "L1"})
    first_ok, _ = led.consume(ap.token, **consume_kw)
    reuse_ok, _ = led.consume(ap.token, **consume_kw)

    expired = ApprovalLedger(ttl=0)
    ap2 = expired.issue(**issue_kw)
    expired_ok, _ = expired.consume(ap2.token, **consume_kw)

    ctx.check(wrong_url is False, "URL 不同的票据不得消费")
    ctx.check(wrong_method is False, "方法不同的票据不得消费")
    ctx.check(wrong_digest is False, "请求指纹不同的票据不得消费")
    ctx.check(wrong_level is False, "风险等级不同的票据不得消费")
    ctx.check(first_ok is True, "票面完全一致 → 消费成功")
    ctx.check(reuse_ok is False, "已消费票据不得复用")
    ctx.check(expired_ok is False, "过期票据不得消费")
    ctx.set("first_ok", first_ok)
    ctx.set("wrong_url_ok", wrong_url)
    ctx.set("wrong_digest_ok", wrong_digest)
    ctx.set("reuse_ok", reuse_ok)
    ctx.set("expired_ok", expired_ok)


def approval_no_cross_consume(ctx) -> None:
    led = ApprovalLedger(ttl=60)
    issue_common = dict(
        command="删除测试数据", target_id="t1", run_id="r1", identity="i1",
        method="DELETE", level="L2", approver="alice",
    )
    consume_common = {k: v for k, v in issue_common.items() if k != "approver"}
    a = led.issue(url="http://h:8080/api/users/1", request_digest="d-a", **issue_common)
    b = led.issue(url="http://h:8080/api/users/2", request_digest="d-b", **issue_common)
    cross_ok, _ = led.consume(
        a.token, url="http://h:8080/api/users/2", request_digest="d-b",
        **consume_common,
    )
    a_ok, _ = led.consume(
        a.token, url="http://h:8080/api/users/1", request_digest="d-a",
        **consume_common,
    )
    b_ok, _ = led.consume(
        b.token, url="http://h:8080/api/users/2", request_digest="d-b",
        **consume_common,
    )
    # 两张票据互不干扰：A 的消费不影响 B；交叉消费必须失败
    ctx.check(cross_ok is False, "A 的票据不能用于 B 的请求")
    ctx.check(a_ok is True, "A 的票据用于 A → 成功")
    ctx.check(b_ok is True, "B 的票据不受 A 的消费影响")
    ctx.check(led.outstanding() == 0, "两张票都消费后无有效票据")
    reap, _ = led.consume(
        a.token, url="http://h:8080/api/users/1", request_digest="d-a",
        **consume_common,
    )
    ctx.check(reap is False, "重放已消费票据必须失败")
    ctx.set("a_ok", a_ok)
    ctx.set("b_ok", b_ok)
    ctx.set("cross_ok", cross_ok)
    ctx.set("reuse_ok", reap)


__all__ = [
    "l3_decide_all_envs", "approval_refuses_l3", "unknown_command_denied",
    "unknown_method_denied", "export_denied", "auth_denied", "no_export_auth_rows",
    "fileread_unmapped", "sqli_maps_l3", "scope_matrix",
    "host_scope_only_for_host_tools", "ledger_strict_id",
    "ledger_approval_cannot_replace_identity", "ticket_binding",
    "approval_no_cross_consume",
]
