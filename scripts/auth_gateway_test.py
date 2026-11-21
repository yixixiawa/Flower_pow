"""AUTH_BOOTSTRAP + 统一外部工具出口 专项测试（第七轮整改）。

覆盖用户验收清单的 14 条：

 1. 合法、受限的登录初始化可以完成策略判定
 2. 未绑定目标的登录请求拒绝
 3. UNKNOWN 环境的登录请求拒绝
 4. 未获允许的测试背景不能执行登录
 5. 登录成功后，未授权 GET 仍然拒绝
 6. 登录接口以外的 AUTH 管理操作不能借助 AUTH_BOOTSTRAP 放行
 7. curl 的 HTTP POST 必须经过统一 Gateway
 8. curl 不能绕过 L3
 9. curl 不能绕过 UNKNOWN
10. curl 不能绕过目标范围
11. Header application/json 不再被误判为文件路径
12. -H @file 仍受文件路径授权控制
13. 重定向到未授权目标时拒绝
14. Detector、MCP、Scheduler、后台任务均使用同一策略入口

外加两条边界：登录频率限制、敏感凭证不落审计明文，以及一条产品口径：
**6c. 清单未登记时按路径识别认证入口**——末段含 login / signin / refresh /
logout 即认（`loginByPassword`、`doLogin` 都算），只读后缀
（history / logs / list / records）不算；放宽的只是"入口识别"，方法、
参数结构、凭证字段、环境、频率一条未松。

所有"被拒绝"的用例都同时看三件事：返回值、**真实网络**（MockNet 计数）、
**审计**（读 JSONL 文件）。只用 mock 目标，不向任何真实地址发请求。

运行：``.venv/Scripts/python.exe scripts/auth_gateway_test.py``（退出码 0 = 全过）。
"""

from __future__ import annotations

import ast
import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import Config
from core.session import Session
from core.state import Asset
from core.tools.runner import ToolRunner
from policy import auth_bootstrap as ab
from policy.request_guard import GuardContext, RequestGuard
from scripts.acceptance.mocknet import MockNet

PROJECT = Path(__file__).resolve().parent.parent
PASS = 0
FAIL: list[str] = []


def check(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


def section(title: str) -> None:
    print(f"\n{title}")


# ── 夹具 ──────────────────────────────────────────────────────────


def make_cfg(tmp: Path, *, env: str = "isolated_test", binding: str = "",
             default_env: str = "unknown") -> Config:
    cfg = Config()
    cfg.scan.timeout = 5.0
    cfg.scan.follow_redirects = True
    cfg.scan.proxy = None
    cfg.scan.no_proxy = []
    cfg.scan.proxy_autodetect = False
    cfg.scan.verify_tls = False
    cfg.llm.enabled = False
    cfg.rag.enabled = False
    cfg.data_dir = str(tmp / "data")
    cfg.output_dir = str(tmp / "out")
    cfg.scan.audit_dir = cfg.data_dir
    cfg.policy.default_environment = default_env
    cfg.policy.audit = True
    cfg.policy.environments = {binding: env} if binding else {}
    return cfg


def auth_assets() -> list[Asset]:
    """接口清单里的四条认证入口 + 一条导出接口（用于"登录后仍被拒"）。"""
    return [
        Asset(kind="api", value="/api/auth/login",
              meta={"method": "POST", "path": "/api/auth/login",
                    "body_fields": ["username", "password"]}),
        Asset(kind="api", value="/api/auth/captcha",
              meta={"method": "GET", "path": "/api/auth/captcha"}),
        Asset(kind="api", value="/api/auth/refresh",
              meta={"method": "POST", "path": "/api/auth/refresh",
                    "body_fields": ["refresh_token"]}),
        Asset(kind="api", value="/api/auth/logout",
              meta={"method": "POST", "path": "/api/auth/logout"}),
    ]


def make_session(net: MockNet, *, with_assets: bool = True) -> Session:
    s = Session(target=net.target)
    s.result.target = s.target
    s.result.target_id = s.target
    if with_assets:
        s.result.assets.extend(auth_assets())
    return s


def audit_text(cfg: Config) -> str:
    p = Path(cfg.data_dir) / "policy" / "audit.jsonl"
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def run_login(runner, session, **kw):
    args = {"url": session.target, "username": "tester", "password": "S3cret!pass"}
    args.update(kw)
    return asyncio.run(runner.execute("login", args, session))


def guard_for(cfg: Config) -> RequestGuard:
    return RequestGuard(cfg)


def ctx_for(cfg: Config, session: Session) -> GuardContext:
    g = guard_for(cfg)
    return GuardContext(
        target_id=session.target,
        bound_target=session.target,
        environment=g.environment_for(session.target),
        identity_bound=True,
        identity="test|sess|tgt",
        session_id=session.session_id,
        auth_entries=ab.entries_for(session.target, session.result.assets),
        credentials_present=bool(session.credentials.get("token")),
    )


# ── 1. 合法受限登录 ───────────────────────────────────────────────


def scenario_legal_login(tmp: Path, net: MockNet) -> None:
    section("1. 合法、受限的登录初始化可以完成策略判定（真实登录成功）")
    cfg = make_cfg(tmp / "s1", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    mark = net.snapshot()
    out = run_login(runner, s)
    hits = net.delta(mark)

    check(not out.startswith("【已拦截】"), f"合法登录不应被拦截：{out[:160]}")
    check("登录成功" in out, f"登录应真实成功（mock 返回 JWT）：{out[:200]}")
    check(bool(s.credentials.get("token")), "登录成功应写入会话 Token")
    check("S3cret!pass" not in out, "工具输出不得回显明文密码")
    login_hits = [r for r in hits if r.path == "/api/auth/login" and r.method == "POST"]
    check(len(login_hits) == 1, f"登录请求应真实发出一次（实际 {len(login_hits)}）")
    check(any(r.path == "/api/auth/captcha" for r in hits),
          "验证码读取也经过闸门并被放行（同一条 AUTH_BOOTSTRAP 通道）")


def scenario_rate_limit(tmp: Path) -> None:
    section("1b. 登录频率受限（滑动窗口）")
    entries = ab.entries_for("http://127.0.0.1:8080", auth_assets())
    ab.configure_rate_limit(max_attempts=2, window=60.0, min_interval=0.0)
    ab.reset_rate_limits()
    try:
        kw = dict(
            url="http://127.0.0.1:8080/api/auth/login", method="POST",
            params={"username": "u", "password": "p"}, entries=entries,
            target_id="t", bound_target="http://127.0.0.1:8080",
            environment="isolated_test", session_id="rate-1",
        )
        first = ab.check(**kw)
        second = ab.check(**kw)
        third = ab.check(**kw)
    finally:
        ab.configure_rate_limit(max_attempts=5, window=60.0, min_interval=0.5)
        ab.reset_rate_limits()
    check(first.allowed and second.allowed, "配额内的登录请求放行")
    check(not third.allowed and third.code == "RATE_LIMITED",
          f"超配额必须拒绝且给出 RATE_LIMITED（实际 {third.code}）")


# ── 2/3/4. 拒绝条件 ───────────────────────────────────────────────


def scenario_unbound_target(tmp: Path) -> None:
    section("2. 未绑定目标的登录请求拒绝")
    cfg = make_cfg(tmp / "s2", binding="127.0.0.1:1")
    g = guard_for(cfg)
    d = g.check_auth(
        "http://127.0.0.1:8080/api/auth/login", method="POST",
        params={"username": "u", "password": "p"},
        ctx=GuardContext(
            target_id="", bound_target="",
            environment="isolated_test",
            auth_entries=ab.entries_for("http://127.0.0.1:8080", auth_assets()),
        ),
    )
    check(not d.allowed, "未绑定目标必须拒绝")
    check("未绑定目标" in d.reason, f"拒绝理由应说明会话未绑定目标：{d.reason[:120]}")
    check(any("SESSION_UNBOUND" in s for s in d.signals), "判定码应为 SESSION_UNBOUND")


def scenario_unknown_env(tmp: Path, net: MockNet) -> None:
    section("3. UNKNOWN 环境的登录请求拒绝（且不触网）")
    cfg = make_cfg(tmp / "s3", default_env="unknown")   # 无 environments 绑定
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    mark = net.snapshot()
    out = run_login(runner, s)
    hits = net.delta(mark)
    check(out.startswith("【已拦截】"), f"unknown 环境登录必须被拒：{out[:160]}")
    check("unknown" in out, "拒绝理由应点名环境未判定")
    check(not hits, f"被拒登录不得触网（实际 {len(hits)} 条）")
    check(not s.credentials.get("token"), "被拒登录不得产生 Token")


def scenario_production_env(tmp: Path, net: MockNet) -> None:
    section("4. 非测试背景（production）不能执行登录")
    cfg = make_cfg(tmp / "s4", env="production", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    mark = net.snapshot()
    out = run_login(runner, s)
    check(out.startswith("【已拦截】"), f"生产环境登录必须被拒：{out[:160]}")
    check("测试背景" in out or "production" in out, "拒绝理由应说明非测试背景")
    check(not net.delta(mark), "生产环境被拒登录不得触网")


# ── 5. 登录成功 ≠ 放行后续请求 ────────────────────────────────────


def scenario_post_login_still_gated(tmp: Path, net: MockNet) -> None:
    section("5. 登录成功后未授权 GET 仍然拒绝")
    cfg = make_cfg(tmp / "s5", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    login_out = run_login(runner, s)
    check("登录成功" in login_out, f"前置：登录应成功：{login_out[:160]}")
    check(bool(s.credentials.get("token")), "前置：应已取得 Token")

    mark = net.snapshot()
    out = asyncio.run(runner.execute(
        "http_request", {"url": net.target + "/api/users/export", "method": "GET"}, s,
    ))
    hits = net.delta(mark)
    check(out.startswith("【已拦截】"), f"登录后导出请求仍须被拒：{out[:200]}")
    check("UNKNOWN" in out or "导出" in out or "EXPORT" in out,
          "拒绝理由应指向 EXPORT 无授权行")
    check(not hits, f"被拒的导出请求不得触网（实际 {len(hits)} 条）")

    mark2 = net.snapshot()
    out2 = asyncio.run(runner.execute(
        "http_request", {"url": net.target + "/api/users/4321", "method": "DELETE"}, s,
    ))
    check(out2.startswith("【已拦截】"), f"登录后删除请求仍须逐请求审批：{out2[:160]}")
    check(not net.delta(mark2), "被拒的删除请求不得触网")


# ── 6. AUTH 管理操作不能借道 ──────────────────────────────────────


def scenario_auth_admin_blocked(tmp: Path) -> None:
    section("6. 登录接口以外的 AUTH 管理操作不能借助 AUTH_BOOTSTRAP 放行")
    cfg = make_cfg(tmp / "s6", binding="127.0.0.1:8080")
    g = guard_for(cfg)
    entries = ab.entries_for("http://127.0.0.1:8080", auth_assets())
    base_ctx = GuardContext(
        target_id="t", bound_target="http://127.0.0.1:8080",
        environment="isolated_test", auth_entries=entries, session_id="s6",
    )
    # 未登记路径（改密码 / 建用户）：不是认证入口
    d1 = g.check_auth("http://127.0.0.1:8080/api/auth/users/create", method="POST",
                      params={"username": "x", "password": "y"}, ctx=base_ctx)
    check(not d1.allowed and "未登记" in d1.reason, f"认证管理写操作必须拒绝：{d1.reason[:120]}")
    # 已登记入口但多带了非认证字段
    d2 = g.check_auth("http://127.0.0.1:8080/api/auth/login", method="POST",
                      params={"username": "x", "password": "y", "role": "admin"}, ctx=base_ctx)
    check(not d2.allowed and "结构" in d2.reason, f"越界参数必须拒绝：{d2.reason[:120]}")
    # 方法不符（GET 登录）
    d3 = g.check_auth("http://127.0.0.1:8080/api/auth/login", method="GET", ctx=base_ctx)
    check(not d3.allowed and "方法" in d3.reason, f"方法不符必须拒绝：{d3.reason[:120]}")
    # 刷新但会话没有凭证
    d4 = g.check_auth("http://127.0.0.1:8080/api/auth/refresh", method="POST",
                      params={"refresh_token": "r"}, ctx=base_ctx)
    check(not d4.allowed and "凭证" in d4.reason, f"无凭证刷新必须拒绝：{d4.reason[:120]}")
    # 登出：已登记 + 方法一致 → 放行（仍只作用于这一次请求）
    d5 = g.check_auth("http://127.0.0.1:8080/api/auth/logout", method="POST", ctx=base_ctx)
    check(d5.allowed, f"已登记登出入口应放行：{d5.reason[:120]}")


# ── 6c. 路径自证：没有接口清单也能登录 ────────────────────────────


def scenario_implicit_endpoint(tmp: Path, net: MockNet) -> None:
    section("6c. 清单未登记时按路径末段识别认证入口（/auth/login 等标准约定）")
    cfg = make_cfg(tmp / "s6c", binding=net.a.binding)   # 端到端用例要真连 MockNet
    g = guard_for(cfg)
    base = "http://127.0.0.1:8080"                        # 纯判定用例用固定 URL

    def judge(url: str, method: str = "POST", body: str = "",
              env: str = "isolated_test", tid: str = "t",
              bound: str = base, cred: bool = False):
        return g.check_auth(
            url, method=method, body=body,
            ctx=GuardContext(
                target_id=tid, bound_target=bound, environment=env,
                auth_entries=(), session_id="s6c",     # 关键：清单为空
                credentials_present=cred,
            ),
            count_rate=False,
        )

    yudao = f"{base}/admin-api/system/auth/login"
    creds = '{"username": "1550", "password": "123456"}'

    # 1) 用户真实场景：芋道 admin-api 登录（清单为空）
    d = judge(yudao, body=creds)
    check(d.allowed, f"标准登录端点无需清单即可单次放行：{d.reason[:160]}")
    check(d.level == "AUTH_BOOTSTRAP", f"等级仍是 AUTH_BOOTSTRAP：{d.level}")
    check(any("路径自证" in s for s in d.signals), f"信号应标明入口来源：{d.signals}")

    # 2) 方法不符：GET 打登录端点
    d = judge(yudao, method="GET")
    check(not d.allowed and "方法" in d.reason, f"GET 登录必须拒绝：{d.reason[:120]}")

    # 3) 普通接口（末段 export）不是认证入口
    d = judge(f"{base}/api/users/export")
    check(not d.allowed and "未登记" in d.reason, f"非认证路径必须拒绝：{d.reason[:120]}")

    # 4) 名字里带 login 但不是登录端点（末段 login-history）
    d = judge(f"{base}/api/auth/login-history", body=creds)
    check(not d.allowed, f"login-history 不得被当登录入口：{d.reason[:120]}")

    # 5) 参数不是认证结构（分页字段）
    d = judge(yudao, body='{"pageNum": 1, "pageSize": 10}')
    check(not d.allowed and "结构" in d.reason, f"非认证参数必须拒绝：{d.reason[:120]}")

    # 6) 有认证字段但没有凭证字段
    d = judge(yudao, body='{"remember": true}')
    check(not d.allowed and "凭证" in d.reason, f"缺凭证字段必须拒绝：{d.reason[:120]}")

    # 7) OAuth2 令牌端点（末段 token，父段 oauth）= 刷新
    d = judge(f"{base}/oauth/token",
              body='{"grant_type": "refresh_token", "refresh_token": "r"}', cred=True)
    check(d.allowed and any("refresh" in s for s in d.signals),
          f"oauth/token 应识别为刷新入口：{d.reason[:140]}")

    # 8) 没有可刷新凭证时，刷新入口不成立
    d = judge(f"{base}/oauth/token",
              body='{"grant_type": "refresh_token", "refresh_token": "r"}')
    check(not d.allowed and "凭证" in d.reason, f"无凭证刷新必须拒绝：{d.reason[:120]}")

    # 9) 验证码不做路径自证（方法语义不唯一，必须清单登记）
    d = judge(f"{base}/api/captcha/get")
    check(not d.allowed, f"/captcha/get 不得路径自证：{d.reason[:120]}")

    # 10) 登出（末段 logout）
    d = judge(f"{base}/admin-api/system/auth/logout")
    check(d.allowed, f"标准登出端点应放行：{d.reason[:140]}")

    # 10b) 放宽口径：末段**包含** login 即认（不要求恰好等于 login）
    for path in (
        "/api/v1/user/loginByPassword",
        "/api/user/doLogin",
        "/api/login.json",
        "/api/login/do",          # 动作在下一段，父段是 login
        "/sso/adminLogin",
    ):
        d = judge(f"{base}{path}", body=creds)
        check(d.allowed, f"{path} 应识别为登录入口：{d.reason[:120]}")

    # 10c) 只读后缀（查询/列表）仍不认，避免"名字带 login 的查询接口"被当登录
    for path in ("/api/auth/login-history", "/api/loginLogs", "/api/login/records"):
        d = judge(f"{base}{path}", body=creds)
        check(not d.allowed, f"{path} 是查询接口，不得当登录入口：{d.reason[:100]}")

    # 11-13) 路径自证不放宽前三条件
    d = judge(yudao, body=creds, tid="", bound="")
    check(not d.allowed and "未绑定目标" in d.reason, f"未绑定目标仍拒绝：{d.reason[:120]}")
    d = judge(yudao, body=creds, env="unknown")
    check(not d.allowed and "unknown" in d.reason, f"unknown 环境仍拒绝：{d.reason[:120]}")
    d = judge(yudao, body=creds, env="production")
    check(not d.allowed and ("测试背景" in d.reason or "production" in d.reason),
          f"生产环境仍拒绝：{d.reason[:120]}")

    # 14) 工具级意图：清单为空也不再硬性要求 recon_openapi（captcha 除外）
    d = g.check_auth_intent("login", ctx=GuardContext(
        target_id="t", bound_target=base, environment="isolated_test",
        auth_entries=(), session_id="s6c",
    ))
    check(d.allowed, f"无清单时 login 意图应放行（端点由请求级自证）：{d.reason[:140]}")
    d = g.check_auth_intent("captcha", ctx=GuardContext(
        target_id="t", bound_target=base, environment="isolated_test",
        auth_entries=(), session_id="s6c",
    ))
    check(not d.allowed, f"captcha 意图无清单仍拒绝：{d.reason[:120]}")

    # 15) 端到端：无清单 + http_request 直连 /login → 真正发出请求、不被拦截
    runner = ToolRunner(cfg, root=tmp)
    s = Session(target=net.target)
    s.result.target = s.target
    s.result.target_id = s.target          # 故意不塞任何 api 资产
    mark = net.snapshot()
    out = asyncio.run(runner.execute(
        "http_request",
        {"url": net.target + "/login", "method": "POST",
         "body": {"username": "1550", "password": "123456"},
         "headers": {"Content-Type": "application/json"}},
        s,
    ))
    hits = [r for r in net.delta(mark) if r.path == "/login"]
    check(not out.startswith("【已拦截】"), f"无清单直连 /login 不应被拦截：{out[:160]}")
    check(len(hits) == 1, f"登录请求应真实发出一次（实际 {len(hits)}）")
    check(not s.credentials.get("token"), "http_request 不会产生任何\"已登录\"状态")


def scenario_no_secrets_in_audit(tmp: Path, net: MockNet) -> None:
    section("6b. 敏感凭证不得进入审计明文 / 工具输出")
    cfg = make_cfg(tmp / "s6b", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    secret = "Sup3r-Secret-Pwd!"
    out = run_login(runner, s, password=secret)
    log = audit_text(cfg)
    check("登录成功" in out, f"前置：登录应成功：{out[:120]}")
    check(secret not in out, "工具输出不得出现明文密码")
    check(secret not in log, "审计日志不得出现明文密码")
    token = s.credentials.get("token", "")
    check(bool(token) and token not in log, "审计日志不得出现明文 Token")
    check("认证初始化" in log, "认证初始化放行必须留痕（allow 事件带命令名）")


# ── 7-10. 外部工具与统一 Gateway ──────────────────────────────────


def _no_spawn(fn):
    """包装 subprocess.run：断言"没有真的启动外部进程"。"""
    real = subprocess.run
    calls: list[tuple] = []

    def fake(*a, **k):
        calls.append(a)
        return subprocess.CompletedProcess(args=a[0] if a else [], returncode=0,
                                           stdout="", stderr="")

    subprocess.run = fake
    try:
        return fn(), calls
    finally:
        subprocess.run = real


def scenario_curl_post_gated(tmp: Path, net: MockNet) -> None:
    section("7. curl 的 HTTP POST 必须经过统一 Gateway（不放行裸外部进程）")
    cfg = make_cfg(tmp / "s7", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    mark = net.snapshot()

    def go():
        return asyncio.run(runner.execute(
            "external_tool",
            {"tool": "curl",
             "args": ["-X", "POST", net.target + "/api/auth/login",
                      "-d", "username=u&password=p"]},
            s,
        ))

    out, spawned = _no_spawn(go)
    check(out.startswith("【已拦截】"), f"curl POST 必须被拦截：{out[:200]}")
    check("http_request" in out, "拒绝文本应给出合法出路（内置 http_request）")
    check(not spawned, "被拒的 curl 不得启动任何外部进程")
    check(not net.delta(mark), "被拒的 curl 不得产生网络请求")


def scenario_curl_l3(tmp: Path, net: MockNet) -> None:
    section("8. curl 不能绕过 L3（SQL 注入 / 命令执行）")
    cfg = make_cfg(tmp / "s8", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    out = asyncio.run(runner.execute(
        "external_tool",
        {"tool": "curl", "args": ["-d", "id=1' OR 1=1 --", net.target + "/search"]},
        s,
    ))
    check(out.startswith("【已拦截】"), f"curl 携带注入 payload 必须被拦：{out[:160]}")
    # 可解析的外部工具也不能绕过 L3：sqlmap 映射 L3 一律拒绝
    out2 = asyncio.run(runner.execute(
        "external_tool", {"tool": "sqlmap", "target": net.target}, s,
    ))
    check(out2.startswith("【已拦截】") and "SQL 注入验证" in out2,
          f"sqlmap 仍按 L3 拒绝：{out2[:160]}")


def scenario_curl_unknown(tmp: Path, net: MockNet) -> None:
    section("9. curl 不能绕过 UNKNOWN")
    cfg = make_cfg(tmp / "s9", default_env="unknown")
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    out = asyncio.run(runner.execute(
        "external_tool", {"tool": "curl", "args": [net.target + "/ok"]}, s,
    ))
    check(out.startswith("【已拦截】"), f"unknown 环境下 curl 必须被拦：{out[:160]}")
    out2 = asyncio.run(runner.execute(
        "external_tool", {"tool": "definitely-not-a-tool", "args": []}, s,
    ))
    check(out2.startswith("【已拦截】") and ("默认拒绝" in out2 or "不在权限矩阵" in out2),
          f"未映射外部工具 → UNKNOWN 默认拒绝：{out2[:160]}")


def scenario_external_scope(tmp: Path, net: MockNet) -> None:
    section("10. 外部工具不能访问未绑定目标（curl 也不能绕过范围）")
    cfg = make_cfg(tmp / "s10", binding=net.a.binding)
    g = guard_for(cfg)
    ctx = GuardContext(
        target_id=net.target, bound_target=net.target,
        environment="isolated_test", identity_bound=True,
    )
    # 可解析外部工具：argv 里的目标必须与绑定目标同主机（换主机 = 换对象）
    other = "http://127.0.0.2:9"
    d = g.check_tool("nmap", {"args": ["-sT", "-Pn", other]}, ctx=ctx)
    check(not d.allowed and "未绑定目标" in d.reason,
          f"nmap 指向外部主机必须拒绝：{d.reason[:140]}")
    d2 = g.check_tool("nmap", {"args": ["-sT", "-Pn", net.target]}, ctx=ctx)
    check(d2.allowed, f"同主机扫描应放行：{d2.reason[:140]}")
    # ffuf：-u 是 URL，按 scheme+host+port 严格授权（同主机换端口也算越界）
    d3 = g.check_tool("ffuf", {"args": ["-u", net.outsider + "/FUZZ", "-w", "x.txt"]}, ctx=ctx)
    check(not d3.allowed and "未绑定目标" in d3.reason,
          f"ffuf 指向其它端口/主机必须拒绝：{d3.reason[:140]}")
    # curl：无论目标在哪都拒（不可验证网络能力）
    d4 = g.check_tool("curl", {"args": [other + "/ok"]}, ctx=ctx)
    check(not d4.allowed and "Gateway" in d4.reason,
          f"curl 必须禁网（不因目标在范围内而放行）：{d4.reason[:140]}")


# ── 11/12. Header 与文件引用 ──────────────────────────────────────


def _spec_with_header_flags():
    from core.tools.external import ExternalTool

    return ExternalTool(
        key="probe-http", name="probe-http", bins=("x",), category="test",
        desc="", flags=("-H", "-d", "-w", "-u", "-mc"),
    )


def scenario_header_not_path(tmp: Path) -> None:
    section("11. Header application/json 不再被误判为文件路径")
    runner = ToolRunner(make_cfg(tmp / "s11"), root=tmp)
    spec = _spec_with_header_flags()
    argv, err = runner._validate_argv(
        spec, ["-H", "Content-Type: application/json", "http://127.0.0.1:9/api"],
    )
    check(err == "", f"普通 Header 应通过参数校验（实际：{err}）")
    check("Content-Type: application/json" in argv, "Header 值应原样保留在 argv 里")

    argv2, err2 = runner._validate_argv(
        spec, ["-H", "Accept: text/html,application/xhtml+xml", "http://127.0.0.1:9/a"],
    )
    check(err2 == "", f"含逗号/斜杠的合法 Header 也应通过（实际：{err2}）")

    # 没有头名的裸值 → 不是合法 Header（fail-closed）
    _, err3 = runner._validate_argv(spec, ["-H", "application/json", "http://127.0.0.1:9/a"])
    check(err3 != "", "缺少 'Name:' 的取值应被拒绝（不能当成 Header 放行）")


def scenario_header_file_ref(tmp: Path) -> None:
    section("12. -H @file / -d @file 仍受文件路径授权控制")
    root = tmp / "s12"
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "data" / "headers.txt").write_text("X-Test: 1\n", encoding="utf-8")
    runner = ToolRunner(make_cfg(root), root=root)
    spec = _spec_with_header_flags()

    argv, err = runner._validate_argv(
        spec, ["-H", "@data/headers.txt", "http://127.0.0.1:9/a"],
    )
    check(err == "" and "@data/headers.txt" in argv, f"项目内 @file 应通过（实际：{err}）")

    for bad in ("@/etc/passwd", "@../../secret.txt", "@/root/.ssh/id_rsa"):
        _, e = runner._validate_argv(spec, ["-H", bad, "http://127.0.0.1:9/a"])
        check(e != "", f"{bad} 必须被拒绝（路径穿越/绝对路径）")
    _, e2 = runner._validate_argv(spec, ["-d", "@/etc/passwd", "http://127.0.0.1:9/a"])
    check(e2 != "", "请求体 @file 绝对路径同样被拒绝")
    _, e3 = runner._validate_argv(spec, ["-d", "@data/missing.txt", "http://127.0.0.1:9/a"])
    check(e3 != "", "不存在的 @file 必须被拒绝")


# ── 13. 重定向 ────────────────────────────────────────────────────


def scenario_redirect_blocked(tmp: Path, net: MockNet) -> None:
    section("13. 重定向到未授权目标时拒绝（每一跳重新检查）")
    from detectors.http_detector import HttpDetector

    cfg = make_cfg(tmp / "s13", binding=net.a.binding)
    mark = net.snapshot()

    async def go():
        det = HttpDetector(cfg.scan)
        try:
            return await det.send_request(net.target + "/redirect-cross")
        finally:
            await det.aclose()

    ev = asyncio.run(go())
    hits = net.delta(mark)
    cross = [r for r in hits if r.server == "B"]
    check(bool(ev.error) and "策略拦截" in ev.error, f"跨主机重定向必须被拦：{ev.error!r}")
    check("重定向" in str(ev.error), "拒绝理由应说明是重定向目标出界")
    check(not cross, f"外部主机不得收到重定向后的请求（实际 {len(cross)} 条）")


# ── 14. 统一策略入口 ──────────────────────────────────────────────


def scenario_single_entry(tmp: Path, net: MockNet) -> None:
    section("14. Detector / Runner / 后台任务 / Scheduler 使用同一策略入口")
    from policy.request_guard import RequestGuard as RG

    cfg = make_cfg(tmp / "s14", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    calls: list[str] = []
    real_check_request = RG.check_request

    def spy(self, url, **kw):
        calls.append(url)
        return real_check_request(self, url, **kw)

    RG.check_request = spy
    try:
        # Runner 的 http_request
        asyncio.run(runner.execute("http_request", {"url": net.target + "/ok"}, s))
        runner_calls = len(calls)
        # Detector 的逐请求闸门
        from detectors.http_detector import HttpDetector

        async def det_go():
            det = HttpDetector(cfg.scan)
            try:
                return await det.send_request(net.target + "/ok")
            finally:
                await det.aclose()

        asyncio.run(det_go())
        det_calls = len(calls) - runner_calls
    finally:
        RG.check_request = real_check_request
    check(runner_calls >= 1, f"Runner 请求必须走 RequestGuard.check_request（{runner_calls}）")
    check(det_calls >= 1, f"Detector 请求必须走同一入口（{det_calls}）")

    # 探测器不再自己复制 decision 逻辑：源码里不应直接 import decide
    src = (PROJECT / "detectors" / "base.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported = {
        alias.name
        for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    check("decide" not in imported, "detectors/base.py 不再直接 import decide（统一走 guard）")

    # runner 不得直接调用 api_policy.decide（历史纪律）
    for name in ("base.py", "external.py", "recon.py", "verify.py"):
        text = (PROJECT / "core" / "tools" / "runner" / name).read_text(encoding="utf-8")
        tree = ast.parse(text)
        direct = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "decide"
        ]
        check(not direct, f"core/tools/runner/{name} 不得直接调用 decide()")

    # 后台任务入口：recon_ports_bg 也过同一闸门
    out = asyncio.run(runner.execute("recon_ports_bg", {"host": "192.0.2.9"}, s))
    check(out.startswith("【已拦截】"), f"后台任务跨主机必须被拒：{out[:140]}")
    check(len(runner._bg_handles) == 0, "被拒的后台任务不得创建 Task")

    # Scheduler / MCP：主动扫描入口统一走 enforcer（生产环境整体拒绝）
    from policy.enforcer import active_scan_check

    prod_cfg = make_cfg(tmp / "s14b", env="production", binding=net.a.binding)
    ok, msg = active_scan_check(prod_cfg, net.target)
    check(not ok and "生产" in msg, f"Scheduler/MCP 入口生产环境拒绝：{msg[:100]}")
    jobs_src = (PROJECT / "mcp_server" / "jobs.py").read_text(encoding="utf-8")
    check("active_scan_check" in jobs_src, "MCP 后台扫描走同一策略入口")

    # Authenticator（Planner / login 工具共用）的每个请求都过 precheck
    from core.auth import Authenticator

    called: list[str] = []

    def precheck(url, method, body=""):
        called.append(f"{method} {url}")
        return "precheck 拒绝（测试）"

    auth = Authenticator(cfg.scan, precheck=precheck)
    try:
        res = auth.login(net.target + "/", s.result.assets, "u", "p")
    finally:
        auth.close()
    check(not res.ok, "precheck 拒绝时登录必须失败")
    check(any("precheck 拒绝" in n for n in res.notes), f"拒绝原因应回给调用方：{res.notes}")
    check(bool(called), f"Authenticator 的请求必须过 precheck（实际 {called[:2]}）")


def scenario_handler_guard(tmp: Path, net: MockNet) -> None:
    section("14b. 直接调用 external handler 也拿不到 curl 网络能力")
    cfg = make_cfg(tmp / "s14c", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)
    mark = net.snapshot()
    out = asyncio.run(runner._h_external_tool(s, tool="curl", args=[net.target + "/ok"]))
    check(out.startswith("【已拦截】"), f"handler 层必须再拦一次：{out[:160]}")
    check(not net.delta(mark), "handler 层拦截后不得触网")


# ── 主流程 ────────────────────────────────────────────────────────


def main() -> int:
    net = MockNet()
    try:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            scenario_legal_login(tmp, net)
            scenario_rate_limit(tmp)
            scenario_unbound_target(tmp)
            scenario_unknown_env(tmp, net)
            scenario_production_env(tmp, net)
            scenario_post_login_still_gated(tmp, net)
            scenario_auth_admin_blocked(tmp)
            scenario_implicit_endpoint(tmp, net)
            scenario_no_secrets_in_audit(tmp, net)
            scenario_curl_post_gated(tmp, net)
            scenario_curl_l3(tmp, net)
            scenario_curl_unknown(tmp, net)
            scenario_external_scope(tmp, net)
            scenario_header_not_path(tmp)
            scenario_header_file_ref(tmp)
            scenario_redirect_blocked(tmp, net)
            scenario_single_entry(tmp, net)
            scenario_handler_guard(tmp, net)
    finally:
        net.close()

    print()
    if FAIL:
        print(f"失败 {len(FAIL)} 项：")
        for f in FAIL:
            print(f"  - {f}")
    print(f"结果：{PASS}/{PASS + len(FAIL)} 通过")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
