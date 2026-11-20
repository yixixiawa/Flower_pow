"""安全功能验收（第七轮整改）：**回归全绿不算安全通过**。

用法：
  .venv/Scripts/python.exe scripts/security_acceptance.py             # 全量验收
  .venv/Scripts/python.exe scripts/security_acceptance.py --only SEC-08
  .venv/Scripts/python.exe scripts/security_acceptance.py --update-baseline

与 ``scripts/run_tests.py`` 的分工：

* ``run_tests.py`` —— 断言回归。回答"代码改坏了没有"；
* 本脚本 —— 安全验收。回答"安全边界**到底测没测、测得多硬、有没有
  真的拦住**"。结论只有 :mod:`policy.acceptance` 的六级状态，
  缺测（NOT_TESTED）与证据不足（INCONCLUSIVE）**永远不会被算成通过**。

约定（对应验收规则第二、三节）：

1. 每项要求都有**负向用例**——只验证"该放行的放行了"的测试一律不算
   安全用例；
2. 全部网络行为跑在本机 **Mock Server** 上：每个用例都统计**真实命中
   次数**，"函数返回了拒绝"和"请求没发出去"必须同时成立才算通过；
3. 拒绝事件必须能在 ``policy/audit.jsonl`` 里查到（可追溯）；
4. 每个用例都要断言"经过哪个出口"，静态扫描兜底"有没有绕开 Gateway
   的调用路径"；
5. 不向任何外部目标发请求（Mock Server 只绑 127.0.0.1）。

报告固定 11 个字段，落 ``reports/security_acceptance/<时间戳>/``。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config_loader import Config  # noqa: E402
from core.session import Session  # noqa: E402
from core.tools.runner import ToolRunner  # noqa: E402
from detectors.http_detector import HttpDetector  # noqa: E402
from policy.acceptance import (  # noqa: E402
    AcceptanceReport,
    Case,
    Kind,
    Requirement,
    Severity,
    TestStatus,
    build_baseline,
    case_fingerprint,
    policy_hash,
    render_markdown,
    run_cases,
    summarize_lines,
    verify_baseline,
)
from policy.api_policy import (  # noqa: E402
    COMMAND_FOR_CATEGORY,
    ApiCategory,
    Decision,
    Environment,
    Environment as Env,
    decide,
)
from policy.request_guard import (  # noqa: E402
    PROBE_KIND_COMMAND,
    GuardContext,
    RequestGuard,
    classify_request,
    in_scope,
    validate_target_url,
)

BASELINE_PATH = ROOT / "policy" / "acceptance_baseline.json"

_L3_COMMANDS = ("批量删除", "SQL 注入验证", "命令执行", "定时任务执行")
_ALL_ENVS = (
    Environment.PRODUCTION, Environment.ISOLATED_TEST,
    Environment.DEDICATED_TEST, Environment.UNKNOWN,
)


# ── 本机 Mock Server ──────────────────────────────────────────────
class MockSite:
    """可控的本地目标：记录**每一次真实命中**（方法+路径）。

    验收的核心证据就是这里的计数：被拦请求必须让计数保持不变，
    放行请求必须让它 +1。任何"只检查返回值"的断言都不能替代它。
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.hits: list[tuple[str, str]] = []
        self.lock = threading.Lock()
        self.redirect_to = ""     # /redirect-out 的绝对跳转目标
        self.redirect_in = ""     # /redirect-in 的同主机跳转目标（路径）
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _do(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                if length:
                    self.rfile.read(length)
                with outer.lock:
                    outer.hits.append((self.command, self.path))
                if self.path.startswith("/redirect-out") and outer.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/redirect-in"):
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_in or "/api/list")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/loop"):
                    self.send_response(302)
                    self.send_header("Location", "/loop")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/fail"):
                    payload = b'{"error": "boom"}'
                    self.send_response(500)
                elif self.command == "POST":
                    payload = b'{"id": "obj-1", "ok": true}'
                    self.send_response(201)
                else:
                    payload = b'{"ok": true}'
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _do

            def log_message(self, *a: Any) -> None:  # noqa: ANN002
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def url(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def count(self, prefix: str = "") -> int:
        with self.lock:
            return sum(1 for _m, p in self.hits if p.startswith(prefix))

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ── 上下文：临时目录 / 站点 / 配置工厂 ────────────────────────────
class Ctx:
    def __init__(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="fp_accept_"))
        self._sites: list[MockSite] = []
        self._n = 0

    # 每个用例一份独立 data 目录，审计互不污染
    def tmp(self) -> Path:
        self._n += 1
        p = self.base / f"case{self._n:02d}"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def site(self, name: str) -> MockSite:
        s = MockSite(name)
        self._sites.append(s)
        return s

    def cfg(self, env: dict[str, str] | None = None, default: str = "unknown", td: Path | None = None):
        cfg = Config()
        base = td or self.tmp()
        cfg.data_dir = str(base / "data")
        cfg.scan.data_dir = cfg.data_dir
        cfg.scan.proxy = None
        cfg.scan.proxy_autodetect = False
        cfg.scan.follow_redirects = True
        cfg.policy.environments = env or {}
        cfg.policy.default_environment = default
        return cfg

    def runner(self, env: dict[str, str] | None = None, default: str = "unknown"):
        td = self.tmp()
        cfg = self.cfg(env, default, td)
        return cfg, ToolRunner(cfg, root=str(td))

    def scan_cfg(self, env: dict[str, str] | None = None, default: str = "unknown"):
        return self.cfg(env, default).scan

    def audit(self, cfg) -> list[dict[str, Any]]:
        p = Path(cfg.data_dir) / "policy" / "audit.jsonl"
        if not p.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def close(self) -> None:
        for s in self._sites:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


@contextmanager
def spy_gateway():
    """给 ``HttpGateway.request`` 装计数器——证明请求真的经过了网关。

    只在本进程内替换方法（验收用完立刻恢复），不改生产代码。
    """
    from core.gateway import HttpGateway

    calls: list[tuple[str, str]] = []
    orig = HttpGateway.request

    async def spy(self, method, url, **kw):  # noqa: ANN001, ANN003
        calls.append((method, url))
        return await orig(self, method, url, **kw)

    HttpGateway.request = spy  # type: ignore[method-assign]
    try:
        yield calls
    finally:
        HttpGateway.request = orig  # type: ignore[method-assign]


def _blocked(text: str) -> bool:
    return "【已拦截】" in (text or "")


def _bind(fn: Callable[[Case, "Ctx"], None], ctx: "Ctx") -> Callable[[Case], None]:
    """把 (case, ctx) 用例函数绑成 run_cases 需要的 (case)。"""

    def run(case: Case) -> None:
        fn(case, ctx)

    return run


# ── 用例实现 ──────────────────────────────────────────────────────
# 每个函数接收 (case, ctx)，自行填断言与观测字段。
# 断言必须写到"可判真假"的程度：expected 是规则，actual 是实测。


def c_l3_unit(c: Case, ctx: Ctx) -> None:
    rows = []
    for env in _ALL_ENVS:
        for cmd in _L3_COMMANDS:
            for approved in (False, True):
                d = decide(cmd, environment=env, identity_bound=True,
                           target_bound=True, approved=approved)
                rows.append((env, cmd, approved, d.decision))
    bad = [r for r in rows if r[3] != Decision.DENY]
    c.check("L3 全组合", f"{len(rows)} 种组合全部 DENY", f"非 DENY {len(bad)}：{bad[:3]}", not bad)
    # 环境绑定 + 审批都满足也不行
    c.check("L3 无审批出路", "审批不改变 L3 结论",
            decide("命令执行", environment=Env.ISOLATED_TEST, identity_bound=True,
                   target_bound=True, approved=True).decision,
            decide("命令执行", environment=Env.ISOLATED_TEST, identity_bound=True,
                   target_bound=True, approved=True).decision == Decision.DENY)


def c_l3_runner(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("l3-runner")
    s = Session(target=site.url())
    before = site.count()
    out = asyncio.run(runner.execute("sqli_probe", {"url": site.url("/api/list?id=1")}, s))
    sent = site.count() - before
    c.http_sent = sent > 0
    c.network_side_effect = sent > 0
    c.gateway = "policy.request_guard.check_builtin（未触网）"
    denies = [e for e in ctx.audit(cfg) if e.get("event") == "deny"]
    c.audit_ok = bool(denies)
    c.check("拒绝回执", "含【已拦截】", out[:60], _blocked(out))
    c.check("真实触网次数", "0", sent, sent == 0)
    c.check("拒绝审计", "至少 1 条 deny", len(denies), bool(denies))


def c_l3_detector(c: Case, ctx: Ctx) -> None:
    cfg = ctx.scan_cfg({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("l3-det")
    det = HttpDetector(cfg)
    det._current_kind = "sqli"
    ev = asyncio.run(det.send_request(site.url("/api/list?id=1"), method="GET"))
    sent = site.count()
    c.http_sent = sent > 0
    c.network_side_effect = sent > 0
    c.gateway = "core.gateway.HttpGateway（拦截后未发送）"
    denies = [e for e in ctx.audit(cfg) if e.get("event") == "deny"]
    c.audit_ok = bool(denies)
    c.check("拦截原因", "SQL 注入验证 L3", (ev.error or "")[:80],
            "SQL 注入验证" in (ev.error or ""))
    c.check("零触网", "0 命中", sent, sent == 0)
    c.check("审计留痕（探测器路径）", "deny 事件", len(denies), bool(denies))


def c_unknown_unit(c: Case, ctx: Ctx) -> None:
    cfg, _ = ctx.runner()
    guard = RequestGuard(cfg)
    d1 = decide("", environment=Environment.ISOLATED_TEST, identity_bound=True, target_bound=True)
    d2 = decide("矩阵里没有的命令", environment=Environment.UNKNOWN,
                identity_bound=True, target_bound=True)
    d3 = guard.check_tool("no-such-tool", {"target": "http://127.0.0.1:1/"})
    d4 = guard.check_builtin("no-such-builtin", "http://127.0.0.1:1/")
    c.check("空命令", "UNKNOWN", d1.decision, d1.decision == Decision.UNKNOWN)
    c.check("矩阵外命令", "UNKNOWN", d2.decision, d2.decision == Decision.UNKNOWN)
    c.check("未知外部工具", "UNKNOWN", d3.decision, d3.decision == Decision.UNKNOWN)
    c.check("未知内置工具", "UNKNOWN", d4.decision, d4.decision == Decision.UNKNOWN)


def c_unknown_runner(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner()
    site = ctx.site("unknown")
    s = Session(target=site.url())
    before = site.count()
    out = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/list"), "method": "TRACE",
    }, s))
    sent = site.count() - before
    c.http_sent = sent > 0
    c.network_side_effect = sent > 0
    c.gateway = "policy.request_guard.check_request（未触网）"
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(cfg))
    c.check("未识别方法", "拦截", out[:60], _blocked(out))
    c.check("零触网", "0", sent, sent == 0)
    c.check("拒绝审计", "deny", c.audit_ok, c.audit_ok is True)


def c_export_auth_unit(c: Case, ctx: Ctx) -> None:
    c.check("EXPORT 无矩阵授权", "", COMMAND_FOR_CATEGORY[ApiCategory.EXPORT],
            COMMAND_FOR_CATEGORY[ApiCategory.EXPORT] == "")
    c.check("AUTH 无矩阵授权", "", COMMAND_FOR_CATEGORY[ApiCategory.AUTH],
            COMMAND_FOR_CATEGORY[ApiCategory.AUTH] == "")
    exp = classify_request("http://h/api/export/users", method="GET")
    auth = classify_request("http://h/api/login", method="POST")
    c.check("EXPORT 分类保留", "EXPORT", exp.category, exp.category == ApiCategory.EXPORT)
    c.check("AUTH 分类保留", "AUTH", auth.category, auth.category == ApiCategory.AUTH)
    c.check("EXPORT 命令为空", "命令=''", repr(exp.command), exp.command == "")
    c.check("AUTH 命令为空", "命令=''", repr(auth.command), auth.command == "")


def _runner_block_case(c: Case, ctx: Ctx, name: str, args: dict, label: str) -> None:
    cfg, runner = ctx.runner()
    site = ctx.site(f"block-{label}")
    s = Session(target=site.url())
    args = {k: (v.format(url=site.url("/api/list")) if isinstance(v, str) else v)
            for k, v in args.items()}
    before = site.count()
    out = asyncio.run(runner.execute(name, args, s))
    sent = site.count() - before
    c.http_sent = sent > 0
    c.network_side_effect = sent > 0
    c.gateway = "policy.request_guard（未触网）"
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(cfg))
    c.check(f"{label} 拒绝", "【已拦截】", out[:60], _blocked(out))
    c.check(f"{label} 零触网", "0", sent, sent == 0)
    c.check(f"{label} 审计", "deny", c.audit_ok, c.audit_ok is True)


def c_export_runner(c: Case, ctx: Ctx) -> None:
    _runner_block_case(c, ctx, "http_request",
                       {"url": "{url}/api/export/users", "method": "GET"}, "GET /export")


def c_auth_runner(c: Case, ctx: Ctx) -> None:
    _runner_block_case(c, ctx, "http_request",
                       {"url": "{url}/api/login", "method": "POST", "body": '{"u":"a"}'},
                       "POST /login")


def c_auth_builtin(c: Case, ctx: Ctx) -> None:
    _runner_block_case(c, ctx, "login",
                       {"url": "{url}/api/login", "username": "a", "password": "b"}, "login 工具")


def c_fileread_unit(c: Case, ctx: Ctx) -> None:
    c.check("fileread 不在探针映射", "无该键", sorted(PROBE_KIND_COMMAND),
            "fileread" not in PROBE_KIND_COMMAND)
    cfg, _ = ctx.runner()
    guard = RequestGuard(cfg)
    d = guard.check_probe("http://127.0.0.1:1/api/list", "fileread",
                          ctx=GuardContext(bound_target="http://127.0.0.1:1",
                                           identity_bound=True))
    c.check("fileread 探针决策", "UNKNOWN", d.decision, d.decision == Decision.UNKNOWN)


def c_fileread_runner(c: Case, ctx: Ctx) -> None:
    _runner_block_case(c, ctx, "exploit_probe",
                       {"url": "{url}/api/list", "kinds": "fileread"}, "exploit_probe fileread")


def c_egress_static(c: Case, ctx: Ctx) -> None:
    allow = {"core/gateway.py"}
    offenders: list[str] = []
    skip = (".venv/", "scripts/", "data/", "output/", ".backup/", "reports/", "doc/")
    for py in ROOT.rglob("*.py"):
        rel = py.relative_to(ROOT).as_posix()
        if rel.startswith(skip):
            continue
        text = py.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"httpx\.(?:Async)?Client\(", text):
            if rel in allow:
                continue
            line = text[: m.start()].count("\n") + 1
            offenders.append(f"{rel}:{line}")
    c.check("唯一客户端构造点", "仅 core/gateway.py", offenders or "无越界", not offenders)
    gw = (ROOT / "core" / "gateway.py").read_text(encoding="utf-8")
    c.check("Gateway 固定不自动跟跳", "follow_redirects=False",
            "follow_redirects=False" in gw, "follow_redirects=False" in gw)


def c_gateway_runner(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner()
    site = ctx.site("gw-runner")
    s = Session(target=site.url())
    with spy_gateway() as calls:
        out = asyncio.run(runner.execute("http_request", {"url": site.url("/api/list")}, s))
    c.http_sent = site.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway"
    c.check("放行执行", "无【已拦截】", out[:40], not _blocked(out))
    c.check("真实到达", "1 次命中", site.count(), site.count() == 1)
    c.check("经过 Gateway", "1 次调用", len(calls), len(calls) == 1)


def c_gateway_blocked(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner()
    site = ctx.site("gw-block")
    s = Session(target=site.url())
    with spy_gateway() as calls:
        out = asyncio.run(runner.execute("sqli_probe", {"url": site.url("/api/list?id=1")}, s))
    c.http_sent = site.count() > 0
    c.network_side_effect = site.count() > 0
    c.gateway = "policy.request_guard.check_builtin（路径级拒绝，零触网）"
    c.check("拦截", "【已拦截】", out[:40], _blocked(out))
    c.check("零触网", "0", site.count(), site.count() == 0)
    c.check("不存在绕过网关的发送", "命中 0", site.count(), site.count() == 0)


def c_tools_gated(c: Case, ctx: Ctx) -> None:
    from policy.request_guard import BUILTIN_POLICY_TOOLS, _BUILTIN_TOOL_COMMAND

    expected = {
        "http_request", "external_tool", "exploit_probe", "sqli_probe", "login",
        "authz_probe", "recon_fingerprint", "recon_ports", "recon_ports_bg",
        "recon_paths", "recon_js", "js_audit", "recon_openapi", "recon_subdomains",
    }
    actual = set(ToolRunner._POLICY_TOOLS)
    c.check("面向目标的工具全部入闸", "⊇ 14 个", sorted(actual - expected) or "完整",
            expected <= actual)
    c.check("内置工具映射被闸门覆盖", "映射键 ⊆ 闸门集合",
            sorted(set(_BUILTIN_TOOL_COMMAND) - actual), set(_BUILTIN_TOOL_COMMAND) <= actual)
    c.check("内置工具集合一致", "guard 表 = runner 表",
            sorted(set(BUILTIN_POLICY_TOOLS) ^ set(ToolRunner._BUILTIN_POLICY_TOOLS)),
            set(BUILTIN_POLICY_TOOLS) == set(ToolRunner._BUILTIN_POLICY_TOOLS))


def c_entries_gated(c: Case, ctx: Ctx) -> None:
    entries = {
        "cli/scan.py": "active_scan_check",
        "mcp_server/jobs.py": "active_scan_check",
        "core/repl/auto.py": "active_scan_check",
        "core/tools/runner/verify.py": "active_scan_check",
        "core/subdomain.py": "active_scan_check",
    }
    missing = []
    for rel, kw in entries.items():
        text = (ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        if kw not in text:
            missing.append(rel)
    c.check("五个入口都过主动扫描检查", "无缺失", missing or "全部命中", not missing)
    # 任务/后台路径：MCP 的后台任务线程必须用 enforcer 定过性的配置
    jobs = (ROOT / "mcp_server" / "jobs.py").read_text(encoding="utf-8")
    c.check("MCP 后台任务用降级后配置", "scoped_scan_config",
            "scoped_scan_config" in jobs, "scoped_scan_config" in jobs)


def c_bypass_behavior(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("bypass")
    s = Session(target=site.url())
    attempts = [
        ("sqli_probe", {"url": site.url("/api/list?id=1")}),
        ("login", {"url": site.url("/api/login"), "username": "a", "password": "b"}),
        ("exploit_probe", {"url": site.url("/api/list"), "kinds": "rce"}),
        ("external_tool", {"tool": "sqlmap", "target": site.url("/api/list")}),
    ]
    results = []
    for name, args in attempts:
        out = asyncio.run(runner.execute(name, args, s))
        results.append((name, _blocked(out)))
    c.http_sent = site.count() > 0
    c.network_side_effect = site.count() > 0
    c.gateway = "policy.request_guard + policy.enforcer"
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(cfg))
    c.check("四条高危路径全部拦截", "全部【已拦截】", results, all(ok for _, ok in results))
    c.check("零触网", "0", site.count(), site.count() == 0)


def c_enforcer(c: Case, ctx: Ctx) -> None:
    from policy.enforcer import active_scan_check, scoped_scan_config

    cfg = ctx.cfg({"prod.example.com": Environment.PRODUCTION,
                   "10.0.0.5": Environment.ISOLATED_TEST})
    ok_prod, msg = active_scan_check(cfg, "http://prod.example.com/")
    ok_test, _ = active_scan_check(cfg, "http://10.0.0.5/")
    ok_unknown, note = active_scan_check(cfg, "http://192.0.2.9/")
    c.check("生产环境拒绝主动扫描", "False", ok_prod, ok_prod is False)
    c.check("测试环境放行（但 L3 关）", "True", ok_test, ok_test is True)
    c.check("unknown 降级提示", "只读侦察", note[:30], "只读" in note)
    scoped, _ = scoped_scan_config(cfg, "http://10.0.0.5/")
    c.check("测试环境 L3 探针强制关闭", "sqli/rce False",
            (scoped.scan.sqli_probe_enabled, scoped.scan.rce_probe_enabled),
            not scoped.scan.sqli_probe_enabled and not scoped.scan.rce_probe_enabled)
    c.check("原配置未被就地修改", "sqli 仍为原值",
            cfg.scan.sqli_probe_enabled, cfg.scan.sqli_probe_enabled is not False)


def c_scope_unit(c: Case, ctx: Ctx) -> None:
    checks = [
        (in_scope("http://h:8080/a", "http://h:8080"), True, "同源"),
        (in_scope("http://h:9999/a", "http://h:8080"), False, "端口不同"),
        (in_scope("https://h/a", "http://h"), False, "scheme 不同"),
        (in_scope("http://h/app/x", "http://h/app"), True, "路径前缀内"),
        (in_scope("http://h/other", "http://h/app"), False, "路径前缀外"),
        (in_scope("http://h/app/%2e%2e/other", "http://h/app"), False, "编码点段"),
        (in_scope("http://h/app//x", "http://h/app"), True, "双斜杠归一"),
        (in_scope("not-a-url", "http://h"), False, "解析失败 fail-closed"),
    ]
    bad = [(why, got, want) for got, want, why in checks if got != want]
    c.check("范围判定矩阵", "8 组全符合", bad or "全符合", not bad)
    try:
        validate_target_url("ftp://h/x")
        c.check("非 http/https 拒绝", "ValueError", "未抛", False)
    except ValueError:
        c.check("非 http/https 拒绝", "ValueError", "ValueError", True)


def c_scope_runner(c: Case, ctx: Ctx) -> None:
    a = ctx.site("scope-a")
    b = ctx.site("scope-b")
    cfg, runner = ctx.runner()
    s = Session(target=a.url())
    before_a, before_b = a.count(), b.count()
    out = asyncio.run(runner.execute("http_request", {"url": b.url("/api/list")}, s))
    c.http_sent = (b.count() - before_b) > 0
    c.network_side_effect = c.http_sent
    c.gateway = "policy.request_guard.in_scope（未触网）"
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(cfg))
    c.check("跨主机拒绝", "【已拦截】", out[:40], _blocked(out))
    c.check("目标站零命中", "0", b.count() - before_b, b.count() == before_b)
    c.check("授权站也未被打", "0", a.count() - before_a, a.count() == before_a)


def c_scope_detector(c: Case, ctx: Ctx) -> None:
    a = ctx.site("scope-det-a")
    b = ctx.site("scope-det-b")
    det = HttpDetector(ctx.scan_cfg())
    ev1 = asyncio.run(det.send_request(a.url("/api/list")))
    ev2 = asyncio.run(det.send_request(b.url("/api/other")))
    c.http_sent = b.count() > 0
    c.network_side_effect = b.count() > 0
    c.gateway = "core.gateway.HttpGateway（第 1 跳即拒绝）"
    c.audit_ok = bool(ev2.error)
    c.check("首跳放行", "无 error", (ev1.error or "无"), not ev1.error)
    c.check("跨主机出界", "拦截", (ev2.error or "")[:60], "超出" in (ev2.error or ""))
    c.check("B 站零命中", "0", b.count(), b.count() == 0)
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(det.cfg))


def c_redirect_out(c: Case, ctx: Ctx) -> None:
    a = ctx.site("redir-a")
    b = ctx.site("redir-b")
    a.redirect_to = b.url("/evil")
    cfg = ctx.scan_cfg()
    det = HttpDetector(cfg)
    ev = asyncio.run(det.send_request(a.url("/redirect-out")))
    denies = [e for e in ctx.audit(cfg) if e.get("event") == "deny"]
    hops = [d.get("extra", {}).get("hop") for d in denies]
    c.http_sent = b.count() > 0
    c.network_side_effect = b.count() > 0
    c.gateway = "core.gateway.HttpGateway（第 2 跳拒绝）"
    c.audit_ok = bool(denies)
    c.check("第二跳被拒", "error 含『第 2 跳』", (ev.error or "")[:80],
            "第 2 跳" in (ev.error or ""))
    c.check("越界主机零命中", "0", b.count(), b.count() == 0)
    c.check("首跳确已发出", "1", a.count("/redirect-out"), a.count("/redirect-out") == 1)
    c.check("审计记录跳数", "hop=2", hops[:3], 2 in hops)


def c_redirect_in(c: Case, ctx: Ctx) -> None:
    a = ctx.site("redir-in")
    a.redirect_in = "/api/list"
    det = HttpDetector(ctx.scan_cfg())
    ev = asyncio.run(det.send_request(a.url("/redirect-in")))
    c.http_sent = a.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway（同主机跟随）"
    c.check("正常重定向仍可用", "200", (ev.status_code, ev.error),
            ev.status_code == 200 and not ev.error)
    c.check("两跳都发出", "2 次命中", a.count(), a.count() == 2)


def c_redirect_loop(c: Case, ctx: Ctx) -> None:
    a = ctx.site("redir-loop")
    det = HttpDetector(ctx.scan_cfg())
    ev = asyncio.run(det.send_request(a.url("/loop")))
    c.http_sent = a.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway（跳数上限 fail-closed）"
    c.check("跳数上限拦截", "error 含『跳』", (ev.error or "")[:80], "跳" in (ev.error or ""))
    c.check("不无限跟随", "≤ 6 次", a.count(), a.count() <= 6)


def c_identity_unit(c: Case, ctx: Ctx) -> None:
    _, runner = ctx.runner()
    s1 = Session(target="http://t1.local", session_id="sess-A")
    s2 = Session(target="http://t1.local", session_id="sess-B")
    s3 = Session(target="http://t2.local", session_id="sess-A")
    runner._identity = "cred:session:aaaa"
    i1 = runner._current_identity(s1, url="http://t1.local/")
    i2 = runner._current_identity(s2, url="http://t1.local/")
    i3 = runner._current_identity(s3, url="http://t2.local/")
    runner._identity = "cred:session:bbbb"
    i4 = runner._current_identity(s1, url="http://t1.local/")
    runner._identity = ""
    i5 = runner._current_identity(s1, url="http://t1.local/")
    c.check("同凭证不同会话 → 身份不同", "不同", (i1, i2), i1 != i2)
    c.check("同凭证不同目标 → 身份不同", "不同", (i1, i3), i1 != i3)
    c.check("不同凭证 → 身份不同", "不同", (i1, i4), i1 != i4)
    c.check("无凭证 → 显式匿名", "anonymous@", i5, i5.startswith("anonymous@t1.local"))
    c.check("身份带 session/target 维度", "含 sess= 与 tgt=", i1, "sess=sess-A" in i1 and "tgt=" in i1)


def c_identity_audit(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("ident")
    s = Session(target=site.url(), session_id="sess-ident")
    out = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items"), "method": "POST", "body": '{"a":1}',
    }, s))
    allow = [e for e in ctx.audit(cfg) if e.get("event") == "allow"]
    c.http_sent = site.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway"
    c.audit_ok = bool(allow)
    c.check("创建放行", "无【已拦截】", out[:40], not _blocked(out))
    c.check("审计带 target/run", "非空",
            [(e.get("target_id"), e.get("run_id")) for e in allow][:1],
            bool(allow) and all(e.get("target_id") and e.get("run_id") for e in allow))


def c_concurrency(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("conc")
    s_a = Session(target=site.url(), session_id="sess-A")
    s_b = Session(target=site.url(), session_id="sess-B")

    async def _two():
        return await asyncio.gather(
            runner.execute("http_request", {
                "url": site.url("/api/alpha"), "method": "POST", "body": '{"x":1}',
            }, s_a),
            runner.execute("http_request", {
                "url": site.url("/api/beta"), "method": "POST", "body": '{"x":2}',
            }, s_b),
        )

    outs = asyncio.run(_two())
    objs = runner.test_ledger.objects_of()
    ids = {o.identity for o in objs}
    c.http_sent = site.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway"
    c.check("两次并发都执行", "均无拦截", [o[:20] for o in outs],
            all(not _blocked(o) for o in outs))
    c.check("两条台账各自独立身份", "2 个不同身份", len(ids), len(ids) == 2)
    c.check("身份绑定各自会话", "sess-A / sess-B",
            sorted(ids), any("sess-A" in i for i in ids) and any("sess-B" in i for i in ids))


def c_ledger_unit(c: Case, ctx: Ctx) -> None:
    from policy.test_transaction import TestLedger

    led = TestLedger()
    c.check("空台账未知", "False",
            led.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"),
            not led.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"))
    led.record("http://h/api/users", "create", run_id="r", target_id="t",
               identity="i", object_id="9")
    c.check("创建后可删", "True",
            led.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"),
            led.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"))
    c.check("换身份不可删", "False",
            led.known("http://h/api/users/9", run_id="r", target_id="t", identity="x"),
            not led.known("http://h/api/users/9", run_id="r", target_id="t", identity="x"))
    c.check("换目标不可删", "False",
            led.known("http://h/api/users/9", run_id="r", target_id="t2", identity="i"),
            not led.known("http://h/api/users/9", run_id="r", target_id="t2", identity="i"))
    c.check("缺维度不可删", "False",
            led.known("http://h/api/users/9", run_id="r", target_id="t", identity=""),
            not led.known("http://h/api/users/9", run_id="r", target_id="t", identity=""))
    led2 = TestLedger()
    led2.record("http://h/api/users/9", "update", run_id="r", target_id="t",
                identity="i", object_id="9")
    c.check("仅修改过的对象不可删", "False",
            led2.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"),
            not led2.known("http://h/api/users/9", run_id="r", target_id="t", identity="i"))
    c.check("集合端点删除不放行", "False",
            led.known("http://h/api/users", run_id="r", target_id="t", identity="i"),
            not led.known("http://h/api/users", run_id="r", target_id="t", identity="i"))


def c_delete_unknown(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("del-unknown")
    s = Session(target=site.url())
    before = site.count()
    out = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items/999"), "method": "DELETE",
    }, s))
    sent = site.count() - before
    c.http_sent = sent > 0
    c.network_side_effect = sent > 0
    c.gateway = "policy.test_transaction.TestLedger（未触网）"
    c.audit_ok = any(e.get("event") == "deny" for e in ctx.audit(cfg))
    c.check("未知对象删除被拒", "【已拦截】", out[:60], _blocked(out))
    c.check("零触网", "0", sent, sent == 0)
    c.check("拒绝审计", "deny", c.audit_ok, c.audit_ok is True)


def c_delete_known(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("del-known")
    s = Session(target=site.url(), session_id="sess-del")

    async def _approve(_desc: str) -> str:
        return "ops-acceptance"

    runner.approver = _approve
    create = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items"), "method": "POST", "body": '{"name":"x"}',
    }, s))
    delete = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items/obj-1"), "method": "DELETE",
    }, s))
    c.http_sent = site.count() > 0
    c.network_side_effect = False
    c.gateway = "core.gateway.HttpGateway"
    c.audit_ok = any(e.get("event") == "approval" for e in ctx.audit(cfg))
    c.check("创建成功", "无拦截", create[:30], not _blocked(create))
    c.check("本次创建的对象可删（带审批）", "无拦截", delete[:60], not _blocked(delete))
    c.check("两次真实请求", "2", site.count(), site.count() == 2)


def c_approval_binding(c: Case, ctx: Ctx) -> None:
    from policy.test_transaction import ApprovalLedger, request_fingerprint

    fp1 = request_fingerprint(method="DELETE", url="http://h/api/u/1", body="a=1")
    fp2 = request_fingerprint(method="DELETE", url="http://h/api/u/1", body="a=2")
    c.check("请求指纹随内容变化", "不同", (fp1, fp2), fp1 != fp2)
    led = ApprovalLedger(ttl=300)
    ticket = led.issue(url="http://h/api/u/1", command="删除测试数据",
                       target_id="t", run_id="r", identity="i",
                       method="DELETE", request_digest=fp1, level="L2",
                       approver="ops-acceptance")
    c.check("票面绑定审批人", "ops-acceptance", ticket.approver,
            ticket.approver == "ops-acceptance")
    wrong = led.consume(ticket.token, url="http://h/api/u/1", command="删除测试数据",
                        target_id="t", run_id="r", identity="i",
                        method="DELETE", request_digest=fp2)
    c.check("内容变化 → 票据失效", "False", wrong, wrong is False)
    ok1 = led.consume(ticket.token, url="http://h/api/u/1", command="删除测试数据",
                      target_id="t", run_id="r", identity="i",
                      method="DELETE", request_digest=fp1)
    ok2 = led.consume(ticket.token, url="http://h/api/u/1", command="删除测试数据",
                      target_id="t", run_id="r", identity="i",
                      method="DELETE", request_digest=fp1)
    c.check("首次消费成功", "True", ok1, ok1 is True)
    c.check("票据单次有效", "第二次 False", ok2, ok2 is False)
    exp = led.issue(url="http://h/api/u/1", command="删除测试数据", target_id="t",
                    run_id="r", identity="i", method="DELETE", ttl=-1)
    c.check("过期票据不可用", "False",
            led.consume(exp.token, url="http://h/api/u/1", command="删除测试数据",
                        target_id="t", run_id="r", identity="i", method="DELETE"),
            not led.consume(exp.token, url="http://h/api/u/1", command="删除测试数据",
                            target_id="t", run_id="r", identity="i", method="DELETE"))


def c_approval_l3(c: Case, ctx: Ctx) -> None:
    from policy.test_transaction import ApprovalLedger

    led = ApprovalLedger()
    raised = ""
    try:
        led.issue(url="http://h/api/list", command="SQL 注入验证",
                  target_id="t", run_id="r", identity="i")
    except ValueError as exc:
        raised = str(exc)
    c.check("L3 票据拒绝签发", "ValueError", raised[:60], bool(raised))
    c.check("错误信息说明审批无出路", "不得签发", raised[:80], "不得签发" in raised)


def c_approval_per_request(c: Case, ctx: Ctx) -> None:
    cfg, runner = ctx.runner({"127.0.0.*": Environment.ISOLATED_TEST})
    site = ctx.site("approval")
    s = Session(target=site.url(), session_id="sess-apr")
    state = {"n": 0}

    async def _once(_desc: str) -> bool | str:
        state["n"] += 1
        return "ops-acceptance" if state["n"] == 1 else False

    runner.approver = _once
    asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items"), "method": "POST", "body": '{"n":1}',
    }, s))
    first = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items/obj-1"), "method": "DELETE",
    }, s))
    second = asyncio.run(runner.execute("http_request", {
        "url": site.url("/api/items/obj-1"), "method": "DELETE",
    }, s))
    apr = [e for e in ctx.audit(cfg) if e.get("event") == "approval"]
    c.http_sent = site.count() > 0
    c.network_side_effect = site.count() > 1
    c.gateway = "core.gateway.HttpGateway"
    c.audit_ok = bool(apr)
    c.check("首次审批放行", "无拦截", first[:40], not _blocked(first))
    c.check("第二次未审批 → 拒绝", "【已拦截】", second[:40], _blocked(second))
    c.check("只发出一次删除", "命中 2（创建+删除）", site.count(), site.count() == 2)
    if apr:
        extra = apr[-1].get("extra", {}) or {}
        c.check("审批人真实身份入审计", "ops-acceptance", extra.get("approver"),
                extra.get("approver") == "ops-acceptance")
        c.check("认证审批人标记", "True", extra.get("authenticated_approver"),
                extra.get("authenticated_approver") is True)


# ── 需求登记 ──────────────────────────────────────────────────────
def build_requirements(ctx: Ctx) -> list[Requirement]:
    reqs: list[Requirement] = []
    pending: list[tuple[Requirement, Case, Callable[[Case, Ctx], None]]] = []

    def add(req: Requirement, name: str, kind: str, sources: list[str], expected: str,
            fn: Callable[[Case, Ctx], None], *, severity: str = Severity.P1,
            probe_http: bool = False, negative: bool = False, residual: str = "") -> None:
        c = Case(req.req_id, name, kind, list(sources), expected, severity,
                 probe_http=probe_http, negative_covered=negative)
        c.residual = residual
        req.cases.append(c)
        pending.append((req, c, _bind(fn, ctx)))

    # SEC-01 L3 任何环境均拒绝
    r = Requirement("SEC-01", "L3 命令在任何环境下均拒绝",
                    ["policy/api_policy.py", "policy/request_guard.py", "policy/enforcer.py"])
    add(r, "L3 决策：4 环境 × 4 命令 × 审批开关", Kind.UNIT,
        ["policy/api_policy.py"], "全部 DENY", c_l3_unit, severity=Severity.P0)
    add(r, "Runner sqli_probe 在隔离测试环境仍被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py", "policy/enforcer.py"],
        "拦截 + 0 命中 + deny 审计", c_l3_runner, severity=Severity.P0,
        probe_http=True, negative=True)
    add(r, "探测器 sqli 类别请求被拒且零触网", Kind.SECURITY,
        ["detectors/base.py", "core/gateway.py", "policy/request_guard.py"],
        "拦截 + 0 命中 + deny 审计", c_l3_detector, severity=Severity.P0,
        probe_http=True, negative=True)
    reqs.append(r)

    # SEC-02 UNKNOWN 默认拒绝
    r = Requirement("SEC-02", "UNKNOWN 命令默认拒绝",
                    ["policy/api_policy.py", "policy/request_guard.py"])
    add(r, "空命令 / 矩阵外命令 / 未知工具 → UNKNOWN", Kind.UNIT,
        ["policy/api_policy.py", "policy/request_guard.py"], "四项均 UNKNOWN", c_unknown_unit,
        severity=Severity.P0)
    add(r, "未识别 HTTP 方法经 Runner 被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py"],
        "拦截 + 0 命中", c_unknown_runner, severity=Severity.P0,
        probe_http=True, negative=True)
    reqs.append(r)

    # SEC-03 EXPORT / AUTH 无明确授权拒绝
    r = Requirement("SEC-03", "EXPORT 与 AUTH 没有明确授权时拒绝",
                    ["policy/api_policy.py", "policy/request_guard.py"])
    add(r, "EXPORT/AUTH 分类保留但命令为空 → UNKNOWN", Kind.UNIT,
        ["policy/api_policy.py", "policy/request_guard.py"], "命令为空串", c_export_auth_unit,
        severity=Severity.P0)
    add(r, "GET /export 经 Runner 被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/api_policy.py"], "拦截 + 0 命中",
        c_export_runner, severity=Severity.P0, probe_http=True, negative=True)
    add(r, "POST /login 经 Runner 被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/api_policy.py"], "拦截 + 0 命中",
        c_auth_runner, severity=Severity.P0, probe_http=True, negative=True)
    add(r, "内置 login 工具被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py"], "拦截 + 0 命中",
        c_auth_builtin, severity=Severity.P0, probe_http=True, negative=True)
    reqs.append(r)

    # SEC-04 fileread 不得映射 L0
    r = Requirement("SEC-04", "fileread 不得映射为 L0 查询详情",
                    ["policy/request_guard.py", "policy/api_policy.py"])
    add(r, "fileread 不在探针映射且判 UNKNOWN", Kind.UNIT,
        ["policy/request_guard.py"], "无映射 + UNKNOWN", c_fileread_unit,
        severity=Severity.P0)
    add(r, "exploit_probe kinds=fileread 被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py"], "拦截 + 0 命中",
        c_fileread_runner, severity=Severity.P0, probe_http=True, negative=True)
    reqs.append(r)

    # SEC-05 统一 Gateway
    r = Requirement("SEC-05", "所有 HTTP 网络请求必须经过统一 Gateway",
                    ["core/gateway.py", "detectors/base.py", "collectors", "core/auth.py", "kb/intel.py"])
    add(r, "静态扫描：httpx 客户端只能在 core/gateway.py 构造", Kind.UNIT,
        ["core/gateway.py"], "无越界构造点", c_egress_static, severity=Severity.P0)
    add(r, "Runner 放行请求经 Gateway 且真实到达", Kind.INTEGRATION,
        ["core/tools/runner/recon.py", "detectors/base.py", "core/gateway.py"],
        "Gateway 调用 1 次 + 目标命中 1 次", c_gateway_runner, severity=Severity.P0)
    add(r, "被拒请求不得存在绕过 Gateway 的发送路径", Kind.SECURITY,
        ["core/gateway.py", "detectors/base.py"], "拦截 + 0 命中",
        c_gateway_blocked, severity=Severity.P0, probe_http=True, negative=True)
    reqs.append(r)

    # SEC-06 各入口无策略旁路
    r = Requirement("SEC-06", "Runner/Detector/Collector/Scheduler/CLI/MCP/后台任务无策略旁路",
                    ["core/tools/runner/base.py", "policy/enforcer.py", "cli/scan.py",
                     "mcp_server/jobs.py", "core/repl/auto.py", "core/subdomain.py"])
    add(r, "面向目标的工具全部在闸门集合内", Kind.UNIT,
        ["core/tools/runner/base.py", "policy/request_guard.py"], "14 个工具全入闸",
        c_tools_gated, severity=Severity.P0)
    add(r, "五个入口统一走 active_scan_check", Kind.UNIT,
        ["cli/scan.py", "mcp_server/jobs.py", "core/repl/auto.py",
         "core/tools/runner/verify.py", "core/subdomain.py"], "无缺失",
        c_entries_gated, severity=Severity.P0)
    add(r, "四条高危路径经 Runner 全部拦截且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py"], "全部拦截 + 0 命中",
        c_bypass_behavior, severity=Severity.P0, probe_http=True, negative=True)
    add(r, "主动扫描入口按环境定性（含 L3 强制关闭）", Kind.INTEGRATION,
        ["policy/enforcer.py"], "生产拒绝 / 测试环境 L3 关", c_enforcer,
        severity=Severity.P0)
    reqs.append(r)

    # SEC-07 目标范围
    r = Requirement("SEC-07", "目标范围外请求必须拒绝",
                    ["policy/request_guard.py", "core/tools/runner/base.py"])
    add(r, "in_scope 范围矩阵与 URL 合法性", Kind.UNIT,
        ["policy/request_guard.py"], "8 组判定全符合", c_scope_unit, severity=Severity.P0)
    add(r, "Runner 跨主机请求被拒且两个站都零命中", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/request_guard.py"], "拦截 + B 站 0 命中",
        c_scope_runner, severity=Severity.P0, probe_http=True, negative=True)
    add(r, "Detector 跨主机请求被拒且 0 命中", Kind.SECURITY,
        ["detectors/base.py", "core/gateway.py"], "拦截 + 0 命中",
        c_scope_detector, severity=Severity.P0, probe_http=True, negative=True)
    reqs.append(r)

    # SEC-08 重定向逐跳复检
    r = Requirement("SEC-08", "重定向后的每一跳必须重新检查目标范围",
                    ["core/gateway.py", "detectors/base.py"])
    add(r, "跨主机 302：第 2 跳被拒，越界主机 0 命中", Kind.SECURITY,
        ["core/gateway.py", "detectors/base.py"], "拦截第 2 跳 + hop=2 审计",
        c_redirect_out, severity=Severity.P0, probe_http=True, negative=True,
        residual="仅覆盖 http/https 跳转；JS/meta refresh 跳转不在 HTTP 层，未纳入")
    add(r, "同主机 302 正常跟随（不误杀）", Kind.SECURITY,
        ["core/gateway.py"], "200 + 两跳",
        c_redirect_in, severity=Severity.P0, probe_http=True)
    add(r, "重定向环按跳数上限 fail-closed", Kind.SECURITY,
        ["core/gateway.py"], "有界拦截",
        c_redirect_loop, severity=Severity.P1, probe_http=True, negative=True)
    reqs.append(r)

    # SEC-09 身份绑定
    r = Requirement("SEC-09", "身份必须绑定 session、target 和 credential context",
                    ["core/tools/runner/base.py"])
    add(r, "三元组身份：会话/目标/凭证任一变化即不同", Kind.UNIT,
        ["core/tools/runner/base.py"], "四组对比全不同 + 匿名显式",
        c_identity_unit, severity=Severity.P1)
    add(r, "审计记录带 target_id / run_id", Kind.INTEGRATION,
        ["core/tools/runner/base.py", "policy/audit_logger.py"], "非空",
        c_identity_audit, severity=Severity.P1)
    reqs.append(r)

    # SEC-10 并发隔离
    r = Requirement("SEC-10", "不得因并发任务导致身份或审批状态污染",
                    ["core/tools/runner/base.py", "policy/test_transaction.py"])
    add(r, "两会话并发创建：台账身份互不串线", Kind.INTEGRATION,
        ["core/tools/runner/base.py"], "2 个独立身份",
        c_concurrency, severity=Severity.P1)
    reqs.append(r)

    # SEC-11 删除对象校验
    r = Requirement("SEC-11", "删除操作必须验证本次创建或上传的具体对象 ID",
                    ["policy/test_transaction.py", "core/tools/runner/base.py"])
    add(r, "台账四元组与对象 ID 判定", Kind.UNIT,
        ["policy/test_transaction.py"], "未知/换身份/换目标/仅修改 全部不可删",
        c_ledger_unit, severity=Severity.P0)
    add(r, "删除未登记对象被拒且零触网", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/test_transaction.py"], "拦截 + 0 命中",
        c_delete_unknown, severity=Severity.P0, probe_http=True, negative=True)
    add(r, "本次创建的对象 + 审批 → 可删且真实发出", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/test_transaction.py"], "无拦截 + 2 命中",
        c_delete_known, severity=Severity.P0, probe_http=True)
    reqs.append(r)

    # SEC-12 审批绑定
    r = Requirement("SEC-12", "审批必须绑定具体请求，并验证真实审批主体",
                    ["policy/test_transaction.py", "core/tools/runner/base.py"])
    add(r, "请求指纹 + 票据单次有效 + 内容变化失效", Kind.UNIT,
        ["policy/test_transaction.py"], "四项均符合", c_approval_binding,
        severity=Severity.P0)
    add(r, "L3 命令不得签发审批票据", Kind.SECURITY,
        ["policy/test_transaction.py"], "ValueError",
        c_approval_l3, severity=Severity.P0, negative=True)
    add(r, "逐请求审批：第二次未批即拒 + 真实审批人入审计", Kind.SECURITY,
        ["core/tools/runner/base.py", "policy/test_transaction.py"],
        "首次放行 / 第二次拦截 / approver=ops-acceptance",
        c_approval_per_request, severity=Severity.P0, probe_http=True, negative=True)
    reqs.append(r)

    run_cases(pending)
    return reqs


# ── 入口 ──────────────────────────────────────────────────────────
def _git(args: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=str(ROOT), capture_output=True, text=True,
            timeout=10, encoding="utf-8", errors="replace",
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="flower_pow 安全功能验收")
    ap.add_argument("--only", default="", help="只跑指定需求（如 SEC-08）")
    ap.add_argument("--update-baseline", action="store_true",
                    help="用本次结果重建反作弊基线（改测试必须显式执行并留痕）")
    ap.add_argument("--out", default="", help="报告输出目录")
    ap.add_argument("--json-only", action="store_true", help="只打印 JSON")
    args = ap.parse_args(argv)

    ctx = Ctx()
    t0 = time.time()
    try:
        reqs = build_requirements(ctx)
    finally:
        ctx.close()

    if args.only:
        keep = {s.strip().upper() for s in args.only.split(",") if s.strip()}
        reqs = [r for r in reqs if r.req_id.upper() in keep]
    report = AcceptanceReport(requirements=reqs)
    report.policy_hash = policy_hash(ROOT)
    report.stamp_environment(
        cwd=str(ROOT),
        git_commit=_git(["rev-parse", "--short", "HEAD"]),
        git_dirty=_git(["status", "--porcelain"])[:400] or "",
        python=sys.version.split()[0],
        platform=platform.platform(),
        duration_s=round(time.time() - t0, 2),
        mock_targets="127.0.0.1 only（无外部请求）",
    )

    # 反作弊基线
    if args.update_baseline:
        baseline = build_baseline(report, version=datetime.now().strftime("%Y%m%d-%H%M%S"))
        BASELINE_PATH.write_text(json.dumps(baseline, ensure_ascii=False, indent=2), "utf-8")
        report.baseline_version = baseline["version"]
        print(f"已重建基线：{BASELINE_PATH.relative_to(ROOT)}（version={baseline['version']}）")
    elif BASELINE_PATH.exists():
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        report.baseline_version = str(baseline.get("version") or "")
        report.baseline_violations = verify_baseline(report, baseline)
    else:
        report.baseline_violations = [
            "基线文件缺失：先运行 --update-baseline 建立基线（否则无法证明用例未被删改）"
        ]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else (ROOT / "reports" / "security_acceptance" / stamp)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2), "utf-8"
    )
    (out / "report.md").write_text(render_markdown(report), "utf-8")

    if args.json_only:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print()
        for line in summarize_lines(report):
            print(line)
        print(f"\n报告：{out / 'report.md'}")
        print(f"      {out / 'report.json'}")
        counts = {s: len(report.cases_by_status(s)) for s in TestStatus.ALL}
        print("状态计数：" + "，".join(f"{k}={v}" for k, v in counts.items()))
        print("基线指纹：" + "，".join(
            f"{c.name}→{case_fingerprint(c)[:8]}" for c in report.cases[:0]
        ) or "基线指纹：见 report.json")
    return 0 if report.verdict() == TestStatus.SECURITY_PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
