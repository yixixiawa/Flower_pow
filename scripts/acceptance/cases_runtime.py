"""跨模块用例：Runner / Detector / Collector / Scheduler / CLI / MCP / 后台任务。

每条用例都同时看三件事，缺一不算通过：

1. 决策/返回值（``【已拦截】``、异常、状态码）；
2. **真实网络**——mock server 收到了什么（由 harness 自动统计，用例改不了）；
3. **审计**——拒绝事件是否落盘（读 JSONL 文件，不读内存）。

这里没有任何"检查函数返回值就算过"的用例：凡是被拒绝的路径，
``expect`` 里都写着 ``http_sent: False`` 与 ``network.count: 0``。
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

from scripts.acceptance.util import PROJECT, read_yaml_cfg

# ── Runner：L3 / UNKNOWN / EXPORT / AUTH / fileread ───────────────


def _runner_pair(ctx):
    cfg = ctx.cfg(env="isolated_test")
    return cfg, ctx.runner(cfg), ctx.session(cfg)


def runner_sqli_probe_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    url = ctx.net.target + "/search?q=1"
    out = asyncio.run(
        runner.execute("sqli_probe", {"url": url, "param": "q", "payload": "'"}, session)
    )
    blocked = out.startswith("【已拦截】")
    ctx.check(blocked, f"sqli_probe 必须被拒，实际输出：{out[:160]}")
    ctx.check("SQL 注入验证" in out or "L3" in out, "拒绝文本应指明命中的 L3 命令")
    ctx.check("默认禁止" in out or "L3" in out, "拒绝理由应说明 L3 默认禁止")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    ctx.set("blocked", blocked)
    ctx.set("decision", "DENY")


def runner_exploit_sqli_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "exploit_probe",
            {"url": ctx.net.target + "/search", "kinds": "sqli"},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"exploit_probe(sqli) 必须被拒：{out[:160]}")
    ctx.check("SQL 注入验证" in out or "L3" in out, "拒绝文本应指明 L3 命令")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    ctx.set("blocked", out.startswith("【已拦截】"))


def runner_fileread_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "exploit_probe",
            {"url": ctx.net.target + "/download", "kinds": "fileread"},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"fileread 探针必须被拒：{out[:160]}")
    ctx.check("未识别" in out or "UNKNOWN" in out or "默认拒绝" in out,
              "拒绝理由应说明 fileread 未映射 → 默认拒绝")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    ctx.set("blocked", out.startswith("【已拦截】"))


def runner_unknown_method_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/ok", "method": "PROPFIND"},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"未识别方法必须被拒：{out[:160]}")
    ctx.check("UNKNOWN" in out, "拒绝文本应标明判定为 UNKNOWN")
    ctx.check("默认拒绝" in out or "未识别" in out, "拒绝理由应说明默认拒绝")
    ctx.check(out.count("【已拦截】") == 1, "只应返回一条拦截结论")
    ctx.set("blocked", out.startswith("【已拦截】"))


def runner_unknown_tool_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "external_tool",
            {"tool": "definitely-not-a-tool", "target": ctx.net.target},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"未知外部工具必须被拒：{out[:160]}")
    ctx.check("外部工具" in out or "definitely-not-a-tool" in out,
              "拒绝文本应指出是哪个工具")
    ctx.check("默认拒绝" in out or "不在权限矩阵" in out, "应说明未映射 → 默认拒绝")
    ctx.set("blocked", out.startswith("【已拦截】"))


def runner_export_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/export", "method": "GET"},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"导出必须被拒：{out[:160]}")
    ctx.check("UNKNOWN" in out, "EXPORT 无授权行 → 判定应为 UNKNOWN")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    denies = [e for e in ctx.events(cfg)
              if e.get("event") == "deny" and e.get("category") == "EXPORT"]
    ctx.check(bool(denies), "导出拒绝必须写入审计（category=EXPORT）")
    ctx.set("blocked", out.startswith("【已拦截】"))


def runner_login_blocked(ctx) -> None:
    """AUTH 类工具受 AUTH_BOOTSTRAP 约束——不是"分类是 AUTH 就放行"。

    登录放行只针对**认证入口**（清单登记或路径含 login/signin/refresh/
    logout）。这条用例盯的是反向：把 login 指向一个普通业务端点（/export）
    必须被拒、零网络、留审计——AUTH 通道不能变成"任意 URL 提交凭证"。
    """
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute(
            "login",
            {
                "url": ctx.net.target + "/export",
                "username": "u", "password": "p",
            },
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"login 打到非认证路径必须被拒：{out[:160]}")
    ctx.check("未登记" in out or "不是认证入口" in out,
              "拒绝文本应说明该 URL 不是认证入口")
    ctx.check("认证初始化" in out and "拒绝" in out, "应明确拒绝执行")
    ctx.check(not session.credentials.get("token"), "被拒的登录不得产生 Token")
    denies = [e for e in ctx.events(cfg) if e.get("event") == "deny"]
    ctx.check(bool(denies), "登录拒绝必须写入审计")
    ctx.set("blocked", out.startswith("【已拦截】"))


# ── Gateway ──────────────────────────────────────────────────────


def detector_uses_gateway(ctx) -> None:
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")

    async def go():
        det = HttpDetector(cfg.scan)
        try:
            return await det.send_request(ctx.net.target + "/ok")
        finally:
            await det.aclose()

    ev = asyncio.run(go())
    ctx.check(ev.status_code == 200, f"应拿到 200，实际 {ev.status_code} error={ev.error}")
    ctx.check(not ev.error, f"不应有错误：{ev.error}")
    ctx.check((ev.body_excerpt or "").strip() == "ok", "响应正文应为 mock 返回的 ok")
    ctx.check(ev.url == ctx.net.target + "/ok", "证据 URL 应指向实际请求地址")
    ctx.set("status", ev.status_code)


def runner_uses_gateway(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute("http_request", {"url": ctx.net.target + "/ok"}, session)
    )
    blocked = out.startswith("【已拦截】")
    ctx.check(not blocked, f"只读 GET 应放行：{out[:160]}")
    ctx.check("状态码：200" in out, "应真实收到 200")
    ctx.check(out.startswith("GET "), "结果首行应是实际发出的请求行")
    ctx.set("blocked", blocked)


def gateway_static_no_bare_clients(ctx) -> None:
    """AST 扫描：产品代码里的 httpx 客户端必须由 build_client_kwargs 喂参数。"""
    import httpx  # noqa: F401 —— 确认依赖存在

    found: list[tuple[str, int, bool]] = []
    for path in PROJECT.rglob("*.py"):
        parts = set(path.parts)
        if parts & {".venv", ".backup", "__pycache__", "scripts", "tests"}:
            continue
        if not any(p in parts for p in (
            "core", "detectors", "collectors", "cli", "mcp_server", "kb", "output", "intel", "llm",
        )):
            continue
        found.extend(_client_constructions(path))

    ungoverned = [(p, ln) for p, ln, ok in found if not ok]
    ctx.check(len(found) >= 7, f"应至少扫描到 7 处客户端构造，实际 {len(found)}")
    ctx.check(not ungoverned, f"存在裸 httpx 客户端（绕过 Gateway）：{ungoverned}")
    ctx.check(any(p.startswith("detectors/") for p, _, _ in found),
              "扫描必须覆盖 detectors/（扫描主出口）")
    ctx.check(any(p.startswith("collectors/") for p, _, _ in found),
              "扫描必须覆盖 collectors/（采集器出口）")
    ctx.set("constructions", len(found))
    ctx.set("ungoverned", len(ungoverned))
    ctx.set("constructions_at_least_7", len(found) >= 7)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _client_constructions(path: Path) -> list[tuple[str, int, bool]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    out: list[tuple[str, int, bool]] = []
    seen: set[int] = set()
    scopes: list[ast.AST] = [tree]
    scopes.extend(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    for scope in scopes:
        assigned: set[str] = set()
        for node in ast.walk(scope):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _dotted(node.value.func).endswith("build_client_kwargs")
            ):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        assigned.add(t.id)
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name not in ("httpx.AsyncClient", "httpx.Client"):
                continue
            if node.lineno in seen:
                continue
            governed = False
            for kw in node.keywords:
                if kw.arg is not None:
                    continue
                val = kw.value
                if isinstance(val, ast.Call) and _dotted(val.func).endswith(
                    "build_client_kwargs"
                ):
                    governed = True
                elif isinstance(val, ast.Name) and val.id in assigned:
                    governed = True
            seen.add(node.lineno)
            out.append((path.relative_to(PROJECT).as_posix(), node.lineno, governed))
    return out


# ── 无旁路 ───────────────────────────────────────────────────────


def runner_read_allow_write_deny(ctx) -> None:
    """未绑定环境：只读 GET 放行，写操作拒绝——同一入口两种结论。"""
    cfg = ctx.cfg(env="", environments={})
    runner = ctx.runner(cfg)
    session = ctx.session(cfg)

    read_out = asyncio.run(
        runner.execute("http_request", {"url": ctx.net.target + "/ok"}, session)
    )
    write_out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/users", "method": "POST", "body": '{"name":"x"}'},
            session,
        )
    )
    read_blocked = read_out.startswith("【已拦截】")
    write_blocked = write_out.startswith("【已拦截】")
    ctx.check(not read_blocked, f"只读 GET 在 unknown 环境应放行：{read_out[:160]}")
    ctx.check(write_blocked, f"未绑定环境的写操作必须拒绝：{write_out[:160]}")
    ctx.check("未知" in write_out or "unknown" in write_out,
              "拒绝理由应说明环境未绑定")
    ctx.check("状态码：200" in read_out, "放行的只读请求必须真的拿到响应")
    ctx.set("read_blocked", read_blocked)
    ctx.set("write_blocked", write_blocked)


def detector_batch_blocked(ctx) -> None:
    """批量 POC sweep：每条请求都受分类约束，不能靠"批量"糊过去。"""
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")

    async def go():
        det = HttpDetector(cfg.scan)
        # 模拟批量 sweep：探测器写入当前类别（POC 声明的等价物）
        det._current_kind = "sqli"
        try:
            return [
                await det.send_request(f"{ctx.net.target}/search?q={i}")
                for i in range(3)
            ]
        finally:
            await det.aclose()

    evs = asyncio.run(go())
    blocked = sum(1 for e in evs if e.error and "策略拦截" in e.error)
    allowed = sum(1 for e in evs if not e.error)
    ctx.check(blocked == 3, f"3 条 sqli 探测都必须被拦，实际 {blocked}")
    ctx.check(allowed == 0, f"不得有请求漏过，实际放行 {allowed}")
    ctx.check(all(e.error for e in evs), "被拦请求必须带 error 标记")
    ctx.set("blocked", blocked)
    ctx.set("allowed", allowed)


def collector_cross_host_blocked(ctx) -> None:
    from collectors.path_scan import PathScanner

    cfg = ctx.cfg(env="isolated_test")
    mark = ctx.mark()

    async def go():
        ps = PathScanner(cfg.scan)
        try:
            first = await ps.send_request(ctx.net.target + "/ok")
            second = await ps.send_request(ctx.net.outsider + "/steal")
            return first, second
        finally:
            await ps.aclose()

    first, second = asyncio.run(go())
    ctx.check(not first.error, f"首个同源请求应放行：{first.error}")
    ctx.check(bool(second.error) and "策略拦截" in second.error,
              f"Collector 跨主机请求必须被拦：{second.error}")
    cross = [r for r in ctx.hits(mark) if r.server == "B"]
    ctx.check(not cross, f"外部主机不得收到请求，实际 {len(cross)} 条")
    ctx.set("blocked", bool(second.error))
    ctx.set("cross_hits", len(cross))


def enforcer_disables_l3_all_envs(ctx) -> None:
    """L3 探针不是"测试环境就放行"：批量流水线里所有环境都必须关。"""
    from policy.enforcer import scoped_scan_config

    off = 0
    original = True
    for env in ("isolated_test", "dedicated_test"):
        cfg = ctx.cfg(env=env)
        scoped, _ = scoped_scan_config(cfg, ctx.net.target)
        ctx.check(scoped.scan.sqli_probe_enabled is False, f"{env}：SQLi 探针必须关闭")
        ctx.check(scoped.scan.rce_probe_enabled is False, f"{env}：RCE 探针必须关闭")
        off += int(scoped.scan.sqli_probe_enabled is False)
        off += int(scoped.scan.rce_probe_enabled is False)
        original = original and cfg.scan.sqli_probe_enabled is True

    unknown = ctx.cfg(env="", environments={})
    scoped_u, note = scoped_scan_config(unknown, ctx.net.target)
    ctx.check(scoped_u.scan.sqli_probe_enabled is False, "unknown：SQLi 探针必须关闭")
    ctx.check(scoped_u.scan.rce_probe_enabled is False, "unknown：RCE 探针必须关闭")
    ctx.check("L3" in note or "强制关闭" in note, "说明文字应指出探针被强制关闭")

    prod_blocked = False
    try:
        scoped_scan_config(ctx.cfg(env="production"), ctx.net.target)
    except ValueError:
        prod_blocked = True
    ctx.check(prod_blocked, "生产环境不得取得扫描配置")
    ctx.check(off == 4, f"两个测试环境 × 两个探针都必须关闭，实际关闭 {off}")
    ctx.check(original, "不得修改调用方的原配置（必须是副本）")
    ctx.set("all_off", off == 4)
    ctx.set("original_untouched", original)


def scheduler_entry_gate(ctx) -> None:
    from policy.api_policy import Environment
    from policy.enforcer import active_scan_check, scoped_scan_config

    iso = ctx.cfg(env="isolated_test")
    ok_iso, _ = active_scan_check(iso, ctx.net.target)
    scoped, note = scoped_scan_config(iso, ctx.net.target)
    ctx.check(ok_iso is True, "隔离环境应允许进扫描")
    ctx.check(scoped.scan.sqli_probe_enabled is False, "L3：SQLi 探针在流水线中必须关闭")
    ctx.check(scoped.scan.rce_probe_enabled is False, "L3：RCE 探针在流水线中必须关闭")
    ctx.check(iso.scan.sqli_probe_enabled is True, "不得修改调用方的原配置（必须是副本）")

    prod = ctx.cfg(env="production")
    ok_prod, msg = active_scan_check(prod, ctx.net.target)
    ctx.check(ok_prod is False, "生产环境必须拒绝主动扫描")
    ctx.check("生产" in msg, "拒绝文本应说明生产环境")
    raised = False
    try:
        scoped_scan_config(prod, ctx.net.target)
    except ValueError:
        raised = True
    ctx.check(raised, "生产环境取扫描配置必须抛错（调用方不得绕过）")

    unk = ctx.cfg(env="", environments={})
    ok_unk, msg_unk = active_scan_check(unk, ctx.net.target)
    scoped_unk, _ = scoped_scan_config(unk, ctx.net.target)
    ctx.check(ok_unk is True, "未绑定环境放行但必须降级")
    ctx.check("降级" in msg_unk, "未绑定环境的说明应写明降级")
    ctx.check(scoped_unk.scan.file_read_probe_enabled is False,
              "未绑定环境：文件读取探针必须关闭")
    ctx.check(scoped_unk.scan.sqli_probe_enabled is False,
              "未绑定环境：L3 探针必须关闭")
    ctx.set("prod_allowed", ok_prod)
    ctx.set("unknown_note", "降级" in msg_unk)
    ctx.set("probes_off_in_unknown",
             scoped_unk.scan.file_read_probe_enabled is False
             and scoped_unk.scan.sqli_probe_enabled is False)


def cli_production_refused(ctx) -> None:
    import typer

    cfg_path = read_yaml_cfg(ctx, "production")
    from cli.scan import scan

    code = None
    try:
        # 直接调命令函数时 typer 的默认值是 OptionInfo 对象，必须逐项显式传
        scan(
            target=ctx.net.target,
            config=str(cfg_path),
            top_k=None,
            fmt="md",
            no_ai=True,
            no_rag=True,
            save_evidence=False,
            output=str(Path(ctx.tmp) / "out"),
            model=None,
            deep_model=None,
            verbose=False,
        )
    except typer.Exit as exc:  # typer.Exit 继承 click.exceptions.Exit
        code = int(exc.exit_code)
    except SystemExit as exc:  # 兜底：某些路径直接 sys.exit
        code = int(exc.code or 0)
    ctx.check(code == 2, f"生产目标必须 exit(2)，实际 {code}")
    ctx.check(code != 0, "不得以成功退出（否则会被当成扫描完成）")
    ctx.set("exit_code", code)


def mcp_production_refused(ctx) -> None:
    from mcp_server.jobs import JobRegistry

    cfg_path = read_yaml_cfg(ctx, "production")
    reg = JobRegistry(keep=2)
    raised = False
    msg = ""
    try:
        reg.start(ctx.net.target, config=str(cfg_path))
    except ValueError as exc:
        raised = True
        msg = str(exc)
    ctx.check(raised, f"MCP 生产任务必须被拒，实际未抛错（{msg}）")
    ctx.check("生产" in msg, "拒绝理由应说明生产环境")
    ctx.set("raised", raised)


def background_task_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute("recon_ports_bg", {"host": "192.0.2.9", "top": 10}, session)
    )
    ctx.check(out.startswith("【已拦截】"), f"跨主机后台任务必须被拒：{out[:160]}")
    ctx.check(len(runner._bg_handles) == 0, "被拒任务不得创建后台 Task")
    ctx.check("范围" in out or "未绑定" in out or "出界" in out,
              "拒绝理由应指向目标范围")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    ctx.set("blocked", out.startswith("【已拦截】"))
    ctx.set("bg_tasks", len(runner._bg_handles))


def planner_auth_refused(ctx) -> None:
    from policy.request_guard import auth_operation_allowed

    allowed, why = auth_operation_allowed(ctx.net.target)
    ctx.check(allowed is False, f"默认不得授权 AUTH 操作（实际 {allowed}: {why}）")

    src = (PROJECT / "core" / "planner.py").read_text(encoding="utf-8")
    idx = 0
    calls = 0
    ordered = True
    while True:
        idx = src.find("auth.login(", idx)
        if idx < 0:
            break
        calls += 1
        window = src[max(0, idx - 1400):idx]
        # 每个 login 调用点之前都必须有授权判定（同一函数体内）
        if "auth_operation_allowed" not in window:
            ordered = False
        idx += len("auth.login(")
    ctx.check(calls >= 2, f"Planner 至少两处 login 调用点，实际 {calls}")
    ctx.check(ordered, "每个 auth.login 之前必须过 auth_operation_allowed")
    ctx.set("allowed", allowed)
    ctx.set("calls_before_login", ordered)
    ctx.note_risk("Planner 的登录授权目前靠源码顺序约束，未做运行期端到端登录链路验证")


# ── 范围 ─────────────────────────────────────────────────────────


def runner_cross_port_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    out = asyncio.run(
        runner.execute("http_request", {"url": ctx.net.outsider + "/ok"}, session)
    )
    ctx.check(out.startswith("【已拦截】"), f"跨端口请求必须被拒：{out[:160]}")
    ctx.check("范围" in out or "未绑定" in out or "出界" in out,
              "拒绝理由应指向目标范围")
    ctx.check("拒绝执行" in out, "拒绝文本应明确写了拒绝执行")
    denies = [e for e in ctx.events(cfg) if e.get("event") == "deny"]
    ctx.check(bool(denies), "跨范围拒绝必须写入审计")
    ctx.set("blocked", out.startswith("【已拦截】"))


def detector_cross_host_blocked(ctx) -> None:
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")
    mark = ctx.mark()

    async def go():
        det = HttpDetector(cfg.scan)
        try:
            first = await det.send_request(ctx.net.target + "/ok")
            second = await det.send_request(ctx.net.outsider + "/steal")
            return first, second
        finally:
            await det.aclose()

    first, second = asyncio.run(go())
    ctx.check(not first.error, f"首请求应放行：{first.error}")
    ctx.check(bool(second.error) and "策略拦截" in second.error,
              f"跨主机必须被拦：{second.error}")
    cross = [r for r in ctx.hits(mark) if r.server == "B"]
    ctx.check(not cross, "外部主机不得收到请求")
    ctx.set("blocked", bool(second.error))
    ctx.set("cross_hits", len(cross))


# ── 重定向 ───────────────────────────────────────────────────────


def detector_cross_redirect_blocked(ctx) -> None:
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")
    mark = ctx.mark()

    async def go():
        det = HttpDetector(cfg.scan)
        try:
            return await det.send_request(ctx.net.target + "/redirect-cross")
        finally:
            await det.aclose()

    ev = asyncio.run(go())
    cross = [r for r in ctx.hits(mark) if r.server == "B"]
    ctx.check(bool(ev.error) and "策略拦截" in ev.error,
              f"跨主机重定向必须被拦：error={ev.error!r} status={ev.status_code}")
    ctx.check("重定向" in str(ev.error), "拒绝理由应说明是重定向目标出界")
    ctx.check(not cross, f"外部主机不得收到重定向后的请求，实际 {len(cross)} 条")
    ctx.set("blocked", bool(ev.error))
    ctx.set("cross_hits", len(cross))


def detector_same_redirect_followed(ctx) -> None:
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")
    mark = ctx.mark()

    async def go():
        det = HttpDetector(cfg.scan)
        try:
            return await det.send_request(ctx.net.target + "/redirect-same")
        finally:
            await det.aclose()

    ev = asyncio.run(go())
    cross = [r for r in ctx.hits(mark) if r.server == "B"]
    ctx.check(ev.status_code == 200, f"同源重定向应跟到 200，实际 {ev.status_code} {ev.error}")
    ctx.check(not ev.error, f"不应有错误：{ev.error}")
    ctx.check(not cross, "同源重定向不应打到外部主机")
    ctx.set("status", ev.status_code)
    ctx.set("cross_hits", len(cross))


def runner_cross_redirect_blocked(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    mark = ctx.mark()
    out = asyncio.run(
        runner.execute(
            "http_request", {"url": ctx.net.target + "/redirect-cross"}, session
        )
    )
    cross = [r for r in ctx.hits(mark) if r.server == "B"]
    ctx.check("策略拦截" in out, f"重定向被拦的信号应回灌给调用方：{out[:200]}")
    ctx.check(not cross, f"外部主机不得收到请求，实际 {len(cross)} 条")
    ctx.set("blocked_signal", "策略拦截" in out)
    ctx.set("cross_hits", len(cross))


# ── 身份 ─────────────────────────────────────────────────────────


def identity_triplet(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    s1 = ctx.session(cfg, session_id="sess-A")
    s2 = ctx.session(cfg, session_id="sess-B")
    url = ctx.net.target + "/ok"

    runner._observe_identity({"Authorization": "Bearer TOPSECRET"}, url, session=s1)
    id1 = runner._current_identity(s1, url=url)
    runner._observe_identity({"Authorization": "Bearer TOPSECRET"}, url, session=s2)
    id2 = runner._current_identity(s2, url=url)

    ctx.check(id1 != id2, "同一凭证在不同 session 下必须是不同身份")
    ctx.check("sess=sess-A" in id1 and "sess=sess-B" in id2, "身份必须带 session 绑定")
    ctx.check("tgt=127.0.0.1:" in id1, "身份必须带 target 绑定")
    ctx.check("TOPSECRET" not in id1 and "TOPSECRET" not in id2,
              "凭证原值不得出现在身份标签（只允许指纹）")
    ctx.check(id1.startswith("cred:authorization:"), f"凭证身份格式应为 cred:<头名>:<指纹>，实际 {id1}")
    ctx.set("same_token_diff_session", id1 != id2)
    ctx.set("has_sess", "sess=" in id1)
    ctx.set("has_tgt", "tgt=" in id1)
    ctx.set("leaked_token", "TOPSECRET" in id1)


def identity_no_inherit(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    s = ctx.session(cfg, session_id="sess-I")
    url = ctx.net.target + "/ok"

    runner._observe_identity({"Cookie": "session=abc"}, url, session=s)
    before = runner._current_identity(s, url=url)
    runner._observe_identity({}, url, session=s)
    after = runner._current_identity(s, url=url)

    ctx.check(before.startswith("cred:cookie:"), f"带凭证时身份应为凭证身份，实际 {before}")
    ctx.check(after.startswith("anonymous@"), f"无凭证必须回落匿名，实际 {after}")
    ctx.check("cred:cookie" not in after, "无凭证请求不得继承前次实名身份")
    ctx.set("before_with_cred", before.split(":", 1)[0])
    ctx.set("after_without_cred", "anonymous" if after.startswith("anonymous@") else "other")


def identity_target_change(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    s = ctx.session(cfg, session_id="sess-T")
    tid_old, rid_old = runner._policy_scope(s)
    id_old = runner._current_identity(s, url=ctx.net.target)
    runner.test_ledger.record(
        ctx.net.target + "/api/users", "create",
        run_id=rid_old, target_id=tid_old, identity=id_old, object_id="4321",
    )

    s.target = ctx.net.outsider
    s.result.target = ctx.net.outsider
    s.result.target_id = ctx.net.outsider
    s.result.new_run("换目标")
    id_new = runner._current_identity(s, url=ctx.net.outsider)
    tid_new, rid_new = runner._policy_scope(s)

    ctx.check(id_old != id_new, "换目标后身份必须变化（tgt 维度）")
    ctx.check(tid_old != tid_new or rid_old != rid_new, "换目标必须开新轮次/新目标归属")
    known = runner.test_ledger.known(
        ctx.net.target + "/api/users/4321",
        target_id=tid_new, run_id=rid_new, identity=id_new,
    )
    ctx.check(not known, "旧目标登记的对象对新目标/新轮次不可复用")
    ctx.set("identity_changed", id_old != id_new)
    ctx.set("old_object_not_known", not known)


# ── 并发 ─────────────────────────────────────────────────────────


def concurrent_ledger_isolated(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    s1 = ctx.session(cfg, session_id="sess-C1")
    s2 = ctx.session(cfg, session_id="sess-C2")
    url = ctx.net.target + "/api/users"

    async def both():
        return await asyncio.gather(
            runner.execute(
                "http_request",
                {"url": url, "method": "POST", "body": '{"name":"a"}'},
                s1,
            ),
            runner.execute(
                "http_request",
                {"url": url, "method": "POST", "body": '{"name":"b"}'},
                s2,
            ),
        )

    outs = asyncio.run(both())
    ctx.check(all("状态码：201" in o for o in outs),
              f"两次创建都应成功：{[o[:80] for o in outs]}")
    objs = runner.test_ledger.objects_of()
    ctx.check(len(objs) == 2, f"应登记两个对象，实际 {len(objs)}")
    idents = {o.identity for o in objs}
    ctx.check(len(idents) == 2, f"并发两会话的身份必须不同，实际 {idents}")
    ctx.check(all("sess=" in i for i in idents), "台账身份必须带 session 绑定")
    ctx.check(runner._pending_ledger is None, "并发执行后不得残留 pending 条目")
    ctx.set("objects", len(objs))
    ctx.set("identities_distinct", len(idents) == 2)
    ctx.set("pending_left", runner._pending_ledger is not None)


# ── 台账 ─────────────────────────────────────────────────────────


def runner_delete_requires_created_id(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    session = ctx.session(cfg, session_id="sess-L")

    async def approve(_msg: str) -> str:
        return "alice"

    runner.approver = approve

    create_out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/users", "method": "POST", "body": '{"name":"x"}'},
            session,
        )
    )
    create_ok = "状态码：201" in create_out
    tid, rid = runner._policy_scope(session)
    ident = runner._current_identity(session, url=ctx.net.target + "/api/users")
    recorded = runner.test_ledger.known(
        ctx.net.target + "/api/users/4321",
        target_id=tid, run_id=rid, identity=ident,
    )

    del_created = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/users/4321", "method": "DELETE"},
            session,
        )
    )
    del_other = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/users/9999", "method": "DELETE"},
            session,
        )
    )

    ctx.check(create_ok, f"创建应成功：{create_out[:120]}")
    ctx.check(recorded, "创建成功且取得对象 ID → 必须登记台账")
    ctx.check("状态码：200" in del_created,
              f"删除本次创建的对象应放行：{del_created[:160]}")
    ctx.check(del_other.startswith("【已拦截】"),
              f"删除未创建的具体 ID 必须拒绝：{del_other[:160]}")
    ctx.check("台账" in del_other, "拒绝理由应指向对象台账检查")
    ctx.check("9999" in del_other, "拒绝文本应点名被拒的具体对象 ID")
    ctx.check(del_created != del_other, "两类删除必须给出不同结论")
    ctx.set("create_ok", create_ok)
    ctx.set("recorded", recorded)
    ctx.set("delete_created_ok", "状态码：200" in del_created)
    ctx.set("delete_other_blocked", del_other.startswith("【已拦截】"))


def failed_create_not_recorded(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    session = ctx.session(cfg, session_id="sess-F")

    async def approve(_msg: str) -> str:
        return "alice"

    runner.approver = approve
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/fail", "method": "POST", "body": '{"name":"x"}'},
            session,
        )
    )
    ctx.check("状态码：500" in out, f"应收到 500：{out[:120]}")
    ctx.check(len(runner.test_ledger.objects_of()) == 0,
              "创建失败的请求不得登记台账（对象不存在）")
    del_out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/fail", "method": "DELETE"},
            session,
        )
    )
    ctx.check(del_out.startswith("【已拦截】"),
              f"删除不存在的对象必须拒绝：{del_out[:160]}")
    ctx.check("台账" in del_out, "拒绝理由应指向对象台账检查")
    ctx.set("objects", len(runner.test_ledger.objects_of()))
    ctx.set("delete_blocked", del_out.startswith("【已拦截】"))


# ── 审批 ─────────────────────────────────────────────────────────


def approver_identity_recorded(ctx) -> None:
    cfg = ctx.cfg(env="dedicated_test")
    runner = ctx.runner(cfg)
    runner.approver_identity = "alice@example.com"

    async def approve(_msg: str) -> str:
        return "alice@example.com"

    runner.approver = approve
    session = ctx.session(cfg, session_id="sess-P")
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/upload", "method": "POST", "body": "file=1"},
            session,
        )
    )
    allowed = "状态码：201" in out
    events = ctx.events(cfg)
    approvals = [e for e in events if e.get("event") == "approval"]
    ok_approver = bool(approvals) and (
        (approvals[-1].get("extra") or {}).get("approver") == "alice@example.com"
    )
    authenticated = bool(approvals) and (
        (approvals[-1].get("extra") or {}).get("authenticated_approver") is True
    )
    ctx.check(allowed, f"审批通过后上传应执行：{out[:160]}")
    ctx.check(bool(approvals), f"必须写入 approval 审计事件（实际 {len(events)} 条）")
    ctx.check(ok_approver, "审计里的审批人必须是真实身份 alice@example.com")
    ctx.check(authenticated, "authenticated_approver 必须为 True")
    token = (approvals[-1].get("extra") or {}).get("approval_token") if approvals else ""
    ctx.check(bool(token), "审计必须带一次性票据号（可追溯、不可重放）")
    ctx.set("allowed", allowed)
    ctx.set("authenticated_approver", authenticated)


def bare_true_approver_unauthenticated(ctx) -> None:
    cfg = ctx.cfg(env="dedicated_test")
    runner = ctx.runner(cfg)
    runner.approver_identity = ""

    async def approve(_msg: str) -> bool:
        return True

    runner.approver = approve
    session = ctx.session(cfg, session_id="sess-P2")
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/upload", "method": "POST", "body": "file=2"},
            session,
        )
    )
    events = [e for e in ctx.events(cfg) if e.get("event") == "approval"]
    authenticated = bool(events) and (
        (events[-1].get("extra") or {}).get("authenticated_approver") is True
    )
    approver = (events[-1].get("extra") or {}).get("approver") if events else ""
    ctx.check("状态码：201" in out, f"裸 True 审批仍应放行（但留痕为未认证）：{out[:160]}")
    ctx.check(not authenticated, "裸 True 审批不得记为已认证审批人")
    ctx.check("未认证" in str(approver), f"审批人字段应明确标注未认证，实际 {approver!r}")
    ctx.set("allowed", "状态码：201" in out)
    ctx.set("authenticated_approver", authenticated)


def approval_not_reused_after_change(ctx) -> None:
    cfg = ctx.cfg(env="dedicated_test")
    runner = ctx.runner(cfg)
    calls: list[str] = []

    async def approve(msg: str) -> str:
        calls.append(msg)
        return "bob"

    runner.approver = approve
    session = ctx.session(cfg, session_id="sess-P3")
    out1 = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/upload", "method": "POST", "body": "v=1"},
            session,
        )
    )
    out2 = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/upload", "method": "POST", "body": "v=2"},
            session,
        )
    )
    ctx.check("状态码：201" in out1 and "状态码：201" in out2,
              f"两次上传都应执行：{out1[:80]} / {out2[:80]}")
    ctx.check(len(calls) == 2, f"请求内容变化必须重新审批，实际审批 {len(calls)} 次")
    ctx.set("approver_calls", len(calls))


# ── 审计 ─────────────────────────────────────────────────────────


def deny_event_persisted(ctx) -> None:
    cfg, runner, session = _runner_pair(ctx)
    asyncio.run(
        runner.execute(
            "sqli_probe",
            {"url": ctx.net.target + "/search?q=1", "param": "q"},
            session,
        )
    )
    path = ctx.audit_path(cfg)
    exists = path.exists()
    lines = ctx.events(cfg)
    denies = [e for e in lines if e.get("event") == "deny"]
    ctx.check(exists, "拒绝事件必须落盘到 policy/audit.jsonl")
    ctx.check(len(denies) >= 1, f"应有 deny 事件，实际 {len(denies)} 条")
    ctx.check(any(e.get("command") == "SQL 注入验证" for e in denies),
              "deny 事件必须记录命中的命令")
    ctx.check(any(e.get("run_id") for e in denies), "deny 事件必须带 run_id（可对账）")
    ctx.set("file_exists", exists)
    ctx.set("deny_lines", len(denies))


def audit_disabled_blocks_write(ctx) -> None:
    cfg = ctx.cfg(env="isolated_test", audit=False)
    runner = ctx.runner(cfg)
    session = ctx.session(cfg, session_id="sess-AU")
    out = asyncio.run(
        runner.execute(
            "http_request",
            {"url": ctx.net.target + "/api/users", "method": "POST", "body": '{"n":1}'},
            session,
        )
    )
    ctx.check(out.startswith("【已拦截】"), f"审计不可写时写操作必须拒绝：{out[:200]}")
    ctx.check("审计" in out, "拒绝理由应说明审计不可持久化")
    ctx.check(not ctx.audit_path(cfg).exists(), "审计关闭时不应产生审计文件（拒绝不靠内存记录）")
    ctx.set("blocked", out.startswith("【已拦截】"))


def detector_block_audited(ctx) -> None:
    from detectors.http_detector import HttpDetector

    cfg = ctx.cfg(env="isolated_test")

    async def go():
        det = HttpDetector(cfg.scan)
        det._current_kind = "sqli"
        try:
            return await det.send_request(ctx.net.target + "/search?q=1")
        finally:
            await det.aclose()

    ev = asyncio.run(go())
    events = ctx.events(cfg)
    denies = [e for e in events if e.get("event") == "deny"]
    ctx.check(bool(ev.error), "探测器请求应被策略拦截")
    ctx.check(bool(denies), f"Detector 层拦截也必须写审计，实际 {len(events)} 条事件")
    ctx.check(any(e.get("command") == "SQL 注入验证" for e in denies),
              "审计应记录命中的命令")
    ctx.set("blocked", bool(ev.error))


# ── AUTH_BOOTSTRAP：受限认证初始化 ───────────────────────────────


def _seed_auth_assets(session) -> None:
    """往会话接口清单里登记四条认证入口（Agent 侦察后的等价状态）。"""
    from core.state import Asset

    session.result.assets.extend([
        Asset(kind="api", value="/api/auth/login", meta={
            "method": "POST", "path": "/api/auth/login",
            "body_fields": ["username", "password"],
        }),
        Asset(kind="api", value="/api/auth/captcha", meta={
            "method": "GET", "path": "/api/auth/captcha",
        }),
        Asset(kind="api", value="/api/auth/logout", meta={
            "method": "POST", "path": "/api/auth/logout",
        }),
    ])


def auth_bootstrap_single_use(ctx) -> None:
    """合法登录放行**单次**，登录成功后未授权请求照样拒绝。"""
    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    session = ctx.session(cfg)
    _seed_auth_assets(session)
    secret = "Sup3r-Secret-Pwd!"
    mark = ctx.mark()
    out = asyncio.run(runner.execute(
        "login",
        {"url": ctx.net.target, "username": "tester", "password": secret},
        session,
    ))
    login_hits = ctx.hits(mark)
    ctx.check(not out.startswith("【已拦截】"), f"合法登录不应被拦：{out[:160]}")
    ctx.check("登录成功" in out, f"应真实登录成功：{out[:200]}")
    ctx.check(bool(session.credentials.get("token")), "登录成功应写入 Token")
    ctx.check(secret not in out, "工具输出不得回显明文凭证")
    ctx.check(any(r.path == "/api/auth/login" and r.method == "POST" for r in login_hits),
              f"登录请求应真实发出（实际 {[r.line() for r in login_hits]}）")

    mark2 = ctx.mark()
    out2 = asyncio.run(runner.execute(
        "http_request", {"url": ctx.net.target + "/api/users/export", "method": "GET"}, session,
    ))
    export_hits = [r for r in ctx.hits(mark2) if "export" in r.path]
    ctx.check(out2.startswith("【已拦截】"), f"登录后导出仍须被拒：{out2[:200]}")
    ctx.check(not export_hits, "登录成功不得放行后续请求（导出请求不得发出）")
    ctx.set("login_ok", "登录成功" in out)
    ctx.set("token_present", bool(session.credentials.get("token")))
    ctx.set("export_blocked", out2.startswith("【已拦截】"))
    ctx.set("export_hits", len(export_hits))


def auth_bootstrap_conditions_enforced(ctx) -> None:
    """十条前置条件逐条验证：任一不满足即拒绝，且零请求。"""
    from policy.auth_bootstrap import entries_for
    from policy.request_guard import GuardContext as Ctx
    from policy.request_guard import RequestGuard

    cfg = ctx.cfg(env="isolated_test")
    guard = RequestGuard(cfg)
    # 入口清单直接构造（不依赖会话），保证 URL 与目标一致
    from core.state import Asset

    entries = entries_for(ctx.net.target, [
        Asset(kind="api", value="/api/auth/login", meta={
            "method": "POST", "path": "/api/auth/login",
            "body_fields": ["username", "password"],
        }),
    ])
    url = ctx.net.target + "/api/auth/login"
    creds = {"username": "u", "password": "p"}

    def mk(env: str, *, tid: str | None = None, bound: str | None = None) -> Ctx:
        return Ctx(
            target_id=ctx.net.target if tid is None else tid,
            bound_target=ctx.net.target if bound is None else bound,
            environment=env, identity_bound=True, auth_entries=entries,
        )

    cases = [
        ("会话未绑定目标", guard.check_auth(url, method="POST", params=creds,
                                            ctx=mk("isolated_test", tid="", bound=""))),
        ("未知环境", guard.check_auth(url, method="POST", params=creds, ctx=mk("unknown"))),
        ("非测试背景", guard.check_auth(url, method="POST", params=creds, ctx=mk("production"))),
        ("认证管理路径（未登记入口）", guard.check_auth(
            ctx.net.target + "/api/auth/users/create", method="POST", params=creds,
            ctx=mk("isolated_test"))),
        ("参数越界", guard.check_auth(url, method="POST",
                                      params={**creds, "role": "admin"}, ctx=mk("isolated_test"))),
        ("方法不符", guard.check_auth(url, method="GET", ctx=mk("isolated_test"))),
    ]
    for name, d in cases:
        ctx.check(not d.allowed, f"{name} 必须拒绝（实际 {d.decision}）：{d.reason[:100]}")
    denied = sum(1 for _, d in cases if not d.allowed)
    ctx.check(denied == len(cases), f"六种不满足条件必须全部拒绝，实际 {denied}")
    ctx.set("denied", denied)


# ── 外部工具：统一 Gateway ───────────────────────────────────────


def external_tool_curl_no_network(ctx) -> None:
    """curl 的网络能力被禁用：不建进程、不发请求、给出合法出路。"""
    import subprocess

    cfg = ctx.cfg(env="isolated_test")
    runner = ctx.runner(cfg)
    session = ctx.session(cfg)
    mark = ctx.mark()
    real = subprocess.run
    spawned: list[tuple] = []

    def fake(*a, **k):
        spawned.append(a)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    subprocess.run = fake
    try:
        out = asyncio.run(runner.execute(
            "external_tool",
            {"tool": "curl",
             "args": ["-X", "POST", ctx.net.target + "/api/auth/login", "-d", "a=1"]},
            session,
        ))
    finally:
        subprocess.run = real
    hits = ctx.hits(mark)
    ctx.check(out.startswith("【已拦截】"), f"curl POST 必须被拦：{out[:200]}")
    ctx.check(not spawned, f"被拒的 curl 不得启动外部进程（实际 {len(spawned)}）")
    ctx.check(not hits, f"被拒的 curl 不得发网络请求（实际 {len(hits)}）")
    ctx.check("http_request" in out, "拒绝文本应给出合法出路（http_request）")
    ctx.set("blocked", out.startswith("【已拦截】"))
    ctx.set("spawned", len(spawned))


def external_tool_scope_and_header(ctx) -> None:
    """外部工具目标出界拒绝；-H 普通头不再被当路径；-H @file 仍受限。"""
    from core.tools.external import ExternalTool
    from policy.request_guard import GuardContext as Ctx
    from policy.request_guard import RequestGuard

    cfg = ctx.cfg(env="isolated_test")
    guard = RequestGuard(cfg)
    gctx = Ctx(
        target_id=ctx.net.target, bound_target=ctx.net.target,
        environment="isolated_test", identity_bound=True,
    )
    d1 = guard.check_tool("nmap", {"args": ["-sT", "-Pn", "http://127.0.0.2:9"]}, ctx=gctx)
    d2 = guard.check_tool("ffuf", {"args": ["-u", ctx.net.outsider + "/FUZZ", "-w", "x.txt"]},
                          ctx=gctx)
    ctx.check(not d1.allowed and "未绑定目标" in d1.reason,
              f"nmap 指向外部主机必须拒绝：{d1.reason[:120]}")
    ctx.check(not d2.allowed and "未绑定目标" in d2.reason,
              f"ffuf 指向其它端口/主机必须拒绝：{d2.reason[:120]}")

    runner = ctx.runner(cfg)
    spec = ExternalTool(key="probe-http", name="probe-http", bins=("x",), category="t",
                        desc="", flags=("-H",))
    _, err_ok = runner._validate_argv(
        spec, ["-H", "Content-Type: application/json", ctx.net.target + "/api"],
    )
    _, err_file = runner._validate_argv(
        spec, ["-H", "@" + str(PROJECT / "config.yaml"), ctx.net.target + "/api"],
    )
    _, err_traversal = runner._validate_argv(
        spec, ["-H", "@../../etc/passwd", ctx.net.target + "/api"],
    )
    ctx.check(err_ok == "", f"Header application/json 不得被误判为路径：{err_ok}")
    ctx.check(err_file != "", "项目内绝对路径的 @file 仍受路径白名单控制")
    ctx.check(err_traversal != "", "路径穿越的 @file 必须拒绝")
    ctx.set("out_of_scope_denied", int(not d1.allowed) + int(not d2.allowed))
    ctx.set("header_ok", err_ok == "")
    ctx.set("header_file_denied", err_file != "" and err_traversal != "")


__all__ = [
    "runner_sqli_probe_blocked", "runner_exploit_sqli_blocked",
    "runner_fileread_blocked", "runner_unknown_method_blocked",
    "runner_unknown_tool_blocked", "runner_export_blocked", "runner_login_blocked",
    "detector_uses_gateway", "runner_uses_gateway", "gateway_static_no_bare_clients",
    "runner_read_allow_write_deny", "detector_batch_blocked",
    "collector_cross_host_blocked", "enforcer_disables_l3_all_envs",
    "scheduler_entry_gate",
    "cli_production_refused", "mcp_production_refused", "background_task_blocked",
    "planner_auth_refused", "runner_cross_port_blocked", "detector_cross_host_blocked",
    "detector_cross_redirect_blocked", "detector_same_redirect_followed",
    "runner_cross_redirect_blocked", "identity_triplet", "identity_no_inherit",
    "identity_target_change", "concurrent_ledger_isolated",
    "runner_delete_requires_created_id", "failed_create_not_recorded",
    "approver_identity_recorded", "bare_true_approver_unauthenticated",
    "approval_not_reused_after_change", "deny_event_persisted",
    "audit_disabled_blocks_write", "detector_block_audited",
    "auth_bootstrap_single_use", "auth_bootstrap_conditions_enforced",
    "external_tool_curl_no_network", "external_tool_scope_and_header",
]
