"""探针与工具清单：``exploit``（一次性高危探针）/ ``tools`` / ``discover``。"""

from __future__ import annotations

import asyncio
from pathlib import Path
import typer
from rich.panel import Panel
from rich.table import Table
from core.state import POC, ScanResult, Severity, safe_name
from cli.app import app
from cli.app import console
from cli.app import err
from cli.app import _SEV_STYLE
from cli.boot import _cfg
from cli.engines import _cell
from cli.engines import _basis_of


# ── exploit：一次性高危探针 ───────────────────────────────────────


@app.command()
def exploit(
    target: str = typer.Argument(..., help="目标 URL，如 http://example.com"),
    config: str = typer.Option(None, "--config", "-c"),
    only: str = typer.Option(
        "sqli,rce,fileread", "--only",
        help="探测类别：sqli|rce|fileread|upload，逗号分隔；all=全部",
    ),
    upload: bool = typer.Option(
        False, "--upload",
        help="**开启任意文件上传探测**（会往目标写文件）。"
             "与 readonly 无关；每次上传前都会在终端逐条人工确认，"
             "非交互环境下（没有确认通道）一个上传请求都不会发",
    ),
    max_ops: int = typer.Option(
        0, "--max-ops", "-n", help="最多探测多少个接口，0=用配置值（默认 40）"
    ),
    ops_file: str = typer.Option(
        None, "--ops-file", help="从文件读取接口清单（每行 METHOD /path）"
    ),
    output: str = typer.Option(None, "--output", "-o", help="输出目录"),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """一次性高危探针：SQL 注入 / RCE / 任意文件读 / 任意文件上传。

    策略（三类漏洞完全一致）：

    * **每个接口只尝试一次**——命中就停，没命中就跳过，不在同一点反复重打
    * **SQL 注入只取数据库版本号**——拿到即收手，不拖库、不读表结构、不写文件
    * **出错即跳过**——请求异常/被 WAF 拦截就跳过该接口，累计出错达
      ``probe_error_abort`` 次自动跳过该类型剩余扫描

    接口清单来源优先级：``--ops-file`` > 会话资产（OpenAPI / JS 端点）> 站点根。
    先用 ``scan`` 或 ``jsaudit`` 跑一遍拿到接口清单，命中率会高得多。
    """
    cfg = _cfg(config)
    if output:
        cfg.output_dir = output
    if max_ops:
        cfg.scan.probe_max_ops = max(1, max_ops)
    if upload:
        cfg.scan.file_upload_probe_enabled = True
        # 不再顺手把 readonly 关掉：上传的闸门已经换成「每次人工审核」
        # （detectors/exploit.py 的 _upload_allowed + probe_upload），
        # readonly 管的是别的东西，替用户改它属于越权。

    want = tuple(k.strip() for k in (only or "").split(",") if k.strip())
    if not want or "all" in want:
        want = ("sqli", "rce", "fileread", "upload")

    console.print(Panel(
        "一次性高危探针 —— 每接口 1 次 · 出错即跳过", style="red", expand=False
    ))

    async def _go():
        import re as _re

        from detectors.exploit import ExploitProbeDetector, Op, ops_from_assets
        from detectors.poc_loader import load_poc_map

        base = (target if "://" in target else f"http://{target}").rstrip("/") + "/"
        poc_map, _ = load_poc_map(cfg.rag.poc_dir)

        if ops_file:
            ops: list[Op] = []
            for line in Path(ops_file).read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 1)
                if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "DELETE"):
                    ops.append(Op(method=parts[0].upper(), path=parts[1].strip(), source="file"))
                else:
                    ops.append(Op(method="GET", path=s, source="file"))
        else:
            # 没有会话资产时，至少用 OpenAPI / JS 端点喂一遍——
            # 直接只打站点根几乎没有意义。
            from collectors.openapi import OpenApiCollector

            oa = OpenApiCollector(cfg.scan, verbose=False)
            assets: list = []
            try:
                assets = await oa.run(base, verbose=False)
            except Exception:  # noqa: BLE001
                pass
            finally:
                await oa.aclose()
            from detectors.js_logic import JsLogicDetector

            jl = JsLogicDetector(cfg.scan, poc_map)
            jl.cfg.js_logic_probe_api = False
            try:
                js_assets, _ = await jl.run(base, verbose=False)
                assets = [*assets, *js_assets]
            except Exception:  # noqa: BLE001
                pass
            finally:
                await jl.aclose()
            ops = ops_from_assets(assets, cfg.scan.probe_max_ops)

        # approver 必须传：缺了它，上传闸门会判定"无审核通道"而全部跳过
        det = ExploitProbeDetector(cfg.scan, poc_map, approver=_cli_approve)
        try:
            return det, await det.run(base, ops, kinds=want, verbose=verbose)
        finally:
            await det.aclose()

    async def _cli_approve(desc: str) -> bool:
        """CLI 模式的上传人工审核通道。

        没有这一步，``detectors/exploit.py`` 的闸门会判定"无审核通道"
        并跳过全部上传 —— ``--upload`` 就永远是个摆设（这正是修之前的症状）。
        为什么要一次一问：上传会在目标上留下文件，批量放行等于把
        "只写一次"变成"想写几次写几次"。
        """
        console.print()
        console.rule("[yellow]⚠ 写操作待审核[/yellow]")
        for ln in (desc or "").splitlines():
            console.print(f"  {ln}")
        console.rule()
        try:
            ans = await asyncio.to_thread(
                input, "  允许这一次？[y/N] "
            )
        except (EOFError, KeyboardInterrupt):
            return False
        ok = (ans or "").strip().lower() in ("y", "yes")
        console.print("  → " + ("[green]已放行[/green]" if ok else "[red]已拒绝[/red]"))
        return ok

    try:
        det, (findings, stats) = asyncio.run(_go())
    except KeyboardInterrupt:
        err.print("[yellow]已中断[/yellow]")
        raise typer.Exit(130) from None

    console.print()
    t = Table(title="探测统计（每接口 1 次）")
    t.add_column("类别", style="cyan")
    t.add_column("尝试")
    t.add_column("命中")
    t.add_column("未命中")
    t.add_column("出错跳过")
    t.add_column("中止后跳过")
    for k, s in stats.items():
        t.add_row(k, str(s["attempted"]), str(s["hit"]), str(s["miss"]),
                  str(s["error"]), str(s.get("skipped", 0)))
    console.print(t)
    for n in det.notes:
        console.print(f"[yellow]· {n}[/yellow]")

    if not findings:
        console.print(
            "\n[green]未命中[/green][dim]：所有接口各尝试 1 次均未取得证据，"
            "已按策略跳过（不重试、不换 payload 重打）。[/dim]"
        )
        return

    t2 = Table(title="命中")
    t2.add_column("等级", width=6)
    t2.add_column("类别", style="cyan", no_wrap=True)
    t2.add_column("位置", overflow="fold")
    t2.add_column("判定依据", overflow="fold")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        t2.add_row(
            f"[{_SEV_STYLE.get(f.severity, 'dim')}]{f.severity.label}[/]",
            f.poc_id,
            _cell(f.matched_at[:70]),
            _cell(_basis_of(f, "判定依据：")[5:105]),
        )
    console.print(t2)

    out = Path(cfg.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = out / f"exploit_{safe_name(target)}.md"
    lines = [f"# 一次性高危探针：{target}", "",
             "策略：每接口 1 次，命中即停，没命中跳过，出错即跳过。", ""]
    for k, s in stats.items():
        lines.append(
            f"- {k}：尝试 {s['attempted']}、命中 {s['hit']}、未命中 {s['miss']}、"
            f"出错跳过 {s['error']}、中止后跳过 {s.get('skipped', 0)}"
        )
    lines.append("")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        lines += [f"## [{f.severity.label}] {f.poc_id} —— {f.name}", "",
                  f"位置：{f.matched_at}", "", f.description or "", "",
                  f"**修复建议**：{f.remediation}", ""]
    p.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[dim]已写入：{p}[/dim]")


# ── tools：本机可调用工具清单 ─────────────────────────────────────


@app.command()
def tools(
    probe: bool = typer.Option(True, "--probe/--no-probe", help="是否探测版本号"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """列出本机可用于 AI Agent 的工具（外部 CLI + 内置能力）。

    这一层是 Agent 能力的天花板：机器上装了什么，模型就能多用什么。
    没装的东西不会暴露给模型——否则它会去调用然后拿到"命令不存在"。
    """
    from core.tools import BUILTINS, EXTERNAL_TOOLS, probe_external, write_user_tools_template

    cfg = _cfg(config)
    # 模板不存在就生成一份：否则用户想加工具时不知道有这条路，
    # 唯一能想到的办法就是去改 tools.py 源码。
    write_user_tools_template(".")
    probes, errs = probe_external(versions=probe)

    t = Table(title=f"外部工具（{sum(1 for p in probes if p.found)}/{len(probes)} 可用）")
    t.add_column("", width=2)
    t.add_column("工具", style="cyan", no_wrap=True)
    t.add_column("来源", no_wrap=True)
    t.add_column("类别")
    t.add_column("版本", no_wrap=True)
    t.add_column("只读模式下", no_wrap=True)
    t.add_column("路径", style="dim", overflow="fold")
    builtin_keys = {s.key for s in EXTERNAL_TOOLS}
    for p in probes:
        blocked = p.spec.intrusive and cfg.scan.readonly
        t.add_row(
            "[green]✓[/green]" if p.found else "[yellow]✗[/yellow]",
            p.spec.key,
            "内置" if p.spec.key in builtin_keys else "[cyan]自定义[/cyan]",
            p.spec.category,
            p.status,
            "[yellow]拒绝执行[/yellow]" if blocked else "可用",
            p.path or "—",
        )
    console.print(t)

    for e in errs:
        console.print(f"[yellow]![/yellow] {e}")

    # 计数直接用 len(BUILTINS)：分组名只是表格的行，不是工具。
    # 曾经写成 len(BUILTINS) - 1（以为要扣掉某个表头），结果标题写 16、
    # 表里却实实在在列了 17 个——标题与内容对不上。
    bt = Table(title=f"内置能力（{len(BUILTINS)} 个，纯 Python，无外部依赖）")
    bt.add_column("分组", style="cyan", no_wrap=True)
    bt.add_column("工具")
    groups: dict[str, list[str]] = {}
    for b in BUILTINS:
        groups.setdefault(b.group, []).append(b.name)
    for g, names in groups.items():
        bt.add_row(g, ", ".join(names))
    console.print(bt)
    console.print(
        "[dim]提示：不带参数运行 `python flower_pow.py` 会自动做一次完整体检，"
        "包括这些工具的探测结果。[/dim]"
    )
    console.print(
        "[dim]装了清单外的新工具？在 data/tools.local.yaml 里登记即可"
        "（不用改 Python 源码），改完重跑本命令生效。\n"
        "注意只支持能在终端直接敲起来的命令行工具——"
        "IDA / Burp 这类图形界面程序无法通过 PATH 探测。[/dim]"
    )


@app.command()
def discover(
    grep: str = typer.Option(None, "--grep", "-g", help="按名字/路径包含关键字过滤"),
    limit: int = typer.Option(40, "--limit", "-n", help="最多列出多少条"),
    all_files: bool = typer.Option(
        False, "--all", help="列出 PATH 下全部可执行文件（数量很大，建议先过滤）"
    ),
) -> None:
    """查看 PATH 里的可执行文件，以及哪些**尚未登记**为工具。

    这是"我明明装了工具 / 配了环境变量，程序却说未安装"的排查入口：
    差集里的每一项都是"存在于PATH 但工具层不认"的命令。

    为什么只列不自动登记：PATH 里有大量同名噪音（``psql`` 是数据库客户端、
    ``ffprobe`` 是视频工具、``secpol`` 是系统组件），**按名字猜哪些是安全
    工具必然出错**。所以把候选摆出来，由你确认后再写进
    ``data/tools.local.yaml``。
    """
    from core.tools import (
        USER_TOOLS_FILE,
        scan_path_executables,
        unregistered_executables,
        write_user_tools_template,
    )

    if all_files:
        rows = scan_path_executables()
        t = Table(title=f"PATH 下可执行文件（{len(rows)} 个，已跳过系统与开发工具目录）")
        t.add_column("名称", style="cyan", no_wrap=True)
        t.add_column("路径", style="dim", overflow="fold")
        for n, f in rows[:limit]:
            t.add_row(n, f)
        console.print(t)
        return

    rows = unregistered_executables()
    if grep:
        g = grep.lower()
        rows = [(n, f) for n, f in rows if g in n.lower() or g in f.lower()]

    console.print(
        f"[dim]PATH 里存在、但工具清单未登记的可执行文件：{len(rows)} 个"
        f"（已跳过系统与开发工具目录）。[/dim]"
    )
    if not rows:
        console.print("[green]没有漏登记的工具——PATH 里能被识别的都已在清单中。[/green]")
    else:
        t = Table(title=f"未登记（显示 {min(len(rows), limit)} / {len(rows)} 条）")
        t.add_column("名称", style="cyan", no_wrap=True)
        t.add_column("路径", style="dim", overflow="fold")
        for n, f in rows[:limit]:
            t.add_row(n, f)
        console.print(t)

    p = write_user_tools_template(".")
    console.print(
        "\n[bold]确认某个确实是安全工具后[/bold]，在 "
        f"[cyan]{p}[/cyan] 里登记（不用改 Python 源码）：\n"
        "  tools:\n"
        "    - key: 工具名\n"
        "      bins: [可执行文件名]\n"
        "      category: 类别\n"
        "      desc: 一句话说明它做什么\n"
        "      flags: [-选项1, -选项2]   # 白名单，留空 = 一个选项都不许传\n"
        "\n[dim]注意两点：\n"
        "  1. 同名不同物很常见（httpx 有 ProjectDiscovery 版和 Python 库版；\n"
        "     curl/wget 在 Unix 与 Windows 上行为不同），先用 `工具名 -version` 核对。\n"
        "  2. 图形界面工具（IDA / Burp / 蚁剑 / Cobalt Strike）无法通过 PATH\n"
        "     探测，登记了也不会被调用——它们没有命令行入口。[/dim]"
    )


