"""引擎状态与 JS 审计：``engines`` / ``jsaudit``。"""

from __future__ import annotations

import asyncio
from pathlib import Path
import typer
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from core.scheduler import Scheduler
from core.state import POC, ScanResult, Severity, safe_name
from detectors.poc_loader import filter_executable, load_poc_map
from kb.indexer import VectorStore, build_index, dump_index_stats
from cli.app import app
from cli.app import console
from cli.app import err
from cli.app import _SEV_STYLE
from cli.boot import _cfg
from cli.boot import _print_model_warnings


# ── engines ───────────────────────────────────────────────────────


@app.command()
def engines(
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """检查引擎、采集器、索引、LLM 的可用状态。"""
    cfg = _cfg(config)
    sched = Scheduler(cfg)
    console.print(Panel(sched.describe(), title="运行状态", border_style="cyan"))
    # 模型名被静默降级时必须在这里说出来——engines 是"体检"命令，
    # 用户来看状态却发现不了自己配了个已下线的模型，那这个命令就失职了。
    _print_model_warnings(cfg)
    if cfg.llm.model_warnings:
        console.print(
            "[dim]（用 `models` 命令查看完整模型清单与旧名对照）[/dim]"
        )

    pocs, errs = load_poc_map(cfg.rag.poc_dir)
    exec_pocs, skip = filter_executable(list(pocs.values()), cfg.scan.readonly)
    t = Table(title="POC 与索引")
    t.add_column("项", style="cyan")
    t.add_column("值")
    t.add_row("POC 目录", cfg.rag.poc_dir)
    t.add_row("已加载", f"{len(pocs)} 条")
    t.add_row(f"可执行（{'只读' if cfg.scan.readonly else '含写操作'}）", f"{len(exec_pocs)} 条")
    t.add_row("被过滤", f"{len(skip)} 条")
    db = Path(cfg.rag.db_dir) / "poc_index.json"
    store = VectorStore.load(db) if db.is_file() else None
    t.add_row(
        "向量索引",
        f"{len(store)} 条 @ {db}" if store else "[yellow]未构建（运行 index）[/yellow]",
    )
    console.print(t)

    for e in errs:
        console.print(f"[yellow]![/yellow] {e}")


def _cell(s: str) -> Text:
    """表格单元格用 :class:`rich.text.Text` 包一层。

    直接传字符串会被 Rich 当 markup 解析，还会做 emoji 替换——
    实测 ``root:x:0:0`` 里的 ``:x:`` 被渲染成 ❌，判定依据当场变成乱码。
    ``Text`` 不做这两件事。
    """
    return Text(s)


def _basis_of(f, prefix: str) -> str:
    """从 finding.description 里取出以 prefix 开头的那一行（判定/命中依据）。"""
    for line in (f.description or "").splitlines():
        if line.startswith(prefix):
            return line[:110]
    return (f.description or "").split("\n")[0][:110]


# ── jsaudit：JS 页面内容审计 ──────────────────────────────────────


@app.command()
def jsaudit(
    target: str = typer.Argument(..., help="目标 URL，如 http://example.com"),
    config: str = typer.Option(None, "--config", "-c"),
    no_probe: bool = typer.Option(
        False, "--no-probe", help="只做静态分析，不打免凭证请求验证接口"
    ),
    max_endpoints: int = typer.Option(
        0, "--max-endpoints", "-n", help="最多探测多少个 JS 接口，0=用配置值"
    ),
    output: str = typer.Option(None, "--output", "-o", help="输出目录"),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """扫描页面 JS 内容，分析前端逻辑漏洞与未鉴权接口。

    与 ``recon_js``（资产提取）不同，这里找的是**只成立于前端代码的漏洞**：

    * 权限判断写在前端（``role === 'admin'``、把 role 存进 localStorage）
    * 调试/后门开关没关（``bypassAuth: true``、``isMock: true``）
    * 金额在前端算完再提交（改 JS 就能改价）
    * 路由声明了 ``requiresAuth`` 却没有全局守卫
    * 注释里残留的测试账号 / 待办
    * **JS 里硬编码的接口，不带凭证就能读到业务数据**

    这些打再多后端请求也测不出来——必须先读 JS。
    """
    cfg = _cfg(config)
    if output:
        cfg.output_dir = output
    if max_endpoints:
        cfg.scan.js_logic_max_endpoints = max(1, max_endpoints)
    cfg.scan.js_logic_probe_api = not no_probe

    console.print(Panel("JS 页面内容审计 —— 前端逻辑 / 未鉴权接口", style="cyan", expand=False))

    async def _go():
        from detectors.js_logic import JsLogicDetector
        from detectors.poc_loader import load_poc_map

        base = target if "://" in target else f"http://{target}"
        poc_map, _ = load_poc_map(cfg.rag.poc_dir)
        det = JsLogicDetector(cfg.scan, poc_map)
        try:
            return await det.run(base.rstrip("/") + "/", verbose=verbose)
        finally:
            await det.aclose()

    try:
        assets, findings = asyncio.run(_go())
    except KeyboardInterrupt:
        err.print("[yellow]已中断[/yellow]")
        raise typer.Exit(130) from None

    eps = [a for a in assets if a.kind == "endpoint"]
    console.print(
        f"\n[bold]JS 来源[/bold]：{len(assets) and '已分析' or '无'}；"
        f"提取接口 {len(eps)} 个；发现 {len(findings)} 项"
    )
    if not findings:
        console.print(
            "[green]未发现前端逻辑缺陷[/green]"
            "[dim]（也可能是页面为纯静态站、JS 未下载到，或 bundle 已混淆）[/dim]"
        )
        return

    t = Table(title="JS 审计发现")
    t.add_column("等级", width=6)
    t.add_column("规则", style="cyan", no_wrap=True)
    t.add_column("位置", overflow="fold")
    t.add_column("说明", overflow="fold")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        t.add_row(
            f"[{_SEV_STYLE.get(f.severity, 'dim')}]{f.severity.label}[/]",
            f.poc_id,
            _cell(f.matched_at[:70]),
            _cell(_basis_of(f, "命中")),
        )
    console.print(t)

    # 落一份 Markdown，便于贴进报告
    out = Path(cfg.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = out / f"jsaudit_{safe_name(target)}.md"
    lines = [f"# JS 页面内容审计：{target}", ""]
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        lines += [f"## [{f.severity.label}] {f.poc_id} —— {f.name}", "",
                  f"位置：{f.matched_at}", "", f.description or "", "",
                  f"**修复建议**：{f.remediation}", ""]
    p.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[dim]已写入：{p}[/dim]")


