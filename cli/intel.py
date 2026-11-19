"""动态规则库管理：``intel check / update / status / rollback / cve``。

原来的 ``intel`` 是单命令（查 CVE 情报），升级为子命令组后迁移为
``intel cve``——语义不变，只是挂到了同一棵子树下，避免与规则管理命令撞名。

四个规则命令对应更新器的四种动作：

================== =====================================================
命令                 动作
================== =====================================================
``intel check``     fetch 远程、比较 SHA、报告待更新数量（**不落盘**）
``intel update``    增量同步：只处理旧 Commit → 新 Commit 之间变化的 YAML
``intel status``    本地仓库克隆状态、规则版本统计、发布数量
``intel rollback``  回退到上一个（或 ``--to`` 指定的）已同步 Commit
================== =====================================================
"""

from __future__ import annotations

import typer
from rich.table import Table

from cli.app import app, console, err

intel_app = typer.Typer(
    help="动态规则库：Git 驱动的 POC 增量更新与版本管理",
    no_args_is_help=True,
)
app.add_typer(intel_app, name="intel")


def _updater(config: str | None):
    """按配置构造 Updater。独立小函数是为了让四个命令共享路径解析逻辑。"""
    from cli.boot import _cfg
    from intel.updater.scheduler import _updater_from_config

    return _updater_from_config(_cfg(config))


def _print_summary(results: list[dict]) -> None:
    """update / 回滚结果的统一打印。"""
    t = Table(title="规则同步结果")
    t.add_column("仓库", style="cyan", no_wrap=True)
    t.add_column("状态")
    t.add_column("新增", justify="right")
    t.add_column("更新", justify="right")
    t.add_column("下架", justify="right")
    t.add_column("非法", justify="right")
    t.add_column("发布", justify="right")
    t.add_column("备注", style="dim")
    for r in results:
        status = r.get("status") or "?"
        style = {
            "updated": "green",
            "up-to-date": "dim",
            "skipped": "dim",
            "no-url": "dim",
            "error": "red",
        }.get(status, "yellow")
        note = r.get("to_sha") or ""
        if r.get("errors"):
            note = f"{note}; {r['errors'][0]}" if note else r["errors"][0]
        if len(r.get("errors") or []) > 1:
            note += f"（共 {len(r['errors'])} 条）"
        t.add_row(
            r["repo"],
            f"[{style}]{status}[/]",
            str(r.get("added", 0)),
            str(r.get("updated", 0)),
            str(r.get("removed", 0)),
            str(r.get("invalid", 0)),
            str(r.get("published", 0)),
            note[:80],
        )
    console.print(t)


# ── intel check ──────────────────────────────────────────────────


@intel_app.command("check")
def check(
    repo: str = typer.Option(None, "--repo", help="只检查指定仓库（默认全部启用的）"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """检查远程规则更新：fetch + SHA 比较，不做任何修改。"""
    from intel.updater.git_sync import GitSyncError

    upd = _updater(config)
    try:
        rows = upd.check(repo)
    except GitSyncError as exc:
        err.print(f"[red]检查失败：{exc}[/red]")
        raise typer.Exit(1)
    if not rows:
        err.print("[yellow]没有已启用且配置了 URL 的仓库[/yellow]")
        raise typer.Exit(1)
    t = Table(title="远程规则更新检查")
    t.add_column("仓库", style="cyan", no_wrap=True)
    t.add_column("远程 Commit", style="dim")
    t.add_column("本地记录", style="dim")
    t.add_column("状态")
    t.add_column("待处理 YAML", justify="right")
    for r in rows:
        state = (
            "[green]已是最新[/green]" if r["up_to_date"] else "[yellow]有更新[/yellow]"
        )
        t.add_row(
            r["repo"],
            r["remote_sha"] or "-",
            r["local_sha"] or "-（首次同步将全量）",
            state,
            str(r["pending_yaml"]),
        )
    console.print(t)
    for w in upd.warnings:
        console.print(f"[dim]· {w}[/dim]")


# ── intel update ─────────────────────────────────────────────────


@intel_app.command("update")
def update(
    repo: str = typer.Option(None, "--repo", help="只更新指定仓库"),
    force: bool = typer.Option(False, "--force", help="忽略 SHA 记录，强制全量重注册"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """执行增量更新：只处理上次同步以来变化的 YAML 并发布到 poc/community。"""
    upd = _updater(config)
    results = upd.update(repo, force=force)
    _print_summary(results)
    for w in upd.warnings:
        console.print(f"[dim]· {w}[/dim]")
    changed = any(r.get("status") == "updated" for r in results)
    if changed:
        console.print("[dim]· 规则已变化，建议运行 flower-pow index 刷新 RAG 索引[/dim]")


# ── intel status ─────────────────────────────────────────────────


@intel_app.command("status")
def status(config: str = typer.Option(None, "--config", "-c")) -> None:
    """查看本地规则状态：仓库 / Commit / 版本统计 / 发布数量。"""
    upd = _updater(config)
    rows = upd.status()
    t = Table(title="本地规则状态")
    t.add_column("仓库", style="cyan", no_wrap=True)
    t.add_column("启用")
    t.add_column("克隆")
    t.add_column("上次同步 Commit", style="dim")
    t.add_column("上次同步时间", style="dim")
    t.add_column("approved", justify="right")
    t.add_column("removed", justify="right")
    t.add_column("发布", justify="right")
    t.add_column("flower/nuclei", justify="right")
    for r in rows:
        t.add_row(
            r["repo"],
            "[green]✓[/]" if r["enabled"] else "[dim]✗[/]",
            "[green]✓[/]" if r["cloned"] else "[dim]✗[/]",
            r["last_commit"],
            r["last_sync"],
            str(r.get("approved", 0)),
            str(r.get("removed", 0)),
            str(r["published"]),
            f"{r.get('flower', 0)}/{r.get('nuclei', 0)}",
        )
    console.print(t)
    last_auto = upd.state.state.get("last_auto_check")
    if last_auto:
        console.print(f"[dim]· 上次自动更新日期：{last_auto}[/dim]")
    for w in upd.warnings:
        console.print(f"[dim]· {w}[/dim]")


# ── intel rollback ───────────────────────────────────────────────


@intel_app.command("rollback")
def rollback(
    repo: str = typer.Option(None, "--repo", help="目标仓库（多个仓库时必填）"),
    to: str = typer.Option(None, "--to", help="回退到的 Commit（前缀即可；默认上一个版本）"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """回滚规则版本：重置到已同步过的 Commit 并全量重注册。"""
    from intel.updater.git_sync import GitSyncError

    upd = _updater(config)
    enabled = [c.name for c in upd.repos if c.enabled]
    target = repo or (enabled[0] if len(enabled) == 1 else None)
    if not target:
        err.print("[red]存在多个仓库，请用 --repo 指定要回滚的仓库[/red]")
        raise typer.Exit(1)
    try:
        result = upd.rollback(target, to=to)
    except GitSyncError as exc:
        err.print(f"[red]回滚失败：{exc}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]✓[/green] {result['repo']} 已回滚到 {result['to_commit']}，"
        f"重新发布 {result['published']} 条规则"
    )
    for e in result["errors"]:
        err.print(f"[yellow]![/yellow] {e}")


# ── intel cve（原 intel 命令迁移）────────────────────────────────


@intel_app.command("cve")
def cve(
    cve_id: str = typer.Argument(..., help="CVE 编号，如 CVE-2021-44228"),
    refresh: bool = typer.Option(False, "--refresh", help="强制刷新本地缓存"),
) -> None:
    """查询外部 CVE 情报（CVSS / KEV / EPSS，来自 pocindex.io 元数据）。"""
    from rich.panel import Panel

    from kb.intel import get_intel

    store = get_intel()
    if refresh:
        n = store.refresh(force=True)
        console.print(f"[+] 已刷新，本地共 {n} 条 CVE 情报")
    info = store.lookup(cve_id)
    if not info:
        err.print(f"[yellow]未找到 {cve_id} 的情报（可能该 CVE 尚无公开 PoC记录）[/yellow]")
        raise typer.Exit(1)

    t = Table(title=f"{cve_id}")
    t.add_column("字段")
    t.add_column("值")
    t.add_row("CVSS", f"{info.cvss}" if info.cvss is not None else "-")
    t.add_row("等级", info.severity or "-")
    t.add_row("向量", info.vector or "-")
    t.add_row("CISA KEV", "[red]在野利用[/red]" if info.kev else "否")
    t.add_row(
        "EPSS",
        f"{info.epss:.1%}" if info.epss is not None else "-",
    )
    t.add_row("有公开 PoC", "是" if info.has_poc else "否")
    t.add_row("有 Nuclei 模板", "是" if info.has_nuclei else "否")
    console.print(t)
    if info.description:
        console.print(Panel(info.description[:800], title="描述", border_style="dim"))
    if store.errors:
        for e in store.errors:
            console.print(f"[dim]· {e}[/dim]")
