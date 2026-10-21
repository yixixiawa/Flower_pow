"""POC 库与知识库三件套：``index`` / ``knowledge`` / ``pocs``。"""

from __future__ import annotations

from pathlib import Path
import typer
from rich.panel import Panel
from rich.table import Table
from detectors.poc_loader import filter_executable, load_poc_map
from kb.indexer import VectorStore, build_index, dump_index_stats
from cli.app import app
from cli.app import console
from cli.app import err
from cli.app import _SEV_STYLE
from cli.boot import _cfg


# ── index ─────────────────────────────────────────────────────────


@app.command()
def index(
    config: str = typer.Option(None, "--config", "-c"),
    rebuild: bool = typer.Option(False, "--rebuild", help="强制重建（忽略缓存）"),
) -> None:
    """构建 / 重建 POC 向量索引。"""
    cfg = _cfg(config)
    db = Path(cfg.rag.db_dir) / "poc_index.json"

    pocs, errs = load_poc_map(cfg.rag.poc_dir)
    if errs:
        for e in errs:
            err.print(f"[yellow]![/yellow] {e}")

    if not rebuild and db.is_file():
        store = VectorStore.load(db)
        if store and len(store) >= len(pocs):
            console.print(f"[green]✓[/green] 索引已是最新：{dump_index_stats(store)}")
            console.print(f"[dim]  {db}[/dim]")
            return

    console.print(f"[+] 正在索引 {len(pocs)} 条 POC（维度 {cfg.rag.dim}）…")
    store, errs = build_index(
        cfg.rag.poc_dir, db, dim=cfg.rag.dim, boost_terms=cfg.rag.boost_terms
    )
    for e in errs:
        err.print(f"[yellow]![/yellow] {e}")
    console.print(f"[green]✓[/green] {dump_index_stats(store)}")
    console.print(f"[dim]  保存到 {db}[/dim]")


# ── knowledge ─────────────────────────────────────────────────────


@app.command()
def knowledge(
    action: str = typer.Argument("list", help="list（默认）| search | clear"),
    query: str = typer.Option(None, "--query", "-q", help="search 时的查询词"),
    limit: int = typer.Option(10, "--limit", "-n", help="显示条数"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """查看沉淀知识库（扫描发现回灌）。

    知识库与 POC 索引分开存放：``poc_index.json`` 是人写的检测规则，
    ``knowledge_index.json`` 是历次扫描**确认过**的真实发现。
    同一个站重复测时，后者会被召回，不必从头再踩一遍坑。
    """
    from kb.knowledge import KnowledgeStore

    cfg = _cfg(config)
    db = Path(cfg.rag.knowledge_db)

    if action == "clear":
        if not db.is_file():
            console.print("知识库本来就是空的")
            return
        if not typer.confirm(f"确认删除 {db}？该文件不可恢复"):
            console.print("已取消")
            return
        db.unlink()
        console.print(f"[green]✓[/green] 已清空知识库")
        return

    ks = KnowledgeStore.open(db, cfg.rag.dim, max_entries=cfg.rag.knowledge_max_entries)
    if not len(ks):
        console.print("[yellow]知识库为空[/yellow]")
        console.print(
            "[dim]还没有沉淀过扫描发现。跑一次 scan 或 chat，"
            "确认过的发现（medium 及以上、非误报）会自动入库。[/dim]"
        )
        return

    if action == "search":
        if not query:
            err.print("[red]--query 不能为空[/red]")
            raise typer.Exit(1)
        hits = ks.search(query, top_k=limit)
        if not hits:
            console.print(f"无命中：{query}")
            return
        console.print(f"[cyan]知识库检索 {query!r}（{len(hits)} 条）[/cyan]")
        for pid, score in hits:
            m = (ks.records.get(pid) or {}).get("meta") or {}
            console.print(
                f"  {score:.4f}  [{m.get('severity','?')}] {m.get('name', pid)}"
            )
            console.print(f"           {m.get('matched_at','')}  [dim]{pid}[/dim]")
        return

    # 默认 list
    console.print(f"[cyan]{ks.summary()}[/cyan]")
    console.print(f"[dim]  {db}[/dim]\n")
    for r in ks.recent(limit):
        sev = r.get("severity", "?")
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(str(sev), "dim")
        console.print(
            f"  [{color}]{str(sev):<8}[/{color}] {r.get('name', r.get('id'))}"
        )
        console.print(f"           [dim]{r.get('matched_at','')}  {r.get('target','')}[/dim]")


# ── pocs ──────────────────────────────────────────────────────────


@app.command()
def pocs(
    grep: str = typer.Option(None, "--grep", "-g", help="按名称/ID/标签过滤"),
    detail: bool = typer.Option(False, "--detail", help="显示每条 POC 详情"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """列出 POC 库。"""
    cfg = _cfg(config)
    poc_map, errs = load_poc_map(cfg.rag.poc_dir)
    items = list(poc_map.values())
    for e in errs:
        err.print(f"[yellow]![/yellow] {e}")

    if grep:
        low = grep.lower()
        items = [
            p for p in items
            if low in p.id.lower() or low in p.name.lower()
            or any(low in t for t in p.tags)
            or any(low in a for a in p.applies_to)
        ]
    if not items:
        console.print("[yellow]无匹配 POC[/yellow]")
        return

    t = Table(title=f"POC 库（{len(items)} 条，来自 {cfg.rag.poc_dir}）")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("名称")
    t.add_column("类别")
    t.add_column("等级")
    t.add_column("适用技术", style="dim")
    t.add_column("CVE", style="dim")
    for p in sorted(items, key=lambda x: x.severity.rank, reverse=True):
        t.add_row(
            p.id, p.name, p.category.value,
            f"[{_SEV_STYLE[p.severity]}]{p.severity.label}[/]",
            ",".join(p.applies_to) or "通用",
            ",".join(p.cve) or "-",
        )
    console.print(t)

    if detail:
        for p in items:
            rules = "；".join(
                f"{r.op.value}({'/'.join(r.patterns[:3]) or r.header})" for r in p.rules
            ) or "仅状态码"
            console.print(
                Panel(
                    f"[bold]{p.name}[/bold]  ({p.id})\n\n"
                    f"说明：{p.description or '-'}\n"
                    f"修复：{p.remediation or '-'}\n"
                    f"路径：{', '.join(p.request.search_paths[:8])}\n"
                    f"规则：{rules}\n"
                    f"标签：{', '.join(p.tags)}\n"
                    f"来源：{p.source}",
                    title=p.category.value,
                    border_style="dim",
                )
            )


