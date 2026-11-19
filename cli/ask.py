"""检索：``ask``（只 RAG 检索，不发请求）。

原来的 ``intel``（CVE 情报查询）已迁移为 ``cli.intel`` 的 ``intel cve`` 子命令，
与规则库管理命令（check/update/status/rollback）挂在同一棵子树下。
"""

from __future__ import annotations

import typer
from rich.panel import Panel
from rich.table import Table
from core.scheduler import Scheduler
from detectors.poc_loader import filter_executable, load_poc_map
from cli.app import app
from cli.app import console
from cli.app import err
from cli.app import _SEV_STYLE
from cli.boot import _cfg
from cli.boot import _apply_model
from cli.boot import _print_model_warnings


# ── ask（只检索，不发请求）──────────────────────────────────────────


@app.command()
def ask(
    query: str = typer.Argument(..., help="自由文本，如 'spring boot actuator 暴露'"),
    top_k: int = typer.Option(8, "--top-k", "-k"),
    config: str = typer.Option(None, "--config", "-c"),
    no_ai: bool = typer.Option(False, "--no-ai", help="跳过 LLM 重排"),
    model: str = typer.Option(
        None, "--model", "-m", help="覆盖重排用的模型（见 models 命令）"
    ),
) -> None:
    """只做 RAG 检索，不发任何请求——用来调 POC 库与索引。"""
    from kb.retriever import Retriever

    cfg = _cfg(config)
    if no_ai:
        cfg.llm.enabled = False
    _apply_model(cfg, model)
    _print_model_warnings(cfg)
    pocs, errs = load_poc_map(cfg.rag.poc_dir)
    for e in errs:
        err.print(f"[yellow]![/yellow] {e}")

    retr, errs = Retriever.from_config(cfg.rag, pocs, verbose=True)
    for e in errs:
        err.print(f"[yellow]![/yellow] {e}")
    if retr is None:
        err.print("[red]索引不可用[/red]")
        raise typer.Exit(1)

    # 构造一个最小 ScanResult 复用 retrieve 的 query 逻辑
    from core.state import Fingerprint, ScanResult

    sr = ScanResult(target=query, fingerprints=[Fingerprint(target=query, title=query)])
    out = retr.retrieve(sr, top_k=top_k)

    if not no_ai:
        sched_llm = Scheduler(cfg)
        out = retr.rerank_with_llm(out, query, query, sched_llm.llm)

    t = Table(title=f"RAG 检索：{query[:60]}")
    t.add_column("得分", justify="right")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("名称")
    t.add_column("等级")
    t.add_column("依据", style="dim")
    for r in out.results:
        t.add_row(
            f"{r.final_score:.3f}",
            r.poc.id,
            r.poc.name,
            f"[{_SEV_STYLE[r.poc.severity]}]{r.poc.severity.label}[/]",
            r.reason,
        )
    console.print(t)
    if out.notes:
        for n in out.notes:
            console.print(f"[dim]· {n}[/dim]")