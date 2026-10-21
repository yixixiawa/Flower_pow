"""``scan`` —— 一次性完整扫描（不开交互）。"""

from __future__ import annotations

import asyncio
from pathlib import Path
import typer
from rich.panel import Panel
from core.config_loader import BANNER, Config, load_config
from core.scheduler import Scheduler
from output.evidence import EvidenceStore
from cli.app import app
from cli.app import console
from cli.app import err
from cli.boot import _cfg
from cli.boot import _apply_model
from cli.boot import _print_model_warnings
from cli.summary import _print_summary


# ── scan ──────────────────────────────────────────────────────────


@app.command()
def scan(
    target: str = typer.Argument(..., help="目标 URL，如 http://example.com"),
    config: str = typer.Option(None, "--config", "-c", help="配置文件路径"),
    top_k: int = typer.Option(None, "--top-k", help="RAG 召回条数，覆盖配置"),
    fmt: str = typer.Option("all", "--format", help="md | html | all | json"),
    no_ai: bool = typer.Option(False, "--no-ai", help="禁用 LLM（跳过重排与研判）"),
    no_rag: bool = typer.Option(False, "--no-rag", help="禁用 RAG（全库按严重度）"),
    save_evidence: bool = typer.Option(
        False, "--save-evidence", help="把原始请求响应落盘到 output/evidence/"
    ),
    output: str = typer.Option(None, "--output", "-o", help="输出目录"),
    model: str = typer.Option(
        None, "--model", "-m", help="覆盖模型，如 deepseek-v4-pro（见 models 命令）"
    ),
    deep_model: str = typer.Option(
        None, "--deep-model", help="报告/建模用的强模型，如 deepseek-v4-pro"
    ),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """扫描单个目标：侦察 → RAG → 验证 → 研判 → 报告。"""
    cfg = _cfg(config)
    if no_ai:
        cfg.llm.enabled = False
    if no_rag:
        cfg.rag.enabled = False
    if top_k:
        cfg.rag.top_k = top_k
    if output:
        cfg.output_dir = output
    _apply_model(cfg, model, deep_model)

    console.print(Panel(BANNER.strip("\n"), style="cyan", expand=False))
    _print_model_warnings(cfg)
    sched = Scheduler(cfg)

    try:
        result = asyncio.run(sched.scan(target, verbose=verbose))
    except KeyboardInterrupt:
        err.print("[yellow]已中断[/yellow]")
        raise typer.Exit(130) from None

    if save_evidence and result.findings:
        store = EvidenceStore(Path(cfg.output_dir) / "evidence")
        stats = store.save_result(result)
        if verbose:
            console.print(
                f"[dim]证据落盘：{stats['saved']} 份新文件、"
                f"{stats['reused']} 份去重复用 → {store.root}[/dim]"
            )

    _print_summary(result)
    paths = sched.report(result, fmt=fmt, verbose=verbose)


