"""``subs`` —— 子域批量发现与逐个下探。

这一族最重（发现 → 指纹 → 摘要 → dirsearch 下探都在里面），所以单独成块。"""

from __future__ import annotations

import asyncio
import json
import os
import time
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


# ── subs：子域批量扫描 ─────────────────────────────────────────────


def _load_targets(source: str, root: str) -> tuple[list[str], list[str]]:
    """从文件/剪贴板/字面量读入目标。返回 ``(urls, notes)``。

    刻意支持 **直接传一段文本**：findSubDomain 的输出就是纯文本，
    让用户先存成文件再跑一步是多余的。
    """
    from core.subdomain import parse_input

    # "-" 表示读剪贴板（扩展的"复制到剪贴板"按钮就是为这个准备的）
    raw = source
    if source == "-":
        try:
            import subprocess

            ps = (
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"]
                if os.name == "nt"
                else ["pbpaste"]
            )
            r = subprocess.run(
                ps, capture_output=True, timeout=15, creationflags=getattr(
                    subprocess, "CREATE_NO_WINDOW", 0
                ) if os.name == "nt" else 0,
            )
            # **Windows 剪贴板常是 GBK**，直接按 utf-8 解会抛 UnicodeDecodeError
            # （实测：扩展写的是 ASCII 内容，用 GBK 解也无妨；但用户自己往剪贴板里
            #  贴的中文域名说明就废了）。这里按 utf-8 → gbk → 兜底逐个试。
            raw = ""
            for enc in ("utf-8", "gbk", "utf-16"):
                try:
                    raw = r.stdout.decode(enc)
                    break
                except (UnicodeDecodeError, AttributeError):
                    continue
            if not raw:
                raw = (r.stdout or b"").decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return [], [f"读取剪贴板失败：{type(exc).__name__}: {exc}"]
        if not raw.strip():
            return [], ["剪贴板是空的"]

    p = Path(raw)
    if p.is_file():
        text = p.read_text(encoding="utf-8", errors="replace")
    else:
        text = raw  # 当作字面量文本处理

    # 优先按 JSON 解，失败再当纯文本——JSON 能保留 hosts 的结构信息
    data: object = text
    if p.is_file() and p.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], [f"{p} 不是合法 JSON：{exc}"]
    try:
        return parse_input(data, root)
    except Exception as exc:  # noqa: BLE001
        return [], [f"解析失败：{type(exc).__name__}: {exc}"]


@app.command()
def subs(
    source: str = typer.Argument(
        ..., help="域名清单：文件路径、字面量文本，或 - 表示读剪贴板"
    ),
    root: str = typer.Option(
        "", "--root", "-r", help="主域，只扫它的子域（如example.com）"
    ),
    mode: str = typer.Option(
        "probe", "--mode", help="probe=只探活+指纹（默认） | full=每个都跑完整流水线"
    ),
    concurrency: int = typer.Option(8, "--concurrency", "-c", help="并发数（默认 8）"),
    timeout: float = typer.Option(60.0, "--timeout", "-t", help="单域上限秒数"),
    dirsearch: str = typer.Option(
        "", "--dirsearch", help="用 dirsearch 对所有在线子域做路径爆破（填 true/false）"
    ),
    output: str = typer.Option(None, "--output", "-o", help="报告输出目录"),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """子域批量扫描：读入域名清单 → 并发逐个探活 → 汇总报告。

    输入可以是任意来源的主机名清单：纯文本（域名 / hosts / URL / 邮箱混排
    都能解析）、JSON 数组，或 ``-`` 表示读剪贴板。

    默认 ``--mode probe`` **只做探活 + 指纹 + 当前页 JS，不跑 POC**：
    一百个子域全跑 POC 与"筛出值得深挖的子域"是两件事，混在一起只会
    得到几百条低危配置缺失，把真正的问题淹掉。
    """
    from core.subdomain import SubdomainScanner

    cfg = _cfg(None)
    if output:
        cfg.output_dir = output
    urls, notes = _load_targets(source, root)
    for n in notes:
        console.print(f"[yellow]![/yellow] {n}")
    if not urls:
        err.print("[red]没有可扫描的目标[/red]")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"目标 [bold]{len(urls)}[/bold] 个"
            + (f"（限定主域 {root}）" if root else "")
            + f"\n模式 {mode}｜并发 {concurrency}｜单域上限 {timeout:.0f}s",
            title="子域批量扫描",
            border_style="cyan",
        )
    )

    scanner = SubdomainScanner(cfg, concurrency=concurrency, per_host_timeout=timeout)
    report = asyncio.run(scanner.run(urls, mode=mode, verbose=verbose))

    _print_subs_summary(report)

    # 报告落盘
    outdir = Path(cfg.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    base = outdir / f"subs_{root or 'batch'}_{stamp}"
    (base.with_suffix(".json")).write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md = _subs_markdown(report)
    base.with_suffix(".md").write_text(md, encoding="utf-8")
    console.print(f"\n[dim]报告：{base}.json / {base}.md[/dim]")

    if dirsearch.lower() in ("1", "true", "yes", "y"):
        paths = asyncio.run(_subs_dirsearch(cfg, report, verbose))
        console.print(
            f"[dim]dirsearch 结果已汇总：{len(paths)} 个在线子域完成路径爆破[/dim]"
        )


def _print_subs_summary(report) -> None:
    t = Table(title="子域扫描汇总")
    t.add_column("项", style="cyan")
    t.add_column("值", justify="right")
    agg = report.by_severity()
    t.add_row("目标总数", str(len(report.entries)))
    t.add_row("在线", f"[green]{len(report.reachable)}[/green]")
    t.add_row("不可达", str(len(report.entries) - len(report.reachable)))
    t.add_row("发现合计", f"[bold]{report.total_findings}[/bold]")
    for k, v in agg.items():
        if v:
            t.add_row(f"  {_SEV_STYLE.get(Severity(k), '')}{Severity(k).label}[/]", str(v))
    t.add_row("耗时", f"{report.finished_at - report.started_at:.1f}s")
    console.print(t)

    if report.reachable:
        rt = Table(title=f"在线子域（{len(report.reachable)}）")
        rt.add_column("主机", style="cyan", no_wrap=True)
        rt.add_column("状态", justify="right")
        rt.add_column("技术栈", style="dim")
        rt.add_column("资产", justify="right")
        rt.add_column("发现", justify="right")
        rt.add_column("耗时", justify="right")
        for e in report.reachable[:60]:
            tech = ""
            if e.result and e.result.fingerprints:
                tech = ",".join(e.result.fingerprints[0].tech)[:28]
            rt.add_row(
                e.host.split("//")[-1],
                str(e.status),
                tech or "—",
                str(len(e.result.assets) if e.result else 0),
                str(e.findings_count),
                f"{e.elapsed:.1f}s",
            )
        console.print(rt)

    offline = [e for e in report.entries if not e.reachable]
    if offline:
        console.print(
            f"[dim]不可达 {len(offline)} 个："
            + ", ".join(e.host.split("//")[-1] for e in offline[:15])
            + ("…" if len(offline) > 15 else "")
            + "[/dim]"
        )


def _subs_markdown(report) -> str:
    agg = report.by_severity()
    lines = [
        f"# 子域扫描报告 — {report.root or '批量'}",
        "",
        f"- 目标：{len(report.entries)} 个，在线 {len(report.reachable)} 个",
        f"- 发现：{report.total_findings} 项",
        f"- 耗时：{report.finished_at - report.started_at:.1f}s",
        "",
        "## 按等级",
        "",
        "| 等级 | 数量 |",
        "| --- | --- |",
    ]
    for k, v in agg.items():
        lines.append(f"| {Severity(k).label} | {v} |")
    lines += ["", "## 在线子域", "", "| 主机 | 状态 | 技术栈 | 发现 |", "| --- | --- | --- | --- |"]
    for e in report.reachable:
        tech = ",".join(e.result.fingerprints[0].tech) if e.result and e.result.fingerprints else ""
        lines.append(
            f"| {e.host} | {e.status} | {tech} | {e.findings_count} |"
        )
    if report.notes:
        lines += ["", "## 说明", ""] + [f"- {n}" for n in report.notes]
    return "\n".join(lines) + "\n"


async def _subs_dirsearch(cfg, report, verbose: bool) -> list[str]:
    """对在线子域跑 dirsearch 路径爆破（并行）。

    用 ``dirsearch -l`` 一次喂整份 URL 清单，而不是每个子域起一个进程——
    dirsearch 自带多线程，用它的批处理比外层并发更省进程、也更快。

    被 WAF / 限流拦截时自动降速到 ``-t 1`` 重跑（见
    :mod:`collectors.dirsearch_runner`）：单线程 + ``--delay`` + ``--max-rate``
    三重降速——单线程只解决并发压力，不解决请求速率。
    """
    import tempfile

    from collectors.dirsearch_runner import run_with_throttle_retry
    from core.tools import EXTERNAL_TOOLS, probe_external

    spec = next((s for s in EXTERNAL_TOOLS if s.key == "dirsearch"), None)
    probes, _ = probe_external(keys=["dirsearch"], versions=False)
    probe = probes[0] if probes else None
    if spec is None or probe is None or not probe.found:
        console.print(
            "[yellow]![/yellow] 未探测到 dirsearch，跳过路径爆破"
            "（可在 data/tools.local.yaml 登记路径）"
        )
        return []

    urls = [e.host for e in report.reachable]
    if not urls:
        return []

    wl = Path(cfg.rag.db_dir).parent / "wordlists" / "builtin.txt"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    ) as fh:
        fh.write("\n".join(urls))
        list_file = fh.name

    dict_size = 0
    if wl.is_file():
        try:
            dict_size = sum(
                1
                for ln in wl.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip()
            )
        except OSError:
            dict_size = 0
    if verbose:
        console.print(
            f"[dim]dirsearch -l {list_file}（{len(urls)} 个子域，"
            f"字典 {dict_size or '内置'} 条）[/dim]"
        )

    events: list[dict] = []

    def on_event(kind: str, payload: dict) -> None:
        events.append({"kind": kind, **payload})
        if not verbose:
            return
        if kind == "dirsearch_throttle":
            console.print(
                f"[yellow]![/yellow] dirsearch 被拦截（{payload.get('reason')}），"
                f"降速到 -t {payload.get('next_threads')} 重试"
            )
        elif kind == "dirsearch_still_blocked":
            console.print(
                "[red]![/red] 单线程重试后仍被拦截，判定目标存在 WAF 行为检测"
            )

    try:
        outcome = await run_with_throttle_retry(
            probe.path,
            list_file=Path(list_file),
            wordlist=wl if wl.is_file() else None,
            dictionary_size=dict_size,
            threads=max(10, cfg.concurrency),
            timeout=1800,
            max_retries=1,
            on_event=on_event,
        )
    finally:
        try:
            Path(list_file).unlink(missing_ok=True)
        except OSError:
            pass

    # 落盘完整过程，便于事后复盘「是否降速过、为什么」
    outdir = Path(cfg.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    (outdir / f"dirsearch_subs_{stamp}.json").write_text(
        json.dumps(
            {
                "urls": len(urls),
                "dictionary_size": dict_size,
                "threads_attempts": outcome.attempts,
                "throttled": outcome.throttled,
                "block_reasons": outcome.block_reasons,
                "results": len(outcome.assets),
                "events": events,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    if verbose:
        console.print(
            f"[dim]dirsearch 过程已存：output/dirsearch_subs_{stamp}.json"
            f"（{len(outcome.assets)} 条命中，线程尝试 {outcome.attempts}）[/dim]"
        )
    return urls


