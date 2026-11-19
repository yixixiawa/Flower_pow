"""扫描结果摘要打印（各命令共用）。"""

from __future__ import annotations

from rich.table import Table
from core.state import POC, ScanResult, Severity, safe_name
from cli.app import console
from cli.app import _SEV_STYLE


# ── 输出辅助 ──────────────────────────────────────────────────────


def _print_summary(result: ScanResult) -> None:
    counts = result.counts()
    sc = result.status_counts()
    t = Table(title=f"扫描结果 — {result.target}")
    t.add_column("等级")
    t.add_column("数量", justify="right")
    for s in Severity:
        t.add_row(s.label, str(counts.get(s.value, 0)))
    # 合计只算**已确认**：待复核与误报不是漏洞，加进来会虚增战果
    t.add_row("[bold]合计[/bold]", f"[bold]{sc['confirmed']}[/bold]")
    console.print(t)
    console.print(
        f"[dim]定级：已确认 {sc['confirmed']} · 待人工复核 {sc['needs_review']}"
        f"（不计入漏洞数） · 误报/无效命中 {sc['rejected']}[/dim]"
    )
    clue_n = len(result.active_clues())
    if clue_n:
        console.print(
            f"[dim]另有 {clue_n} 条待验证线索（被质量闸门拦下，未进报告）："
            "flower_pow findings --pending[/dim]"
        )

    info: list[str] = [
        f"POC库 {result.pocs_loaded}",
        f"召回 {result.pocs_selected}",
        f"执行 {result.pocs_executed}",
        f"耗时 {result.duration:.1f}s",
        f"RAG {'on' if result.rag_enabled else 'off'}",
        f"LLM {'on' if result.llm_enabled else 'off'}",
    ]
    console.print("[dim]" + "  ".join(info) + "[/dim]")

    confirmed = result.confirmed_findings()
    if confirmed:
        ft = Table(title=f"发现明细（已确认 {len(confirmed)} 条）")
        ft.add_column("等级", no_wrap=True)
        ft.add_column("编号", style="cyan", no_wrap=True)
        ft.add_column("名称")
        ft.add_column("命中位置")
        ft.add_column("证据分", justify="right", no_wrap=True)
        ft.add_column("研判", style="dim")
        for f in confirmed[:30]:
            verdict = f.verdict or "-"
            score = f"{f.evidence_score:.2f}" if f.evidence_score else "-"
            ft.add_row(
                f"[{_SEV_STYLE[f.severity]}]{f.severity.label}[/]",
                f.poc_id,
                f.name,
                f.matched_at[:52],
                score,
                verdict,
            )
        console.print(ft)

    review = result.needs_review_findings()
    if review:
        console.print(
            f"[yellow]待人工复核 {len(review)} 条[/yellow]"
            f"[dim]（证据不足，不计入漏洞数；详见报告附录）[/dim]"
        )
        for f in review[:8]:
            console.print(
                f"  [dim]· {f.poc_id} @ {f.matched_at[:60]}"
                f"（{f.evidence_score:.2f}）{f.status_reason[:60]}[/dim]"
            )

    assets = result.assets
    if assets:
        at = Table(title=f"侦察资产（{len(assets)} 项）")
        at.add_column("类型", style="cyan")
        at.add_column("数量", justify="right")
        at.add_column("示例")
        for kind in ("port", "path", "endpoint", "secret", "internal", "map"):
            xs = result.assets_of(kind)
            if xs:
                at.add_row(kind, str(len(xs)), ", ".join(x.value[:40] for x in xs[:3]))
        console.print(at)

    for n in result.notes:
        console.print(f"[dim]· {n}[/dim]")
    for e in result.errors[:8]:
        console.print(f"[yellow]![/yellow] {e}")


# ⚠ 这份模板必须与仓库根目录的 config.yaml 保持同构。
# 以前它是旧版：缺 17 个参数（JS 逻辑审计 3 个、探针开关 4 个、探针策略 5 个、
# 知识沉淀 5 个），跑完 init 拿到的配置与项目实际能力差一代。
# 改配置项时**两处都要改**——scripts/test_init_template.py 会把差异测出来。
