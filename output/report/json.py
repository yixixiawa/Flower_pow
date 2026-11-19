"""JSON 产物：机器可读，给 CI / 二次分析。

会额外带上 RAG 检索详情、LLM 调用统计、阶段耗时——让「为什么报了这条」
事后可复盘。"""

from __future__ import annotations

import json
from pathlib import Path
from core.state import ScanResult
from output.report.paths import _target
from output.report.paths import _report_stem


def write_json(
    result: ScanResult,
    outdir: Path,
    ai_body: str = "",
    extra: dict | None = None,
    *,
    overwrite: bool = True,
    path: Path | None = None,
) -> Path:
    if path is None:
        path = _target(outdir, _report_stem(result, outdir), ".json", overwrite)
    # ── 三层隔离：报告只属于当前目标 + 当前扫描轮次 ─────────────
    # 不能再直接用整个会话的发现列表——换目标或开了新一轮扫描后，
    # 旧目标/旧轮次的发现混进来就是串台。scoped_view 返回浅拷贝，
    # Finding 对象本身共享，后面的导出前复核仍写回原对象。
    result = result.scoped_view()
    # 出口兜底：见 markdown.py 同位置注释（core/validation/gate.py）
    from core.validation.gate import ensure_reportable

    ensure_reportable(result)
    # 见 markdown.py 同位置注释：建 path.parent，覆盖显式 path 的新目录。
    path.parent.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    data["ai_report"] = ai_body
    # 顶层再给一份汇总：消费方经常直接读 JSON 出图表，不该逼它自己去
    # 遍历 findings 数 dismissed 标记（写漏一次统计就多算一条误报）。
    data["active_findings"] = len(result.active_findings())
    # 三档口径（与报告一致）：只有 confirmed 计入漏洞数量；
    # needs_review 单列、rejected 单列，都不删——复核记录本身是交付物的一部分。
    data["status_counts"] = result.status_counts()
    data["needs_review"] = [
        {
            "poc_id": f.poc_id,
            "name": f.name,
            "severity": f.severity.value,
            "matched_at": f.matched_at,
            "evidence_score": round(f.evidence_score, 4),
            "quality": f.quality.to_dict() if f.quality else None,
            "reason": f.status_reason,
        }
        for f in result.needs_review_findings()
    ]
    data["rejected"] = [
        {
            "poc_id": f.poc_id,
            "name": f.name,
            "severity": f.severity.value,
            "matched_at": f.matched_at,
            "evidence_score": round(f.evidence_score, 4),
            "reason": f.dismiss_reason or f.status_reason,
            "dismissed_at": f.dismissed_at,
        }
        for f in result.rejected_findings()
    ]
    data["excluded"] = [
        {
            "poc_id": f.poc_id,
            "name": f.name,
            "severity": f.severity.value,
            "matched_at": f.matched_at,
            "reason": f.dismiss_reason,
            "dismissed_at": f.dismissed_at,
        }
        for f in result.dismissed_findings()
    ]
    if extra:
        data.update(extra)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


# ── Markdown ──────────────────────────────────────────────────────

