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
    # 见 markdown.py 同位置注释：建 path.parent，覆盖显式 path 的新目录。
    path.parent.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    data["ai_report"] = ai_body
    # 顶层再给一份汇总：消费方经常直接读 JSON 出图表，不该逼它自己去
    # 遍历 findings 数 dismissed 标记（写漏一次统计就多算一条误报）。
    data["active_findings"] = len(result.active_findings())
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

