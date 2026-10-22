"""HTML 产物：自包含单文件，无外部 CSS/JS 依赖，可直接发邮件。

原 ``report.py`` 的 html 段。**LLM 正文优先**，拿不到就回退到模板正文——
模板永远能出结果，不依赖任何外部服务。"""

from __future__ import annotations

import html
import re as _re
from pathlib import Path
from core.state import ScanResult
from core.state import Severity
from output.report.notes import _ts
from output.report.paths import _target
from output.report.paths import _report_stem
from output.report.markdown import _render_template_md


_SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#2563eb",
    "info": "#4b5563",
}

def write_html(
    result: ScanResult,
    outdir: Path,
    ai_body: str = "",
    *,
    overwrite: bool = True,
    path: Path | None = None,
) -> Path:
    """把 Markdown 做最小转换输出自包含 HTML（无外部依赖）。"""
    if path is None:
        path = _target(outdir, _report_stem(result, outdir), ".html", overwrite)
    # 见 markdown.py 同位置注释：建 path.parent，覆盖显式 path 的新目录。
    path.parent.mkdir(parents=True, exist_ok=True)

    counts = result.counts()
    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s.value]}">'
        f"{s.label} {counts.get(s.value, 0)}</span>"
        for s in Severity
    )

    # AI 正文优先；否则直接渲染 Markdown（避免二次读文件）
    md = ai_body or _render_template_md(result)

    def _inline(s: str) -> str:
        s = html.escape(s)
        s = _re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        return s

    blocks: list[str] = []
    in_code = False
    in_list = False
    in_table = False
    for line in md.splitlines():
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code:
                blocks.append("</code></pre>")
                in_code = False
            else:
                blocks.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            blocks.append(html.escape(line))
            continue

        # 列表
        if _re.match(r"^\s*[-*]\s+", line):
            if not in_list:
                blocks.append("<ul>")
                in_list = True
            blocks.append(f"<li>{_inline(_re.sub(r'^\s*[-*]\s+', '', line))}</li>")
            continue
        if in_list:
            blocks.append("</ul>")
            in_list = False

        # 表格
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(_re.fullmatch(r":?-{2,}:?", c) for c in cells):
                continue  # 分隔行
            if not in_table:
                blocks.append("<table>")
                in_table = True
            blocks.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            blocks.append("</table>")
            in_table = False

        if m := _re.match(r"^(#{1,6})\s+(.*)$", line):
            lvl = min(len(m.group(1)), 6)
            blocks.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            continue
        if _re.match(r"^---+$", stripped):
            blocks.append("<hr>")
            continue
        if not stripped:
            blocks.append("")
        else:
            blocks.append(f"<p>{_inline(line)}</p>")

    for flag, close in ((in_list, "</ul>"), (in_table, "</table>"), (in_code, "</code></pre>")):
        if flag:
            blocks.append(close)

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>渗透测试报告 — {html.escape(result.target)}</title>
<style>
 body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
   max-width:960px;margin:32px auto;padding:0 20px;color:#1f2937;line-height:1.7;
   background:#fff}}
 h1,h2,h3,h4{{font-weight:600;margin:1.5em 0 .6em}}
 h1{{border-bottom:2px solid #e5e7eb;padding-bottom:10px}}
 code{{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:.9em}}
 pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow-x:auto}}
 pre code{{background:none;color:inherit;padding:0}}
 table{{border-collapse:collapse;width:100%;margin:1em 0}}
 td{{border:1px solid #e5e7eb;padding:7px 10px}}
 ul{{padding-left:1.4em}}
 .chip{{display:inline-block;color:#fff;padding:4px 12px;border-radius:999px;
   font-size:12px;margin:0 6px 6px 0}}
 .meta{{color:#6b7280;font-size:13px;margin-bottom:18px}}
</style></head><body>
<div>{chips}</div>
<div class="meta">目标 {html.escape(result.target)} · {_ts(result.started_at)} ·
 耗时 {result.duration:.1f}s · 有效发现 {len(result.active_findings())} 条{
   f' · 已排除（误报）{len(result.dismissed_findings())} 条'
   if result.dismissed_findings() else ''}</div>
<hr>
{"".join(blocks)}
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    return path


# ── Burp 式完整报文（PoC 段的数据源）─────────────────────────────

# 报告里单个请求/响应的展示上限：超过就不值得全文进报告（读不动），
# 完整内容永远在 evidence/*.http 里，报告注明路径。
