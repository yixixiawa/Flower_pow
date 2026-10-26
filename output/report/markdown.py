"""Markdown 产物：人读 / 交付给甲方的主格式。

原 ``report.py`` 的 markdown 段（``_model_rows`` / ``_asset_section`` /
``write_markdown`` / 模板正文）。HTML 产物会复用这里的 ``_render_template_md``
作为「AI 正文不可用时」的兜底。"""

from __future__ import annotations

from pathlib import Path
from core.state import ScanResult
from core.state import Severity
from core.rawmsg import unescape_md
from output.report.naming import _stamp
from output.report.notes import _ts
from output.report.notes import _dedupe_notes
from output.report.paths import _target
from output.report.paths import _report_stem
from output.report.evidence import _looks_like_analysis
from output.report.evidence import _burp_transcript


def _model_rows(result: ScanResult) -> list[str]:
    """报告概要表里的模型行。

    为什么要写进报告：模型名是可以"配错却没人发现"的东西——把
    `deepseek-v4-pro` 拼成旧名会被服务端静默换模型，日志里只有警告，
    而报告会被存档、被交付。**交付物里必须能看出这份报告是谁分析的。**
    统计为空（未启用 LLM）时不输出，避免出现空行撑坏表格。
    """
    st = result.llm_stats or {}
    if not st.get("models"):
        return []
    # 优先用 detail（每个模型带各自的服务方）；老快照没有该字段时退回 models
    detail = st.get("detail")
    if isinstance(detail, list) and detail:
        label = "、".join(
            f"`{d.get('name')}`（{d.get('served_by')}）"
            if d.get("served_by")
            else f"`{d.get('name')}`"
            for d in detail
            if isinstance(d, dict) and d.get("name")
        )
    else:
        label = "、".join(f"`{m}`" for m in st["models"])
    rows = [f"| 使用模型 | {label} |"]
    if st.get("calls"):
        rows.append(
            f"| LLM 调用 | {st['calls']} 次"
            f"（耗时 {st.get('total_ms', 0) / 1000:.1f}s，"
            f"失败 {st.get('errors', 0)} 次） |"
        )
    return rows


# ── JSON ──────────────────────────────────────────────────────────



def _asset_section(result: ScanResult) -> list[str]:
    """侦察资产清单——Web 漏扫里这部分往往比漏洞列表更有价值。"""
    L: list[str] = []
    secrets = result.assets_of("secret")
    internals = result.assets_of("internal")
    endpoints = result.assets_of("endpoint")
    ports = result.assets_of("port")
    paths = result.assets_of("path")
    maps = result.assets_of("map")

    if ports:
        L += ["", "### 开放端口", "", "| 端口/服务 | Web |", "| --- | --- |"]
        for a in ports[:30]:
            L.append(f"| `{a.value}` | {'是' if a.meta.get('web') else '否'} |")

    if paths:
        L += ["", "### 发现的路径", ""]
        L += [
            f"- `{a.value}` （HTTP {a.meta.get('status', '?')}）"
            for a in paths[:40]
        ]

    if endpoints:
        L += ["", "### 前端接口端点（来自 JS 静态分析）", ""]
        L += [f"- `{a.value}`" for a in endpoints[:40]]

    if maps:
        L += ["", "### Source Map 引用", ""]
        L += [f"- `{a.value}`（可尝试还原完整前端源码）" for a in maps[:10]]

    if internals:
        L += ["", "### 前端泄露的内网地址", ""]
        L += [f"- `{a.value}`" for a in internals[:20]]

    if secrets:
        L += ["", "### ⚠ 前端硬编码凭据", "",
              "> 以下内容出现在前端 JS 中，等同于无凭据保护。请立即轮换。", ""]
        L += [f"- `{a.value[:80]}`" for a in secrets[:20]]

    return L


def write_markdown(
    result: ScanResult,
    outdir: Path,
    ai_body: str = "",
    *,
    overwrite: bool = True,
    path: Path | None = None,
) -> Path:
    if path is None:
        path = _target(outdir, _report_stem(result, outdir), ".md", overwrite)
    # 报告住在自己的文件夹里，显式 path（plan_reports 定好的）同样可能
    # 指向还没建过的目录——建的是 path.parent，不是 outdir。
    path.parent.mkdir(parents=True, exist_ok=True)

    counts = result.counts()
    grouped = result.by_severity()
    session_no = result.session_id or int(result.started_at)
    L: list[str] = [
        f"# 渗透测试报告 — {result.target}",
        "",
        "> 【保密声明】本报告包含敏感安全信息，仅供授权人员查阅。"
        "未经授权不得复制、传播或泄露。",
        "",
        "| 项目 | 值 |",
        "| --- | --- |",
        f"| 报告编号 | `FP-{_stamp(result.started_at)}-{session_no}` |",
        f"| 目标 | `{result.target}` |",
        f"| 会话 ID | `{session_no}` |",
        f"| 开始时间 | {_ts(result.started_at)} |",
        f"| 耗时 | {result.duration:.1f}s |",
        f"| POC 库 | {result.pocs_loaded} 条 |",
        f"| RAG 召回 | {result.pocs_selected} 条"
        f"（{'启用' if result.rag_enabled else '未启用'}） |",
        f"| 执行 POC | {result.pocs_executed} 条 |",
        f"| AI 研判 | {'启用' if result.llm_enabled else '未启用'} |",
        *_model_rows(result),
        f"| 有效发现 | {len(result.active_findings())} 条 |",
        *(
            [f"| 已排除（误报） | {len(result.dismissed_findings())} 条"
             f"（见文末复核附录） |"]
            if result.dismissed_findings()
            else []
        ),
        "",
        "## 风险概览",
        "",
        "| 等级 | 数量 |",
        "| --- | --- |",
    ]
    for s in Severity:
        if counts.get(s.value, 0):
            L.append(f"| {s.label} | {counts[s.value]} |")

    if result.fingerprints:
        L += ["", "## 目标指纹", ""]
        for fp in result.fingerprints:
            # summary() 内部用 " | " 分隔字段，直接放进 Markdown 表格或
            # 紧跟表格的段落里会把表格结构冲掉——这里换成逗号分隔
            summary = fp.summary().replace(" | ", "，")
            L.append(f"- `{fp.target}` — {summary}")

    if result.assets:
        L += ["", "## 侦察资产", ""]
        L += _asset_section(result)

    if result.attack_chains:
        L += ["", "## 攻击链路", ""]
        L.append(
            "> 以下链路只展示 Agent 显式登记的前置条件、动作、证据与结果；"
            "未登记的推测不计入最终影响。"
        )
        L.append("")
        for chain_no, chain in enumerate(result.attack_chains, 1):
            L += [f"### 攻击链 {chain_no}：{unescape_md(chain.title)}", ""]
            L += [
                f"- 链条 ID：`{chain.chain_id}`",
                f"- 整体等级：{chain.severity.label}",
                f"- 入口点：{unescape_md(chain.entry_point)}",
                f"- 最终影响：{unescape_md(chain.final_impact)}",
                "",
                "| 步骤 | 关联发现 | 动作 | 核心证据 | 结果 |",
                "| --- | --- | --- | --- | --- |",
            ]
            for step_no, step in enumerate(chain.steps, 1):
                cells = [
                    str(step_no),
                    f"`{step.finding_id}`" if step.finding_id else "-",
                    unescape_md(step.action).replace("|", "\\|"),
                    unescape_md(step.evidence).replace("|", "\\|").replace("\n", "<br>"),
                    unescape_md(step.result).replace("|", "\\|").replace("\n", "<br>"),
                ]
                L.append("| " + " | ".join(cells) + " |")
            L.append("")

    # 阶段耗时——告诉使用者时间花在哪
    if result.phases:
        L += ["", "## 执行阶段耗时", "", "| 阶段 | 耗时 |", "| --- | --- |"]
        names = {
            "recon": "① 侦察（指纹/端口/JS）",
            "match": "② RAG 检索 + 重排",
            "verify": "③ 批量验证",
            "triage": "④ LLM 降误报",
        }
        for k, v in result.phases.items():
            L.append(f"| {names.get(k, k)} | {v}s |")

    L += ["", "---", ""]
    # 详情段**始终**由模板渲染，不依赖 LLM。
    # 早先这里是 if ai_body: 用 AI 正文**替换**整个详情段，
    # 于是 AI 一旦失败/输出占位语，所有命中的 URL、响应片段、修复建议
    # 全部消失——交付物里只剩下概述，这才是「报告不完整」的真正原因。
    # 结构对齐交付惯例（参考正式渗透报告）：每条漏洞固定
    # 「漏洞描述 / PoC / 安全建议」三个子节。PoC 里是 Burp Suite 式报文
    # （>>> 请求 / <<< 响应），其中**请求完整保留、响应只给概要**——
    # 复现靠的是请求，少一个 Cookie 或路径参数粘到 Repeater 就不是同一个请求；
    # 完整响应留在证据文件里，报告只指路。
    # 早先这里是 if ai_body: 用 AI 正文**替换**整个详情段，
    # 于是 AI 一旦失败/输出占位语，所有命中的 URL、响应片段、修复建议
    # 全部消失——交付物里只剩下概述，这才是「报告不完整」的真正原因。
    L += [
        "## 渗透测试结果",
        "",
        "> 每条漏洞按「漏洞描述 / PoC / 安全建议」组织；PoC 中的**请求为完整"
        "发送包**（可直接粘贴到 Burp Repeater 复现），响应给出状态行、响应头与"
        "正文概要——完整报文见各条末尾标注的证据文件。",
        "",
    ]
    idx = 0
    for sev, items in grouped.items():
        for f in items:
            idx += 1
            # 全部走一遍转义清洗：模型常从 Markdown 里复制粘贴，
            # `\``、`\*` 会跟着进来，交付物里出现一堆反斜杠。
            name = unescape_md(f.name or "").strip()
            desc = unescape_md((f.description or "").strip())
            fix = unescape_md((f.remediation or "").strip())
            L += [f"### 4.{idx} [{f.severity.label}] {name}", ""]

            # ── 4.X.1 漏洞描述 ──
            L += [f"#### 4.{idx}.1 漏洞描述", ""]
            L.append(
                f"- 编号：`{f.poc_id}`　检测器：{f.detector}　"
                f"RAG 得分：{f.rag_score:.3f}"
            )
            L.append(f"- 命中：{unescape_md(f.matched_at)}")
            if f.cve:
                L.append(f"- CVE：{', '.join(f.cve)}")
            if f.verdict:
                L.append(f"- 研判：{f.verdict}（置信度 {f.confidence:.0%}）")
            if f.rationale:
                L.append(f"- 研判依据：{f.rationale}")
            if f.tags:
                L.append(f"- 标签：{', '.join(f.tags)}")
            if f.chain_id:
                L.append(f"- 攻击链：`{f.chain_id}` 第 {f.step_index + 1} 步")
                if f.exploit_payload:
                    L.append(f"- 串联载荷：`{unescape_md(f.exploit_payload)}`")
            L.append("")
            if desc:
                # 说明按**段落**渲染，不再塞进 `- 说明：xxx` 一条列表项：
                # 模型写的说明常常是多行（攻击链分步、泄露字段清单），
                # 从第二行起就不属于列表内容了，Markdown 会把它拆成
                # 独立段落，读起来像两段不相干的文字。
                L += ["**漏洞说明**", "", *desc.splitlines(), ""]

            # ── 4.X.2 PoC（Burp 式完整报文）──
            L += [f"#### 4.{idx}.2 PoC", ""]
            ev = f.evidence
            if ev is None:
                L += ["（本条未附原始报文：登记时既没有 payload 也没有响应证据）", ""]
            else:
                # 怎么打的、发了什么、预期是什么——可复现的最小集合
                if ev.poc_id:
                    L.append(f"- 触发 POC：`{ev.poc_id}`{f'（{ev.poc_name}）' if ev.poc_name else ''}")
                if ev.expected:
                    L.append(f"- 预期返回：{unescape_md(ev.expected)}")
                # 「实际命中」只在它带来新信息时才写：手工登记的判定依据
                # 已经写在「漏洞说明」里，两处都写＝同一段话出现两遍
                # （旧报告里每条漏洞都有这个重复段）。
                pattern = unescape_md(ev.matched_pattern or "").strip()
                if pattern and not _looks_like_analysis(pattern, desc):
                    L.append(f"- 实际命中：{pattern}")
                if ev.status_code is not None:
                    L.append(
                        f"- 响应：HTTP {ev.status_code}，{ev.body_size} 字节，"
                        f"{ev.elapsed_ms}ms"
                    )
                req, resp, note = _burp_transcript(ev, outdir, description=desc)
                if req:
                    L += ["", "```http", ">>> 请求:", *req.splitlines()]
                    if resp:
                        L += ["", "<<< 响应:", *resp.splitlines()]
                    L += ["```", ""]
                    if not resp:
                        # 只有请求没有响应时**必须说清楚**：读者会以为
                        # 响应被省略了，其实是根本没记录。
                        L += [
                            "> ⚠ 本条只记录了请求，**没有原始响应报文**——"
                            "对方无法对照复现。用 `record_finding` 的 "
                            "`response` 参数把响应整段补上后重导。",
                            "",
                        ]
                # payload 与请求文本重复时不再单列；多行 payload 用围栏块，
                # 行内反引号包不住多行内容（会渲染成一行乱码）。
                payload = unescape_md(ev.payload_sent or "").strip()
                if payload and payload not in req:
                    if "\n" in payload:
                        L += ["- 发送 payload：", "", "```http",
                              *payload.splitlines(), "```", ""]
                    else:
                        L.append(f"- 发送 payload：`{payload}`")
                if note:
                    L.append(f"- {note}")
                elif ev.artifact:
                    L.append(f"- 完整原始报文：`{ev.artifact}`")
                L.append("")

            # ── 4.X.3 安全建议 ──
            L += [f"#### 4.{idx}.3 安全建议", ""]
            L.append(fix or "（暂无针对性建议，请按漏洞类别做专项排查）")
            L.append("")

    # ── 误报复核附录 ───────────────────────────────────────────────
    # 为什么被排除的发现**不能悄悄消失**：客户一定会问「上次报的 XX 怎么没了」。
    # 报告要么能解释，要么就是不可信的。所以排除项单列一节，写明位置、原因、时间。
    dismissed = result.dismissed_findings()
    if dismissed:
        from datetime import datetime as _dt

        L += [
            "",
            "## 已排除的发现（误报复核）",
            "",
            "> 以下项经复核判定为**误报**，未计入上面的风险统计。"
            "列在这里是为了让排除本身可复核——"
            "每条都附了排除原因：人工排除写的是判定依据，自动判定的会写明取证结果。",
            "",
            "> 最常见的误报类型是「公开演示站点」：站点本就建给人看，"
            "其中暴露的配置、默认账号、接口文档属于设计而非漏洞。"
            "这类项由**公开性核验**自动判定（回源站根目录取首页自述 / 站点自己公开的"
            "链接 / sitemap / robots 作为证据），证据够强才自动排除。",
            "",
            "| 编号 | 等级 | 名称 | 位置 | 排除原因 | 时间 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for f in sorted(dismissed, key=lambda x: x.severity.rank, reverse=True):
            when = (
                _dt.fromtimestamp(f.dismissed_at).strftime("%Y-%m-%d %H:%M")
                if f.dismissed_at
                else "-"
            )
            loc = f.matched_at.replace("|", "\\|")[:90]
            rsn = (f.dismiss_reason or "-").replace("|", "\\|")[:80]
            name = f.name.replace("|", "\\|")[:40]
            L.append(
                f"| `{f.poc_id}` | {f.severity.label} | {name} | {loc} | {rsn} | {when} |"
            )
        L.append("")

    if result.notes:
        L += ["", "## 执行说明", ""]
        L += [f"- {n}" for n in _dedupe_notes(result.notes)]
    if result.errors:
        L += ["", "## 执行日志", ""]
        # 同一条错误可能重复出现（多个阶段报同一个错），去重后输出
        seen: set[str] = set()
        for e in result.errors:
            if e not in seen:
                seen.add(e)
                L.append(f"- {e}")

    L += [
        "",
        "---",
        "",
        "## 合规声明",
        "",
        "本报告仅用于对**已获得书面授权**的目标进行安全测试。"
        "未经授权的渗透测试可能违反法律。请确认测试范围已与目标所有者书面确认。",
        "",
    ]
    path.write_text("\n".join(L), encoding="utf-8")
    return path


# ── HTML ──────────────────────────────────────────────────────────



def _render_template_md(result: ScanResult) -> str:
    """HTML 用的模板 Markdown（与 write_markdown 的发现详情部分同源）。"""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        p = write_markdown(result, Path(tmp))
        return p.read_text(encoding="utf-8")
