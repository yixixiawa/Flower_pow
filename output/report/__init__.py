"""报告输出：JSON / Markdown / HTML。

三份产物的分工
--------------
* **JSON** —— 机器可读，给 CI / 二次分析。会额外带上 RAG 检索详情、
  LLM 调用统计、阶段耗时，这样「为什么报了这条」也能事后复盘。
* **Markdown** —— 人读 / 交付给甲方的主格式。
* **HTML** —— 自包含单文件（无外部 CSS/JS 依赖），可直接发邮件。

LLM 正文与模板正文的关系：**LLM 正文优先**。模型生成失败或未启用时，
回退到纯模板报告——模板永远能出结果，不依赖任何外部服务。

模块分块
========
=====================  ==========================================================
``naming``             slugify / 主域名裁剪 / 时间戳后缀（依赖链的根）
``paths``              产物落哪、叫什么、撞名怎么办——``overwrite`` 只在这里定
``notes``              时间戳格式化 + notes 去重（让三份产物共用而不成环）
``json``               JSON 产物
``markdown``           Markdown 产物 + 模板正文兜底
``evidence``           Burp 式报文转写（markdown 与 html **必须共享**，否则
                       同一条漏洞会贴出两份不一致的报文）
``html``               HTML 产物
=====================  ==========================================================

**对外接口不变**：所有调用方仍写 ``from output.report import write_markdown``。
"""

from __future__ import annotations

from output.report.evidence import _artifact_path, _burp_transcript, _looks_like_analysis
from output.report.html import write_html
from output.report.json import write_json
from output.report.markdown import write_markdown
from output.report.naming import (
    registrable_domain,
    slugify,
    target_domain,
    target_host,
)
from output.report.notes import _dedupe_notes, _ts
from output.report.paths import (
    _disambiguator,
    _existing_owner,
    _recorded_target,
    _report_stem,
    _same_target,
    _target,
    _unique_path,
    plan_reports,
    report_paths,
)

__all__ = [
    # 三份产物
    "write_json", "write_markdown", "write_html",
    # 路径规划
    "plan_reports", "report_paths",
    "_report_stem", "_unique_path", "_target", "_same_target",
    "_recorded_target", "_existing_owner", "_disambiguator",
    # 命名
    "slugify", "target_host", "registrable_domain", "target_domain",
    # 小件
    "_ts", "_dedupe_notes",
    # 证据转写
    "_burp_transcript", "_artifact_path", "_looks_like_analysis",
]
