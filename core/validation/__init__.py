"""Finding Validator：Agent 与正式报告之间的质量闸门。

对外只暴露四样东西：

* :class:`FindingValidator` —— 七字段准入校验（提交时用）；
* :class:`Submission` / :class:`ValidationResult` —— 校验的输入输出；
* :func:`audit_for_report` —— 导出前兜底复核（防止绕过提交路径）。

设计说明见 :mod:`core.validation.validator` 的模块 docstring。
"""

from __future__ import annotations

from core.validation.gate import AuditReport, audit_for_report, ensure_reportable
from core.validation.spec import LABELS, REQUIRED_FIELDS, FieldSpec
from core.validation.validator import (
    FieldIssue,
    FindingValidator,
    Submission,
    ValidationResult,
    summarize_issues,
)

__all__ = [
    "FindingValidator",
    "Submission",
    "ValidationResult",
    "FieldIssue",
    "FieldSpec",
    "REQUIRED_FIELDS",
    "LABELS",
    "audit_for_report",
    "ensure_reportable",
    "AuditReport",
    "summarize_issues",
]
