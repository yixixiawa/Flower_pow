"""枚举：严重度与漏洞分类。

原 :mod:`core.state` 的「枚举」段。``Severity`` / ``Category`` 被几乎所有
下游模块 import，单独成块——改动面最小、依赖为零。
"""

from __future__ import annotations

from enum import Enum


# ── 枚举 ──────────────────────────────────────────────────────────


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "信息",
            Severity.LOW: "低危",
            Severity.MEDIUM: "中危",
            Severity.HIGH: "高危",
            Severity.CRITICAL: "严重",
        }[self]

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        """从 YAML / 模型输出里宽松解析等级。"""
        s = str(raw or "").strip().lower()
        alias = {
            "info": cls.INFO, "information": cls.INFO, "信息": cls.INFO,
            "low": cls.LOW, "minor": cls.LOW, "低危": cls.LOW,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "中危": cls.MEDIUM,
            "high": cls.HIGH, "严重高危": cls.HIGH, "高危": cls.HIGH,
            "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "urgent": cls.CRITICAL, "严重": cls.CRITICAL,
        }
        if s in alias:
            return alias[s]
        for member in cls:
            if member.value in s:
                return member
        return cls.INFO


class FindingStatus(str, Enum):
    """漏洞定级——三档，互斥，不允许"既是误报又是已确认"。

    为什么必须三档而不是"确认 / 误报"两档：**证据不足**和**证据反证**是
    两件事。前者是"还没查清"（待人工复核），后者才是"查清了、不是漏洞"
    （误报/无效命中）。两档制会把前者硬塞进后者，于是要么冤枉真漏洞、
    要么把可疑项混进正式报告——两种错都不可接受。

    ``CONFIRMED`` 是**唯一**进入正式漏洞列表、计入漏洞数量、沉淀进知识库的档位；
    ``NEEDS_REVIEW`` 与 ``REJECTED`` 都只出现在附录里，保留复核痕迹。
    """

    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"

    @property
    def label(self) -> str:
        return {
            FindingStatus.CONFIRMED: "已确认漏洞",
            FindingStatus.NEEDS_REVIEW: "待人工复核",
            FindingStatus.REJECTED: "误报或无效命中",
        }[self]

    @property
    def description(self) -> str:
        return {
            FindingStatus.CONFIRMED: "有明确证据，满足漏洞判定条件，可以进入正式漏洞报告。",
            FindingStatus.NEEDS_REVIEW: "有可疑现象，但证据不足，不计入已确认漏洞数量。",
            FindingStatus.REJECTED: "不符合漏洞条件，保留复核记录，但不进入正式漏洞列表。",
        }[self]

    @property
    def official(self) -> bool:
        """是否算"正式漏洞"——报告正文/数量统计只认这一档。"""
        return self is FindingStatus.CONFIRMED

    @property
    def rank(self) -> int:
        return {
            FindingStatus.CONFIRMED: 2,
            FindingStatus.NEEDS_REVIEW: 1,
            FindingStatus.REJECTED: 0,
        }[self]

    @classmethod
    def parse(cls, raw: object, default: "FindingStatus" = None) -> "FindingStatus":  # type: ignore[assignment]
        """宽松解析。``default`` 缺省为 ``CONFIRMED``——老代码/老快照没有这个
        字段时，它们的语义就是"未被否定的命中"。"""
        if isinstance(raw, cls):
            return raw
        fallback = default or cls.CONFIRMED
        s = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
        alias = {
            "confirmed": cls.CONFIRMED, "true_positive": cls.CONFIRMED,
            "tp": cls.CONFIRMED, "确认": cls.CONFIRMED, "已确认": cls.CONFIRMED,
            "已确认漏洞": cls.CONFIRMED, "approved": cls.CONFIRMED,
            "needs_review": cls.NEEDS_REVIEW, "needs_manual": cls.NEEDS_REVIEW,
            "review": cls.NEEDS_REVIEW, "suspected": cls.NEEDS_REVIEW,
            "待复核": cls.NEEDS_REVIEW, "待人工复核": cls.NEEDS_REVIEW,
            "可疑": cls.NEEDS_REVIEW, "uncertain": cls.NEEDS_REVIEW,
            "rejected": cls.REJECTED, "false_positive": cls.REJECTED,
            "fp": cls.REJECTED, "误报": cls.REJECTED,
            "误报或无效命中": cls.REJECTED, "dismissed": cls.REJECTED,
        }
        return alias.get(s, fallback)


class Category(str, Enum):
    """POC 类别——决定用哪种探测器逻辑验证。"""

    FINGERPRINT = "fingerprint"      # 指纹识别
    PATH_PROBE = "path_probe"        # 敏感路径 / 后台探测
    CONTENT_MATCH = "content_match"  # 响应内容关键字匹配
    HEADER_CHECK = "header_check"    # 响应头缺失或配置缺陷
    FILE_EXT = "file_ext"            # 特定扩展名文件探测
    CVE_PROBE = "cve_probe"          # CVE 暴露面识别
    PARAM_PROBE = "param_probe"      # 参数 / 注入点探测（只读）
    JS_LEAK = "js_leak"              # 前端 JS 敏感信息
    API_AUTHZ = "api_authz"          # 接口鉴权类（未授权 / 越权 / IDOR / 敏感字段出网）
    # ── 以下四类由专用探测器执行（detectors/exploit.py、detectors/js_logic.py），
    #    不走 HttpDetector 的静态路径探测，故在 filter_executable 里被排除。
    INJECTION = "injection"          # SQL 注入（只取数据库版本号即停）
    RCE = "rce"                      # 命令注入 / 服务端模板注入
    FILE_OP = "file_op"              # 任意文件读取 / 任意文件上传
    JS_LOGIC = "js_logic"            # 前端逻辑缺陷 / 前端鉴权可绕过

