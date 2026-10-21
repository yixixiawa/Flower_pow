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

