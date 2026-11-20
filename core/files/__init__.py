"""本地文件访问子系统（对话式文件分析的第一阶段）。

对外只暴露这几样东西——**没有扫描磁盘的入口，也没有按内容扩展范围的入口**：

* :class:`FileAccess` —— 一个会话的授权台账；``authorize()`` 是唯一入口
* :class:`FileContext` —— 上下文渲染（不可信数据容器）+ 解析缓存
* :func:`use_files` / :func:`current_files` —— 按任务绑定上下文（并发隔离）
* :func:`parse_bytes` / :class:`ParsedFile` —— 解析（失败即报错）
* :func:`redact_secrets` —— 派生文本脱敏
"""

from core.files.access import (
    MAX_FILE_BYTES,
    MAX_FILES_PER_SESSION,
    MAX_PARSE_SECONDS,
    FileAccess,
    FileAccessDenied,
    FileRecord,
    Limits,
    redact_secrets,
)
from core.files.context import (
    TAG_CLOSE,
    TAG_OPEN,
    UNTRUSTED_PREAMBLE,
    FileContext,
    current_files,
    use_files,
)
from core.files.parser import (
    DEFAULT_MAX_CHARS,
    ParsedFile,
    detect_kind,
    parse_bytes,
)

__all__ = [
    "MAX_FILE_BYTES", "MAX_FILES_PER_SESSION", "MAX_PARSE_SECONDS",
    "DEFAULT_MAX_CHARS",
    "FileAccess", "FileAccessDenied", "FileRecord", "Limits",
    "FileContext", "current_files", "use_files",
    "TAG_OPEN", "TAG_CLOSE", "UNTRUSTED_PREAMBLE",
    "parse_bytes", "ParsedFile", "detect_kind",
    "redact_secrets",
]
