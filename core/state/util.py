"""纯函数工具：正则缓存 / 文件名清洗 / dataclass 序列化。

原 :mod:`core.state` 的「工具函数」段。零依赖，被 poc 与 models 共用。
"""

from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


# ── 工具函数 ──────────────────────────────────────────────────────

_RE_CACHE: dict[str, re.Pattern[str]] = {}


def re_search(pattern: str, text: str) -> bool:
    """带缓存的 ``re.search``，避免 POC 执行时反复编译同一正则。"""
    try:
        rx = _RE_CACHE.get(pattern)
        if rx is None:
            rx = re.compile(pattern, re.IGNORECASE)
            _RE_CACHE[pattern] = rx
        return bool(rx.search(text or ""))
    except re.error:
        return False


_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def safe_name(text: str, limit: int = 60) -> str:
    """把 URL 转成安全的文件名片段。

    Windows 下 ``:`` ``/`` ``?`` ``*`` 非法，不清洗会生成半截文件名，
    结果是报告文件写成 0 字节。
    """
    s = _UNSAFE.sub("_", text or "target")
    s = s.strip("._") or "target"
    return s[:limit].rstrip("._")


def dataclass_to_dict(obj: Any) -> Any:
    """递归 dataclass → dict（给调试/日志用）。"""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (list, tuple)):
        return [dataclass_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
