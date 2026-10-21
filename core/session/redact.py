"""脱敏：会话快照要落盘、会话标题要上屏，所以凭据不能原样留在里面。

压成 ``键: ***`` 而不是整段删掉——**保留原始键名便于排查**，
删掉的话出问题时就不知道是哪类凭据漏了。"""

from __future__ import annotations

import re
from typing import Any


from core.state import Finding, ScanResult, Severity, safe_name

# 落盘前对历史做脱敏：会话快照可能被复制/分享，
# 而对话历史里往往混着工具返回的原始响应（Cookie、Token、密码回显）。
_KEY = r"(?:api[-_]?key|secret[-_]?key|access[-_]?token|refresh[-_]?token|session[-_]?id|auth[-_]?token|pwd|passwd|password|token|secret|authorization|cookie|bearer)"


def _mask_kv(m: re.Match[str]) -> str:
    """把 ``键: 值`` 压成 ``键: ***``，保留原始键名便于排查。"""
    raw = m.group(0)
    head = raw.split("=")[0]
    sep = ":" if ":" in head else "="
    return f"{raw.split(sep)[0].strip()}: ***"


_REDACT_PATTERNS: list[tuple[re.Pattern[str], object]] = [
    # 形如 `Authorization: Bearer xxx` / `X-API-Key: xxx` / `token = xxx`：
    # 键名可含连字符、下划线、任意大小写，值吃到行尾或下一个分隔符。
    # 这是主力规则——覆盖 X-Api-Key、Bearer、Cookie 等各种变体。
    (re.compile(rf"(?i)\b{_KEY}\b\s*[:=]\s*[^\s,;\"']+(?:[ \t]+[^\s,;\"']+)?"), _mask_kv),
    # 裸 `Bearer xxx`（前面没有键名，例如响应体里只回了一段）
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"), r"\1 ***"),
    # JWT / 长 base64 段：三段式，特征明确
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"), "***JWT***"),
    # 查询串里的敏感参数
    (re.compile(r"(?i)([?&](?:token|access_token|api_key|apikey|key|secret)=)([^&\s]{6,})"), r"\1***"),
]


def redact(text: str) -> str:
    """脱敏一段文本里的疑似凭据。"""
    for pat, repl in _REDACT_PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_messages(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """脱敏整段对话历史（仅处理字符串字段，保留结构）。"""
    out: list[dict[str, Any]] = []
    for msg in history:
        m = dict(msg)
        for k, v in m.items():
            if isinstance(v, str) and v:
                m[k] = redact(v)
            elif isinstance(v, list):
                # tool_calls 里的 arguments 是 JSON 字符串
                m[k] = [
                    {**c, "function": {**c.get("function", {}),
                                      "arguments": redact(c.get("function", {}).get("arguments") or "")}}
                    if isinstance(c, dict) and "function" in c else c
                    for c in v
                ]
        out.append(m)
    return out

