"""纯函数工具：IP 判定与「画像」文本渲染。

无依赖、无状态，所以排在依赖链最底——各阶段都能直接用。"""

from __future__ import annotations

import re
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)


def _is_ip(host: str) -> bool:
    """目标是不是 IPv4 字面量——子域枚举对 IP 毫无意义，直接跳过。"""
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", (host or "").strip()))


def _profile_text(result: ScanResult) -> str:
    """给 LLM 重排用的目标画像文本。"""
    from llm.prompt import render_profile

    return render_profile(
        result.fingerprints, [a.to_dict() for a in result.assets[:30]]
    )


