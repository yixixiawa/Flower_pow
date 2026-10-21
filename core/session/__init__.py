"""会话状态：一个交互式测试从头到尾的全部记忆。

模块分块
========
=====================  ==========================================================
``redact``            凭据脱敏——快照要落盘、标题要上屏，不能留明文
``models``            阶段 / 轮次 / 对话轮 / 业务模型（纯数据，可单独测）
``session``           ``Session`` 本体：轮次推进、发现台账、快照读写
``store``             磁盘存取：列出 / 取最近 / 清扫空壳（``purge`` 会删目录）
=====================  ==========================================================

**对外接口不变**：``from core.session import Session, redact, ...`` 照旧。
"""

from __future__ import annotations

from core.session.models import (
    BusinessModel,
    ConversationTurn,
    Phase,
    Turn,
)
from core.session.redact import redact, redact_messages
from core.session.session import Session
from core.session.store import latest_session, list_sessions, purge_empty_sessions

__all__ = [
    "Session", "Phase", "Turn", "ConversationTurn", "BusinessModel",
    "redact", "redact_messages",
    "list_sessions", "latest_session", "purge_empty_sessions",
]
