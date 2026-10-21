"""交互式终端——``Repl`` 是命令的唯一入口。

``Repl`` 由 base + 七个命令域 mixin 多继承组装而成。方法体逐行来自拆分前的单文件
版本，行为完全一致；对上层只有 ``from core.repl import Repl, run_repl, HELP`` 这一个入口。

模块分块
========
=====================  ==========================================================
``consts``            命令表 / 帮助文本 / 阶段别名（补全与 ``/help`` 共用一份）
``base``              ``_ReplBase``：构造与控制台
``history``           对话历史与轮次标题
``auto``              一键全自动（``/auto`` 与 Alt+Shift）
``context``           补全器与会话候选源
``loop``              主循环与 ``_handle`` 命令分发
``commands``          目标 / 工具 / 凭证 / 轮询 / 状态 / 资产 / 发现
``session``           误报 / 对话轮 / 模型 / 报告 / 会话存取
``entry``             ``run_repl`` 启动入口
=====================  ==========================================================

``_handle`` 是**唯一**的命令入口，拆到 ``loop`` 里；其余 mixin 只提供被它调用的方法，
彼此之间不互相调用，所以拆的是文件不是对象——一个 Repl 实例拥有全部命令。
"""

from __future__ import annotations

from core.repl.auto import _AutoMixin
from core.repl.base import _ReplBase
from core.repl.commands import _CommandMixin
from core.repl.consts import (
    AUTO_WARN,
    BANNER,
    BANNER_AGENT,
    COMMANDS,
    HELP,
    NATURAL,
    PHASE_ALIAS,
)
from core.repl.context import _ContextMixin
from core.repl.history import _HistoryMixin
from core.repl.loop import _LoopMixin
from core.repl.session import _SessionMixin


class Repl(
    _SessionMixin,
    _CommandMixin,
    _LoopMixin,
    _ContextMixin,
    _AutoMixin,
    _HistoryMixin,
    _ReplBase,
):
    """交互式终端——本类只把各命令域拼起来，不新增实现。"""


# 必须放在 class 定义**之后**：entry.run_repl 要实例化 Repl，
# 提前导入会在本模块还没定义完时去取 Repl，直接 ImportError。
from core.repl.entry import run_repl  # noqa: E402

__all__ = ["Repl", "run_repl", "COMMANDS", "HELP", "AUTO_WARN"]
