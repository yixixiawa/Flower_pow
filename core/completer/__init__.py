"""Tab 补全与行编辑——把输入区当成一块**要盯住的屏幕**。

为什么这么讲究：补全出错时肉眼看的是「屏幕长什么样」，不是转义序列。
所以这里的分层是按「一块屏幕需要的知识」切的：

=====================  ==========================================================
``keys``              平台按键哨兵 + VT(ANSI) 开关
``width``             双宽字符 / ANSI 剥离 / 按词跳转
``layout``            把缓冲区摊成物理行（右边缘留待定折行位）
``paint``             重绘（ANSI 移动光标；不支持就退回单行裁剪重绘）
``candidate``         候选生成——**纯逻辑**，可脱离终端单测
``reader``            单键读取（msvcrt / termios 裸模式 / input 降级）
=====================  ==========================================================

**对外接口不变**：``Completer`` / ``PromptReader`` / ``available`` /
``HOTKEY_FULL_AUTO`` 仍从 ``core.completer`` 直接 import。
"""

from __future__ import annotations

from core.completer.candidate import Completer, _common_prefix
from core.completer.keys import (
    HOTKEY_FULL_AUTO,
    _enable_vt,
    available,
)
from core.completer.layout import _erase_input, _finish_line, _layout, _move_to
from core.completer.paint import (
    _plain_row_text,
    _repaint,
    _repaint_plain,
    _split_prompt,
)
from core.completer.reader import PromptReader
from core.completer.width import (
    _ANSI_RE,
    _cell_width,
    _cols,
    _display_width,
    _next_word,
    _prev_word,
)

__all__ = ["Completer", "PromptReader", "available", "HOTKEY_FULL_AUTO"]
