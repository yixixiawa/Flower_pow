"""终端宽度计算：双宽字符、ANSI 剥离、按词跳转。

中文/emoji 按 **显示列宽** 算而不是字符数，否则一输入就折行错位。"""

from __future__ import annotations

import re
import shutil
import unicodedata


# ── 终端宽度计算 ────────────────────────────────────────────────

# 重绘时要清掉旧内容，而 prompt 里可能有颜色转义序列——
# 按字符数算宽度会把转义序列也数进去，结果清多或清少，行就歪了。
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")


def _cell_width(ch: str) -> int:
    """单个字符占几列（CJK / 全角 2 列，其余 1 列）。

    **全项目只有这一处定义"字符占几列"**——`_display_width` 与折行布局
    `_layout` 都调它。分成两套实现的话，一处改了另一处没改，重绘就会错位。
    """
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _display_width(s: str) -> int:
    """字符串在终端里实际占几列（CJK 与全角算 2 列，去掉 ANSI 转义）。"""
    s = _ANSI_RE.sub("", s or "")
    return sum(_cell_width(ch) for ch in s)


# 按词跳转时的分隔符。**只按空白切**——早先把 ``/`` 也算边界，结果
# ``/report md`` 里 Ctrl+← 会停在 ``/`` 后面（第 1 列），那不是一个
# 有意义的落点；命令与其参数才是自然的词。
_WORD_SEP = " \t"


def _prev_word(buf: str, pos: int) -> int:
    """``Ctrl+←``：跳到前一个词的开头。"""
    i = pos
    while i > 0 and buf[i - 1] in _WORD_SEP:
        i -= 1
    while i > 0 and buf[i - 1] not in _WORD_SEP:
        i -= 1
    return i


def _next_word(buf: str, pos: int) -> int:
    """``Ctrl+→``：跳到下一个词的末尾。"""
    n = len(buf)
    i = pos
    while i < n and buf[i] not in _WORD_SEP:
        i += 1
    while i < n and buf[i] in _WORD_SEP:
        i += 1
    return i


def _cols() -> int:
    try:
        return max(20, shutil.get_terminal_size().columns)
    except Exception:  # noqa: BLE001
        return 80


