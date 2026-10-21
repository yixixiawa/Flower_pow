"""平台按键层：功能键哨兵 + VT(ANSI) 开关。

``HOTKEY_FULL_AUTO`` 是全模式热键的哨兵串——补全把它作为候选回灌，
``PromptReader`` 见到它就切自动模式，全程不依赖真实按键。"""

from __future__ import annotations

import os
import sys


# ── 平台按键层 ──────────────────────────────────────────────────

try:  # Windows
    import msvcrt  # type: ignore

    _WIN = True
except ImportError:  # POSIX
    msvcrt = None  # type: ignore
    _WIN = False

try:
    import termios
    import tty

    _HAS_TERMIOS = True
except ImportError:
    termios = None  # type: ignore
    tty = None  # type: ignore
    _HAS_TERMIOS = False


# 兜底开关：任何终端下补全交互表现异常时，设这个环境变量即可退回原生 input()
_PLAIN_INPUT_ENV = "FLOWER_POW_PLAIN_INPUT"

# Alt+Shift 热键的返回值。用「不可能由键盘产生」的哨兵串，
# 调用方只需判断 ``raw == HOTKEY_FULL_AUTO``。
HOTKEY_FULL_AUTO = "\x00__full_auto__"

_VK_SHIFT = 0x10
_VK_MENU = 0x12   # Alt


def _mods_held() -> bool:
    """Alt 与 Shift 是否**同时**按下（Windows）。

    为什么用 GetAsyncKeyState 轮询而不是等按键事件：单纯按下 Alt+Shift
    **不会产生任何字符**——控制台根本不会往输入缓冲里放东西，只等字符的话
    永远等不到。（顺带一提 Alt+Shift 也是 Windows 切换输入法的快捷键，
    所以触发时输入法会跟着切一次，这是系统行为，绕不开。）
    """
    if not _WIN:
        return False
    try:
        import ctypes

        get = ctypes.windll.kernel32.GetAsyncKeyState
        return bool(get(_VK_MENU) & 0x8000) and bool(get(_VK_SHIFT) & 0x8000)
    except Exception:  # noqa: BLE001
        return False


def available() -> bool:
    """当前环境是否支持自实现的补全交互。"""
    if os.environ.get(_PLAIN_INPUT_ENV):
        return False
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    return _WIN or _HAS_TERMIOS



# ── VT（ANSI）支持 ──────────────────────────────────────────────

_VT_ENABLED: bool | None = None


def _enable_vt() -> bool:
    """确保 Windows 控制台开启 **VT 处理**，返回是否可用 ANSI 序列。

    为什么必须显式开：Windows 10 的控制台**默认不会**把 ``\\x1b[...`` 当指令，
    而是当普通字符原样打出来；必须置上 ``ENABLE_VIRTUAL_TERMINAL_PROCESSING``
    （0x0004）位。这个位是**进程级**的，设一次即可。

    拿不到句柄（管道/重定向/非控制台）时返回 False，调用方回退到
    ``\\r`` + 空格的单行重绘——那条路虽然处理不了折行，但至少不出乱码。
    """
    global _VT_ENABLED
    if _VT_ENABLED is not None:
        return _VT_ENABLED
    if os.name != "nt":
        _VT_ENABLED = True          # POSIX 终端本来就支持
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)     # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            _VT_ENABLED = False
            return False
        if not (mode.value & 0x0004):
            k.SetConsoleMode(h, mode.value | 0x0004)
        _VT_ENABLED = True
    except Exception:  # noqa: BLE001
        _VT_ENABLED = False
    return _VT_ENABLED


