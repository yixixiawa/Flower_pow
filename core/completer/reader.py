"""交互读取：Windows 用 ``msvcrt`` 读单键，POSIX 走 termios 裸模式。

拿到控制台走 Windows 分支；拿不到就退化成 ``input()`` 单行模式
（``FLOWER_POW_PLAIN_INPUT`` 可强制）。"""

from __future__ import annotations

import sys
import time
from core.completer.width import _prev_word
from core.completer.width import _next_word
from core.completer import width
from core.completer import keys
from core.completer.keys import _WIN
from core.completer.keys import _mods_held
from core.completer.keys import available
from core.completer.keys import HOTKEY_FULL_AUTO
from core.completer.keys import msvcrt
try:
    from core.completer.keys import termios, tty
except ImportError:
    termios = tty = None
from core.completer.layout import _layout
from core.completer.layout import _finish_line
from core.completer.layout import _erase_input
from core.completer.paint import _repaint
from core.completer.paint import _plain_row_text
from core.completer.paint import _split_prompt
from core.completer.candidate import Completer


# ── 交互读取 ────────────────────────────────────────────────────


class PromptReader:
    """带补全与历史提示符的行读取器。"""

    def __init__(
        self,
        completer: Completer,
        history: list[str] | None = None,
        *,
        stream=None,
    ) -> None:
        self.completer = completer
        self.history = history if history is not None else []
        self._stream = stream or sys.stdout
        self.enabled = available()

    def read(self, prompt: str = "> ") -> str:
        if not self.enabled:
            return input(prompt)
        # prompt 可能带前导换行（调用方用来与上一轮输出隔开）。
        # 那段只打一次，只有最后一行参与重绘——否则每敲一个键都会多换一行。
        prefix, inline = _split_prompt(prompt)
        try:
            self._stream.write(prefix)
            self._stream.flush()
            return (
                self._read_win(inline) if _WIN else self._read_posix(inline)
            )
        except (KeyboardInterrupt, EOFError):
            raise
        except Exception:  # noqa: BLE001
            # 任何异常都必须退回普通 input，不能让补全功能拖垮整个程序
            return input(prompt)

    def _show_candidates(
        self,
        prompt: str,
        buf: str,
        pos: int,
        cands: list[str],
        *,
        cur_row: int = 0,
    ) -> int:
        """在输入区下方打印候选列表，并把输入区重新画好。

        折行时必须先擦掉旧的输入区（可能占多行），否则列表会把旧内容挤上去、
        残留一片——见 :func:`_erase_input`。

        ``cur_row`` 是光标此刻所在行。先 ``\\n`` 下到输入区下方，再上移
        ``cur_row + 1`` 行正好回到输入区首行。返回**候选列表打印完之后**
        光标相对新输入区首行的行号，调用方存下来传给下一次重绘。
        """
        cols = width._cols()
        rows_full, _ = _layout(prompt + buf, cols)
        if not keys._enable_vt():
            # 无 ANSI：擦不掉旧的，直接把候选打到下一行并重画；
            # 重画同样要裁进一行，否则输入区又会往下掉。
            self._stream.write(
                "\n" + "\n".join(_plain_row_text(c, cols) for c in cands) + "\n"
            )
            self._stream.write(_plain_row_text(prompt + buf, cols))
            self._stream.flush()
            return 0

        self._stream.write("\n")               # 下到输入区下方
        _erase_input(self._stream, cur_row + 1)  # 上移回输入区首行并清除
        self._stream.write("\n".join(cands))   # 候选（每行一个，避免超宽再折行）
        self._stream.write("\n")
        self._stream.write(prompt + buf)       # 重画输入区
        self._stream.flush()
        return rows_full

    # ── Windows ──────────────────────────────────────────────────
    def _read_win(self, prompt: str) -> str:
        buf = ""
        pos = 0                 # 插入点：0..len(buf)，**不是**只能改末尾
        # 光标此刻所在行（相对输入区首行）。prompt 刚写出，所以就是 prompt
        # 折行后的行号——prompt 本身也可能长到折行。
        crow = _layout(prompt, width._cols())[0]
        hist_idx = len(self.history)
        shown: list[str] = []   # 当前展示过的候选（空表示还没展示过）

        def redraw() -> None:
            nonlocal crow
            crow = _repaint(self._stream, prompt, buf, pos, cur_row=crow)

        self._stream.write(prompt)
        self._stream.flush()
        while True:
            # Alt+Shift 热键：必须在**等按键之前**轮询，因为单纯按下
            # Alt+Shift 不产生字符，只等字符的话永远等不到。
            if _mods_held():
                _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                return HOTKEY_FULL_AUTO
            if not msvcrt.kbhit():  # type: ignore[union-attr]
                time.sleep(0.02)
                continue
            ch = msvcrt.getwch()  # type: ignore[union-attr]

            # ── 功能键：\x00 / \xe0 前缀 + 扫描码 ──
            # 对照表（Windows 控制台）：
            #   0x48 H ↑        0x50 P ↓        0x4B K ←        0x4D M →
            #   0x47 G Home     0x4F O End      0x52 R Ins      0x53 S Del
            #   0x73 s Ctrl+←   0x74 t Ctrl+→   0x77 w Ctrl+Home 0x75 u Ctrl+End
            # 早先这里把 'I' 当 End、把 'S' 当 Ctrl+Left——都是错的，
            # 而且 'M'(→) 被塞在一个已被 'H' 抢先的分支后面，永远走不到，
            # 表现就是「左右方向键完全没反应」。
            if ch in ("\x00", "\xe0"):
                ch2 = msvcrt.getwch()  # type: ignore[union-attr]
                if ch2 == "K":                          # ←
                    pos = max(0, pos - 1)
                    redraw()
                    continue
                if ch2 == "M":                          # →
                    pos = min(len(buf), pos + 1)
                    redraw()
                    continue
                if ch2 == "H":                          # ↑ 历史
                    if hist_idx > 0:
                        hist_idx -= 1
                        buf = self.history[hist_idx]
                        pos = len(buf)
                        shown = []
                        redraw()
                    continue
                if ch2 == "P":                          # ↓ 历史
                    if hist_idx < len(self.history) - 1:
                        hist_idx += 1
                        buf = self.history[hist_idx]
                    else:
                        hist_idx = len(self.history)
                        buf = ""
                    pos = len(buf)
                    shown = []
                    redraw()
                    continue
                if ch2 == "G":                          # Home
                    pos = 0
                    redraw()
                    continue
                if ch2 == "O":                          # End
                    pos = len(buf)
                    redraw()
                    continue
                if ch2 == "S":                          # Delete
                    if pos < len(buf):
                        buf = buf[:pos] + buf[pos + 1:]
                        redraw()
                    continue
                if ch2 == "s":                          # Ctrl+←
                    pos = _prev_word(buf, pos)
                    redraw()
                    continue
                if ch2 == "t":                          # Ctrl+→
                    pos = _next_word(buf, pos)
                    redraw()
                    continue
                if ch2 in ("w", "u"):                   # Ctrl+Home / Ctrl+End
                    pos = 0 if ch2 == "w" else len(buf)
                    redraw()
                    continue
                continue                                # 其余（F1-F12、Ins…）忽略

            if ch == "\x03":                 # Ctrl+C
                _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                raise KeyboardInterrupt
            if ch in ("\r", "\n"):
                _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                return buf
            if ch == "\b":                   # Backspace：删光标前一个字符
                if pos > 0:
                    buf = buf[: pos - 1] + buf[pos:]
                    pos -= 1
                    shown = []
                    redraw()
                continue
            if ch == "\x7f":                 # Ctrl+Backspace：删光标前一个词
                if pos > 0:
                    i = _prev_word(buf, pos)
                    buf = buf[:i] + buf[pos:]
                    pos = i
                    shown = []
                    redraw()
                continue
            if ch == "\x01":                 # Ctrl+A 行首
                pos = 0
                redraw()
                continue
            if ch == "\x05":                 # Ctrl+E 行尾
                pos = len(buf)
                redraw()
                continue
            if ch == "\x15":                 # Ctrl+U 清空
                buf, pos = "", 0
                shown = []
                redraw()
                continue
            if ch == "\x0b":                 # Ctrl+K 删到行尾
                buf = buf[:pos]
                shown = []
                redraw()
                continue
            if ch == "\t":                   # Tab 补全
                buf, cands, _ = self.completer.complete(buf)
                pos = len(buf)
                if len(cands) > 1:
                    # 首次 Tab 只算公共前缀，再次 Tab 才展示列表
                    if not shown:
                        shown = cands
                    else:
                        # 候选列表把输入区推到了下面，行号要跟着更新，
                        # 否则紧接着的 redraw() 会上移过头、把候选擦掉。
                        crow = self._show_candidates(
                            prompt, buf, pos, cands, cur_row=crow
                        )
                redraw()
                continue
            if ch == "\x1b":                 # Esc
                continue
            if ch < " " and ch != "\t":
                continue
            buf = buf[:pos] + ch + buf[pos:]  # 在光标处插入，不是追加到末尾
            pos += 1
            shown = []
            redraw()


    # ── POSIX ────────────────────────────────────────────────────
    @staticmethod
    def _read_escape() -> str:
        """读完一个转义序列（``[A``、``[3~``、``[1;5C``…）。

        一直读到终止字节（``~`` 或字母）为止——``Ctrl+→`` 是 6 字节的
        ``\\x1b[1;5C``，只固定读 3 字节的话后面的 ``;5C`` 会被当成普通字符
        插进命令行里。
        """
        seq = ""
        for _ in range(8):
            c = sys.stdin.read(1)
            if not c:
                break
            seq += c
            if c == "~" or c.isalpha():
                break
        return seq

    def _read_posix(self, prompt: str) -> str:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)  # type: ignore[union-attr]
        buf = ""
        pos = 0
        crow = _layout(prompt, width._cols())[0]   # 光标此刻所在行
        hist_idx = len(self.history)
        shown: list[str] = []

        def redraw() -> None:
            nonlocal crow
            crow = _repaint(self._stream, prompt, buf, pos, cur_row=crow)

        try:
            tty.setraw(fd)  # type: ignore[union-attr]
            self._stream.write(prompt)
            self._stream.flush()
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                    return buf
                if ch == "\x03":
                    _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                    raise KeyboardInterrupt
                if ch == "\x04":
                    _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                    raise EOFError
                if ch == "\x7f":            # POSIX 下 DEL 就是退格
                    if pos > 0:
                        buf = buf[: pos - 1] + buf[pos:]
                        pos -= 1
                        shown = []
                        redraw()
                    continue
                if ch == "\x01":            # Ctrl+A 行首
                    pos = 0
                    redraw()
                    continue
                if ch == "\x05":            # Ctrl+E 行尾
                    pos = len(buf)
                    redraw()
                    continue
                if ch == "\x15":            # Ctrl+U 清空
                    buf, pos = "", 0
                    shown = []
                    redraw()
                    continue
                if ch == "\x0b":            # Ctrl+K 删到行尾
                    buf = buf[:pos]
                    shown = []
                    redraw()
                    continue
                if ch == "\x17":            # Ctrl+W 删前一个词
                    if pos > 0:
                        i = _prev_word(buf, pos)
                        buf = buf[:i] + buf[pos:]
                        pos = i
                        shown = []
                        redraw()
                    continue
                if ch == "\t":
                    buf, cands, _ = self.completer.complete(buf)
                    pos = len(buf)
                    if len(cands) > 1:
                        if not shown:
                            shown = cands
                        else:
                            crow = self._show_candidates(
                                prompt, buf, pos, cands, cur_row=crow
                            )
                    redraw()
                    continue
                if ch == "\x1b":
                    seq = self._read_escape()
                    if seq == "[A" and hist_idx > 0:            # ↑ 历史
                        hist_idx -= 1
                        buf = self.history[hist_idx]
                        pos = len(buf)
                        shown = []
                        redraw()
                        continue
                    if seq == "[B" and hist_idx < len(self.history) - 1:  # ↓
                        hist_idx += 1
                        buf = self.history[hist_idx]
                        pos = len(buf)
                        shown = []
                        redraw()
                        continue
                    if seq == "[D":                             # ←
                        pos = max(0, pos - 1)
                        redraw()
                        continue
                    if seq == "[C":                             # →
                        pos = min(len(buf), pos + 1)
                        redraw()
                        continue
                    if seq in ("[H", "[1~", "[7~"):             # Home
                        pos = 0
                        redraw()
                        continue
                    if seq in ("[F", "[4~", "[8~"):             # End
                        pos = len(buf)
                        redraw()
                        continue
                    if seq == "[3~":                            # Delete
                        if pos < len(buf):
                            buf = buf[:pos] + buf[pos + 1:]
                            redraw()
                        continue
                    if seq in ("[1;5D", "[1;3D", "b"):          # Ctrl/Alt+←
                        pos = _prev_word(buf, pos)
                        redraw()
                        continue
                    if seq in ("[1;5C", "[1;3C", "f"):          # Ctrl/Alt+→
                        pos = _next_word(buf, pos)
                        redraw()
                        continue
                    # POSIX 下 Alt 表现为 ESC 前缀，Shift 让字母变大写 →
                    # Alt+Shift+字母 就是 "\x1b" + 大写字母
                    if len(seq) == 1 and seq.isupper():
                        _finish_line(self._stream, prompt, buf, pos, cur_row=crow)
                        return HOTKEY_FULL_AUTO
                    continue
                if ch < " ":
                    continue
                buf = buf[:pos] + ch + buf[pos:]
                pos += 1
                shown = []
                redraw()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)  # type: ignore[union-attr]


