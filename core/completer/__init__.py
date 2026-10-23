"""行编辑与补全——**全部交给 prompt_toolkit**，不再自造轮子。

以前这里有 7 个文件、将近 1000 行：``keys``（平台按键哨兵）、``width``
（双宽字符/ANSI 剥离）、``layout``（折行摊平）、``paint``（ANSI 重绘）、
``candidate``（候选生成）、``reader``（msvcrt / termios 裸模式按键循环）。
那些代码解决的是「自己实现一个终端」的问题——而 prompt_toolkit 已经把
宽字符、折行、历史、补全菜单、按键优先级全都做好了，且在 Windows /
POSIX 上行为一致。

现在只剩三样东西值得留在项目里：

=====================  ==================================================
``Completer``         **补全词表**：命令 + 参数两级候选（唯一资产）
``PromptReader``      ``PromptSession`` 的薄包装：多行编辑、语法高亮、
                      Ctrl+C 双语义、历史翻取
``HOTKEY_FULL_AUTO``  全自动热键的哨兵串（不可能由键盘产生）
=====================  ==================================================

补全语义沿用旧实现：**候选总是替换 tail（正在输入的最后一个词）**，
而不是追加——这样 ``/re<Tab> → /report`` 与 ``/report m<Tab> → /report md``
才能同时成立。
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import threading
from collections.abc import Sequence

from prompt_toolkit.completion import Completer as _PTCompleter
from prompt_toolkit.completion import Completion
from prompt_toolkit.history import History
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.shortcuts.prompt import CompleteStyle
from prompt_toolkit.style import Style


# ── 兼容旧接口的常量 ────────────────────────────────────────────

# 兜底开关：任何终端下交互表现异常时，设这个环境变量即退回原生 input()
_PLAIN_INPUT_ENV = "FLOWER_POW_PLAIN_INPUT"

# 全自动热键的返回值。用「不可能由键盘产生」的哨兵串，
# 调用方只需判断 ``raw == HOTKEY_FULL_AUTO``。
HOTKEY_FULL_AUTO = "\x00__full_auto__"

_VK_SHIFT = 0x10
_VK_MENU = 0x12   # Alt

# 输入框的配色：提示符青色、命令绿色、参数黄色
STYLE = Style.from_dict(
    {
        "prompt": "ansicyan bold",
        "command": "ansigreen bold",
        "argument": "ansiyellow",
        "completion-menu.completion": "bg:#222222 #ffffff",
        "completion-menu.completion.current": "bg:#005f87 #ffffff",
    }
)


# ── 补全词表（唯一的"自己的东西"）────────────────────────────────


class Completer(_PTCompleter):
    """命令 + 参数两级补全。

    ``commands`` 是命令清单（含 ``/`` 前缀），``args`` 是
    ``命令 -> 参数候选`` 的映射（键可带或不带前缀，内部会归一）。

    同时提供两种消费方式：

    * ``get_completions()`` —— prompt_toolkit 的标准接口，
      候选**替换 tail**（``start_position`` 为负长度）。
    * ``complete()`` —— 旧接口，返回 ``(新缓冲区, 候选列表, 公共前缀长度)``，
      保留给不接终端的纯逻辑单测。
    """

    def __init__(
        self,
        commands: Sequence[str],
        args: dict[str, Sequence[str]] | None = None,
    ) -> None:
        self.commands = sorted({c for c in commands if c})
        # 归一化成不带前斜杠的键，避免调用方到处写 '/'
        self.args = {
            k.lstrip("/"): list(v) for k, v in (args or {}).items() if v
        }

    # ── 纯逻辑：候选生成 ────────────────────────────────────────
    def _candidates(self, text: str) -> tuple[list[str], int]:
        """给定输入，返回 ``(候选列表, 待替换片段长度)``。

        ``待替换片段长度`` 是"正在输入的最后一个词"的长度——补全时用
        ``start_position=-长度`` 把它替换掉。
        """
        if " " not in text:
            return [c for c in self.commands if c.startswith(text)], len(text)
        head, _, tail = text.rpartition(" ")
        cmd = head.strip().lstrip("/")
        return [a for a in self.args.get(cmd, []) if a.startswith(tail)], len(tail)

    def complete(self, buf: str) -> tuple[str, list[str], int]:
        """旧接口：算出一个 ``(新缓冲区, 候选列表, 公共前缀长度)``。"""
        cands, n = self._candidates(buf)
        if not cands:
            return buf, [], 0
        if n == len(buf):  # 命令级：整个缓冲都是 tail
            return _common_prefix(cands), cands, 0
        head = buf[: len(buf) - n]
        return f"{head} {_common_prefix(cands)}", cands, 0

    # ── prompt_toolkit 接口 ─────────────────────────────────────
    def get_completions(self, document, complete_event):
        """产出候选：只替换 tail，不追加。"""
        text = document.text_before_cursor
        cands, n = self._candidates(text)
        for c in cands:
            yield Completion(c, start_position=-n, display=c)


def _common_prefix(cands: Sequence[str]) -> str:
    if not cands:
        return ""
    s = cands[0]
    for other in cands[1:]:
        i = 0
        m = min(len(s), len(other))
        while i < m and s[i] == other[i]:
            i += 1
        s = s[:i]
        if not s:
            break
    return s


# ── 语法高亮 ────────────────────────────────────────────────────


def _tokenize_line(line: str) -> list[tuple[str, str]]:
    """把一行拆成 ``(样式类, 文本)``：命令名绿色，参数黄色。"""
    out: list[tuple[str, str]] = []
    for i, tok in enumerate(line.split(" ")):
        if i:
            out.append(("", " "))
        if not tok:
            continue
        if i == 0 and tok.startswith("/"):
            out.append(("class:command", tok))
        else:
            out.append(("class:argument", tok))
    return out


class _CommandLexer(Lexer):
    """按行高亮：第一个词是命令（绿色），其余是参数（黄色）。"""

    def lex_document(self, document):
        def get_line(lineno: int) -> list[tuple[str, str]]:
            try:
                line = document.lines[lineno]
            except IndexError:  # pragma: no cover - 竞态
                return []
            return _tokenize_line(line)

        return get_line


# ── 历史：list 语义 + prompt_toolkit 语义 ───────────────────────


class _ListHistory(History):
    """把 prompt_toolkit 的 History 接口接到一个**普通 list** 上。

    为什么不是直接用 ``InMemoryHistory``：REPL 侧的历史是按 list 语义用的
    （``h[-1]`` 看上一条、``h.append`` 追加、``del h[:n]`` 截断），
    两边共用同一个 list 对象，才不会出现"补全里翻了、REPL 里没有"。

    顺序约定：``items`` 是**最旧 → 最新**；``load()`` 按 prompt_toolkit
    的要求产出**最新优先**，buffer 侧再 ``appendleft`` 还原成时间序。
    """

    def __init__(self, items: list[str] | None = None) -> None:
        super().__init__()
        self.items: list[str] = items if items is not None else []

    # ── prompt_toolkit 侧 ────────────────────────────────────────
    async def load(self):
        for item in reversed(self.items):
            yield item

    def load_history_strings(self):
        for item in reversed(self.items):
            yield item

    def store_string(self, string: str) -> None:
        """只存在内存里，不落盘。"""

    def append_string(self, string: str) -> None:
        """buffer 接受输入时自动调用——统一 strip + 去重后入列。"""
        text = (string or "").strip()
        if not text:
            return
        if self.items and self.items[-1] == text:
            return
        self.items.append(text)
        if len(self.items) > 200:
            del self.items[: len(self.items) - 200]
        self._loaded_strings.insert(0, text)

    def get_strings(self) -> list[str]:
        """最旧 → 最新。"""
        return list(self.items)


# ── 平台按键（仅剩 Alt+Shift 热键需要轮询）────────────────────────


def _mods_held() -> bool:
    """Alt 与 Shift 是否**同时**按下（Windows）。

    为什么用 GetAsyncKeyState 轮询而不是等按键事件：单纯按下 Alt+Shift
    **不会产生任何字符**——控制台根本不会往输入缓冲里放东西，只等字符的话
    永远等不到。（顺带一提 Alt+Shift 也是 Windows 切换输入法的快捷键，
    所以触发时输入法会跟着切一次，这是系统行为，绕不开。）
    """
    if os.name != "nt":
        return False
    try:
        get = ctypes.windll.kernel32.GetAsyncKeyState
        return bool(get(_VK_MENU) & 0x8000) and bool(get(_VK_SHIFT) & 0x8000)
    except Exception:  # noqa: BLE001
        return False


def available() -> bool:
    """当前环境是否支持交互式输入。

    非 tty（管道、CI、重定向）时退回原生 ``input()``——prompt_toolkit
    在那种环境下的渲染没有意义。
    """
    if os.environ.get(_PLAIN_INPUT_ENV):
        return False
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:  # noqa: BLE001
        return False


# ── 输入框 ──────────────────────────────────────────────────────


class PromptReader:
    """``PromptSession`` 的包装：补全、语法高亮、Ctrl+C 双语义。

    Ctrl+C 有**两种语义**，这是刻意区分的：

    * **输入框内**按 Ctrl+C —— 有文字就清空（``buffer.reset()``），
      没文字才退出程序。所以"想退出"要敲两下：先清空，再退。
    * **会话途中**（Agent / 扫描执行中）按 Ctrl+C —— 中断当前这一轮，
      **不退出程序**。这由 :mod:`core.repl.loop` 负责捕获。
    """

    def __init__(
        self,
        completer: Completer | None = None,
        history: list[str] | None = None,
        *,
        input=None,
        output=None,
    ) -> None:
        self._completer = completer
        self.history: list[str] = history if history is not None else []
        self.enabled = available()
        self._session: PromptSession | None = None
        self._input = input
        self._output = output

    # ── 补全器（可动态替换）─────────────────────────────────────
    @property
    def completer(self) -> Completer | None:
        return self._completer

    @completer.setter
    def completer(self, value: Completer | None) -> None:
        self._completer = value
        if self._session is not None:
            # PromptSession 用 DynamicCompleter 包了一层，改这里即刻生效
            self._session.completer = value

    # ── 会话 ────────────────────────────────────────────────────
    def _ensure_session(self) -> PromptSession:
        if self._session is not None:
            return self._session
        self._session = PromptSession(
            message="",
            completer=self._completer,
            history=_ListHistory(self.history),
            style=STYLE,
            lexer=_CommandLexer(),
            complete_while_typing=True,
            complete_style=CompleteStyle.COLUMN,
            reserve_space_for_menu=8,
            wrap_lines=True,
            multiline=False,
            enable_history_search=False,
            input=self._input,
            output=self._output,
            key_bindings=self._key_bindings(),
        )
        return self._session

    def _key_bindings(self) -> KeyBindings:
        kb = KeyBindings()

        @kb.add("c-c")
        def _ctrl_c(event) -> None:
            """Ctrl+C：有字清空，没字退出。"""
            buf = event.current_buffer
            if buf.text:
                buf.reset()
            else:
                event.app.exit(exception=KeyboardInterrupt(), style="class:aborting")

        return kb

    async def read(self, prompt: str = "> ") -> str:
        """读一行。**协程**——底层是 prompt_toolkit 的异步输入。"""
        if not self.enabled:
            # 非 tty 环境的退路：原生 input()（放在线程里，别阻塞事件循环）
            return await asyncio.to_thread(input, prompt)

        session = self._ensure_session()
        loop = asyncio.get_running_loop()
        watcher = _HotkeyWatcher(loop, session)
        watcher.start()
        try:
            text = await session.prompt_async(prompt)
        finally:
            watcher.stop()
            # 收尾时把光标推到下一行，否则后续输出会接在输入行尾巴上
            sys.stdout.write("\n")
            sys.stdout.flush()
        return text


class _HotkeyWatcher:
    """后台线程：轮询 Alt+Shift，命中就让当前输入返回哨兵串。

    Alt+Shift 在 Windows 控制台**不产生任何字符**，所以只能轮询
    ``GetAsyncKeyState``。命中后调用 ``Application.exit(result=...)``，
    ``prompt_async`` 就会把哨兵串当作"用户输入"返回给 REPL。
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, session: PromptSession) -> None:
        self._loop = loop
        self._session = session
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._fired = False

    def start(self) -> None:
        if os.name != "nt":
            return
        self._thread = threading.Thread(
            target=self._run, name="hotkey-alt-shift", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=1.0)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(0.02):
            if self._fired or not _mods_held():
                continue
            self._fired = True
            try:
                self._loop.call_soon_threadsafe(self._exit_with_sentinel)
            except RuntimeError:  # pragma: no cover - 事件循环已关
                return

    def _exit_with_sentinel(self) -> None:
        app = getattr(self._session, "app", None)
        if app is None:
            return
        try:
            app.exit(result=HOTKEY_FULL_AUTO)
        except Exception:  # noqa: BLE001 - 应用没在跑就算了
            pass


__all__ = [
    "Completer",
    "PromptReader",
    "available",
    "HOTKEY_FULL_AUTO",
    "STYLE",
]
