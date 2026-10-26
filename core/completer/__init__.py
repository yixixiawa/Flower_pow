# core/completer/__init__.py
"""终端输入层——基于 prompt_toolkit 的补全、历史与语法高亮。

以前这里是 7 个文件近 1000 行自造轮子（reader / layout / paint / width /
keys …），自己处理裸模式按键、ANSI 重绘与宽字符对齐。现在全部废弃，
只留三样东西：

* :class:`Completer` —— 补全词表（命令级 + 参数级两级候选）
* :class:`PromptReader` —— :class:`prompt_toolkit.PromptSession` 的薄包装
* :data:`HOTKEY_FULL_AUTO` —— Alt+Shift 热键的哨兵串

宽字符、多行编辑、终端转义序列全部交给 prompt_toolkit 自己处理。
"""

from __future__ import annotations

from collections.abc import Iterable
import os
import sys
from typing import cast

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer as PromptCompleter
from prompt_toolkit.completion import Completion
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.history import History
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style

HOTKEY_FULL_AUTO = "\x00__full_auto__"


class Completer(PromptCompleter):
    """自定义补全：支持主命令和带参数的二级补全。"""

    def __init__(
        self,
        cmds: Iterable[str] = (),
        args_map: dict[str, list[str]] | None = None,
    ) -> None:
        self.cmds = tuple(cmds)
        self.args_map = {key.lstrip("/"): list(values) for key, values in (args_map or {}).items()}

    @staticmethod
    def _common_prefix(candidates: list[str]) -> str:
        if not candidates:
            return ""
        prefix = candidates[0]
        for candidate in candidates[1:]:
            size = 0
            for left, right in zip(prefix, candidate):
                if left != right:
                    break
                size += 1
            prefix = prefix[:size]
            if not prefix:
                break
        return prefix

    def _candidates(self, text: str) -> tuple[list[str], int]:
        if " " not in text:
            return [cmd for cmd in self.cmds if cmd.startswith(text)], len(text)
        head, _, tail = text.rpartition(" ")
        command = head.strip().lstrip("/")
        candidates = [arg for arg in self.args_map.get(command, []) if arg.startswith(tail)]
        return candidates, len(tail)

    def complete(self, text: str) -> tuple[str, list[str], int]:
        """Return the legacy completion result used by non-terminal callers."""
        candidates, tail_length = self._candidates(text)
        if not candidates:
            return text, [], 0
        common = self._common_prefix(candidates)
        if tail_length == len(text):
            return common, candidates, 0
        head = text[: len(text) - tail_length]
        return f"{head}{common}", candidates, 0

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        line = text.rsplit("\n", 1)[-1]
        if not line.startswith("/"):
            return

        # 主命令补全
        if " " not in line:
            for c in self.cmds:
                if c.startswith(line):
                    yield Completion(c, start_position=-len(line))
            return

        # 参数补全
        parts = line.split()
        if len(parts) == 2:
            cmd = parts[0].lstrip("/")
            current_arg = parts[1]
            if cmd in self.args_map:
                for arg in self.args_map[cmd]:
                    if arg.startswith(current_arg):
                        yield Completion(arg, start_position=-len(current_arg))


FlowerCompleter = Completer


class _CommandLexer(Lexer):
    """Highlight a slash command and its arguments on every input line."""

    @staticmethod
    def _tokens(line: str) -> StyleAndTextTuples:
        if not line:
            return []
        first, separator, rest = line.partition(" ")
        tokens = [("class:command", first)] if first.startswith("/") else [("", first)]
        if separator:
            tokens.append(("", separator))
            if rest:
                tokens.append(("class:argument", rest))
        return cast(StyleAndTextTuples, tokens)

    def lex_document(self, document):
        def get_line(line_no: int) -> StyleAndTextTuples:
            return self._tokens(document.lines[line_no])

        return get_line


class _ListHistory(History):
    """Expose the REPL's ordinary list history through prompt-toolkit."""

    def __init__(self, items: list[str] | None = None) -> None:
        super().__init__()
        self.items = items if items is not None else []

    async def load(self):
        for item in reversed(self.items):
            yield item

    def load_history_strings(self):
        return iter(reversed(self.items))

    def store_string(self, string: str) -> None:
        return None

    def append_string(self, string: str) -> None:
        text = (string or "").strip()
        if not text or (self.items and self.items[-1] == text):
            return
        self.items.append(text)
        if len(self.items) > 200:
            del self.items[:-200]


class PromptReader:
    """REPL 的输入层——包住一个 :class:`PromptSession`。

    两个设计要点：

    * **懒创建 session**。``PromptSession`` 在构造时就会去探测输出设备，
      没有 Windows 控制台时直接抛 ``NoConsoleScreenBufferError``。所以
      这里不急着建，等真要读一行时才建；建不出来就退回普通 ``input()``。
    * **Ctrl+C 双语义**。有文字 → 只清空文字（程序活着）；空输入 → 抛
      ``KeyboardInterrupt`` 退出程序（敲两下退出）。
    """

    def __init__(
        self,
        completer: PromptCompleter | None = None,
        history: list[str] | None = None,
        *,
        input=None,
        output=None,
    ) -> None:
        self._completer = completer
        self.history: list[str] = history if history is not None else []
        self._input = input
        self._output = output
        self.enabled = available(input=input, output=output)
        self._session: PromptSession | None = None
        self._key_bindings = self._build_bindings()
        self.style = Style.from_dict(
            {
                "prompt": "ansicyan bold",
                "command": "ansigreen bold",
                "argument": "ansiyellow",
            }
        )

    def _build_bindings(self) -> KeyBindings:
        """自定义键位——只有这里覆盖了 prompt_toolkit 的默认行为。"""
        kb = KeyBindings()

        @kb.add("c-c")
        def _(event):
            buf = event.current_buffer
            if buf.text:
                # 有文字时：清空文字，重置光标（不毁历史）
                buf.text = ""
                buf.cursor_position = 0
            else:
                # 空文字时：抛中断，让外层捕获并退出
                event.app.exit(exception=KeyboardInterrupt())

        @kb.add("c-j")
        def _(event):
            event.current_buffer.validate_and_handle()

        @kb.add("enter")
        def _(event):
            event.current_buffer.validate_and_handle()

        @kb.add("escape", "enter")
        def _(event):
            event.current_buffer.insert_text("\n")

        return kb

    def _session_history(self) -> History:
        return _ListHistory(self.history)

    def _ensure_session(self) -> PromptSession | None:
        """懒建 session；环境不支持交互时返回 ``None``（调用方退回 input()）。"""
        if self._session is not None:
            return self._session
        try:
            self._session = PromptSession(
                input=self._input,
                output=self._output,
                completer=self._completer,
                history=self._session_history(),
                style=self.style,
                complete_while_typing=True,
                key_bindings=self._key_bindings,
                lexer=_CommandLexer(),
                multiline=True,
            )
        except Exception:  # noqa: BLE001 - 没有控制台 / 管道环境
            self._session = None
        return self._session

    @property
    def session(self) -> PromptSession | None:
        return self._ensure_session()

    @property
    def completer(self) -> PromptCompleter | None:
        return self._completer

    @completer.setter
    def completer(self, value: PromptCompleter | None) -> None:
        self._completer = value
        if self._session is not None:
            self._session.completer = value

    async def read(self, prompt_text: str = "[agent] > ") -> str:
        """读一行输入。

        正常走 prompt_toolkit（多行编辑 / 补全 / 高亮 / 历史）。
        没有交互终端时退回内置 ``input()``——至少还能用。

        退出语义：``EOFError`` / ``KeyboardInterrupt`` 原样抛给调用方，
        由主循环决定是"退出程序"还是"中断这一轮"。
        """
        session = self._ensure_session() if self.enabled else None
        if session is None:
            import asyncio

            return await asyncio.to_thread(input, prompt_text)
        return await session.prompt_async(message=prompt_text)


def available(*, input=None, output=None) -> bool:
    """Whether the current streams support an interactive prompt."""
    if os.environ.get("FLOWER_POW_PLAIN_INPUT"):
        return False
    stdin = input if input is not None else sys.stdin
    stdout = output if output is not None else sys.stdout
    try:
        return bool(stdin.isatty() and stdout.isatty())
    except (AttributeError, OSError):
        return False