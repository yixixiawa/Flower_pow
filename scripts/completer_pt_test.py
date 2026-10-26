"""交互层的**行为级**回归——真的按 prompt_toolkit 的键。

为什么不再自己模拟终端：这套东西现在**就是** prompt_toolkit，自造一个假屏幕
去断言 ANSI 序列，测的是"我们对 prompt_toolkit 的用法对不对"这件事的影子。
所以这里直接用 prompt_toolkit 自带的管道输入（``create_pipe_input``）把按键
真的喂进去，断言**最终缓冲区里的文字**。

覆盖三件事：

1. Tab 补全：``/re`` + Tab → ``/report``；``/report m`` + Tab → ``/report md``。
2. Ctrl+C 双语义：**有文字**时清空文字（程序不退出）；**空输入**时退出程序。
3. 历史：``↑`` 能翻出上一条输入。

运行：.venv/Scripts/python.exe scripts/completer_pt_test.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_toolkit.document import Document  # noqa: E402
from prompt_toolkit.input import create_pipe_input  # noqa: E402
from prompt_toolkit.key_binding import KeyBindings  # noqa: E402
from prompt_toolkit.output import DummyOutput  # noqa: E402
from prompt_toolkit.shortcuts import PromptSession  # noqa: E402

from core.completer import Completer, PromptReader, _ListHistory  # noqa: E402

CMDS = ["/help", "/status", "/report", "/resume"]
ARGS = {"report": ["md", "html", "json", "all"]}


def _bindings() -> KeyBindings:
    """复用 PromptReader 里的那套自定义键位（含 Ctrl+C 双语义）。"""
    return PromptReader(Completer(CMDS, ARGS))._key_bindings


async def _drive(keys: list[str], *, prefill: str = "", settle: float = 0.30):
    """喂一串按键，返回 ``PromptSession`` 收到的那一行。

    每次喂键之间留一点空隙：prompt_toolkit 的补全是**异步**的
    （``_async_completer`` 是个后台任务），不 sleep 的话 Tab 还没生效
    就被回车收走了，测出来的会是"补全没生效"的假象。

    ``complete_while_typing=True`` 与 :class:`PromptReader` 的真实配置一致——
    关掉它的话，第一次 Tab 只是弹出候选菜单不动文本，第二次才填入，
    那测的是另一个配置下的行为。
    """
    with create_pipe_input() as inp:
        session = PromptSession(
            input=inp,
            output=DummyOutput(),
            completer=Completer(CMDS, ARGS),
            complete_while_typing=True,
        )
        task = asyncio.get_running_loop().create_task(session.prompt_async("> "))
        await asyncio.sleep(settle)
        if prefill:
            inp.send_text(prefill)
            await asyncio.sleep(settle)
        for k in keys:
            inp.send_text(k)
            await asyncio.sleep(settle)
        return await asyncio.wait_for(task, timeout=10)


async def _main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    print("场景1 Tab 补全（真按 Tab）")
    r = await _drive(["\t", "\r"], prefill="/re")
    check(r == "/report", f"/re + Tab -> /report，实={r!r}")
    r2 = await _drive(["\t", "\r"], prefill="/report m")
    check(r2 == "/report md", f"/report m + Tab -> /report md，实={r2!r}")

    print("\n场景2 Ctrl+C：输入框里有文字 → 只清空，不退出")
    with create_pipe_input() as inp:
        session = PromptSession(
            input=inp,
            output=DummyOutput(),
            completer=Completer(CMDS, ARGS),
            key_bindings=_bindings(),
        )
        task = asyncio.get_running_loop().create_task(session.prompt_async("> "))
        await asyncio.sleep(0.30)
        inp.send_text("/hel")
        await asyncio.sleep(0.30)
        inp.send_text("\x03")          # Ctrl+C：此时有文字
        await asyncio.sleep(0.40)
        check(not task.done(), "有文字时 Ctrl+C 没有退出程序")
        check(session.default_buffer.text == "",
              f"有文字时 Ctrl+C 把文字清空了，实={session.default_buffer.text!r}")
        # 清空后还能继续输入 → 说明程序活着
        inp.send_text("/quit")
        await asyncio.sleep(0.30)
        inp.send_text("\r")
        try:
            got = await asyncio.wait_for(asyncio.shield(task), timeout=10)
        except KeyboardInterrupt:
            got = "<KeyboardInterrupt>"
        check(got == "/quit", f"清空后仍可继续输入，实={got!r}")

    print("\n场景3 Ctrl+C：空输入 → 退出程序")
    with create_pipe_input() as inp:
        session = PromptSession(
            input=inp,
            output=DummyOutput(),
            key_bindings=_bindings(),
        )

        async def _feed_ctrl_c():
            await asyncio.sleep(0.30)
            inp.send_text("\x03")      # Ctrl+C：此时空输入

        # 直接 await（与生产路径一致），不用 create_task + wait_for：
        # KeyboardInterrupt 是 BaseException，wait_for 遇到它会直接向上抛，
        # 绕过了"等待 future 完成"这一步，测出来的行为和生产不一致。
        feeder = asyncio.get_running_loop().create_task(_feed_ctrl_c())
        try:
            await session.prompt_async("> ")
            check(False, "空输入时 Ctrl+C 应该抛 KeyboardInterrupt 退出")
        except KeyboardInterrupt:
            check(True, "空输入时 Ctrl+C 抛 KeyboardInterrupt 退出程序")
        except asyncio.CancelledError:
            check(False, "空输入时 Ctrl+C 抛 KeyboardInterrupt 退出程序")
        finally:
            feeder.cancel()

    print("\n场景4 历史：↑ 翻出上一条输入")
    with create_pipe_input() as inp:
        session = PromptSession(
            input=inp,
            output=DummyOutput(),
            history=PromptReader(Completer(CMDS, ARGS), history=["/help"])._session_history(),
        )
        task = asyncio.get_running_loop().create_task(session.prompt_async("> "))
        await asyncio.sleep(0.30)
        inp.send_text("\x1b[A")        # ↑
        await asyncio.sleep(0.40)
        check(session.default_buffer.text == "/help",
              f"↑ 翻出上一条 /help，实={session.default_buffer.text!r}")
        inp.send_text("\r")
        await asyncio.wait_for(task, timeout=10)

    print("\n场景5 补全的 start_position 与 tail 长度一致")
    c = Completer(CMDS, ARGS)
    comps = list(c.get_completions(Document("/re", 3), None))
    check(all(x.start_position == -3 for x in comps),
          f"命令级 -3，实={[x.start_position for x in comps]}")
    comps2 = list(c.get_completions(Document("/report m", 9), None))
    check(comps2 and comps2[0].start_position == -1,
          f"参数级 -1，实={[x.start_position for x in comps2]}")

    print("\n场景6 PromptReader 在无控制台环境不炸")
    reader = PromptReader(Completer(CMDS, ARGS))
    check(reader.session is not None or not reader.enabled,
          "无控制台时应优雅降级而不是抛异常")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
