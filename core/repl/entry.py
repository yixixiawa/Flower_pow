"""``run_repl`` —— 启动交互终端。

三件在这里兜底的事：

* **``patch_stdout()``** —— prompt_toolkit 接管屏幕期间，REPL 自己的
  ``print`` 会把提示符画面冲掉（"吃掉了你在 REPL 里的打印"）。
  套上它之后，这些内容会画在提示符**上方**，两不打架。
  **但它绑死了控制台**：Windows 上没有控制台（管道、重定向、
  ``FLOWER_POW_PLAIN_INPUT=1``、被别的程序嵌入当子进程）时，
  ``patch_stdout()`` 进入时直接抛 ``NoConsoleScreenBufferError``——
  以前这异常会把整个 REPL 打挂（症状：session 功能"莫名挂了"）。
  现在改成可降级：拿不到控制台就不接管屏幕（此时也没有提示符可被冲掉），
  REPL 照常跑。
* **捕获 ``CancelledError`` / ``KeyboardInterrupt``** —— Ctrl+C 落在
  最外层（保存会话、收尾）时，不要让 traceback 糊在终端上：会话已经存过，
  安静退出即可。
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from collections.abc import Iterator

from prompt_toolkit.patch_stdout import patch_stdout

from core.completer import available
from core.config_loader import Config
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl import Repl
from core.repl.loop import uncancel

try:  # pragma: no cover - 非 Windows 构建里这个模块照常可导入
    from prompt_toolkit.output.win32 import NoConsoleScreenBufferError
except ImportError:  # pragma: no cover
    NoConsoleScreenBufferError = OSError  # type: ignore[assignment,misc]


@contextmanager
def _stdout_guard() -> Iterator[None]:
    """``patch_stdout()`` 的**可降级**版本。

    不能直接 ``with patch_stdout():``：它的 ``__enter__`` 会去拿 Windows
    控制台输出句柄，拿不到就抛 ``NoConsoleScreenBufferError``，整个 REPL
    连第一个提示符都出不来。降级判据两条：

    1. 输入流根本不是 TTY（``available()`` 为假）→ 没有提示符，不需要
       接管，直接跳过（``input()`` 降级路径本来就不会被 print 冲掉）；
    2. 是 TTY 但探测仍失败（异常环境）→ 吞掉异常继续跑：**能不给
       用户屏幕上糊 traceback，就绝不糊**。

    这里显式调 ``__enter__`` / ``__exit__`` 而不是嵌套 ``with``，避免
    "进入失败后再 yield"造成同一次 ``with`` 体内 yield 两次。
    """
    if not available():
        yield
        return
    cm = patch_stdout()
    try:
        cm.__enter__()
    except (NoConsoleScreenBufferError, OSError, AttributeError):
        yield
        return
    try:
        yield
    finally:
        try:
            cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001 - 收尾失败不该反过来打挂 REPL
            pass


async def run_repl(
    cfg: Config,
    session: Session,
    *,
    agent: bool = True,
    probes: list | None = None,
    kickoff: bool = False,
    history: list[str] | None = None,
) -> Session:
    repl = Repl(
        cfg, session, agent=agent, probes=probes, kickoff=kickoff, history=history
    )
    try:
        with _stdout_guard():
            return await repl.loop()
    except (asyncio.CancelledError, KeyboardInterrupt):
        # 最外层的中断：会话在 loop() 收尾时已经存过一次，这里再兜一次，
        # 保证"中断不丢数据"。uncancel() 把取消计数退回去，任务才能正常结束。
        uncancel()
        try:
            repl._save()
        except Exception:  # noqa: BLE001 - 存盘失败也不该再抛
            pass
        return repl.session


__all__ = ["Repl", "run_repl"]
