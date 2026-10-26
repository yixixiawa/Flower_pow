"""``run_repl`` —— 启动交互终端。

两件在这里兜底的事：

* **``patch_stdout()``** —— prompt_toolkit 接管屏幕期间，REPL 自己的
  ``print`` 会把提示符画面冲掉（"吃掉了你在 REPL 里的打印"）。
  套上它之后，这些内容会画在提示符**上方**，两不打架。
* **捕获 ``CancelledError`` / ``KeyboardInterrupt``** —— Ctrl+C 落在
  最外层（保存会话、收尾）时，不要让 traceback 糊在终端上：会话已经存过，
  安静退出即可。
"""

from __future__ import annotations

import asyncio

from prompt_toolkit.patch_stdout import patch_stdout

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
        with patch_stdout():
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
