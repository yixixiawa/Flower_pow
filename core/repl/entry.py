"""``run_repl`` —— 启动交互终端。"""

from __future__ import annotations

from core.config_loader import Config
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl import Repl


async def run_repl(
    cfg: Config,
    session: Session,
    *,
    agent: bool = True,
    probes: list | None = None,
    kickoff: bool = False,
    history: list[str] | None = None,
) -> Session:
    return await Repl(
        cfg, session, agent=agent, probes=probes, kickoff=kickoff, history=history
    ).loop()


__all__ = ["Repl", "run_repl"]
