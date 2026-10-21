"""``_ContextMixin``：补全器与会话候选源。

命令候选来自 :data:`~core.repl.consts.COMMANDS`，会话标题候选来自磁盘上的
会话目录——所以 ``/resume`` 的 Tab 能补出真实存在的会话 id。"""

from __future__ import annotations

from pathlib import Path
from core.completer import Completer, HOTKEY_FULL_AUTO, PromptReader
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl.consts import COMMANDS


class _ContextMixin:
    def _session_ids(self, limit: int = 8) -> list[str]:
        """可恢复的会话 id——用于 ``/resume <Tab>`` 补全。"""
        try:
            base = Path(self.cfg.data_dir) / "sessions"
            return [name for name, _s in list_sessions(base, limit=limit)]
        except Exception:  # noqa: BLE001
            return []

    def _completer(self) -> Completer:
        """构建补全器：命令 + 各命令的参数候选。

        参数候选刻意做得比 ``/help`` 写的更多——``/help`` 是给人看的，
        补全是给手不用离开键盘的人用的。
        """
        args: dict[str, list[str]] = {
            "report": ["md", "html", "json", "all"],
            "assets": ["port", "path", "api", "endpoint", "secret", "internal", "js"],
            "findings": ["critical", "high", "medium", "low", "info", "all"],
            "fp": ["auto", "list", "undo", "del", "poc"],
            # 常见轮数，外加 0（不限）
            "poll": ["5", "8", "12", "20", "0"],
            "phase": ["recon", "model", "exploit", "iterate"],
            "agent": ["on", "off"],
            "resume": self._session_ids(),
            # 标题编号只列已存在的 + 下一个（避免补出一堆不存在的编号）
            "title": [str(i) for i in range(1, len(self.session.conversations) + 2)],
        }
        # 目标相关的动态候选
        if self.session.target:
            base = self.session.target.rstrip("/")
            args["target"] = [base, f"{base}/api", f"{base}/admin"]
        # /turns 可按编号回看，编号跟着实际轮数走
        if self.session.turns:
            args.setdefault("turns", [str(t.no) for t in self.session.turns][-10:])
        return Completer(COMMANDS, args)

    def _refresh_completer(self) -> None:
        """会话变化后重建补全器（候选依赖当前会话）。"""
        try:
            self.reader.completer = self._completer()
        except Exception:  # noqa: BLE001
            pass

    # ── 延迟构建 ──────────────────────────────────────────────────

    @staticmethod
    def _probe() -> list:
        from core.tools import probe_external

        try:
            probes, _errs = probe_external()
            return probes
        except Exception:  # noqa: BLE001
            return []

    def _build_agent(self) -> None:
        from core.agent import Agent
        from core.tools import ToolRunner
        from core.tools import llm_schemas
        from llm.client import LLMClient

        self.llm = LLMClient(self.cfg.llm)
        self.runner = ToolRunner(self.cfg, self.probes, ".")
        self.tools = llm_schemas(self.probes)
        self.agent = Agent(
            self.cfg, self.session, self.runner, self.tools, self.llm, probes=self.probes
        )

    @property
    def planner(self):
        if self._planner is None:
            from core.planner import Planner

            self._planner = Planner(self.cfg, verbose=True)
        return self._planner

    @property
    def agent_on(self) -> bool:
        return self.agent is not None

    # ── 主循环 ────────────────────────────────────────────────────
