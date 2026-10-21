"""``_ReplBase``：构造与控制台。

持有会话、Agent、LLM 客户端、补全器与配置。多继承里排在**最后**——
靠后的基类属性优先级更高，这样 mixin 里的方法能安全地覆写基类钩子。"""

from __future__ import annotations

from core.completer import Completer, HOTKEY_FULL_AUTO, PromptReader
from core.config_loader import Config
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)


class _ReplBase:
    """交互式会话循环。"""

    def __init__(
        self,
        cfg: Config,
        session: Session,
        *,
        agent: bool = True,
        probes: list | None = None,
        kickoff: bool = False,
        history: list[str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.session = session
        self._planner = None
        self.kickoff = kickoff

        # Agent 相关：Key 可用才启用。没有 Key 时自动落到剧本模式，
        # 而不是让用户对着一堆"调用失败"发呆。
        self.runner = None
        self.agent = None
        self.llm = None
        self.tools: list = []
        self.probes = probes if probes is not None else self._probe()
        if agent and cfg.llm.enabled and cfg.llm.api_key:
            self._build_agent()
        self.reader = PromptReader(self._completer(), history=history)
        # 写操作的人工审核通道：每次上传前逐条问一遍
        if self.runner is not None:
            self.runner.approver = self._approve

    # ── 对话标题 ──────────────────────────────────────────────────
