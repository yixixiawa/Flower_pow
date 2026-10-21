"""``_SchedulerBase``：构造与共享状态。

持有配置、LLM 客户端、检索器、向量库与各类采集/检测器实例。
阶段方法通过 ``self.xxx`` 拿它们，所以 base 一定排在所有 mixin 之后
（多继承里靠后的基类属性更优先）。"""

from __future__ import annotations

from collections.abc import Awaitable
from collections.abc import Callable
from core.config_loader import Config, sessions_dir
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)
from llm.client import LLMClient


class _SchedulerBase:
    """扫描编排。"""

    def __init__(
        self,
        cfg: Config,
        approver: Callable[[str], Awaitable[bool]] | None = None,
    ) -> None:
        self.cfg = cfg
        self.llm = LLMClient(cfg.llm)
        # 写操作的人工审核通道。None 时上传类探测会被跳过（不会偷偷写目标）。
        self.approver = approver
        self._intel = None  # 延迟加载
        # POC 库：JS 逻辑审计与一次性探针都要用它做漏洞模板兜底，
        # 所以在侦察阶段之前就要有值（空字典也能跑，只是用内置模板）。
        self._poc_map: dict[str, POC] = {}
        self._selected: list[POC] = []
        self._scores: dict[str, float] = {}

    # ── 主流程 ────────────────────────────────────────────────────
