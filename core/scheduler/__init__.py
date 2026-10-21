"""扫描调度器——把「侦察 → 召回 → 验证 → 研判 → 报告」串成一条流水线。

``Scheduler`` 由 base + 四个阶段 mixin 多继承组装而成。方法体逐行来自拆分前的
单文件版本，所以行为完全一致；对上层只有 ``from core.scheduler import Scheduler``
这一个名字。

模块分块
========
=====================  ==========================================================
``helpers``           纯函数：IP 判定 / 画像文本（依赖链最底）
``base``              ``_SchedulerBase``：构造与共享状态
``recon``             ``_ReconMixin``：主流程 ``scan`` + 侦察 + 公开性核验
``match``             ``_MatchMixin``：RAG 召回 + 基线合并 + 情报增强
``verify``            ``_VerifyMixin``：验证 + 高危探针 + LLM 研判 + 知识库沉淀
``report``            ``_ReportMixin``：报告导出 + 自身描述
=====================  ==========================================================

方法全是 ``self._phaseN_xxx`` 互相调用，mixin 共享同一个 ``self``，
所以拆的是**文件**不是**对象**——一个 Scheduler 实例同时拥有全部阶段方法。
"""

from __future__ import annotations

from core.scheduler.base import _SchedulerBase
from core.scheduler.match import _MatchMixin
from core.scheduler.recon import _ReconMixin
from core.scheduler.report import _ReportMixin
from core.scheduler.verify import _VerifyMixin


class Scheduler(
    _ReportMixin,
    _VerifyMixin,
    _MatchMixin,
    _ReconMixin,
    _SchedulerBase,
):
    """整条扫描流水线的编排者——本类只负责把各阶段拼起来，不新增实现。"""


__all__ = ["Scheduler"]
