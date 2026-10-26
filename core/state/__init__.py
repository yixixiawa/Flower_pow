"""扫描状态与数据模型——本包是整个工具的"事实来源"。

采集器（collectors）往里写资产，检测器（detectors）往里写发现，
RAG（kb）读它做检索匹配，调度器（core/scheduler）读它决定下一步做什么，
报告层（output）序列化它。

设计约束
--------
1. **证据优先**：每条 ``Finding`` 必须能追溯到一个 ``Evidence``（原始请求 + 响应）。
   没有证据的"发现"不允许进入报告——这是反幻觉的地基。
2. **可快照**：``ScanResult`` 能完整 to_dict / from_dict，支撑
   ``data/sessions/`` 下的会话快照与断点续扫。
3. **零重依赖**：不引入 numpy / pydantic 之外的运行时负担，向量检索用纯 Python
   实现（见 :mod:`kb.indexer`），保证在只有 httpx + yaml + openai 的环境也能跑。

模块分块
========
=====================  ==========================================================
``enums``             ``Severity`` / ``Category``——依赖为零的下游公共底座
``poc``               POC 声明模型（对应 ``poc/*.yaml``）：怎么匹配，不含状态
``models``            运行时对象（Evidence/Finding/ScanResult…）与误报排除
``util``              纯函数（正则缓存 / 文件名清洗 / dataclass 序列化）
=====================  ==========================================================

**对外接口不变**：所有调用方仍写 ``from core.state import Finding``，
符号在这里集中 re-export，拆分对上层完全透明。

依赖方向单向、无环：``util`` ← ``enums`` ← ``poc`` ← ``models``。
"""

from __future__ import annotations

from core.state.enums import Category, Severity
from core.state.models import (
   AttackChain,
   AttackStep,
    Asset,
    Evidence,
    Finding,
    Fingerprint,
    ScanResult,
    dismiss_finding,
    restore_finding,
)
from core.state.poc import MatchOp, MatchRule, MatchTarget, POC, RequestSpec
from core.state.util import dataclass_to_dict, re_search, safe_name

__all__ = [
    "Severity", "Category",
    "MatchTarget", "MatchOp", "MatchRule", "RequestSpec", "POC",
   "Evidence", "Fingerprint", "Asset", "AttackStep", "AttackChain", "Finding",
    "dismiss_finding", "restore_finding",
    "ScanResult",
    "re_search", "safe_name", "dataclass_to_dict",
]
