"""会话里的四个数据类：阶段 / 轮次 / 对话轮 / 业务模型。

都是纯数据 + 往返序列化，不碰磁盘也不碰网络，可以脱离会话单独测。"""

from __future__ import annotations

import time
from typing import Any
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from core.session.redact import redact


# ── 字段级容错解析 ────────────────────────────────────────────────
#
# 为什么要这一层：快照是**外部输入**——可能是旧版本写的、手改过的、
# 写到一半被 Ctrl+C 截断的。以前 ``from_dict`` 里直接 ``int(...)`` /
# ``Phase(...)``，任何一个字段对不上就抛异常；而 ``list_sessions`` 没有
# 逐条兜底，一条坏快照能让整个 ``/sessions`` / ``flower_pow sessions``
# 直接报错退出，用户看到的是"历史会话全都没了"。
#
# 现在的原则：**字段坏了退回默认值，快照还能用**。真读不出来（JSON 坏）
# 才由 ``Session.load`` 返回 None 并在列表里被跳过。


def as_phase(value: Any, default: "Phase | None" = None) -> "Phase":
    """``"recon"`` / ``Phase.RECON`` / 中文标签 → ``Phase``；不认识退回默认。"""
    if isinstance(value, Phase):
        return value
    text = str(value or "").strip()
    if not text:
        return default or Phase.RECON
    for p in Phase:
        if text == p.value:
            return p
    # 旧版/手改的快照可能存的是中文标签（"信息收集"）
    for p in Phase:
        if text == p.label:
            return p
    return default or Phase.RECON


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def as_list(value: Any) -> list:
    """非列表一律当空——字符串尤其不能 ``list("abc")`` 成三个字符。"""
    return list(value) if isinstance(value, (list, tuple)) else []


def as_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


class Phase(str, Enum):
    """测试阶段。顺序即推进方向。"""

    RECON = "recon"        # 第 1 轮：信息收集（资产面）
    MODEL = "model"        # 第 2 轮：业务逻辑建模（理解系统在做什么）
    EXPLOIT = "exploit"    # 第 3 轮：渗透测试（动手验证）
    ITERATE = "iterate"    # 第 4 轮及以后：基于结果反复深挖

    @property
    def label(self) -> str:
        return {
            Phase.RECON: "信息收集",
            Phase.MODEL: "业务建模",
            Phase.EXPLOIT: "渗透测试",
            Phase.ITERATE: "迭代深挖",
        }[self]

    @property
    def goal(self) -> str:
        return {
            Phase.RECON: "摸清目标有什么：端口、路径、JS、接口清单、技术栈",
            Phase.MODEL: "理解系统在做什么：资源、状态流转、权限边界、资金与凭据相关操作",
            Phase.EXPLOIT: "动手验证：鉴权是否生效、资源归属是否校验、敏感数据是否出网",
            Phase.ITERATE: "基于已有发现深挖：换参数、换角色、换顺序，找漏网之鱼",
        }[self]

    @property
    def next(self) -> "Phase":
        order = [Phase.RECON, Phase.MODEL, Phase.EXPLOIT, Phase.ITERATE]
        i = order.index(self)
        return order[min(i + 1, len(order) - 1)]


@dataclass
class Turn:
    """一轮对话的记录。"""

    no: int
    phase: Phase
    intent: str = ""                      # 这轮想干什么（用户输入或规划器意图）
    actions: list[str] = field(default_factory=list)   # 实际执行的动作
    new_assets: int = 0
    new_findings: int = 0
    notes: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)  # 建议下一轮做什么
    at: float = field(default_factory=time.time)
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "no": self.no,
            "phase": self.phase.value,
            "intent": self.intent,
            "actions": self.actions,
            "new_assets": self.new_assets,
            "new_findings": self.new_findings,
            "notes": self.notes,
            "suggestions": self.suggestions,
            "at": self.at,
            "elapsed": round(self.elapsed, 2),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Turn":
        d = as_dict(d)
        return cls(
            no=as_int(d.get("no"), 0),
            phase=as_phase(d.get("phase")),
            intent=as_str(d.get("intent")),
            actions=[as_str(x) for x in as_list(d.get("actions"))],
            new_assets=as_int(d.get("new_assets"), 0),
            new_findings=as_int(d.get("new_findings"), 0),
            notes=[as_str(x) for x in as_list(d.get("notes"))],
            suggestions=[as_str(x) for x in as_list(d.get("suggestions"))],
            at=as_float(d.get("at"), time.time()),
            elapsed=as_float(d.get("elapsed"), 0.0),
        )


@dataclass
class ConversationTurn:
    """一轮**对话**的索引条目。

    为什么需要独立于 ``Turn``
    -------------------------
    ``Turn`` 记的是「剧本模式跑了一轮测试」（阶段、耗时、+多少资产），
    而Agent 模式下的一轮对话没有这些——它只是一次问答。恢复会话后想看
    「上次聊到哪了」，需要按对话切分的标题列表，否则只能翻 39 条原始消息。

    标题生成策略（``llm`` 可用时）
    ----------------------------
    优先用小模型把这一轮压成一句≤20 字的中文标题；失败则退回「取用户输入
    前 N 字」。**不额外调大模型**——标题是索引，不是交付物。

    落盘时``raw``（用户输入与模型回复摘要）会被 ``redact`` 脱敏，
    与对话历史同一套规则。
    """

    no: int
    title: str = ""
    at: float = field(default_factory=time.time)
    # 该轮用到的工具名，报告与回溯时有用
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "no": self.no,
            "title": redact(self.title),
            "at": self.at,
            "tools": list(self.tools),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConversationTurn":
        d = as_dict(d)
        return cls(
            no=as_int(d.get("no"), 0),
            title=as_str(d.get("title")),
            at=as_float(d.get("at"), time.time()),
            tools=[as_str(x) for x in as_list(d.get("tools"))],
        )


@dataclass
class BusinessModel:
    """第 2 轮的产物：从接口清单推导出的业务理解。

    建模不是走过场——**渗透测试点的选择完全依赖它**。
    不知道「充值/提现」是哪个接口，就不会去测那里的越权。
    """

    resources: list[str] = field(default_factory=list)      # /api/users、/api/orders…
    auth_domains: dict[str, int] = field(default_factory=dict)  # public/user/admin 各多少
    high_value: list[str] = field(default_factory=list)     # 资金、凭据、权限相关操作
    state_flows: list[str] = field(default_factory=list)    # 推断出的业务流
    admin_ops: list[str] = field(default_factory=list)      # 后台管理操作
    upload_ops: list[str] = field(default_factory=list)     # 上传/代理类（SSRF 候选）
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resources": self.resources,
            "auth_domains": self.auth_domains,
            "high_value": self.high_value,
            "state_flows": self.state_flows,
            "admin_ops": self.admin_ops,
            "upload_ops": self.upload_ops,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BusinessModel":
        d = as_dict(d)
        return cls(
            resources=[as_str(x) for x in as_list(d.get("resources"))],
            auth_domains={as_str(k): as_int(v) for k, v in as_dict(d.get("auth_domains")).items()},
            high_value=[as_str(x) for x in as_list(d.get("high_value"))],
            state_flows=[as_str(x) for x in as_list(d.get("state_flows"))],
            admin_ops=[as_str(x) for x in as_list(d.get("admin_ops"))],
            upload_ops=[as_str(x) for x in as_list(d.get("upload_ops"))],
            notes=[as_str(x) for x in as_list(d.get("notes"))],
        )

    def summary(self) -> str:
        return (
            f"资源 {len(self.resources)} 类、"
            f"权限域 {self.auth_domains}、"
            f"高价值操作 {len(self.high_value)}、"
            f"后台操作 {len(self.admin_ops)}、"
            f"上传/代理 {len(self.upload_ops)}"
        )


