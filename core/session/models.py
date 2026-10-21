"""会话里的四个数据类：阶段 / 轮次 / 对话轮 / 业务模型。

都是纯数据 + 往返序列化，不碰磁盘也不碰网络，可以脱离会话单独测。"""

from __future__ import annotations

import time
from typing import Any
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from core.session.redact import redact


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
        return cls(
            no=int(d.get("no") or 0),
            phase=Phase(d.get("phase") or Phase.RECON.value),
            intent=str(d.get("intent") or ""),
            actions=list(d.get("actions") or []),
            new_assets=int(d.get("new_assets") or 0),
            new_findings=int(d.get("new_findings") or 0),
            notes=list(d.get("notes") or []),
            suggestions=list(d.get("suggestions") or []),
            at=float(d.get("at") or time.time()),
            elapsed=float(d.get("elapsed") or 0.0),
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
        return cls(
            no=int(d.get("no") or 0),
            title=str(d.get("title") or ""),
            at=float(d.get("at") or time.time()),
            tools=[str(x) for x in (d.get("tools") or [])],
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
        return cls(
            resources=list(d.get("resources") or []),
            auth_domains=dict(d.get("auth_domains") or {}),
            high_value=list(d.get("high_value") or []),
            state_flows=list(d.get("state_flows") or []),
            admin_ops=list(d.get("admin_ops") or []),
            upload_ops=list(d.get("upload_ops") or []),
            notes=list(d.get("notes") or []),
        )

    def summary(self) -> str:
        return (
            f"资源 {len(self.resources)} 类、"
            f"权限域 {self.auth_domains}、"
            f"高价值操作 {len(self.high_value)}、"
            f"后台操作 {len(self.admin_ops)}、"
            f"上传/代理 {len(self.upload_ops)}"
        )


