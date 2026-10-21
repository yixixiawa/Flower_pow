"""轮次穷尽判定与自动轮询驱动。

要解决什么
----------
会话里每轮之间要**手工回车**才继续（回车 = 跑一轮）。跑一个站点往往要十几轮，
人得一直守着敲回车；而"什么时候算测完了"也只能靠人自己看。

这个模块把两件事抽出来，让 REPL 与 CLI 共用同一套：

1. :class:`Exhaustion` —— **穷尽判定**（纯状态机，不碰网络、不碰会话）
2. :func:`poll_until_done` —— **轮询驱动**（反复跑轮，直到判定停下）

穷尽判据
--------
**连续 ``idle_limit`` 轮完全没有推进**。一轮算"有推进"的条件是三者之一：

* 新增了资产（`new_assets > 0`）
* 新增了发现（`new_findings > 0`）
* 新增了业务模型条目（`new_model > 0`）—— 建模阶段的主要产出不是资产也不是发现

三者都没有 = 这一轮只是空转（模型在复述、在整理、在重读已有信息）。

**为什么要求连续两轮**：单轮没产出可能是"这轮在研判/整理"，不代表没得测了。
连着一轮又一轮什么都没有，才说明真的穷尽了。

.. warning::

   **判据只看硬状态，不看"下一步建议"。** 一开始把"没有下一步建议"也算作空转条件，
   实测直接失败：``Planner._suggest()`` 是**阶段驱动**的（迭代阶段的兜底文本恒为
   "继续迭代或导出报告"），**每轮都非空** —— 那个条件永远不成立，"穷尽了才停"
   就退化成"每次都跑到上限"。建议文本是给人看的旁白，不是可依赖的负信号；
   只有"状态有没有变化"是硬的。

**为什么硬上限仍然保留**：穷尽判据基于"状态没变化"，而 Agent 可以每轮都调一次
工具、每轮都不产出结论——那样永远不会被判穷尽，token 会一直烧。所以另设轮数上限
兜底。到上限的语义是**"自动轮询到此为止"，不是"测完了"**，两者的措辞必须分开说，
否则用户会以为覆盖完整了。上限设 0 表示不限（愿意自己盯着的可以关掉）。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

# 连续多少轮无产出判定穷尽。2 是刻意的：单轮可能是"在整理"。
IDLE_LIMIT = 2

# 自动轮询的硬上限（安全阀，不是穷尽判据）。0 = 不限。
DEFAULT_MAX_ROUNDS = 12

# 停止原因
STOP_EXHAUSTED = "exhausted"
STOP_CAPPED = "capped"


@dataclass
class RoundOutcome:
    """一轮的结果，穷尽判定只看这几个数。"""

    no: int
    new_assets: int = 0
    new_findings: int = 0
    new_model: int = 0
    suggestions: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    # 模型自己在回复里说了"已无可测"之类。**只用于措辞**，不参与判定——
    # 靠关键词判停太脆（一句"本轮无新增"就能误触发），而状态没变化是硬信号。
    declared_done: bool = False

    @property
    def produced(self) -> bool:
        """这一轮有没有推进（新增资产 / 发现 / 业务模型条目）。"""
        return self.new_assets > 0 or self.new_findings > 0 or self.new_model > 0

    @property
    def idle(self) -> bool:
        """这一轮是不是空转：**什么都没新增**。

        刻意不看 ``suggestions``：planner 的建议是阶段驱动的兜底文本，每轮都非空，
        拿它当负信号 = 永远判不出穷尽（详见模块文档的 warning）。
        """
        return not self.produced

    def line(self) -> str:
        head = f"第 {self.no} 轮：+{self.new_assets} 资产、+{self.new_findings} 发现"
        if self.new_model:
            head += f"、+{self.new_model} 建模项"
        if self.elapsed:
            head += f"（{self.elapsed:.1f}s）"
        if self.idle:
            head += "  ← 本轮无推进"
        elif self.suggestions:
            head += "  建议：" + "；".join(self.suggestions[:2])
        return head


class Exhaustion:
    """穷尽判定的状态机。

    用法：每跑完一轮调一次 :meth:`observe`，返回非空字符串就表示该停了。
    """

    def __init__(
        self,
        *,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        idle_limit: int = IDLE_LIMIT,
    ) -> None:
        self.max_rounds = max(0, int(max_rounds or 0))
        self.idle_limit = max(0, int(idle_limit or 0))
        self.idle_streak = 0
        self.stop_kind = ""
        self.stop_round = 0
        self.last: RoundOutcome | None = None

    def observe(self, out: RoundOutcome) -> str:
        """吃一轮结果。返回 ``"exhausted"`` / ``"capped"`` / ``""``（继续）。"""
        self.last = out
        if out.idle:
            self.idle_streak += 1
        else:
            # 有推进就把连击清零——中间产出过一轮就不能算"连续空转"
            self.idle_streak = 0

        # 穷尽优先于上限：同一轮同时命中时，"真的没得测了"比"到上限了"更该说
        if self.idle_limit and self.idle_streak >= self.idle_limit:
            self.stop_kind, self.stop_round = STOP_EXHAUSTED, out.no
            return STOP_EXHAUSTED
        if self.max_rounds and out.no >= self.max_rounds:
            self.stop_kind, self.stop_round = STOP_CAPPED, out.no
            return STOP_CAPPED
        return ""

    def verdict(self) -> str:
        """停下来时给用户的一句话。**穷尽与到上限必须分开说。**"""
        hint = "（模型也表示已无可测项）" if (self.last and self.last.declared_done) else ""
        if self.stop_kind == STOP_EXHAUSTED:
            return (
                f"✅ 已穷尽：连续 {self.idle_streak} 轮无新增资产/发现/建模项"
                f"{hint}。自动轮询结束——"
                f"要再挖一轮就直接说下一步做什么，或 /poll <更大轮数> 重跑。"
            )
        if self.stop_kind == STOP_CAPPED:
            return (
                f"⏸ 已到自动轮询上限 {self.max_rounds} 轮，**不是测完了**。"
                f"要继续就再来一次（或把上限调大：scan.auto_max_rounds / "
                f"POCS_AUTO_MAX_ROUNDS），也可以直接说下一步要做什么。"
            )
        return f"已跑 {self.last.no if self.last else 0} 轮（未触发停止条件）。"


async def poll_until_done(
    run_round: Callable[[int], Awaitable[RoundOutcome]],
    *,
    ex: Exhaustion,
    on_round: Callable[[RoundOutcome], None] | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[str, list[RoundOutcome]]:
    """反复跑轮，直到 :class:`Exhaustion` 判定停下。

    ``run_round(i)`` 负责真正跑一轮（Agent 或剧本）并**自己测量**这一轮
    新增了多少资产/发现——驱动层不关心怎么跑的，这样 REPL 与 CLI 能共用同一个
    循环与同一套判定。

    ``KeyboardInterrupt`` **不吞**：中断要能立刻穿透出去，让调用方决定怎么收尾
    （保存会话、提示用户）。吞掉的话 Ctrl-C 会变成"跑到下一轮才响应"。

    返回 ``(停止原因, 各轮结果)``。
    """
    history: list[RoundOutcome] = []
    while True:
        out = await run_round(len(history) + 1)
        history.append(out)
        if on_round:
            on_round(out)
        if checkpoint:
            checkpoint()
        kind = ex.observe(out)
        if kind:
            return kind, history


__all__ = [
    "RoundOutcome",
    "Exhaustion",
    "poll_until_done",
    "IDLE_LIMIT",
    "DEFAULT_MAX_ROUNDS",
    "STOP_EXHAUSTED",
    "STOP_CAPPED",
]
