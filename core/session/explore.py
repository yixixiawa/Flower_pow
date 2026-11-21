"""探索台账与无进展守卫——把"我做过什么、结果如何"从模型记忆里搬到代码里。

要解决的问题
------------
模型的多轮规划靠的是上下文里的历史消息，而历史会被 ``_trim`` 裁掉
（``MAX_HISTORY_MSGS=40`` / ``MAX_HISTORY_CHARS=120000``）。一旦早期那几轮
"这个路径已试过、403"被裁出窗口，模型就会**重新提出同一个动作**——
这不是模型笨，是它确实看不到了。会话越深，重复越严重，额度全烧在原地转圈。

所以这里维护一份**独立于对话历史**的轻量台账：

* ``objective``        这一轮要达成什么；
* ``entries``          每次工具调用：轮次 / 工具 / **参数指纹** / 状态 / 摘要；
* ``facts``            已确认事实（一行一条）；
* ``failed``           已失败方法：参数指纹 → 失败原因；
* ``last_evidence_round`` 最近一次"真的拿到新证据"的轮次（发现/资产增加）。

两条纪律
--------
1. **不得仅通过工具名称判断重复**（任务书 三）。``http_request`` 打 A 路径
   和打 B 路径是完全不同的动作，靠名字判重会把正常探索全拦死。判重键是
   ``工具 + 规范化参数指纹``，参数变了就是新动作。
2. **判重只拦"已经做过的那一次"**，不拦同轮内的快速连击——同轮连击由
   :mod:`core.agent` 里的精确/骨架死循环检测负责（那套阈值是按真实事故
   调过的，两套机制同时拦会让同一个场景被扣两次）。

``NoProgressGuard`` 单独一层：它看的是**每一步的整体签名**（这步调了哪些
动作 + 结果摘要 + 发现/资产/任务状态），连续多步完全一致就判定"没有任何
推进"，交给 Agent 去收尾（任务书 四）。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

#: 台账最多保留多少条调用记录（只影响 prompt_note 的展示，不参与判重截断）
LEDGER_KEEP = 200

#: 连续多少步整体签名完全相同 → 判定无进展
NO_PROGRESS_LIMIT = 3

#: 状态取值
ST_OK = "ok"
ST_FAILED = "failed"
ST_BLOCKED = "blocked"

#: "用户明确要求重试"的语义词。命中即视为新授权上下文：上一轮失败/成功过的
#: 同参数动作允许重做（任务书 二.4）。不靠模型自我声明，靠用户这句话。
RETRY_HINTS: tuple[str, ...] = (
    "重试", "再试", "重新", "再来", "重跑", "复位后", "换了个", "换了代理",
    "retry", "try again", "again,", "once more",
)

#: "继续当前探索"的语义词。这类指令**不构成**新目标：判重继续生效——
#: 否则模型只要等到下一轮用户说一句"继续"，就能把上一轮失败的动作原样重放。
CONTINUE_HINTS: tuple[str, ...] = (
    "继续", "接着", "下一步", "往下", "然后呢", "go on", "continue", "next",
)


def is_retry_instruction(text: str) -> bool:
    """用户这一轮是否明确要求重试/换了条件重来。"""
    t = (text or "").strip().lower()
    return any(h in t for h in RETRY_HINTS)


def is_continuation(text: str) -> bool:
    """用户这一轮是否只是"继续"，没有提出新的目标。"""
    t = (text or "").strip().lower()
    if not t:
        return True
    if len(t) > 40:           # 长句通常带新信息/新方向，不按"继续"处理
        return False
    return any(h in t for h in CONTINUE_HINTS)


def classify_result(text: str) -> str:
    """把工具结果文本归类成 ``ok`` / ``failed`` / ``blocked``。

    只有三种：拦截（安全边界正常工作，换参数才有意义）、失败（执行层面
    没跑通）、成功。安全性结论不需要在这里做，台账只管"值不值得再试一次"。
    """
    t = (text or "").lstrip()
    if t.startswith("【已拦截】") or t.startswith("[执行被拒绝]"):
        return ST_BLOCKED
    for marker in ("【执行失败】", "【工具失败】", "【超时】", "【启动失败】", "【未知工具】"):
        if t.startswith(marker):
            return ST_FAILED
    return ST_OK


def result_digest(text: str) -> str:
    """结果内容摘要（用于无进展判定，不保存原文）。"""
    body = (text or "").strip()
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:8]


@dataclass
class ExplorationEntry:
    """一次工具调用的台账记录。"""

    round: int
    tool: str
    args_fp: str
    status: str
    summary: str = ""
    at: float = field(default_factory=time.time)
    # 属于哪个探索目标（epoch）。跨目标的重做不算重复。
    epoch: int = 1

    @property
    def key(self) -> str:
        """判重键：工具 + 参数指纹。**不含**结果。"""
        return f"{self.tool}|{self.args_fp}"

    def line(self) -> str:
        icon = {ST_OK: "✓", ST_FAILED: "✗", ST_BLOCKED: "⛔"}.get(self.status, "·")
        body = f"[轮{self.round}] {self.tool} {icon}"
        if self.summary:
            body += f"：{self.summary}"
        return body


class ExplorationLedger:
    """本轮任务的探索台账。"""

    def __init__(self, keep: int = LEDGER_KEEP) -> None:
        self.keep = keep
        self.objective: str = ""
        self.round: int = 0
        # 目标代次：objective 一变就 +1。判重只在**同一目标**内成立——
        # 用户明确换了指令（"换了个代理，再试一次"）属于新的授权上下文，
        # 上一轮失败/成功过的动作允许重做。
        self.epoch: int = 1
        self.entries: list[ExplorationEntry] = []
        self.facts: list[str] = []
        self.failed: dict[str, str] = {}
        self.last_evidence_round: int = 0
        # 本轮已经给过"重复动作"劝告的判重键：第二次原样再提就直接拒绝
        self._warned: set[str] = set()

    # ── 轮次 ──────────────────────────────────────────────────────
    def begin(self, objective: str) -> int:
        """开始一轮（一次 ``send``）。

        ``objective`` 变了**不一定**换代次：用户说"继续"属于同一段探索，
        判重必须继续生效——否则模型只要等到下一轮"继续"，就能把上一轮
        失败的动作原样重放一次。只有两种情况换代次：

        * 用户明确要求重试（:func:`is_retry_instruction`）——换了条件重来是
          合法的新授权上下文（任务书 二.4）；
        * 用户给了新的长指令（不是"继续"）——目标是新目标。
        """
        self.round += 1
        obj = (objective or "").strip().replace("\n", " ")
        if not obj:
            return self.round
        changed = obj != self.objective
        if changed:
            self.objective = obj[:200]
        if is_retry_instruction(obj) or (changed and not is_continuation(obj)):
            self.epoch += 1
            self._warned.clear()
        return self.round

    # ── 记录 ──────────────────────────────────────────────────────
    def record(
        self,
        tool: str,
        args_fp: str,
        status: str,
        summary: str = "",
    ) -> ExplorationEntry:
        entry = ExplorationEntry(
            round=self.round,
            tool=tool,
            args_fp=args_fp,
            status=status,
            summary=_one_line(summary),
            epoch=self.epoch,
        )
        self.entries.append(entry)
        if len(self.entries) > self.keep:
            del self.entries[: len(self.entries) - self.keep]
        if status in (ST_FAILED, ST_BLOCKED):
            self.failed[entry.key] = entry.summary or status
        else:
            self.failed.pop(entry.key, None)
        return entry

    def note_fact(self, fact: str) -> None:
        """登记一条已确认事实（去重、限长）。"""
        f = _one_line(fact, 200)
        if f and f not in self.facts:
            self.facts.append(f)
            if len(self.facts) > 50:
                del self.facts[: len(self.facts) - 50]

    def note_evidence(self) -> None:
        """标记"本轮真的拿到了新东西"（有新发现/新资产/新线索时调用）。"""
        self.last_evidence_round = self.round

    # ── 判重 ──────────────────────────────────────────────────────
    def duplicate_of(
        self,
        tool: str,
        args_fp: str,
        *,
        prior_rounds_only: bool = True,
    ) -> ExplorationEntry | None:
        """找出**已执行过**的同动作记录（工具 + 参数指纹都相同）。

        ``prior_rounds_only=True`` 只看之前轮次：同一轮内的快速连击交给
        Agent 的死循环检测，那套阈值是按事故调过的，这里不重复拦。
        """
        key = f"{tool}|{args_fp}"
        for e in reversed(self.entries):
            if e.key != key:
                continue
            # 换了目标（用户新的指令）就不算重复：上一轮"失败过"不构成
            # 这一轮的禁止依据——那是另一个授权上下文。
            if e.epoch != self.epoch:
                continue
            if prior_rounds_only and e.round >= self.round:
                continue
            return e
        return None

    def warned(self, key: str) -> bool:
        return key in self._warned

    def mark_warned(self, key: str) -> None:
        self._warned.add(key)

    # ── 呈现 ──────────────────────────────────────────────────────
    def prompt_note(self, max_entries: int = 10) -> str:
        """给模型看的紧凑台账（进 system 提示的 ``extra``，不是对话消息）。"""
        if not self.entries:
            return ""
        tail = self.entries[-max_entries:]
        head = (
            f"探索记录（objective：{self.objective or '未声明'}；"
            f"已执行 {len(self.entries)} 次，已确认事实 {len(self.facts)} 条，"
            f"已失败方法 {len(self.failed)} 个，"
            f"最近一次新证据："
            + (f"第 {self.last_evidence_round} 轮" if self.last_evidence_round else "尚无")
            + "）"
        )
        lines = [head, "最近动作（**相同工具+相同参数的动作不要再提**）："]
        lines += [f"- {e.line()}" for e in tail]
        if self.failed:
            lines.append("已失败方法（参数相同再提会被直接拒绝）：")
            for key, why in list(self.failed.items())[-5:]:
                tool, _, fp = key.partition("|")
                lines.append(f"- {tool} …{fp[-6:]} → {why}")
        if self.facts:
            lines.append("已确认事实：" + "；".join(self.facts[-4:]))
        lines.append(
            "重新执行上面任何一个动作前，必须能说清**新证据或参数差异**；"
            "说不清就转总结或停止本轮探索。"
        )
        return "\n".join(lines)

    def stats(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "objective": self.objective,
            "calls": len(self.entries),
            "failed": len(self.failed),
            "facts": len(self.facts),
            "last_evidence_round": self.last_evidence_round,
        }

    def reset(self) -> None:
        self.entries.clear()
        self.facts.clear()
        self.failed.clear()
        self._warned.clear()
        self.last_evidence_round = 0


class NoProgressGuard:
    """连续多步整体签名不变 → 判定没有推进。

    签名由 :mod:`core.agent` 组装（这一步的动作指纹集合 + 结果摘要 +
    发现/资产/任务状态计数）。**不看自然语言**：换一种说法重复同一操作，
    动作指纹不变，照样被识别（任务书 四.5）。
    """

    def __init__(self, limit: int = NO_PROGRESS_LIMIT) -> None:
        self.limit = max(2, int(limit))
        self._sigs: list[str] = []
        self.tripped = False

    def observe(self, signature: str) -> bool:
        """记录一步的签名，返回是否触发无进展。"""
        self._sigs.append(signature)
        if len(self._sigs) > self.limit:
            self._sigs.pop(0)
        self.tripped = len(self._sigs) >= self.limit and len(set(self._sigs)) == 1
        return self.tripped

    def reset(self) -> None:
        self._sigs.clear()
        self.tripped = False


def _one_line(text: str, limit: int = 120) -> str:
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    if len(first) > limit:
        first = first[: limit - 1] + "…"
    return first


__all__ = [
    "ExplorationEntry",
    "ExplorationLedger",
    "NoProgressGuard",
    "classify_result",
    "result_digest",
    "ST_OK",
    "ST_FAILED",
    "ST_BLOCKED",
    "NO_PROGRESS_LIMIT",
]
