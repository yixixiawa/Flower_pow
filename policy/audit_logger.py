"""审计日志（111.md 模块职责之四）：记录允许、拒绝和审批相关事件。

为什么允许也要记：权限控制的交付物不只是"拦住了什么"，还有
"放过了什么、依据是什么"。出事复盘时，**没有记录的允许和没有记录的
拒绝一样无法解释**。

落盘形态：JSONL 追加写 ``<data_dir>/policy/audit.jsonl``——

* 一行一个事件，崩溃/中断不会损坏已有记录；
* 与三层隔离对齐：每条事件都带 ``run_id`` / ``target_id``，
  审计能按扫描轮次对账；
* 写失败**绝不抛异常**——审计是旁路观察，不能反过来把扫描卡死。

落盘失败的明确策略（P2-11，不是静默吞掉）::

    失败的事件进内存待写队列（_pending，上限 _PENDING_KEEP），
    之后每次 log() 都会先重试把队列冲进文件；连续 ``_MAX_RETRY``
    次冲不出去（磁盘持续不可写）才丢弃最旧的，丢弃数量记入
    ``dropped`` 计数。任何时刻 ``pending_count`` / ``dropped``
    都可查，``summary_line`` 会把这两个数写进状态行——审计缺口
    必须可见，而不是"看起来记了其实没记"。
"""

from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path
from typing import Any

_RECENT_KEEP = 200
_PENDING_KEEP = 1000  # 待写队列上限（超过丢最旧，转 dropped 计数）
_MAX_RETRY = 5        # 同一批事件最多重试次数，超过即放弃并计数


class PolicyAudit:
    """策略事件审计器。所有调用都是兜底安全的。"""

    def __init__(self, data_dir: str | Path = "./data", enabled: bool = True) -> None:
        self.enabled = enabled
        self.path = Path(data_dir) / "policy" / "audit.jsonl"
        self._recent: deque[dict[str, Any]] = deque(maxlen=_RECENT_KEEP)
        self._pending: deque[dict[str, Any]] = deque(maxlen=_PENDING_KEEP)
        self.dropped = 0      # 因落盘持续失败被丢弃的事件数
        self._fail_streak = 0  # 连续落盘失败次数

    # ── 落盘 ─────────────────────────────────────────────────────
    def _flush(self, entries: list[dict[str, Any]]) -> bool:
        """把待写事件追加进 JSONL。成功返回 True。"""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            return True
        except OSError:
            return False

    def log(
        self,
        event: str,
        *,
        command: str = "",
        level: str = "",
        decision: str = "",
        category: str = "",
        url: str = "",
        target_id: str = "",
        run_id: str = "",
        reason: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """记一条事件。event: allow | deny | review | approval | error。"""
        if not self.enabled:
            return
        entry: dict[str, Any] = {
            "ts": round(time.time(), 3),
            "event": event,
            "command": command,
            "level": level,
            "decision": decision,
            "category": category,
            "url": (url or "")[:300],
            "target_id": target_id,
            "run_id": run_id,
            "reason": (reason or "")[:500],
        }
        if extra:
            entry["extra"] = extra
        self._recent.append(entry)
        # 先冲历史欠账，再写当前条：都成功则队列清空
        batch = list(self._pending) + [entry]
        if self._flush(batch):
            self._pending.clear()
            self._fail_streak = 0
            return
        self._pending.append(entry)
        self._fail_streak += 1
        if self._fail_streak >= _MAX_RETRY:
            # 连续 _MAX_RETRY 次写不进去：磁盘大概率持续不可写。
            # 丢最旧的欠账（已有 recent 内存兜底），别让队列无限膨胀。
            while len(self._pending) >= _PENDING_KEEP:
                self._pending.popleft()
                self.dropped += 1
            self._fail_streak = 0

    def recent(self, n: int = 20) -> list[dict[str, Any]]:
        """最近 n 条事件（内存态；重启后从文件读的场景由调用方负责）。"""
        return list(self._recent)[-n:]

    @property
    def pending_count(self) -> int:
        """尚未落盘的事件数（审计缺口，必须可见）。"""
        return len(self._pending)

    def summary_line(self) -> str:
        """状态行用：本轮允许/拒绝/复核的粗计数 + 审计缺口。"""
        allow = sum(1 for e in self._recent if e["event"] == "allow")
        deny = sum(1 for e in self._recent if e["event"] == "deny")
        review = sum(1 for e in self._recent if e["event"] == "review")
        line = (
            f"策略：放行 {allow} / 拒绝 {deny} / 待审 {review}"
            f"（最近 {len(self._recent)} 条事件）"
        )
        if self.pending_count or self.dropped:
            line += f" | ⚠ 审计未落盘 {self.pending_count} 条、累计丢弃 {self.dropped} 条"
        return line
