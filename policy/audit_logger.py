"""审计日志（111.md 模块职责之四）：记录允许、拒绝和审批相关事件。

为什么允许也要记：权限控制的交付物不只是"拦住了什么"，还有
"放过了什么、依据是什么"。出事复盘时，**没有记录的允许和没有记录的
拒绝一样无法解释**。

落盘形态：JSONL 追加写 ``<data_dir>/policy/audit.jsonl``——

* 一行一个事件，崩溃/中断不会损坏已有记录；
* 与三层隔离对齐：每条事件都带 ``run_id`` / ``target_id``，
  审计能按扫描轮次对账；
* 写失败**绝不抛异常**——审计是旁路观察，不能反过来把扫描卡死；
  失败记内存 recent，工具层还能读到最近发生了什么。
"""

from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path
from typing import Any

_RECENT_KEEP = 200


class PolicyAudit:
    """策略事件审计器。所有调用都是兜底安全的。"""

    def __init__(self, data_dir: str | Path = "./data", enabled: bool = True) -> None:
        self.enabled = enabled
        self.path = Path(data_dir) / "policy" / "audit.jsonl"
        self._recent: deque[dict[str, Any]] = deque(maxlen=_RECENT_KEEP)

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
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            # 落盘失败不阻断扫描；内存里仍有最近 200 条可查
            pass

    def recent(self, n: int = 20) -> list[dict[str, Any]]:
        """最近 n 条事件（内存态；重启后从文件读的场景由调用方负责）。"""
        return list(self._recent)[-n:]

    def summary_line(self) -> str:
        """状态行用：本轮允许/拒绝/复核的粗计数。"""
        allow = sum(1 for e in self._recent if e["event"] == "allow")
        deny = sum(1 for e in self._recent if e["event"] == "deny")
        review = sum(1 for e in self._recent if e["event"] == "review")
        return f"策略：放行 {allow} / 拒绝 {deny} / 待审 {review}（最近 {len(self._recent)} 条事件）"
