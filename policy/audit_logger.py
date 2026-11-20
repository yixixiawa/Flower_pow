"""审计日志（111.md 模块职责之四）：记录允许、拒绝和审批相关事件。

为什么允许也要记：权限控制的交付物不只是"拦住了什么"，还有
"放过了什么、依据是什么"。出事复盘时，**没有记录的允许和没有记录的
拒绝一样无法解释**。

落盘形态：JSONL 追加写 ``<data_dir>/policy/audit.jsonl``——

* 一行一个事件，崩溃/中断不会损坏已有记录；
* 与三层隔离对齐：每条事件都带 ``run_id`` / ``target_id``，
  审计能按扫描轮次对账；
* 写失败**绝不抛异常**——审计是旁路观察，不能反过来把扫描卡死。

落盘失败的明确策略（P2-11 + P1-⑤ 整改，不是静默吞掉）::

    失败的事件进内存待写队列（_pending，上限 _PENDING_KEEP），
    之后每次 log() 都会先重试把队列冲进文件；连续 ``_MAX_RETRY``
    次冲不出去（磁盘持续不可写）才丢弃最旧的，丢弃数量记入
    ``dropped`` 计数。任何时刻 ``pending_count`` / ``dropped``
    都可查，``summary_line`` 会把这两个数写进状态行——审计缺口
    必须可见，而不是"看起来记了其实没记"。

    **P1-⑤（审计是写操作的先决条件，不是旁路）**：``writable``
    属性给出"现在还能不能持久化审计"的判定（探针 append + TTL 缓存）。
    调用方（runner 闸门）据此分流：

    * 写操作（创建/修改/上传/删除）与审批执行 → 审计不可持久化时
      **拒绝执行**——不能用内存记录替代持久化审计（内存随进程死，
      复盘时什么都没有）；
    * 只读操作 → 照常放行，但记 ``warn`` 事件并让状态行可见告警。

    ``audit.enabled=false``（配置关审计）同样视为不可持久化——
    写操作一律拒绝。要跑写操作，持久化审计必须在工作。

第二轮整改（#6 审计故障处理收口）::

    * ``_flush`` / ``log`` / ``writable`` 的异常面从裸 ``OSError``
      扩到 ``(OSError, TypeError, ValueError)``——``json.dumps`` 遇到
      不可序列化的 extra 抛 TypeError，旧实现会让它一路炸到调用方；
    * ``extra`` 在入队**前**就做可序列化消毒：序列化失败降级为
      ``{"repr": ...}``——待写队列里永远只放能安全写盘的字典，
      重试补写时不会因为同一条坏数据反复失败。
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
_WRITABLE_TTL = 2.0   # writable 探针结果缓存秒数（避免每次写闸门都开文件）


class PolicyAudit:
    """策略事件审计器。所有调用都是兜底安全的。"""

    def __init__(self, data_dir: str | Path = "./data", enabled: bool = True) -> None:
        self.enabled = enabled
        self.path = Path(data_dir) / "policy" / "audit.jsonl"
        self._recent: deque[dict[str, Any]] = deque(maxlen=_RECENT_KEEP)
        self._pending: deque[dict[str, Any]] = deque(maxlen=_PENDING_KEEP)
        self.dropped = 0      # 因落盘持续失败被丢弃的事件数
        self._fail_streak = 0  # 连续落盘失败次数
        self._probe_ok: bool | None = None   # writable 探针缓存（None = 未探测）
        self._probe_at = 0.0

    # ── 落盘 ─────────────────────────────────────────────────────
    def _flush(self, entries: list[dict[str, Any]]) -> bool:
        """把待写事件追加进 JSONL。成功返回 True。

        异常面（第二轮整改 #6）：``OSError``（磁盘/权限）之外，
        ``TypeError``/``ValueError``（序列化意外失败）同样按落盘失败
        处理——审计是旁路，任何一类故障都不许把执行链炸断。
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            return True
        except (OSError, TypeError, ValueError):
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
    ) -> bool:
        """记一条事件。event: allow | deny | review | approval | error | warn。

        返回是否**成功持久化**（True = 已写进 JSONL）。调用方据此执行
        P1-⑤ 分流：写操作/审批在 False 时必须拒绝执行。
        """
        if not self.enabled:
            return False
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
        if extra is not None:
            # 入队前消毒（第二轮整改 #6）：待写队列里只放能安全写盘的
            # 字典——不可序列化的 extra 降级为 repr 摘要，否则重试补写
            # 会因为同一条坏数据永远失败。
            try:
                json.dumps(extra, ensure_ascii=False)
                entry["extra"] = extra
            except (TypeError, ValueError):
                entry["extra"] = {"repr": str(extra)[:200]}
        self._recent.append(entry)
        # 先冲历史欠账，再写当前条：都成功则队列清空
        batch = list(self._pending) + [entry]
        if self._flush(batch):
            self._pending.clear()
            self._fail_streak = 0
            self._probe_ok = True
            self._probe_at = time.monotonic()
            return True
        self._pending.append(entry)
        self._fail_streak += 1
        self._probe_ok = False
        self._probe_at = time.monotonic()
        if self._fail_streak >= _MAX_RETRY:
            # 连续 _MAX_RETRY 次写不进去：磁盘大概率持续不可写。
            # 丢最旧的欠账（已有 recent 内存兜底），别让队列无限膨胀。
            while len(self._pending) >= _PENDING_KEEP:
                self._pending.popleft()
                self.dropped += 1
            self._fail_streak = 0
        return False

    # ── 持久化健康（P1-⑤）─────────────────────────────────────────
    @property
    def writable(self) -> bool:
        """审计文件现在能否持久化。探针结果按 ``_WRITABLE_TTL`` 缓存。

        * ``enabled=False``（配置关审计）→ False：没有持久化审计，
          写操作不得执行；
        * 探针 = 以 append 模式打开文件（存在则不动内容）。打开成功
          即视为可写；失败（权限/路径/磁盘）→ False。
        """
        if not self.enabled:
            return False
        now = time.monotonic()
        if self._probe_ok is not None and (now - self._probe_at) < _WRITABLE_TTL:
            return self._probe_ok
        ok = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8"):
                ok = True
        except (OSError, TypeError, ValueError):
            ok = False
        self._probe_ok = ok
        self._probe_at = now
        return ok

    def warn(self, reason: str, **kw: Any) -> None:
        """只读场景的落盘告警：内存记录（_recent 可见），不落盘。

        P1-⑤：只读操作在审计不可持久化时**放行但必须告警**——告警
        进内存 recent 与 summary_line，让操作者能看见审计缺口。
        """
        entry: dict[str, Any] = {
            "ts": round(time.time(), 3),
            "event": "warn",
            "command": str(kw.get("command") or ""),
            "level": str(kw.get("level") or ""),
            "decision": "",
            "category": "",
            "url": str(kw.get("url") or "")[:300],
            "target_id": str(kw.get("target_id") or ""),
            "run_id": str(kw.get("run_id") or ""),
            "reason": (reason or "")[:500],
        }
        self._recent.append(entry)

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
        warn = sum(1 for e in self._recent if e["event"] == "warn")
        line = (
            f"策略：放行 {allow} / 拒绝 {deny} / 待审 {review}"
            f"（最近 {len(self._recent)} 条事件）"
        )
        if warn:
            line += f" | ⚠ {warn} 条只读操作在审计不可持久化下放行"
        if self.pending_count or self.dropped:
            line += f" | ⚠ 审计未落盘 {self.pending_count} 条、累计丢弃 {self.dropped} 条"
        return line
