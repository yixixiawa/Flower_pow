"""后台任务的统一台账——所有"先触发、后取结果"的工作都记在这里。

为什么要统一
------------
后台任务如果各存各的（端口扫描一个 dict、dirsearch 一个 list），会出现三个
必然问题：Agent 不知道该问谁要结果、会话落盘时漏掉一半、换目标/退出时
没人负责收尾。所以任务状态只有一个事实来源：``Session.tasks``。

状态机
------
::

    running ──► done          正常跑完（result 有内容）
       │
       ├─────► failed        抛异常（error 有原因）
       ├─────► cancelled     被取消（用户中断 / 主动取消）
       └─────► interrupted   快照恢复时发现"上次没跑完"（进程已退出，任务不可能还在跑）

``interrupted`` 不是运行时状态，只在 :meth:`TaskManager.from_dict` 里出现：
快照里躺着 ``running`` 的任务，恢复会话时如实标成"已中断"，否则
``list_tasks`` 会永远显示一个根本不存在的"运行中"任务，Agent 会一直等它。

并发模型
--------
本模块全部是**同步方法**（无 ``await``），运行在 asyncio 单线程里天然原子；
真正的异步执行在 :mod:`core.tools.runner.tasks`（创建 asyncio task 并回写状态）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# 任务状态。字符串常量而不是 Enum：要直接写进 session.json 给人读
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_INTERRUPTED = "interrupted"

STATUS_LABEL = {
    STATUS_RUNNING: "运行中",
    STATUS_DONE: "已完成",
    STATUS_FAILED: "失败",
    STATUS_CANCELLED: "已取消",
    STATUS_INTERRUPTED: "已中断",
}


@dataclass
class BackgroundTask:
    """一个后台任务。"""

    task_id: str                     # bg-1 / bg-2 ……会话内唯一
    tool: str                        # 触发它的工具名（recon_ports_bg / background_run）
    label: str                       # 人读描述："端口扫描 example.com（前 500 个端口）"
    status: str = STATUS_RUNNING
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    result: str = ""                 # 完成后回灌给模型的文本（与前台工具同格式）
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def status_label(self) -> str:
        return STATUS_LABEL.get(self.status, self.status)

    @property
    def finished(self) -> bool:
        return self.status in (STATUS_DONE, STATUS_FAILED,
                               STATUS_CANCELLED, STATUS_INTERRUPTED)

    def line(self) -> str:
        """一行摘要（列表用）。"""
        return f"{self.task_id}｜{self.status_label}｜{self.label}（{self.elapsed:.1f}s）"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tool": self.tool,
            "label": self.label,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BackgroundTask":
        t = cls(
            task_id=str(d.get("task_id") or ""),
            tool=str(d.get("tool") or ""),
            label=str(d.get("label") or ""),
            status=str(d.get("status") or STATUS_RUNNING),
            started_at=float(d.get("started_at") or time.time()),
            finished_at=(
                float(d["finished_at"]) if d.get("finished_at") is not None else None
            ),
            result=str(d.get("result") or ""),
            error=str(d.get("error") or ""),
            meta=dict(d.get("meta") or {}),
        )
        # 快照里的 running 一定是"上次进程退出时没跑完"——进程都没了，
        # 任务不可能还活着。如实改写，否则 Agent 会一直等一个幽灵任务。
        if t.status == STATUS_RUNNING:
            t.status = STATUS_INTERRUPTED
            t.finished_at = t.finished_at or time.time()
            t.error = t.error or "会话恢复时该任务已不存在（进程退出前未完成）"
        return t


class TaskManager:
    """会话内全部后台任务的台账。"""

    def __init__(self, tasks: list[BackgroundTask] | None = None) -> None:
        self._tasks: dict[str, BackgroundTask] = {}
        self._seq = 0
        for t in tasks or []:
            self._tasks[t.task_id] = t
            self._seq = max(self._seq, _seq_of(t.task_id))

    # ── 生命周期 ──────────────────────────────────────────────────
    def start(self, tool: str, label: str = "", meta: dict[str, Any] | None = None) -> BackgroundTask:
        """登记一个新任务，返回 running 态记录（真正的执行由调用方启动）。"""
        self._seq += 1
        tid = f"bg-{self._seq}"
        while tid in self._tasks:      # 极端情况（手工注入过同号）也不撞
            self._seq += 1
            tid = f"bg-{self._seq}"
        t = BackgroundTask(task_id=tid, tool=tool, label=label or tool,
                           meta=dict(meta or {}))
        self._tasks[tid] = t
        return t

    def get(self, task_id: str) -> BackgroundTask | None:
        return self._tasks.get((task_id or "").strip())

    def finish(self, task_id: str, result: str = "") -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        t.status = STATUS_DONE
        t.result = result or ""
        t.finished_at = time.time()
        return t

    def fail(self, task_id: str, error: str) -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        t.status = STATUS_FAILED
        t.error = error or "未知错误"
        t.finished_at = time.time()
        return t

    def cancel(self, task_id: str, reason: str = "已取消") -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        t.status = STATUS_CANCELLED
        t.error = reason
        t.finished_at = time.time()
        return t

    # ── 查询 ──────────────────────────────────────────────────────
    def all(self) -> list[BackgroundTask]:
        return sorted(self._tasks.values(), key=lambda t: t.started_at)

    def running(self) -> list[BackgroundTask]:
        return [t for t in self.all() if t.status == STATUS_RUNNING]

    def done(self) -> list[BackgroundTask]:
        return [t for t in self.all() if t.status == STATUS_DONE]

    def by_status(self, status: str) -> list[BackgroundTask]:
        return [t for t in self.all() if t.status == status]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for t in self._tasks.values():
            out[t.status] = out.get(t.status, 0) + 1
        return out

    def summary_line(self) -> str:
        if not self._tasks:
            return "后台任务：无"
        parts = [f"{STATUS_LABEL.get(k, k)} {v}" for k, v in self.counts().items()]
        return f"后台任务：{len(self._tasks)} 个（{' / '.join(parts)}）"

    # ── 持久化 ────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {"seq": self._seq, "items": [t.to_dict() for t in self.all()]}

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "TaskManager":
        d = d or {}
        items = [BackgroundTask.from_dict(x) for x in (d.get("items") or [])]
        mgr = cls(items)
        # 序号以快照里的 seq 为准：ids 已被 from_dict 改写为 interrupted，
        # 重新从 1 开始会与历史 id 撞号。
        mgr._seq = max(mgr._seq, int(d.get("seq") or 0))
        return mgr

    # ── 容器协议（``if session.tasks:`` 很好用）───────────────────
    def __len__(self) -> int:
        return len(self._tasks)

    def __bool__(self) -> bool:
        return bool(self._tasks)

    def __iter__(self):
        return iter(self.all())


def _seq_of(task_id: str) -> int:
    """从 ``bg-12`` 里取出 12；认不出来就当 0（不让脏数据把序号顶飞）。"""
    try:
        return int(task_id.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return 0


__all__ = [
    "BackgroundTask",
    "TaskManager",
    "STATUS_RUNNING",
    "STATUS_DONE",
    "STATUS_FAILED",
    "STATUS_CANCELLED",
    "STATUS_INTERRUPTED",
    "STATUS_LABEL",
]
