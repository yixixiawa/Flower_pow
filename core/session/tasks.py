"""后台任务的统一台账——所有"先触发、后取结果"的工作都记在这里。

为什么要统一
------------
后台任务如果各存各的（端口扫描一个 dict、dirsearch 一个 list），会出现三个
必然问题：Agent 不知道该问谁要结果、会话落盘时漏掉一半、换目标/退出时
没人负责收尾。所以任务状态只有一个事实来源：``Session.tasks``。

状态机（六态 + 两个"非运行时"终态）
-----------------------------------
::

    queued ──► running ──┬──► done         正常跑完（result 有内容）
      │         │        ├──► failed       抛异常（error 有原因）
      │         │        ├──► cancelled    被取消（用户中断 / 主动取消）
      │         │        └──► timeout      **超时**（wait_for 到点 / sweep 收割）
      │         │
      └─────────┴────────────► interrupted  快照恢复时发现"上次没跑完"

* ``done`` 就是任务书里的 SUCCEEDED（字符串保持 ``done``：历史快照、
  报告与既有测试都按这个字面值读，改名只会制造无收益的迁移）。
* ``interrupted`` 不是运行时状态，只在 :meth:`TaskManager.from_dict` 里出现：
  快照里躺着 ``running`` 的任务，恢复会话时如实标成"已中断"，否则
  ``list_tasks`` 会永远显示一个根本不存在的"运行中"任务，Agent 会一直等它。
* **超时是终态**：``timeout`` 之后任务不会再回到 running，也不会被自动重跑
  （任务书 一.8 / 六.3）。唯一的重新执行路径是调用方**显式** force / 换参数。

事件推送（Agent 不再轮询）
--------------------------
每次进入终态（done / failed / cancelled / timeout / interrupted）都会**恰好**
产生一条 :class:`TaskEvent`，写进 ``_events`` 并推进 ``_event_seq``。Agent 每步
``events_since(cursor)`` 只取"自己还没见过的那几条"，游标推进后**同一个状态
不会被二次注入**（任务书 一.3/4/5）。

为什么不直接回调：本项目的 Agent 循环是"同步阻塞在模型流上"的，没有可用的
事件循环钩子往模型上下文里塞消息；让 TaskManager 记事件、Agent 每步取增量，
是同一语义（只消费变化）在现有架构下的最小实现。

并发模型
--------
本模块全部是**同步方法**（无 ``await``），运行在 asyncio 单线程里天然原子；
真正的异步执行在 :mod:`core.tools.runner.tasks`（创建 asyncio task 并回写状态）。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

# ── 状态 ──────────────────────────────────────────────────────────
# 字符串常量而不是 Enum：要直接写进 session.json 给人读
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_SUCCEEDED = STATUS_DONE          # 任务书里的 SUCCEEDED，取值保持 done
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_TIMEOUT = "timeout"              # 任务书里的 TIMED_OUT
STATUS_INTERRUPTED = "interrupted"

STATUS_LABEL = {
    STATUS_QUEUED: "排队中",
    STATUS_RUNNING: "运行中",
    STATUS_DONE: "已完成",
    STATUS_FAILED: "失败",
    STATUS_CANCELLED: "已取消",
    STATUS_TIMEOUT: "已超时",
    STATUS_INTERRUPTED: "已中断",
}

#: 终态集合。进入其中任何一个就**不再变化**，且产生一条状态变更事件。
FINISHED_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_DONE,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_TIMEOUT,
        STATUS_INTERRUPTED,
    }
)

#: 成功结果的复用窗口（秒）。窗口内相同指纹直接复用结果，不再起进程。
TASK_RESULT_TTL = 600.0

#: 事件日志最多保留多少条（只在内存里，用于 Agent 增量消费）。
_EVENT_KEEP = 200


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
    # ── 去重与产物 ────────────────────────────────────────────────
    # 指纹绑定 session/target/工具/规范化参数/任务类型，见 task_fingerprint()
    fingerprint: str = ""
    # 超时秒数；0 = 不设超时（只对确实可能长跑且无法估时的任务使用）
    timeout_s: float = 0.0
    # 超过阈值的结果落盘路径（相对项目根），Agent 上下文只留摘要 + 这个引用
    artifact: str = ""
    # 一句话摘要：事件注入与列表展示都只给摘要，不重复注入完整输出
    summary: str = ""

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    @property
    def status_label(self) -> str:
        return STATUS_LABEL.get(self.status, self.status)

    @property
    def finished(self) -> bool:
        return self.status in FINISHED_STATUSES

    @property
    def ok(self) -> bool:
        return self.status == STATUS_DONE

    def brief(self, limit: int = 160) -> str:
        """一句话结果摘要（优先用登记时算好的 summary）。"""
        text = (self.summary or self.error or self.result or "").strip()
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        if len(first) > limit:
            first = first[: limit - 1] + "…"
        return first

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
            "fingerprint": self.fingerprint,
            "timeout_s": self.timeout_s,
            "artifact": self.artifact,
            "summary": self.summary,
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
            fingerprint=str(d.get("fingerprint") or ""),
            timeout_s=float(d.get("timeout_s") or 0.0),
            artifact=str(d.get("artifact") or ""),
            summary=str(d.get("summary") or ""),
        )
        # 快照里的 running 一定是"上次进程退出时没跑完"——进程都没了，
        # 任务不可能还活着。如实改写，否则 Agent 会一直等一个幽灵任务。
        if t.status in (STATUS_RUNNING, STATUS_QUEUED):
            t.status = STATUS_INTERRUPTED
            t.finished_at = t.finished_at or time.time()
            t.error = t.error or "会话恢复时该任务已不存在（进程退出前未完成）"
        return t


@dataclass(frozen=True)
class TaskEvent:
    """一次状态变更。**只在进入终态时产生**，且每个状态只产生一次。"""

    seq: int
    task_id: str
    from_status: str
    to_status: str
    at: float
    label: str = ""
    detail: str = ""

    def text(self) -> str:
        """渲染成给模型看的一行（摘要 + 产物引用，不含完整输出）。"""
        frm = STATUS_LABEL.get(self.from_status, self.from_status)
        to = STATUS_LABEL.get(self.to_status, self.to_status)
        name = f"{self.task_id}（{self.label}）" if self.label else self.task_id
        out = f"{name}：{frm} → {to}"
        if self.detail:
            out += f"：{self.detail}"
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "task_id": self.task_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "at": self.at,
            "label": self.label,
            "detail": self.detail,
        }


class TaskManager:
    """会话内全部后台任务的台账。"""

    def __init__(self, tasks: list[BackgroundTask] | None = None) -> None:
        self._tasks: dict[str, BackgroundTask] = {}
        self._seq = 0
        self._events: list[TaskEvent] = []
        self._event_seq = 0
        for t in tasks or []:
            self._tasks[t.task_id] = t
            self._seq = max(self._seq, _seq_of(t.task_id))

    # ── 生命周期 ──────────────────────────────────────────────────
    def start(
        self,
        tool: str,
        label: str = "",
        meta: dict[str, Any] | None = None,
        *,
        fingerprint: str = "",
        timeout_s: float = 0.0,
        queued: bool = False,
    ) -> BackgroundTask:
        """登记一个新任务，返回记录（真正的执行由调用方启动）。

        ``queued=True`` 时先记排队态，由调用方 :meth:`mark_running` 转运行中——
        这样"已受理但还没起进程"这件事在台账里是可见的，而不是靠时间差猜。
        """
        self._seq += 1
        tid = f"bg-{self._seq}"
        while tid in self._tasks:      # 极端情况（手工注入过同号）也不撞
            self._seq += 1
            tid = f"bg-{self._seq}"
        t = BackgroundTask(
            task_id=tid,
            tool=tool,
            label=label or tool,
            meta=dict(meta or {}),
            status=STATUS_QUEUED if queued else STATUS_RUNNING,
            fingerprint=fingerprint,
            timeout_s=float(timeout_s or 0.0),
        )
        self._tasks[tid] = t
        return t

    def mark_running(self, task_id: str) -> BackgroundTask | None:
        """queued → running。不产生事件（运行中不是"可引起注意的变化"）。"""
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        if t.status == STATUS_QUEUED:
            t.status = STATUS_RUNNING
        return t

    def get(self, task_id: str) -> BackgroundTask | None:
        return self._tasks.get((task_id or "").strip())

    def finish(
        self, task_id: str, result: str = "", *, summary: str = "", artifact: str = ""
    ) -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        return self._transition(
            t, STATUS_DONE, result=result, summary=summary, artifact=artifact
        )

    def fail(self, task_id: str, error: str) -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        return self._transition(t, STATUS_FAILED, error=error or "未知错误")

    def cancel(self, task_id: str, reason: str = "已取消") -> BackgroundTask | None:
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        return self._transition(t, STATUS_CANCELLED, error=reason)

    def timeout(self, task_id: str, reason: str = "超时未完成") -> BackgroundTask | None:
        """进入超时终态。**不会**重新执行任务（任务书 六.3）。"""
        t = self.get(task_id)
        if t is None or t.finished:
            return t
        return self._transition(t, STATUS_TIMEOUT, error=reason)

    def sweep(self, now: float | None = None) -> list[BackgroundTask]:
        """收割超时任务：running/queued 超过 ``timeout_s`` 的一律进终态。

        这是"进程实际上已经死了/卡住，但没人回写状态"的兜底——没有它，
        任务可能永远停在 running，Agent 会一直等（任务书 一.8）。
        """
        now = time.time() if now is None else now
        out: list[BackgroundTask] = []
        for t in self.all():
            if t.finished or t.timeout_s <= 0:
                continue
            if now - t.started_at < t.timeout_s:
                continue
            res = self.timeout(
                t.task_id, f"超过 {t.timeout_s:.0f}s 仍未完成，已按超时结束"
            )
            if res is not None:
                out.append(res)
        return out

    def _transition(
        self,
        t: BackgroundTask,
        to_status: str,
        *,
        result: str | None = None,
        error: str = "",
        summary: str = "",
        artifact: str = "",
    ) -> BackgroundTask:
        """唯一的终态迁移入口：写字段、盖时间、**产生一次**事件。"""
        frm = t.status
        t.status = to_status
        t.finished_at = time.time()
        if result is not None:
            t.result = result
            if not summary:
                summary = _first_line(result)
        if error:
            t.error = error
            if not summary:
                summary = _first_line(error)
        t.summary = summary or t.summary
        if artifact:
            t.artifact = artifact
        self._emit(t, frm, to_status)
        return t

    # ── 事件 ──────────────────────────────────────────────────────
    def _emit(self, t: BackgroundTask, frm: str, to: str) -> TaskEvent:
        self._event_seq += 1
        detail = t.brief()
        if t.artifact:
            detail += f"；完整结果见 {t.artifact}"
        ev = TaskEvent(
            seq=self._event_seq,
            task_id=t.task_id,
            from_status=frm,
            to_status=to,
            at=t.finished_at or time.time(),
            label=t.label,
            detail=detail,
        )
        self._events.append(ev)
        if len(self._events) > _EVENT_KEEP:
            del self._events[: len(self._events) - _EVENT_KEEP]
        return ev

    @property
    def cursor(self) -> int:
        """当前事件游标（= 已产生的事件条数）。"""
        return self._event_seq

    def events_since(self, cursor: int = 0) -> tuple[list[TaskEvent], int]:
        """取 ``cursor`` 之后的新事件，返回 ``(events, new_cursor)``。

        游标是**单调递增的序号**而不是列表下标：日志裁剪（``_EVENT_KEEP``）
        不会让旧游标指向错位的条目。
        """
        cur = max(0, int(cursor or 0))
        fresh = [e for e in self._events if e.seq > cur]
        return fresh, self._event_seq

    # ── 去重 ──────────────────────────────────────────────────────
    def by_fingerprint(self, fingerprint: str) -> list[BackgroundTask]:
        """相同指纹的任务，**最新在前**。"""
        fp = (fingerprint or "").strip()
        if not fp:
            return []
        hits = [t for t in self._tasks.values() if t.fingerprint == fp]
        return sorted(hits, key=lambda t: t.started_at, reverse=True)

    def latest_by_fingerprint(self, fingerprint: str) -> BackgroundTask | None:
        hits = self.by_fingerprint(fingerprint)
        return hits[0] if hits else None

    # ── 查询 ──────────────────────────────────────────────────────
    def all(self) -> list[BackgroundTask]:
        return sorted(self._tasks.values(), key=lambda t: t.started_at)

    def running(self) -> list[BackgroundTask]:
        return [t for t in self.all() if t.status == STATUS_RUNNING]

    def active(self) -> list[BackgroundTask]:
        """还没进终态的任务（queued + running）。"""
        return [t for t in self.all() if not t.finished]

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


def task_fingerprint(
    *,
    session_id: str,
    target_id: str,
    tool: str,
    args: Any,
    task_type: str,
) -> str:
    """后台任务指纹：会话 + 目标 + 工具 + 规范化参数 + 任务类型。

    五个维度缺一不可（任务书 二）：

    * 少了 ``session_id`` —— 两个会话对同一目标跑同一命令会互相"复用"结果，
      但两个会话的资产/发现/凭证是隔离的，复用等于串线；
    * 少了 ``target_id`` —— 换目标后同名命令被判为重复，**新目标根本没扫**；
    * 少了规范化后的 ``args`` —— 参数实质变化（不同字典、不同端口段）会被
      错误合并，模型看到的是上一次的结果却不自知；
    * 少了 ``task_type`` —— ``recon_ports_bg(top=500)`` 与
      ``background_run(tool="recon_ports", top=500)`` 虽然做同一件事，但
      资产合并路径/上限不同，合并没有收益只有风险。
    """
    payload = {
        "session": str(session_id or ""),
        "target": str(target_id or "").rstrip("/"),
        "tool": str(tool or ""),
        "type": str(task_type or ""),
        "args": _canonical(args),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def dedup_verdict(
    mgr: TaskManager,
    fingerprint: str,
    *,
    ttl: float = TASK_RESULT_TTL,
    force: bool = False,
    now: float | None = None,
) -> tuple[str, BackgroundTask | None, str]:
    """同指纹任务的处置结论：``(action, task, reason)``。

    ``action`` 取值：

    * ``new``            —— 没有同指纹任务（或成功结果已过期），可以新建；
    * ``reuse_running``  —— 还在跑，返回现有 task_id，**不得**再起一个进程；
    * ``reuse_result``   —— 已在有效期内成功，直接复用结果（不重跑）；
    * ``blocked``        —— 失败/取消/超时/中断过。**禁止无理由自动重试**：
      调用方必须显式 ``force``（用户明确要求重试）或换参数（指纹自然不同）。
    """
    now = time.time() if now is None else now
    t = mgr.latest_by_fingerprint(fingerprint)
    if t is None:
        return "new", None, ""
    if force:
        return "new", t, "按调用方显式要求重试"
    if not t.finished:
        return "reuse_running", t, f"{t.task_id} 仍在运行，复用同一任务"
    if t.status == STATUS_DONE:
        age = now - (t.finished_at or t.started_at)
        if age <= max(0.0, ttl):
            return "reuse_result", t, f"{t.task_id} 已成功（{age:.0f}s 前），直接复用结果"
        return "new", t, "上次成功结果已过有效期，允许重跑"
    # failed / cancelled / timeout / interrupted
    return (
        "blocked",
        t,
        f"{t.task_id} 上次是「{t.status_label}」（{t.error or t.brief() or '无原因'}），"
        "不会自动重跑",
    )


def _canonical(value: Any) -> Any:
    """参数规范化：URL 去尾斜杠、字典按键排序、其余转字符串。

    只影响指纹，不改变真正发出去的参数——检测层无权替调用方改内容。
    """
    if isinstance(value, str):
        v = value.strip()
        if v.startswith(("http://", "https://")) and v.endswith("/"):
            return v.rstrip("/")
        return v
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def _first_line(text: str, limit: int = 160) -> str:
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    if len(first) > limit:
        first = first[: limit - 1] + "…"
    return first


def _seq_of(task_id: str) -> int:
    """从 ``bg-12`` 里取出 12；认不出来就当 0（不让脏数据把序号顶飞）。"""
    try:
        return int(task_id.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return 0


__all__ = [
    "BackgroundTask",
    "TaskEvent",
    "TaskManager",
    "STATUS_QUEUED",
    "STATUS_RUNNING",
    "STATUS_DONE",
    "STATUS_SUCCEEDED",
    "STATUS_FAILED",
    "STATUS_CANCELLED",
    "STATUS_TIMEOUT",
    "STATUS_INTERRUPTED",
    "STATUS_LABEL",
    "FINISHED_STATUSES",
    "TASK_RESULT_TTL",
    "task_fingerprint",
    "dedup_verdict",
]
