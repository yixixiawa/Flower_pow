"""后台扫描任务：起一个线程跑 ``Scheduler.scan``，可轮询、可取消。

为什么不在工具调用里直接等扫描结束
----------------------------------
一次扫描是分钟级的，而 MCP 客户端（含 WorkBuddy）对单次工具调用有超时。把
三分钟的扫描塞进一次调用，超时后客户端只看到"工具失败"，后台却还在照常打请求
——用户会以为没扫，实际目标已经被打了一遍。这是最难排查的一类状态。

所以拆成三段：``start`` 立刻返回 job_id，``status`` 轮询看进度与结果，
``cancel`` 停止。与 REPL 里 ``/run`` + ``/poll`` 是同一套哲学。

日志怎么来的
------------
``Scheduler._log`` 是静态方法，直接 ``print``。这里在实例上覆盖它，把每条日志
同时塞进环形缓冲——不覆盖的话，status 只能报"还在跑"，用户完全不知道卡在哪一步。
日志仍然照常 print（SDK 会把 fd1 拨到 stderr，不会污染协议通道）。
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from collections import deque
from typing import Any

from mcp_server.services import load_cfg, result_summary


class ScanJob:
    """一次扫描的全部状态。除了 ``state`` 与缓冲，其余字段只由工作线程写。"""

    def __init__(self, target: str, cfg: Any, *, save_evidence: bool = False) -> None:
        self.job_id = uuid.uuid4().hex[:12]
        self.target = target
        self.cfg = cfg
        self.save_evidence = save_evidence
        self.state = "pending"  # pending | running | done | failed | cancelled
        self.error = ""
        self.started_at = 0.0
        self.finished_at = 0.0
        self.result: Any = None
        self.lines: deque[str] = deque(maxlen=200)
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._sched: Any = None

    # ── 生命周期 ─────────────────────────────────────────────────

    def start(self) -> "ScanJob":
        self._thread = threading.Thread(
            target=self._run, name=f"fp-scan-{self.job_id}", daemon=True
        )
        self._thread.start()
        return self

    def _run(self) -> None:
        self.state = "running"
        self.started_at = time.time()
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            from core.scheduler import Scheduler

            sched = Scheduler(self.cfg)
            self._sched = sched

            # 接管日志：既照常输出，也留一份给 status 用
            inner = sched._log

            def _log(msg: str, verbose: bool = True) -> None:
                self.lines.append(str(msg))
                inner(msg, verbose)

            sched._log = _log  # type: ignore[method-assign]

            task = loop.create_task(sched.scan(self.target, verbose=True))
            self._task = task
            self.result = loop.run_until_complete(task)
            self.state = "done"
        except asyncio.CancelledError:
            self.state = "cancelled"
            self.lines.append("已取消")
        except BaseException as exc:  # noqa: BLE001 - 工作线程里任何异常都不能静默
            self.state = "failed"
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.finished_at = time.time()
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass
            self._save_evidence()

    def _save_evidence(self) -> None:
        if not (self.save_evidence and self.result is not None):
            return
        findings = getattr(self.result, "findings", []) or []
        if not findings:
            return
        try:
            from pathlib import Path

            from output.evidence import EvidenceStore

            store = EvidenceStore(Path(self.cfg.output_dir) / "evidence")
            stats = store.save_result(self.result)
            self.lines.append(
                f"证据落盘：{stats.get('saved', 0)} 份新文件、{stats.get('reused', 0)} 份复用"
            )
        except Exception as exc:  # noqa: BLE001 - 落盘失败不影响扫描结论
            self.lines.append(f"证据落盘失败：{type(exc).__name__}: {exc}")

    # ── 查询与控制 ───────────────────────────────────────────────

    def cancel(self) -> bool:
        """请求取消。返回是否真的发出了取消请求。

        线程不能被杀，只能让事件循环取消它自己的任务：``task.cancel()`` 让
        ``Scheduler.scan`` 收到 ``CancelledError``，它内部的 ``finally`` 仍会
        把会话快照落盘——中途取消的现场同样值得保留。
        """
        if self.state not in ("pending", "running"):
            return False
        loop, task = self._loop, self._task
        if loop is None or task is None:
            # 线程还没跑起来：等它建好 loop 之后由 start 时的状态兜底
            self.state = "cancelled"
            return True
        try:
            loop.call_soon_threadsafe(task.cancel)
            return True
        except RuntimeError:  # 事件循环已关闭
            return False

    def summary(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "job_id": self.job_id,
            "target": self.target,
            "state": self.state,
            "elapsed_s": round(
                (self.finished_at or time.time()) - self.started_at, 1
            ) if self.started_at else 0.0,
        }
        if self.state == "done" and self.result is not None:
            data["result"] = result_summary(self.result)
        if self.error:
            data["error"] = self.error
        data["log_tail"] = list(self.lines)[-15:]
        return data

    def report(self, fmt: str = "md") -> dict[str, Any]:
        """导出报告。仅对已完成的扫描有效。"""
        if self.state != "done" or self.result is None:
            return {"error": f"任务状态是 {self.state}，只有 done 才能出报告"}
        if self._sched is None:
            return {"error": "调度器实例已释放，无法出报告"}
        try:
            paths = self._sched.report(self.result, fmt=fmt, verbose=False)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}"}
        return {"job_id": self.job_id, "target": self.target, "files": [str(p) for p in paths]}


class JobRegistry:
    """任务表。只保留最近若干个，避免常驻进程无限攒内存。"""

    def __init__(self, keep: int = 20) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._order: deque[str] = deque()
        self._keep = keep
        self._lock = threading.Lock()

    def start(
        self,
        target: str,
        *,
        config: str = "",
        top_k: int = 0,
        no_ai: bool = False,
        no_rag: bool = False,
        save_evidence: bool = False,
    ) -> ScanJob:
        cfg = load_cfg(config)
        if no_ai:
            cfg.llm.enabled = False
        if no_rag:
            cfg.rag.enabled = False
        if top_k and top_k > 0:
            cfg.rag.top_k = int(top_k)

        job = ScanJob(target, cfg, save_evidence=save_evidence)
        with self._lock:
            self._jobs[job.job_id] = job
            self._order.append(job.job_id)
            while len(self._order) > self._keep:
                old = self._order.popleft()
                self._jobs.pop(old, None)
        return job.start()

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get((job_id or "").strip())

    def all(self) -> list[ScanJob]:
        with self._lock:
            return [self._jobs[i] for i in self._order if i in self._jobs]
