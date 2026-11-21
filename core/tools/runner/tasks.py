"""后台任务类工具：recon_ports_bg、background_run、list_tasks。

为什么需要这一层
----------------
渗透测试里有大量"跑得久但不需要我盯着"的调用：nmap 全端口、dirsearch 大字典、
子网批量发包。前台等它们跑完，模型这段时间**什么也做不了**——思考流程被阻塞，
用户看到的是终端卡住不动。

所以把它们挪到 asyncio 后台：工具**立即**返回「已在后台启动，先干别的」+ 任务号，
模型继续做别的；任务完成时资产/发现**自动并入会话**（handler 本身就在写
``session``），结果文本落在 ``session.tasks`` 里。

六条约束
--------
1. **状态只有一份**：任务记录全部进 :class:`core.session.tasks.TaskManager`，
   不在 runner 里另存一份——否则会话落盘与工具查询会各说各话。
2. **不嵌套**：``background_run`` 拒绝后台化 ``background_run`` / ``list_tasks`` /
   任何 ``*_bg`` 工具。一层套一层只会制造"查任务的任务"。
3. **强引用**：``asyncio.create_task`` 只被事件循环弱引用，不自己存一份的话
   任务可能执行到一半被 GC（官方文档明确要求保留引用）。
4. **启动前去重**：同指纹（会话+目标+工具+规范化参数+任务类型）的任务
   在**起进程之前**就判掉——RUNNING 复用 task_id、SUCCEEDED 直接给结果、
   FAILED/CANCELLED/TIMEOUT 一律不自动重跑（见 :func:`dedup_verdict`）。
5. **超时进终态**：``asyncio.wait_for`` 到点即 timeout，台账里再也不会出现
   "永远 running" 的幽灵任务；``TaskManager.sweep`` 是同一件事的兜底。
6. **结果只给摘要 + artifact 引用**：完整输出落盘，回灌上下文的是摘要和
   一行路径——同一份大输出不会被反复注入（任务书 一.7 / 五.1-2）。
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from core.session import journal as journal_mod
from core.session.tasks import dedup_verdict, task_fingerprint

# 前台快速探测的端口上限 / 后台大范围扫描的端口上限。
# 两个数字分开是为了让"前台=快、后台=大"成为结构性事实，而不是提示词里的劝导。
QUICK_PORTS_MAX = 200
BG_PORTS_MAX = 2000

# 后台结果回灌时的显示上限（完整结果仍在 session.tasks 里）
_TASK_RESULT_PREVIEW = 2500
# 列表里每条结果首行的显示上限
_TASK_LINE_PREVIEW = 120

# 超过这个长度就落 artifact：上下文里只留摘要 + 路径
TASK_ARTIFACT_THRESHOLD = 1500
# 详情里给模型看的结果预览（其余用 artifact_query 定点查）
_TASK_DETAIL_PREVIEW = 1200

# 后台任务默认超时（秒）与硬上限。超时不是"放弃"，是**进终态**：
# 台账不会留一个永远 running 的任务让 Agent 干等。
BG_TIMEOUT_DEFAULT = 900.0
BG_TIMEOUT_MAX = 3600.0

# list_tasks 的有界等待上限（任务书 一.6：有上限的等待 + 指数退避，禁止无限轮询）
WAIT_MAX = 15.0

# 反轮询：连续多少次查询看到的状态完全一样，就拒绝继续查
POLL_REPEAT_LIMIT = 3
# 距上次查询超过这么久，计数清零（隔了很久再看一眼是正常行为）
POLL_RESET_SECONDS = 60.0

# 不允许被后台化的工具：它们本身就是后台入口/查询入口
_NO_BG = {"background_run", "list_tasks"}


class TaskMixin:
    """见模块说明。"""

    # ── 公共设施 ──────────────────────────────────────────────────

    def _spawn(self, session, task, coro, timeout_s: float = 0.0) -> None:
        """启动一个后台协程并把结果/异常回写到任务台账。"""
        limit = float(timeout_s or 0.0)
        # 归档：任务进入"运行中"这件事在这里统一记一次（幂等键 = task_id）。
        # 放在 _spawn 而不是各个入口：recon_ports_bg / background_run / 以后
        # 新增的后台入口都从这里过，少一处就会漏一种任务。
        journal_mod.record(
            session, "TASK_STARTED",
            content=task.label,
            execution_status="running",
            idem=f"task:{task.task_id}:started",
            extra={"task_id": task.task_id, "tool": task.tool, "status": "running"},
        )

        async def run() -> None:
            try:
                if limit > 0:
                    text = await asyncio.wait_for(coro, timeout=limit)
                else:
                    text = await coro
            except (asyncio.TimeoutError, TimeoutError):
                # 到点必须进终态（任务书 一.8 / 六.3）：这里只记状态，
                # 不重跑、不重试——重新执行只能由调用方显式发起。
                session.tasks.timeout(
                    task.task_id, f"超过 {limit:.0f}s 未完成，已按超时结束"
                )
                journal_mod.record(
                    session, "TASK_FAILED",
                    content=f"超过 {limit:.0f}s 未完成，已按超时结束",
                    execution_status="timeout",
                    idem=f"task:{task.task_id}:failed",
                    extra={"task_id": task.task_id, "status": "timeout"},
                )
                return
            except asyncio.CancelledError:
                session.tasks.cancel(task.task_id, "任务被取消（用户中断或切换目标）")
                journal_mod.record(
                    session, "TASK_FAILED",
                    content="任务被取消（用户中断或切换目标）",
                    execution_status="cancelled",
                    idem=f"task:{task.task_id}:failed",
                    extra={"task_id": task.task_id, "status": "cancelled"},
                )
                raise
            except Exception as exc:  # noqa: BLE001
                session.tasks.fail(task.task_id, f"{type(exc).__name__}: {exc}")
                journal_mod.record(
                    session, "TASK_FAILED",
                    content=f"{type(exc).__name__}: {exc}",
                    execution_status="failed",
                    idem=f"task:{task.task_id}:failed",
                    extra={"task_id": task.task_id, "status": "failed"},
                )
                return
            self._finish_task(session, task, text)

        handle = asyncio.create_task(run(), name=f"bg:{task.task_id}")
        # 强引用 + 结束后自动释放（见模块说明第 3 条）
        self._bg_handles[task.task_id] = handle
        handle.add_done_callback(lambda _h: self._bg_handles.pop(task.task_id, None))

    def _finish_task(self, session, task, text: str) -> None:
        """成功收尾：摘要 + （超长时）落 artifact。"""
        body = str(text or "")
        summary = _first_line(body) or "（无输出）"
        artifact = ""
        if len(body) > TASK_ARTIFACT_THRESHOLD:
            try:
                # 复用同一个 store（与 artifact_query 共享查询缓存）
                artifact = self._artifact_store().save(body, f"task-{task.task_id}")
                summary = f"{summary}（完整结果 {len(body)} 字符已存 {artifact}）"
            except OSError:
                # 落盘失败不阻断：结果仍在台账里，只是上下文会看到截断预览
                summary = f"{summary}（完整结果 {len(body)} 字符，落盘失败）"
        session.tasks.finish(task.task_id, body, summary=summary, artifact=artifact)
        journal_mod.record(
            session, "TASK_COMPLETED",
            content=summary,
            execution_status="done",
            idem=f"task:{task.task_id}:done",
            extra={"task_id": task.task_id, "status": "done", "artifact": artifact},
        )

    def cancel_background(self, session, reason: str = "已取消") -> int:
        """取消全部未结束（排队中/运行中）的后台任务，返回个数。

        换目标 / 彻底重置时**必须**调用：旧目标的后台任务跑完会把资产并进
        新会话（``_merge_assets`` 写的就是 session 对象），报告直接串线。
        """
        n = 0
        for t in list(session.tasks.active()):
            h = self._bg_handles.get(t.task_id)
            if h is not None and not h.done():
                h.cancel()
            session.tasks.cancel(t.task_id, reason)
            n += 1
        return n

    @staticmethod
    def _bg_confirm(task, hint: str) -> str:
        """统一的后台启动回执。措辞必须让模型**立刻转去干别的**。"""
        return (
            f"已在后台启动，先干别的。\n"
            f"  任务号：{task.task_id}（{task.label}）\n"
            f"  {hint}\n"
            f"  状态变化（完成/失败/超时）会**自动推送**给你，不需要轮询 list_tasks。\n"
            f"  真要看结果：list_tasks(task_id=\"{task.task_id}\", wait=5) 有上限等待；"
            f"带 task_id 可看摘要与 artifact 引用。"
            f"完成后资产/发现会自动并入会话，不用重跑。"
        )

    # ── 去重 ──────────────────────────────────────────────────────

    def _task_fingerprint(self, session, tool: str, args: Any, task_type: str) -> str:
        return task_fingerprint(
            session_id=getattr(session, "session_id", "") or "",
            target_id=getattr(session, "target", "") or "",
            tool=tool,
            args=args,
            task_type=task_type,
        )

    def _dedup_gate(
        self,
        session,
        *,
        tool: str,
        args: Any,
        task_type: str,
        retry: bool = False,
    ) -> tuple[str, str, str]:
        """在**起进程之前**判重。返回 ``(action, fingerprint, reply_text)``。

        ``action == "new"`` 时 ``reply_text`` 为空，调用方继续启动；
        其余三种都直接把这行文本回给模型，不启动任何东西。
        """
        fp = self._task_fingerprint(session, tool, args, task_type)
        action, task, why = dedup_verdict(session.tasks, fp, force=bool(retry))
        if action == "new" or task is None:
            return "new", fp, ""
        if action == "reuse_running":
            return action, fp, (
                f"【已存在，未重复启动】{task.task_id}（{task.label}）正在跑同一件事"
                f"（会话/目标/工具/参数完全相同）。\n"
                f"  不要重复触发：重复触发不会加速，只会白烧目标资源。\n"
                f"  状态变化会自动推送；需要就在这一步等就 "
                f"list_tasks(task_id=\"{task.task_id}\", wait=5)，"
                f"有上限等待、超时即返回，不会无限轮询。"
            )
        if action == "reuse_result":
            detail = f"\n  摘要：{task.brief()}" if task.brief() else ""
            ref = f"\n  完整结果：{task.artifact}" if task.artifact else ""
            return action, fp, (
                f"【复用已有结果，未重复执行】{task.task_id}（{task.label}）"
                f"刚刚已经成功完成同一件事（{why}）。{detail}{ref}\n"
                f"  需要原文用 list_tasks(task_id=\"{task.task_id}\")；"
                f"要重新跑请说明**参数哪里变了**（换字典/端口段/路径），或明确要求重试。"
            )
        # blocked：failed / cancelled / timeout / interrupted
        return action, fp, (
            f"【不重复执行】同一任务 {task.task_id}（{task.label}）上次结果是"
            f"「{task.status_label}」：{task.error or task.brief() or '无原因'}。\n"
            f"  失败/取消/超时的任务**不会**自动重跑（重跑同样的命令只会得到同样的失败）。\n"
            f"  要继续，二选一：① 改参数让动作真的不同（不同端口段/字典/路径/主机）；"
            f"② 用户明确要求重试时用 retry=true。"
        )

    # ── 端口扫描（后台版）────────────────────────────────────────

    async def _h_recon_ports_bg(
        self,
        session,
        host: str = "",
        top: int = 0,
        retry: bool = False,
        timeout: float = 0,
    ) -> str:
        """后台端口扫描：立即返回，扫描在 asyncio 任务里继续。"""
        h = self._host_of(session, host)
        if not h:
            return "无法确定主机名"
        want = int(top or 0) or int(getattr(self.cfg.scan, "port_scan_top", 0) or 0) or 100
        n = max(1, min(want, BG_PORTS_MAX))
        limit = _clamp_timeout(timeout)
        action, _fp, reply = self._dedup_gate(
            session, tool="recon_ports", args={"host": h, "top": n},
            task_type="recon_ports_bg", retry=retry,
        )
        if action != "new":
            return reply
        task = session.tasks.start(
            tool="recon_ports_bg",
            label=f"端口扫描 {h}（前 {n} 个端口）",
            meta={"host": h, "top": n},
            fingerprint=_fp,
            timeout_s=limit,
            queued=True,
        )
        session.tasks.mark_running(task.task_id)
        self._spawn(
            session, task,
            self._scan_ports(session, h, n, max_top=BG_PORTS_MAX),
            timeout_s=limit,
        )
        return self._bg_confirm(
            task,
            f"扫描范围：{h} 前 {n} 个 TCP 端口（后台上限 {BG_PORTS_MAX}，"
            f"超过 {limit:.0f}s 按超时结束）。"
            "期间可以继续分析已抓到的 JS、整理接口清单、测别的接口。",
        )

    # ── 通用后台化 ────────────────────────────────────────────────

    async def _h_background_run(
        self,
        session,
        tool: str = "",
        args: dict[str, Any] | None = None,
        purpose: str = "",
        retry: bool = False,
        timeout: float = 0,
    ) -> str:
        """把任意前台工具放到后台跑。"""
        name = (tool or "").strip()
        if not name:
            return "【参数不合法】background_run 需要 tool 参数（要后台执行的那个工具名）"
        if name in _NO_BG or name.endswith("_bg"):
            return (
                f"【已拦截】{name} 不能被后台化：它本身就是后台/查询入口，"
                "嵌套触发只会造出查任务的任务。请直接调用它。"
            )
        if getattr(self, f"_h_{name}", None) is None:
            return f"【未知工具】{name}。可用工具见系统提示中的清单。"
        if args is not None and not isinstance(args, dict):
            # 模型常把 args 写成命令行数组（历史提示词里就有这种例子）。
            # 直接 dict(list) 会抛 ValueError 变成"执行失败"，不如明确纠错。
            return (
                "【参数不合法】background_run.args 必须是**被后台化工具自己的参数对象**，"
                f"而不是数组。例如：{{\"tool\": \"{name}\", \"args\": "
                "{\"…该工具的参数…\": \"…\"}}。"
                + ("若目标是 external_tool，正确写法是 "
                   "args={\"tool\": \"dirsearch\", \"args\": [\"-u\", \"…\"]}。"
                   if name == "external_tool" else "")
            )

        call_args = dict(args or {})
        limit = _clamp_timeout(timeout)
        action, fp, reply = self._dedup_gate(
            session, tool=name, args=call_args, task_type="background_run",
            retry=retry,
        )
        if action != "new":
            return reply
        brief = purpose.strip() or name
        task = session.tasks.start(
            tool="background_run",
            label=f"{brief}（{name}）",
            meta={"tool": name, "args": call_args},
            fingerprint=fp,
            timeout_s=limit,
            queued=True,
        )
        session.tasks.mark_running(task.task_id)
        # 走 self.execute 而不是直接调 handler：只读拦截、参数归一、输出截断、
        # 调用记账全部与前台一致——后台版不等于绕过安全边界。
        self._spawn(session, task, self.execute(name, call_args, session), timeout_s=limit)
        short = json.dumps(call_args, ensure_ascii=False, default=str)
        if len(short) > 160:
            short = short[:160] + "…"
        return self._bg_confirm(
            task,
            f"后台执行：{name} {short}（超过 {limit:.0f}s 按超时结束）。"
            f"这期间不要重复触发同一个任务。",
        )

    # ── 查询 ──────────────────────────────────────────────────────

    async def _h_list_tasks(
        self,
        session,
        task_id: str = "",
        status: str = "",
        wait: float = 0,
    ) -> str:
        """列出后台任务；带 task_id 时返回该任务的摘要与 artifact 引用。

        ``wait`` 是**有上限**的等待（≤ 15s，指数退避）：只为"我这一步就必须
        拿到这个结果"准备，不是轮询手段。状态变化本来就会自动推送给 Agent。
        """
        mgr = session.tasks
        mgr.sweep()          # 兜底收割：进程卡死也要进终态
        tid = (task_id or "").strip()
        if tid:
            t = mgr.get(tid)
            if t is None:
                known = "、".join(x.task_id for x in mgr.all()) or "（无）"
                return f"没有任务 {tid}。现有任务：{known}"
            waited = 0.0
            if not t.finished and wait and float(wait) > 0:
                waited, t = await self._bounded_wait(mgr, t, float(wait))
            return self._task_detail(t, waited=waited)

        items = mgr.all()
        want = (status or "").strip().lower()
        if want:
            items = [t for t in items if t.status == want]
        text = self._poll_guard(mgr, tid="", status=want, items=items)
        if text:
            return text
        if not items:
            return "当前没有后台任务。" if not mgr else f"没有状态为 {want} 的后台任务。"
        head = f"后台任务 {len(items)} 个 —— {mgr.summary_line()}"
        lines = [head]
        for t in items:
            lines.append("  " + t.line())
            if t.status == "done" and (t.summary or t.result):
                first = t.brief(_TASK_LINE_PREVIEW)
                lines.append(f"      → {first}")
                if t.artifact:
                    lines.append(f"      完整结果：{t.artifact}（用 artifact_query 定点查）")
            elif t.error:
                lines.append(f"      ✗ {t.error}")
        active = [t for t in items if not t.finished]
        if active:
            lines.append(
                "  还在跑的任务先别等：继续做别的。状态变化会自动推送给你；"
                "确实要等就 list_tasks(task_id=\"bg-x\", wait=5)（上限 15s，指数退避）。"
            )
        elif any(t.status == "done" for t in items):
            lines.append("  已完成的结果用 list_tasks(task_id=\"bg-x\") 看摘要与 artifact。")
        return "\n".join(lines)

    async def _bounded_wait(self, mgr, task, wait: float):
        """有上限的等待 + 指数退避，返回 ``(已等待秒数, 任务)``。"""
        budget = min(max(0.0, float(wait)), WAIT_MAX)
        started = time.monotonic()
        delay = 0.2
        while not task.finished and time.monotonic() - started < budget:
            await asyncio.sleep(min(delay, max(0.0, budget - (time.monotonic() - started))))
            delay = min(delay * 2, 2.0)
            mgr.sweep()
            task = mgr.get(task.task_id) or task
        return time.monotonic() - started, task

    def _task_detail(self, t, *, waited: float = 0.0) -> str:
        lines = [
            f"{t.task_id}｜{t.status_label}｜{t.label}",
            f"  工具：{t.tool}  耗时：{t.elapsed:.1f}s"
            + (f"  （已等待 {waited:.1f}s）" if waited else ""),
        ]
        if t.fingerprint:
            lines.append(f"  指纹：{t.fingerprint}（同指纹不会再起新任务）")
        if t.summary:
            lines.append(f"  摘要：{t.summary}")
        if t.result:
            text = t.result
            preview = text[:_TASK_DETAIL_PREVIEW]
            lines.append("  结果预览：\n" + "\n".join("    " + ln for ln in preview.splitlines()))
            if len(text) > _TASK_DETAIL_PREVIEW:
                if t.artifact:
                    lines.append(
                        f"  ⚠ 完整结果（{len(text)} 字符）在 {t.artifact}——"
                        f"用 artifact_query(path=\"{t.artifact}\", keyword=\"...\") 定点查，"
                        f"不要通读。"
                    )
                else:
                    lines.append(f"  …（已截断，共 {len(text)} 字符）")
        if t.error:
            lines.append(f"  错误：{t.error}")
        if not t.finished:
            lines.append(
                "  还在跑：不要原地等。状态变化会自动推送；"
                "确实必须现在就拿到，可 list_tasks(task_id=..., wait=5) 有界等待。"
            )
        return "\n".join(lines)

    def _poll_guard(self, mgr, *, tid: str, status: str, items) -> str:
        """反轮询：连续看到完全相同的状态就拒绝继续查。

        为什么要有：``list_tasks`` 是模型唯一能自己发起的"等待"手段，它会
        在等结果时反复调用（真实事故：一轮里连查十几次，每次输出一模一样，
        既拿不到新信息又吃掉上下文）。状态由系统推送，轮询本来就没有意义。
        """
        sig = "|".join(
            f"{t.task_id}:{t.status}:{t.finished_at or 0}" for t in sorted(items, key=lambda x: x.task_id)
        )
        now = time.monotonic()
        state = getattr(self, "_poll_state", None)
        if not isinstance(state, dict) or state.get("key") != (tid, status):
            state = {"key": (tid, status), "sig": sig, "n": 1, "at": now}
        elif now - state["at"] > POLL_RESET_SECONDS or sig != state["sig"]:
            state = {"key": (tid, status), "sig": sig, "n": 1, "at": now}
        else:
            state["n"] += 1
            state["at"] = now
        self._poll_state = state
        if state["n"] <= POLL_REPEAT_LIMIT:
            return ""
        state["n"] = 0
        return (
            f"【停止轮询】后台任务状态与上几次查询完全相同，没有任何变化"
            f"（已连续查询超过 {POLL_REPEAT_LIMIT} 次）。\n"
            f"  状态变化（完成/失败/超时）会**自动推送**到你的上下文，"
            f"再查也不会变快。\n"
            f"  现在应该：① 用这段时间做不依赖它的工作；"
            f"② 若没别的可做，就把已知结果给用户，说明「{_running_ids(items)} 还在后台跑」。"
        )


def _clamp_timeout(value: Any) -> float:
    try:
        v = float(value or 0.0)
    except (TypeError, ValueError):
        v = 0.0
    if v <= 0:
        return BG_TIMEOUT_DEFAULT
    return min(v, BG_TIMEOUT_MAX)


def _running_ids(items) -> str:
    ids = [t.task_id for t in items if not t.finished]
    return "、".join(ids) if ids else "相关任务"


def _first_line(text: str, limit: int = 160) -> str:
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    if len(first) > limit:
        first = first[: limit - 1] + "…"
    return first


__all__ = [
    "TaskMixin",
    "QUICK_PORTS_MAX",
    "BG_PORTS_MAX",
    "BG_TIMEOUT_DEFAULT",
    "BG_TIMEOUT_MAX",
    "TASK_ARTIFACT_THRESHOLD",
    "WAIT_MAX",
    "POLL_REPEAT_LIMIT",
]
