"""后台任务类工具：recon_ports_bg、background_run、list_tasks。

为什么需要这一层
----------------
渗透测试里有大量"跑得久但不需要我盯着"的调用：nmap 全端口、dirsearch 大字典、
子网批量发包。前台等它们跑完，模型这段时间**什么也做不了**——思考流程被阻塞，
用户看到的是终端卡住不动。

所以把它们挪到 asyncio 后台：工具**立即**返回「已在后台启动，先干别的」+ 任务号，
模型继续做别的；任务完成时资产/发现**自动并入会话**（handler 本身就在写
``session``），结果文本落在 ``session.tasks`` 里，等模型主动 ``list_tasks`` 取。

三条约束
--------
1. **状态只有一份**：任务记录全部进 :class:`core.session.tasks.TaskManager`，
   不在 runner 里另存一份——否则会话落盘与工具查询会各说各话。
2. **不嵌套**：``background_run`` 拒绝后台化 ``background_run`` / ``list_tasks`` /
   任何 ``*_bg`` 工具。一层套一层只会制造"查任务的任务"。
3. **强引用**：``asyncio.create_task`` 只被事件循环弱引用，不自己存一份的话
   任务可能执行到一半被 GC（官方文档明确要求保留引用）。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

# 前台快速探测的端口上限 / 后台大范围扫描的端口上限。
# 两个数字分开是为了让"前台=快、后台=大"成为结构性事实，而不是提示词里的劝导。
QUICK_PORTS_MAX = 200
BG_PORTS_MAX = 2000

# 后台结果回灌时的显示上限（完整结果仍在 session.tasks 里）
_TASK_RESULT_PREVIEW = 2500
# 列表里每条结果首行的显示上限
_TASK_LINE_PREVIEW = 120

# 不允许被后台化的工具：它们本身就是后台入口/查询入口
_NO_BG = {"background_run", "list_tasks"}


class TaskMixin:
    """见模块说明。"""

    # ── 公共设施 ──────────────────────────────────────────────────

    def _spawn(self, session, task, coro) -> None:
        """启动一个后台协程并把结果/异常回写到任务台账。"""
        async def run() -> None:
            try:
                text = await coro
            except asyncio.CancelledError:
                session.tasks.cancel(task.task_id, "任务被取消（用户中断或切换目标）")
                raise
            except Exception as exc:  # noqa: BLE001
                session.tasks.fail(task.task_id, f"{type(exc).__name__}: {exc}")
                return
            session.tasks.finish(task.task_id, text)

        handle = asyncio.create_task(run(), name=f"bg:{task.task_id}")
        # 强引用 + 结束后自动释放（见模块说明第 3 条）
        self._bg_handles[task.task_id] = handle
        handle.add_done_callback(lambda _h: self._bg_handles.pop(task.task_id, None))

    def cancel_background(self, session, reason: str = "已取消") -> int:
        """取消全部运行中的后台任务，返回个数。

        换目标 / 彻底重置时**必须**调用：旧目标的后台任务跑完会把资产并进
        新会话（``_merge_assets`` 写的就是 session 对象），报告直接串线。
        """
        n = 0
        for t in list(session.tasks.running()):
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
            f"  结果不会自动弹回来——需要时调用 list_tasks（带 task_id 看完整结果）。"
            f"完成后资产/发现会自动并入会话，不用重跑。"
        )

    # ── 端口扫描（后台版）────────────────────────────────────────

    async def _h_recon_ports_bg(self, session, host: str = "", top: int = 0) -> str:
        """后台端口扫描：立即返回，扫描在 asyncio 任务里继续。"""
        h = self._host_of(session, host)
        if not h:
            return "无法确定主机名"
        want = int(top or 0) or int(getattr(self.cfg.scan, "port_scan_top", 0) or 0) or 100
        n = max(1, min(want, BG_PORTS_MAX))
        task = session.tasks.start(
            tool="recon_ports_bg",
            label=f"端口扫描 {h}（前 {n} 个端口）",
            meta={"host": h, "top": n},
        )
        self._spawn(session, task, self._scan_ports(session, h, n, max_top=BG_PORTS_MAX))
        return self._bg_confirm(
            task,
            f"扫描范围：{h} 前 {n} 个 TCP 端口（后台上限 {BG_PORTS_MAX}）。"
            "期间可以继续分析已抓到的 JS、整理接口清单、测别的接口。",
        )

    # ── 通用后台化 ────────────────────────────────────────────────

    async def _h_background_run(
        self,
        session,
        tool: str = "",
        args: dict[str, Any] | None = None,
        purpose: str = "",
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

        call_args = dict(args or {})
        brief = purpose.strip() or name
        task = session.tasks.start(
            tool="background_run",
            label=f"{brief}（{name}）",
            meta={"tool": name, "args": call_args},
        )
        # 走 self.execute 而不是直接调 handler：只读拦截、参数归一、输出截断、
        # 调用记账全部与前台一致——后台版不等于绕过安全边界。
        self._spawn(session, task, self.execute(name, call_args, session))
        short = json.dumps(call_args, ensure_ascii=False, default=str)
        if len(short) > 160:
            short = short[:160] + "…"
        return self._bg_confirm(
            task,
            f"后台执行：{name} {short}。这期间不要重复触发同一个任务。",
        )

    # ── 查询 ──────────────────────────────────────────────────────

    async def _h_list_tasks(self, session, task_id: str = "", status: str = "") -> str:
        """列出后台任务；带 task_id 时返回该任务的完整结果。"""
        mgr = session.tasks
        tid = (task_id or "").strip()
        if tid:
            t = mgr.get(tid)
            if t is None:
                known = "、".join(x.task_id for x in mgr.all()) or "（无）"
                return f"没有任务 {tid}。现有任务：{known}"
            lines = [f"{t.task_id}｜{t.status_label}｜{t.label}",
                     f"  工具：{t.tool}  耗时：{t.elapsed:.1f}s"]
            if t.result:
                text = t.result
                if len(text) > _TASK_RESULT_PREVIEW:
                    text = (text[:_TASK_RESULT_PREVIEW]
                            + f"\n…（已截断，共 {len(t.result)} 字符）")
                lines.append("  结果：\n" + "\n".join("    " + ln for ln in text.splitlines()))
            if t.error:
                lines.append(f"  错误：{t.error}")
            return "\n".join(lines)

        items = mgr.all()
        want = (status or "").strip().lower()
        if want:
            items = [t for t in items if t.status == want]
        if not items:
            return "当前没有后台任务。" if not mgr else f"没有状态为 {want} 的后台任务。"
        head = f"后台任务 {len(items)} 个 —— {mgr.summary_line()}"
        lines = [head]
        for t in items:
            lines.append("  " + t.line())
            if t.status == "done" and t.result:
                first = next((ln.strip() for ln in t.result.splitlines() if ln.strip()), "")
                if len(first) > _TASK_LINE_PREVIEW:
                    first = first[:_TASK_LINE_PREVIEW] + "…"
                lines.append(f"      → {first}")
            elif t.error:
                lines.append(f"      ✗ {t.error}")
        running = [t for t in items if t.status == "running"]
        if running:
            lines.append(
                "  还在跑的任务先别等：继续做别的，需要结果时再 list_tasks；"
                "带 task_id 可看单个任务的完整结果。"
            )
        elif any(t.status == "done" for t in items):
            lines.append("  已完成的结果可用 list_tasks(task_id=\"bg-x\") 取全文。")
        return "\n".join(lines)
