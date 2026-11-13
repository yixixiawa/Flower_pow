# -*- coding: utf-8 -*-
"""后台任务体系回归测试：TaskManager / Session 集成 / 三个新工具 / Prompt 纪律。

覆盖：
  1. TaskManager 生命周期：start / finish / fail / cancel，counts / summary_line
  2. 快照往返：running 恢复成 interrupted（否则 list_tasks 会一直报"运行中"）
  3. Session 集成：tasks 落盘、is_empty、status_line
  4. 前台 recon_ports：端口数被夹到 200，超限时引导 recon_ports_bg
  5. 后台 recon_ports_bg：**立即返回**「已在后台启动，先干别的」、上限 2000、
     期间可继续调工具、完成后资产自动并入、list_tasks 取结果
  6. background_run：拒绝嵌套 / 未知工具；后台执行不绕过安全边界（写越界仍被拒）
  7. list_tasks：空台账 / 列表 / 单任务详情 / 状态过滤 / 未知 id
  8. Prompt 纪律与工具声明

运行：.venv/Scripts/python.exe scripts/background_tasks_test.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import collectors.port_scan as PS  # noqa: E402
from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session, TaskManager  # noqa: E402
from core.state import Asset  # noqa: E402
from core.tools import BUILTINS, ToolRunner  # noqa: E402
from llm import prompt as P  # noqa: E402


class FakeCfg:
    def __init__(self, tmp: Path) -> None:
        self.output_dir = str(tmp / "output")
        (tmp / "output").mkdir(parents=True, exist_ok=True)
        self.scan = ScanConfig()
        self.rag = SimpleNamespace(poc_dir=str(tmp / "poc"))


SEEN: dict[str, object] = {}


async def fake_run(self, host: str, verbose: bool = False):
    """假端口扫描：记录实际端口数，睡一会以便观察"后台还在跑"。"""
    SEEN["top"] = self.cfg.port_scan_top
    SEEN["host"] = host
    await asyncio.sleep(0.15)
    return [Asset(kind="port", value=f"{host}:{self.cfg.port_scan_top}", meta={"port": 1})]


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    print("场景1 TaskManager 生命周期")
    mgr = TaskManager()
    t1 = mgr.start("recon_ports_bg", "扫描 A")
    t2 = mgr.start("background_run", "扫路径")
    check(t1.task_id == "bg-1" and t2.task_id == "bg-2", "任务号自增 bg-1/bg-2")
    check(len(mgr.running()) == 2, "两个都在运行中")
    mgr.finish(t1.task_id, "开放端口 3 个")
    check(t1.status == "done" and t1.result == "开放端口 3 个", "finish 写入结果")
    check(t1.finished and t1.elapsed >= 0, "finished/elapsed 正确")
    mgr.fail(t2.task_id, "boom")
    check(t2.status == "failed" and t2.error == "boom", "fail 写入错误")
    check(mgr.counts() == {"done": 1, "failed": 1}, f"counts 汇总，实={mgr.counts()}")
    check("1 个" in mgr.summary_line() or "2 个" in mgr.summary_line(), "summary_line 可读")
    t3 = mgr.start("x", "待取消")
    mgr.cancel(t3.task_id, "换目标")
    check(t3.status == "cancelled", "cancel 生效")
    check(mgr.get("nope") is None, "未知任务返回 None")

    print("场景2 快照往返：running → interrupted")
    live = TaskManager()
    live.start("recon_ports_bg", "跑到一半就退出了")
    d = live.to_dict()
    restored = TaskManager.from_dict(d)
    r = restored.get("bg-1")
    check(r.status == "interrupted", f"running 恢复为 interrupted，实={r.status}")
    check(bool(r.error), "interrupted 附带原因")
    nxt = restored.start("x", "新任务")
    check(nxt.task_id == "bg-2", f"恢复后序号不撞历史 id，实={nxt.task_id}")

    print("场景3 Session 集成")
    s0 = Session(target="")
    check(s0.is_empty(), "新建空会话判定为空")
    s0.tasks.start("recon_ports_bg", "后台扫端口中")
    check(not s0.is_empty(), "只有后台任务的会话不算空（不能丢快照）")
    check("后台 1 运行中" in s0.status_line(), "status_line 显示后台运行数")
    d0 = s0.to_dict()
    check("tasks" in d0, "to_dict 带 tasks")
    s1 = Session.from_dict(d0)
    check(len(s1.tasks) == 1 and s1.tasks.get("bg-1").status == "interrupted",
          "from_dict 恢复任务台账并标记中断")

    tmp = Path(tempfile.mkdtemp())
    cfg = FakeCfg(tmp)
    runner = ToolRunner(cfg, [], str(tmp))
    sess = Session(target="https://demo.example.com")

    orig_run = PS.PortScanner.run
    PS.PortScanner.run = fake_run
    try:
        async def scenarios() -> None:
            print("场景4 前台 recon_ports（快速版）")
            out = await runner.execute("recon_ports", {"top": 500}, sess)
            check("开放端口" in out, f"前台扫描出结果，实={out[:40]!r}")
            check(SEEN["top"] == 200, f"前台端口数夹到 200，实={SEEN['top']}")
            check("recon_ports_bg" in out, "超限时提示改用后台版")
            check(any(a.kind == "port" for a in sess.result.assets), "前台资产入会话")
            # state_text 必须真的返回内容（曾漏 return，session_state 永远空串）
            st = runner.state_text(sess)
            check(bool(st) and "目标" in st and "资产" in st,
                  f"state_text 返回真实状态（曾返回 None），实={str(st)[:30]!r}")

            print("场景5 后台 recon_ports_bg")
            before_assets = len(sess.result.assets)
            t0 = time.perf_counter()
            out = await runner.execute("recon_ports_bg", {"top": 5000}, sess)
            cost = time.perf_counter() - t0
            check("已在后台启动，先干别的" in out, "回执措辞符合要求")
            check("bg-" in out, "回执带任务号")
            check(cost < 0.12, f"**立即返回**（假扫描要 0.15s），实={cost:.3f}s")
            task = sess.tasks.get("bg-1")
            check(task is not None and task.status == "running", "任务登记为运行中")
            check(task.meta["top"] == 2000, f"后台上限 2000，实={task.meta['top']}")
            out_bg = await runner.execute("session_state", {}, sess)
            check("目标" in out_bg, "后台跑着时照样能调别的工具")
            out_list = await runner.execute("list_tasks", {}, sess)
            check("运行中" in out_list, f"list_tasks 显示运行中，实={out_list[:50]!r}")
            await asyncio.sleep(0.25)
            check(sess.tasks.get("bg-1").status == "done", "任务完成后状态为 done")
            check(len(sess.result.assets) > before_assets, "后台任务资产自动并入会话")
            out_done = await runner.execute("list_tasks", {}, sess)
            check("已完成" in out_done and "bg-1" in out_done, "列表显示已完成")
            out_detail = await runner.execute("list_tasks", {"task_id": "bg-1"}, sess)
            check("开放端口" in out_detail, f"单任务详情带完整结果，实={out_detail[:60]!r}")

            print("场景6 background_run")
            out = await runner.execute("background_run", {"tool": "recon_ports_bg"}, sess)
            check("已拦截" in out, "拒绝后台化 *_bg 工具")
            out = await runner.execute("background_run", {"tool": "background_run"}, sess)
            check("已拦截" in out, "拒绝嵌套 background_run")
            out = await runner.execute("background_run", {"tool": "no_such_tool"}, sess)
            check("未知工具" in out, "未知工具直接报错")
            out = await runner.execute(
                "background_run",
                {"tool": "session_state", "purpose": "看会话状态"},
                sess,
            )
            check("已在后台启动，先干别的" in out, "通用后台化立即返回")
            await asyncio.sleep(0.05)
            last = sess.tasks.all()[-1]
            check(last.status == "done" and "目标" in last.result,
                  "后台任务完成并保存结果")
            # 安全边界不因"后台"而放宽：越界写依然被拒
            out = await runner.execute(
                "background_run",
                {"tool": "write_file", "args": {"path": "../../.env", "content": "x"}},
                sess,
            )
            check("已在后台启动" in out, "越界写也先受理（后台异步）")
            await asyncio.sleep(0.05)
            last = sess.tasks.all()[-1]
            check("已拒绝" in last.result,
                  f"后台执行没有绕过沙箱闸门，实={last.result[:40]!r}")

            print("场景7 list_tasks 细节")
            empty = Session(target="https://x.test")
            out = await runner.execute("list_tasks", {}, empty)
            check("没有后台任务" in out, "空台账明确提示")
            out = await runner.execute("list_tasks", {"task_id": "bg-99"}, sess)
            check("没有任务 bg-99" in out, "未知 id 提示现有任务")
            out = await runner.execute("list_tasks", {"status": "failed"}, sess)
            check("failed" not in out or "没有状态" in out, "状态过滤可用")

            print("场景8 换目标时取消后台任务")
            await runner.execute("recon_ports_bg", {"top": 300}, sess)
            running = sess.tasks.running()
            check(len(running) == 1, "新任务在跑")
            n = runner.cancel_background(sess, "切换目标，后台任务已取消")
            check(n == 1, f"取消 1 个运行中任务，实={n}")
            check(sess.tasks.running() == [], "台账里没有运行中任务了")
            await asyncio.sleep(0.01)

        asyncio.run(scenarios())
    finally:
        PS.PortScanner.run = orig_run

    print("场景9 Prompt 纪律与工具声明")
    for kw in ("30 秒", "background_run", "list_tasks", "recon_ports_bg",
               "已在后台启动，先干别的", "不许原地等"):
        check(kw in P.AGENT_SYSTEM, f"AGENT_SYSTEM 提到 {kw!r}")
    names = {b.name for b in BUILTINS}
    check({"recon_ports", "recon_ports_bg", "background_run", "list_tasks"} <= names,
          "四个工具都已声明")
    rp = next(b for b in BUILTINS if b.name == "recon_ports")
    check("200" in rp.desc and "recon_ports_bg" in rp.desc, "前台版说明快速上限")
    bg = next(b for b in BUILTINS if b.name == "recon_ports_bg")
    check(set(bg.params["properties"]) == {"host", "top"}, "后台版参数齐全")
    br = next(b for b in BUILTINS if b.name == "background_run")
    check(br.params["required"] == ["tool"] and "args" in br.params["properties"],
          "background_run 声明 tool/args/purpose")
    lt = next(b for b in BUILTINS if b.name == "list_tasks")
    check("task_id" in lt.params["properties"] and "status" in lt.params["properties"],
          "list_tasks 声明 task_id/status")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
