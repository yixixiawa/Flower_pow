# -*- coding: utf-8 -*-
"""后台任务治理与重复探索治理专项测试（对应 workflowfix.md 一~七章）。

覆盖任务书第七章要求的 12 项，外加几条配套不变量：

  1. 同一后台任务重复提交时只启动一个进程
  2. RUNNING 状态不会被重复注入 Agent 上下文
  3. 任务完成事件只消费一次
  4. 任务失败后不会自动无限重试
  5. 超时任务能够进入终态
  6. 不同 target 的相同命令不能错误去重
  7. 不同参数的任务不能错误去重
  8. Agent 重复提出相同工具调用时被识别
  9. 相同错误不会导致无限规划循环
 10. 相同大型 artifact 不会重复注入完整内容（且同查询命中缓存）
 11. 任务恢复后仍执行 Policy 与 target 校验
 12. 去重与缓存不能绕过 Request Gateway

配套：指纹/去重判定的单元行为、list_tasks 有界等待、反轮询闸门。

运行：.venv/Scripts/python.exe scripts/workflow_guard_test.py
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
from core.agent import Agent  # noqa: E402
from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session  # noqa: E402
from core.session.tasks import (  # noqa: E402
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_TIMEOUT,
    TaskManager,
    dedup_verdict,
    task_fingerprint,
)
from core.state import Asset  # noqa: E402
from core.tools import ToolRunner  # noqa: E402


class FakeCfg:
    def __init__(self, tmp: Path) -> None:
        self.output_dir = str(tmp / "output")
        (tmp / "output").mkdir(parents=True, exist_ok=True)
        self.scan = ScanConfig()
        self.rag = SimpleNamespace(poc_dir=str(tmp / "poc"))


SEEN: dict[str, object] = {"calls": 0, "hosts": [], "raise": False, "delay": 0.25}


async def fake_run(self, host: str, verbose: bool = False):
    """假端口扫描：可延时（观察 running）、可开关式制造失败。"""
    SEEN["calls"] = int(SEEN["calls"]) + 1
    SEEN["hosts"].append(host)  # type: ignore[union-attr]
    await asyncio.sleep(float(SEEN["delay"]))
    if SEEN["raise"]:
        SEEN["raise"] = False
        raise RuntimeError("模拟扫描失败")
    return [Asset(kind="port", value=f"{host}:80", meta={"port": 80})]


def tc(name, args="{}", cid=None):
    return {"type": "tool_calls", "calls": [
        {"id": cid or f"c_{name}", "name": name, "arguments": args}
    ]}


def txt(s):
    return {"type": "text", "text": s}


TOOLS = [
    {"function": {"name": "http_probe", "description": "d", "parameters": {}}},
    {"function": {"name": "read_file", "description": "d", "parameters": {}}},
]


class FakeLLM:
    def __init__(self, script: list[list[dict]] | None = None):
        self.script = script or []
        self.i = 0
        self.seen: list[list[dict]] = []

    def stream_chat(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        turn = self.script[min(self.i, len(self.script) - 1)]
        self.i += 1
        for ev in turn:
            yield ev


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def state_text(self, session):
        return "state"

    async def execute(self, name, args, session):
        self.calls.append((name, args))
        return "[stub] 无变化的结果"


class ChainLLM:
    """按顺序吐工具调用；一旦看到"未执行/已停止/系统提示"就给结论。"""

    def __init__(self, script_calls: list[list[dict]]):
        self.script_calls = script_calls
        self.i = 0
        self.seen: list[list[dict]] = []

    def stream_chat(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        last = str(messages[-1].get("content") or "")
        if any(k in last for k in ("未执行：重复动作", "已停止执行", "系统提示", "已停止重复探索")):
            yield txt("结论：这个动作已经做过，不再重复。")
            return
        turn = self.script_calls[min(self.i, len(self.script_calls) - 1)]
        self.i += 1
        for ev in turn:
            yield ev


class ForeverLLM:
    """永远只提同一个工具调用、从不给文本——必须被代码强行收尾。"""

    def __init__(self) -> None:
        self.seen: list[list[dict]] = []
        self.n = 0

    def stream_chat(self, messages, tools=None):
        self.seen.append([dict(m) for m in messages])
        self.n += 1
        yield txt("再试一次")
        yield tc("http_probe", '{"url":"http://t/same"}', f"c{self.n}")


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp())
    cfg = FakeCfg(tmp)
    runner = ToolRunner(cfg, [], str(tmp))

    print("场景1 指纹与去重判定（单元）")
    fp_a = task_fingerprint(session_id="s1", target_id="https://a", tool="nmap",
                            args={"top": 500}, task_type="background_run")
    check(fp_a == task_fingerprint(session_id="s1", target_id="https://a/", tool="nmap",
                                   args={"top": 500}, task_type="background_run"),
          "同输入（URL 尾斜杠归一）指纹相同")
    check(fp_a != task_fingerprint(session_id="s2", target_id="https://a", tool="nmap",
                                   args={"top": 500}, task_type="background_run"),
          "不同 session 指纹不同")
    check(fp_a != task_fingerprint(session_id="s1", target_id="https://b", tool="nmap",
                                   args={"top": 500}, task_type="background_run"),
          "不同 target 指纹不同")
    check(fp_a != task_fingerprint(session_id="s1", target_id="https://a", tool="nmap",
                                   args={"top": 800}, task_type="background_run"),
          "不同参数指纹不同")
    check(fp_a != task_fingerprint(session_id="s1", target_id="https://a", tool="nmap",
                                   args={"top": 500}, task_type="recon_ports_bg"),
          "不同任务类型指纹不同")
    mgr0 = TaskManager()
    t0 = mgr0.start("nmap", "x", fingerprint="fp1")
    check(dedup_verdict(mgr0, "fp1")[0] == "reuse_running", "RUNNING → 复用 task_id")
    mgr0.finish(t0.task_id, "ok")
    check(dedup_verdict(mgr0, "fp1")[0] == "reuse_result", "SUCCEEDED（有效期内）→ 复用结果")
    check(dedup_verdict(mgr0, "fp1", ttl=-1)[0] == "new", "结果过期 → 允许重跑")
    mgr1 = TaskManager()
    t1 = mgr1.start("nmap", "y", fingerprint="fp2")
    mgr1.fail(t1.task_id, "boom")
    action, task, why = dedup_verdict(mgr1, "fp2")
    check(action == "blocked" and "不会自动重跑" in why, f"FAILED → 禁止自动重试，实={action}")
    check(dedup_verdict(mgr1, "fp2", force=True)[0] == "new", "显式 retry → 允许新建")

    orig_run = PS.PortScanner.run
    PS.PortScanner.run = fake_run
    try:
        sess = Session(target="https://demo.example.com")

        async def scenarios() -> None:
            print("场景2 同一后台任务重复提交只启动一个进程")
            SEEN.update({"calls": 0, "hosts": [], "delay": 0.35})
            out1 = await runner.execute("recon_ports_bg", {"top": 500}, sess)
            out2 = await runner.execute("recon_ports_bg", {"top": 500}, sess)
            check("已在后台启动" in out1 and "bg-1" in out1, "第一次正常启动 bg-1")
            check("已存在，未重复启动" in out2, f"第二次被判重，实={out2[:40]!r}")
            check("bg-1" in out2, "复用的是同一个任务号")
            check(len(sess.tasks.all()) == 1, f"台账里只有一个任务，实={len(sess.tasks.all())}")
            await asyncio.sleep(0.05)      # 让被调度的协程真正开始跑
            check(int(SEEN["calls"]) == 1, f"实际只启动一个扫描进程，实={SEEN['calls']}")
            check("不需要轮询" in out2 or "自动推送" in out2, "回执明确告知不用轮询")

            print("场景3 成功结果在有效期内复用（不再起进程）")
            await asyncio.sleep(0.5)
            check(sess.tasks.get("bg-1").status == STATUS_DONE, "任务已完成")
            out3 = await runner.execute("recon_ports_bg", {"top": 500}, sess)
            check("复用已有结果" in out3, f"第三次走结果复用，实={out3[:40]!r}")
            check(int(SEEN["calls"]) == 1, f"没有起第二个进程，实={SEEN['calls']}")

            print("场景4 失败任务不会自动重试，retry=true 才重跑")
            # 主机必须在目标范围内（超出范围会被 Policy 拦在执行之前，
            # 那是另一条链路的测试）；这里要测的是"任务失败后的重试纪律"。
            SEEN.update({"calls": 0, "hosts": [], "raise": True, "delay": 0.05})
            out = await runner.execute("recon_ports_bg", {"top": 11}, sess)
            check("已在后台启动" in out, "失败任务也先正常启动")
            await asyncio.sleep(0.2)
            failed = [t for t in sess.tasks.all() if t.status == STATUS_FAILED]
            check(len(failed) == 1, f"任务进入 failed 终态，实={[t.status for t in sess.tasks.all()]}")
            n_before = len(sess.tasks.all())
            out = await runner.execute("recon_ports_bg", {"top": 11}, sess)
            check("不重复执行" in out, f"同指纹再次提交被拒，实={out[:40]!r}")
            check(len(sess.tasks.all()) == n_before, "没有新建任务")
            out = await runner.execute(
                "recon_ports_bg", {"top": 11, "retry": True}, sess
            )
            check("已在后台启动" in out, "显式 retry=true 才允许重跑")
            check(len(sess.tasks.all()) == n_before + 1, "retry 确实新建了任务")
            await asyncio.sleep(0.15)

            print("场景4b 裸主机参数继承绑定目标的 scheme/端口（同主机不误判越界）")
            SEEN.update({"delay": 0.05, "calls": 0, "raise": False})
            out = await runner.execute(
                "recon_ports_bg", {"host": "demo.example.com", "top": 23}, sess
            )
            check("已在后台启动" in out, f"同主机裸主机参数不再被拒，实={out[:50]!r}")
            await asyncio.sleep(0.1)
            out = await runner.execute(
                "recon_ports_bg", {"host": "other.example.com", "top": 23}, sess
            )
            check("【已拦截】" in out, f"换主机的裸主机参数仍被拒，实={out[:50]!r}")

            print("场景5 超时任务进入终态（不再永久 RUNNING）")
            SEEN.update({"delay": 5.0, "calls": 0, "hosts": [], "raise": False})
            out = await runner.execute(
                "recon_ports_bg", {"top": 13, "timeout": 0.2}, sess
            )
            check("已在后台启动" in out, "超时任务先正常启动")
            await asyncio.sleep(0.5)
            slow = [t for t in sess.tasks.all() if t.meta.get("top") == 13][0]
            check(slow.status == STATUS_TIMEOUT, f"状态为 timeout，实={slow.status}")
            check("超时" in slow.error, f"错误里说明超时，实={slow.error!r}")
            check(slow.finished, "超时是终态（finished=True）")
            # sweep 兜底：进程不在了也不能永远 running
            mgr = TaskManager()
            stuck = mgr.start("x", "卡住的任务", timeout_s=1)
            stuck.started_at = time.time() - 10
            reaped = mgr.sweep()
            check(len(reaped) == 1 and mgr.get(stuck.task_id).status == STATUS_TIMEOUT,
                  "sweep 把超时任务收进终态")

            print("场景6 不同 target 的相同命令不会被错误去重")
            SEEN.update({"delay": 0.05, "calls": 0, "hosts": []})
            sess.target = "https://another.example.com"
            before = len(sess.tasks.all())
            out = await runner.execute("recon_ports_bg", {"top": 500}, sess)
            check("已在后台启动" in out, f"换目标后同参数可再次启动，实={out[:40]!r}")
            check(len(sess.tasks.all()) == before + 1, "新目标建了新任务")
            sess.target = "https://demo.example.com"
            await asyncio.sleep(0.15)

            print("场景7 不同参数不会被错误去重")
            SEEN.update({"delay": 0.05, "calls": 0, "hosts": []})
            before = len(sess.tasks.all())
            out = await runner.execute("recon_ports_bg", {"top": 800}, sess)
            check("已在后台启动" in out, "端口数不同 → 新任务")
            check(len(sess.tasks.all()) == before + 1, "参数变化没有被合并")
            await asyncio.sleep(0.15)

            print("场景8 后台事件：RUNNING 不注入、完成事件只消费一次")
            mgr = TaskManager()
            fake_session = SimpleNamespace(
                target="https://demo.example.com", tasks=mgr, result=None,
                status_line=lambda: "状态行",
            )
            agent = Agent(cfg, fake_session, FakeRunner(), TOOLS, FakeLLM([[txt("x")]]),
                          on_text=lambda s: None, on_event=lambda s: None)
            t = mgr.start("recon_ports_bg", "任务A")
            check(agent._inject_task_events() is False, "RUNNING 状态不产生注入")
            check(not any("后台任务状态变更" in str(m.get("content"))
                          for m in agent.history), "上下文里没有多余消息")
            mgr.finish(t.task_id, "结果A")
            check(agent._inject_task_events() is True, "完成事件被注入一次")
            n1 = sum(1 for m in agent.history if "后台任务状态变更" in str(m.get("content")))
            check(n1 == 1, f"注入消息恰好一条，实={n1}")
            check(agent._inject_task_events() is False, "同一事件不会被二次注入")
            n2 = sum(1 for m in agent.history if "后台任务状态变更" in str(m.get("content")))
            check(n2 == 1, f"重复调用不增加消息，实={n2}")
            t2 = mgr.start("x", "任务B")
            mgr.fail(t2.task_id, "炸了")
            check(agent._inject_task_events() is True, "新事件再次注入")
            last = str(agent.history[-1].get("content") or "")
            check("任务B" in last and "任务A" not in last, "只带新事件，不重放旧状态")
            events, cursor = mgr.events_since(0)
            check(len(events) == 2 and cursor >= 2, "事件日志按序号可增量取")
            check(mgr.events_since(cursor)[0] == [], "游标之后再取为空")

            print("场景9 Agent 跨轮重复提出相同动作 → 被识别并跳过")
            llm = ChainLLM([[txt("探测"), tc("http_probe", '{"url":"http://t/a"}', "c1")]])
            fr = FakeRunner()
            s2 = Session(target="https://demo.example.com")
            ag = Agent(cfg, s2, fr, TOOLS, llm, on_text=lambda s: None, on_event=lambda s: None)
            await ag.send("开始测一下")
            n_round1 = len(fr.calls)
            check(n_round1 >= 1, f"第一轮执行了工具，实={n_round1}")
            out2 = await ag.send("继续")
            check(len(fr.calls) == n_round1, f"第二轮同参数没有再次执行，实={len(fr.calls)}")
            check(ag.stats["dup_blocked"] >= 1, f"跳过的重复动作被计数，实={ag.stats['dup_blocked']}")
            msgs = [str(m.get("content") or "") for m in ag.history if m.get("role") == "tool"]
            check(any("未执行：重复动作" in m for m in msgs), "回灌说明是'未执行：重复动作'")
            check(any("新证据或参数差异" in m for m in msgs), "要求说明新证据或参数差异")
            check("结论" in out2, f"模型据此收口，实={out2[:30]!r}")

            print("场景10 相同错误不导致无限规划循环（代码强行收尾）")
            forever = ForeverLLM()
            fr2 = FakeRunner()
            s3 = Session(target="https://demo.example.com")
            ag2 = Agent(cfg, s3, fr2, TOOLS, forever, on_text=lambda s: None, on_event=lambda s: None)
            t0 = time.perf_counter()
            out3 = await asyncio.wait_for(ag2.send("开始"), timeout=10)
            cost = time.perf_counter() - t0
            check(cost < 5, f"没有无限循环，耗时 {cost:.2f}s")
            check(len(fr2.calls) <= 4, f"工具执行次数被收敛，实={len(fr2.calls)}")
            check("已停止重复探索" in out3, f"给出了收尾结论，实={out3[:40]!r}")
            check(forever.n <= 12, f"模型被调用的步数有界，实={forever.n}")

            print("场景11 大结果只给摘要 + artifact 引用，且不重复注入")
            s4 = Session(target="https://demo.example.com")
            mgr3 = s4.tasks
            big = "A" * 5000
            t3 = mgr3.start("recon_ports_bg", "大结果任务")
            runner._finish_task(s4, t3, big)
            done = mgr3.get(t3.task_id)
            check(done.status == STATUS_DONE, "任务完成")
            check(bool(done.artifact), f"结果落成 artifact，实={done.artifact!r}")
            check(len(done.summary) < 400, f"摘要很短，实={len(done.summary)} 字符")
            evs, _ = mgr3.events_since(0)
            check(len(evs[0].detail) < 500, "事件 detail 不含完整输出")
            check(done.artifact in evs[0].detail, "事件里给了 artifact 引用")
            detail = await runner.execute("list_tasks", {"task_id": t3.task_id}, s4)
            check(len(detail) < 3000, f"list_tasks 详情不整段回灌，实={len(detail)} 字符")
            check(done.artifact in detail, "详情里有 artifact 路径")
            q1 = await runner.execute(
                "artifact_query", {"path": done.artifact, "start_line": 1, "end_line": 5}, s4
            )
            q2 = await runner.execute(
                "artifact_query", {"path": done.artifact, "start_line": 1, "end_line": 5}, s4
            )
            check("命中缓存" not in q1 and "命中缓存" in q2, "同 artifact 同查询第二次命中缓存")
            check(len(q1) < len(big) / 2, f"查询只回请求的范围（不是整份 5000 字符），实={len(q1)} 字符")

            print("场景12 任务恢复后仍执行 Policy 与 target 校验")
            s5 = Session(target="https://demo.example.com")
            s5.tasks.start("recon_ports_bg", "跑到一半进程没了")
            snapshot = s5.to_dict()
            restored = Session.from_dict(snapshot)
            check(restored.tasks.get("bg-1").status == "interrupted",
                  "恢复时 running → interrupted，不会永远 running")
            out = await runner.execute(
                "background_run",
                {"tool": "write_file", "args": {"path": "../../.env", "content": "x"}},
                restored,
            )
            check("已在后台启动" in out, "恢复后仍正常受理后台任务")
            await asyncio.sleep(0.1)
            last = restored.tasks.all()[-1]
            check("已拒绝" in last.result, f"沙箱校验仍然生效，实={last.result[:40]!r}")
            out = await runner.execute(
                "background_run",
                {"tool": "http_request", "args": {"url": "http://10.9.9.9/x"}},
                restored,
            )
            await asyncio.sleep(0.1)
            last = restored.tasks.all()[-1]
            check("【已拦截】" in last.result,
                  f"越界目标仍被 Policy 拦截，实={last.result[:50]!r}")

            print("场景13 去重不绕过 Gateway：被拦的结果不会被复用时变成放行")
            s6 = Session(target="https://demo.example.com")
            out = await runner.execute(
                "background_run", {"tool": "http_request", "args": {"url": "http://10.9.9.9/y"}}, s6
            )
            check("已在后台启动" in out, "首次受理")
            await asyncio.sleep(0.1)
            first = s6.tasks.all()[-1]
            check("【已拦截】" in first.result, "首次执行即被 Gateway 拦截")
            out = await runner.execute(
                "background_run", {"tool": "http_request", "args": {"url": "http://10.9.9.9/y"}}, s6
            )
            check("复用已有结果" in out and "不重复执行" not in out,
                  f"同指纹第二次走结果复用，实={out[:40]!r}")
            check("已拦截" in out, "复用的结果仍然是拦截结论，不是放行")
            detail = await runner.execute("list_tasks", {"task_id": first.task_id}, s6)
            check("【已拦截】" in detail, "任务详情保留拦截原文")
            check(len(s6.tasks.all()) == 1, "去重没有新建任务")

            print("场景14 list_tasks：有界等待 + 反轮询")
            SEEN.update({"delay": 1.0, "calls": 0, "hosts": []})
            s7 = Session(target="https://demo.example.com")
            await runner.execute("recon_ports_bg", {"top": 19}, s7)
            t0 = time.perf_counter()
            out = await runner.execute("list_tasks", {"task_id": "bg-1", "wait": 0.4}, s7)
            cost = time.perf_counter() - t0
            check(cost < 1.2, f"等待有上限（请求 0.4s），实={cost:.2f}s")
            check("还在跑" in out or "运行中" in out, "等待后如实返回当前状态")
            outs = [await runner.execute("list_tasks", {}, s7) for _ in range(4)]
            check(any("停止轮询" in o for o in outs), "连续相同状态查询被反轮询闸门拒绝")
            await asyncio.sleep(1.1)

        asyncio.run(scenarios())
    finally:
        PS.PortScanner.run = orig_run

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
