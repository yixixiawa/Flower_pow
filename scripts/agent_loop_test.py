"""core.agent 主循环行为测试（不触网、不调真实模型）。

用假 LLM 驱动，覆盖：
  1. 超过旧上限（12 步）后仍能继续 —— 回归本次改动的核心目标
  2. 无进展重复调用 → 循环检测触发 → 模型收尾（而不是烧额度）
  3. 参数有差异的递进式探索 → **不得**被误判为死循环
  4. 模型不再要工具时正常结束
  5. URL 末尾斜杠差异视为同一调用（指纹规范化）
  6. 单轮无次数上限
  7. **换壳死循环**：external_tool 只换选项取值（curl -w %{...} 连打）→
     骨架检测触发。这是真事故：模型想看被截断的输出，连打十几次 -w，
     每次指纹都不同，精确重复检测拦不住。
  8. 同骨架但中间穿插其他工具 → 连击断开，**不判**死循环
  9. external_tool 换**选项集**（真换打法）→ **不判**死循环

运行：.venv/Scripts/python.exe scripts/test_agent_loop.py
"""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.agent import LOOP_REPEAT_LIMIT, LOOP_SKELETON_LIMIT, Agent  # noqa: E402


class FakeLLM:
    """按脚本逐轮返回事件序列的假模型。"""

    def __init__(self, script: list[list[dict]]):
        self.script = script
        self.i = 0
        self.seen: list[list[dict]] = []  # 每轮收到的 messages 快照

    def stream_chat(self, messages, tools=None):
        # 记录模型实际看到的最后一条消息，用于验证收尾指令是否送达
        self.seen.append([dict(m) for m in messages])
        turn = self.script[min(self.i, len(self.script) - 1)]
        self.i += 1
        for ev in turn:
            yield ev


class FakeCfg:
    class scan:
        readonly = True


class FakeSession:
    target = "http://t"

    def status_line(self):
        return "phase=1"


class FakeRunner:
    """记录执行次数，返回固定结果（模拟「结果没变化」的死循环场景）。"""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def state_text(self, session):
        return "state"

    async def execute(self, name, args, session):
        self.calls.append((name, args))
        return f"[stub] {name} -> 无变化的结果"


def tc(name, args="{}", cid=None):
    return {"type": "tool_calls", "calls": [
        {"id": cid or f"c{len(name)}", "name": name, "arguments": args}
    ]}


def txt(s):
    return {"type": "text", "text": s}


TOOLS = [
    {"function": {"name": "http_probe", "description": "d", "parameters": {}}},
    {"function": {"name": "external_tool", "description": "d", "parameters": {}}},
    {"function": {"name": "read_file", "description": "d", "parameters": {}}},
]


async def run(script, runner=None):
    runner = runner or FakeRunner()
    llm = FakeLLM(script)
    events: list[str] = []
    a = Agent(
        FakeCfg(), FakeSession(), runner, TOOLS, llm,
        on_text=lambda s: None, on_event=events.append,
    )
    out = await a.send("开始")
    return out, llm, runner, events


async def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    print("场景1 超过旧上限（12 步）后仍继续 —— 本次改动的核心回归")
    # 前 20 步每步都调工具，第 21 步给最终文本
    script = [[txt(f"分析中 {i}"), tc("http_probe", '{"url":"http://t/%d"}' % i, f"c{i}")]
              for i in range(20)]
    script.append([txt("最终结论：20 步全部完成")])
    out, llm, runner, events = await run(script)
    check(len(runner.calls) == 20, f"实际执行 20 次工具（未被 12 步截断），实={len(runner.calls)}")
    check("最终结论：20 步全部完成" in out, "返回了最终文本", f"out={out[:60]!r}")
    check(not any("已达工具调用上限" in e for e in events), "未出现旧的上限提示文案")

    print("\n场景2 无进展重复调用 → 循环检测触发 → 注入收尾指令")
    # 永远调同一个工具同一组参数；收到收尾指令后改口给结论
    class ScriptedRepeat(FakeLLM):
        def stream_chat(self, messages, tools=None):
            self.seen.append([dict(m) for m in messages])
            self.i += 1
            last = messages[-1].get("content") or ""
            if "系统提示" in str(last):
                yield txt("基于已有信息：目标无响应，无法进一步验证。")
            else:
                yield txt("再试一次")
                yield tc("http_probe", '{"url":"http://t/"}', "same")

    runner = FakeRunner()
    llm = ScriptedRepeat([])
    events: list[str] = []
    a = Agent(FakeCfg(), FakeSession(), runner, TOOLS, llm,
              on_text=lambda s: None, on_event=events.append)
    out = await a.send("开始")
    check(len(runner.calls) == LOOP_REPEAT_LIMIT,
          f"重复 {LOOP_REPEAT_LIMIT} 次后收尾，实={len(runner.calls)}")
    check(any("无进展" in e for e in events), "打印了无进展提示")
    check("无法进一步验证" in out, "模型输出了收尾结论", f"out={out[:60]!r}")
    check(len(runner.calls) < 10, "没有无限重试烧额度")

    print("\n场景3 参数有差异的递进探索 → 不得误判为死循环")
    script = [[txt(f"探测 {i}"), tc("http_probe", '{"url":"http://t/%d"}' % i, f"c{i}")]
              for i in range(15)]
    script.append([txt("15 个路径探测完毕")])
    out, llm, runner, events = await run(script)
    check(len(runner.calls) == 15, f"15 次不同参数全部执行，实={len(runner.calls)}")
    check(not any("无进展" in e for e in events), "未被误判为死循环")

    print("\n场景4 正常收尾（不调工具即结束）")
    script = [[txt("我需要先探测"), tc("http_probe", '{"url":"http://t/"}', "c0")],
              [txt("目标返回 200，未发现问题。")]]
    out, llm, runner, events = await run(script)
    check(out.strip().endswith("未发现问题。"), "返回最终文本", f"out={out[:60]!r}")
    check(len(runner.calls) == 1, "只调了1 次工具")

    print("\n场景5 URL 末尾斜杠差异视为同一调用（指纹规范化）")
    runner = FakeRunner()
    llm = ScriptedRepeat([])
    llm.stream_chat = lambda messages, tools=None: iter(())  # 先占位，下面单独测指纹
    a = Agent(FakeCfg(), FakeSession(), runner, TOOLS, llm,
              on_text=lambda s: None, on_event=lambda s: None)
    f1 = a._fingerprint("http_probe", {"url": "http://t/"})
    f2 = a._fingerprint("http_probe", {"url": "http://t"})
    f3 = a._fingerprint("http_probe", {"url": "http://t/other"})
    check(f1 == f2, f"有/无末尾斜杠指纹一致\n        {f1!r}\n        {f2!r}")
    check(f1 != f3, "不同路径指纹不同")
    check(a._fingerprint("http_probe", {"b": 1, "a": 2})
          == a._fingerprint("http_probe", {"a": 2, "b": 1}), "参数顺序不影响指纹")

    print("\n场景6 单轮无次数上限")
    check(not hasattr(__import__("core.agent", fromlist=["x"]), "HARD_STEP_CAP"),
          "HARD_STEP_CAP 常量已彻底移除")
    check("max_steps" not in inspect.signature(Agent.__init__).parameters,
          "max_steps 形参已移除（文档说没有，代码就不该留半死参数）")
    # 260 次调用（远超旧上限 200）必须能跑完
    script = [[txt(f"步骤 {i}"), tc("http_probe", '{"url":"http://t/%d"}' % i, f"c{i}")]
              for i in range(260)]
    script.append([txt("260 步全部完成")])
    out, llm, runner, events = await run(script)
    check(len(runner.calls) == 260, f"260 次调用未被截断，实={len(runner.calls)}")
    check(not any("异常兜底" in e or "已达标" in e for e in events),
          "未触发任何截断提示")

    print("\n场景7 换壳死循环：curl -w 换变量连打 → 骨架检测触发")
    # 复刻真实事故：输出被截断，模型想看剩余部分，连打 curl -w %{...}。
    # 每次参数都不同 → 精确指纹拦不住；骨架（curl + -w）相同 → 4 次现形。
    w_vars = ["%{json}", "%{stdout}", "%{http_code}", "%{stderr}",
              "%{content_type}", "%{time_total}", "%{size_header}", "%{num_headers}"]

    class ScriptedShellLoop(FakeLLM):
        def stream_chat(self, messages, tools=None):
            self.seen.append([dict(m) for m in messages])
            last = str(messages[-1].get("content") or "")
            self.i += 1
            if "系统提示" in last:
                yield txt("结论：输出被截断，剩余部分应读 tool-output 文件，不再试 -w。")
            else:
                v = w_vars[(self.i - 1) % len(w_vars)]
                yield txt(f"用 -w 输出 {v}？")
                yield tc("external_tool",
                         '{"tool":"curl","args":["-s","-w","%s","http://t/db"]}' % v,
                         f"w{self.i}")

    runner = FakeRunner()
    llm = ScriptedShellLoop([])
    events: list[str] = []
    a = Agent(FakeCfg(), FakeSession(), runner, TOOLS, llm,
              on_text=lambda s: None, on_event=events.append)
    out = await a.send("把 db 的后半部分拿出来")
    check(len(runner.calls) == LOOP_SKELETON_LIMIT,
          f"骨架相同连打 {LOOP_SKELETON_LIMIT} 次后收尾，实={len(runner.calls)}")
    check(any("排列组合" in e or "更换选项取值" in e for e in events),
          "打印了骨架级无进展提示")
    last_user = [m for m in llm.seen[-1] if m.get("role") == "user"][-1]
    check("tool-output" in last_user["content"], "收尾提示指了 read_file 的出路")
    check("不再试 -w" in out, "模型输出了收尾结论", f"out={out[:60]!r}")
    check(len(runner.calls) < len(w_vars) + 2, "没有把 -w 变量轮完一圈")

    print("\n场景8 同骨架但中间穿插其他工具 → 连击断开，不判死循环")
    # 打两次 curl → 读一下文件 → 再打两次 curl：skeleton 连击被打断
    script = []
    for i in range(3):
        script.append([tc("external_tool",
                          '{"tool":"curl","args":["-s","-w","%%{http_code}","http://t/%d"]}' % i,
                          f"a{i}")])
        script.append([tc("read_file", '{"path":"x.md"}', f"r{i}")])
    script.append([txt("探测完毕")])
    out, llm, runner, events = await run(script)
    check(not any("排列组合" in e or "更换选项取值" in e for e in events),
          "穿插其他工具时未触发骨架判定")

    print("\n场景9 external_tool 换选项集（真换打法）→ 不判死循环")
    script = [
        [tc("external_tool", '{"tool":"curl","args":["-s","-w","%{http_code}","http://t"]}', "b0")],
        [tc("external_tool", '{"tool":"curl","args":["-s","-I","http://t"]}', "b1")],
        [tc("external_tool", '{"tool":"curl","args":["-s","-b","k=v","http://t"]}', "b2")],
        [tc("external_tool", '{"tool":"nmap","args":["-sV","-p80","t"]}', "b3")],
        [tc("external_tool", '{"tool":"curl","args":["-s","-X","POST","http://t"]}', "b4")],
        [txt("多角度探测完毕")],
    ]
    out, llm, runner, events = await run(script)
    check(len(runner.calls) == 5, f"5 种不同打法全部执行，实={len(runner.calls)}")
    check(not any("排列组合" in e or "更换选项取值" in e for e in events),
          "换选项集未被误判为死循环")

    print("\n场景10 _skeleton 单元行为")
    a = Agent(FakeCfg(), FakeSession(), FakeRunner(), TOOLS, FakeLLM([]),
              on_text=lambda s: None, on_event=lambda s: None)
    s1 = a._skeleton("external_tool", {"tool": "curl", "args": ["-s", "-w", "%{json}"]})
    s2 = a._skeleton("external_tool", {"tool": "curl", "args": ["-w", "%{stdout}", "-s"]})
    check(s1 == s2, "取值与顺序不同 → 骨架相同")
    s3 = a._skeleton("external_tool", {"tool": "curl", "args": ["-s", "-o", "x"]})
    check(s1 != s3, "选项集不同 → 骨架不同")
    check(a._skeleton("http_request", {"url": "http://t", "data": "x"}) == "",
          "非 external_tool 不做骨架（防误伤换 payload 的正常渗透）")
    check(a._skeleton("external_tool", {"tool": "curl", "args": "-s"}) != "",
          "args 传成字符串（模型偶发）不崩")

    print("\n场景11 固执模型无视收尾指令、原样重调 → 硬拒绝（不再发请求）")
    # 复刻真实事故：ca.deppon.com 返回 418 + 0 字节（WAF 拦截），
    # 模型看着空响应以为"再试一次说不定就通了"，收尾指令被无视，
    # 同一个 GET 连打。警告后第 4 次必须被拒之门外。
    class StubbornRepeat(FakeLLM):
        """收尾指令后继续原样重调；被拒一次后换路径（应放行），随后给结论。"""

        def __init__(self):
            super().__init__([])
            self.switched = False

        def stream_chat(self, messages, tools=None):
            self.seen.append([dict(m) for m in messages])
            self.i += 1
            last = str(messages[-1].get("content") or "")
            if self.switched:
                yield txt("换路径也没用，最终结论：目标 WAF 拦截，证据不足。")
                return
            if "拒绝" in last and "无进展死循环" in last:
                # 刚被拒绝 → 换路径（指纹不同，必须放行）
                self.switched = True
                yield txt("换条路径试试")
                yield tc("http_probe", '{"url":"http://t/other"}', "switched")
                return
            if "系统提示" in last:
                # 收到收尾指令但无视，继续原样重调（第 4 次）
                yield txt("再试一次说不定就通了")
                yield tc("http_probe", '{"url":"http://t/"}', "stubborn")
                return
            yield txt("探测中")
            yield tc("http_probe", '{"url":"http://t/"}', "same")

    runner = FakeRunner()
    llm = StubbornRepeat()
    events: list[str] = []
    a = Agent(FakeCfg(), FakeSession(), runner, TOOLS, llm,
              on_text=lambda s: None, on_event=events.append)
    out = await a.send("测一下")
    # 执行次数 = 前 3 次原样 + 1 次换路径；第 4 次原样被拒、未执行
    executed_same = sum(1 for name, args in runner.calls if args.get("url") == "http://t/")
    check(executed_same == LOOP_REPEAT_LIMIT,
          f"同一 URL 实际只执行 {LOOP_REPEAT_LIMIT} 次，第 4 次被拒，实={executed_same}")
    check(len(runner.calls) == LOOP_REPEAT_LIMIT + 1,
          f"总执行 = 3 次原样 + 1 次换路径，实={len(runner.calls)}")
    check(any("已拒绝重复执行" in e for e in events), "终端打印了拒绝提示")
    # 拒绝说明以 tool 消息回灌（协议要求每个 tool_call 有结果）
    all_msgs = [m for snap in llm.seen for m in snap]
    refusal_msgs = [m for m in all_msgs
                    if m.get("role") == "tool" and "执行被拒绝" in str(m.get("content") or "")]
    check(len(refusal_msgs) >= 1, "拒绝说明以 tool 消息回灌给模型")
    check("换参数" in str(refusal_msgs[0].get("content") or ""),
          "拒绝说明交代了出路（换参数/换方法/给结论）")
    check("换条路径试试" in out or "other" in str(runner.calls[-1]),
          "被拒后换参数的调用被正常放行")

    print("\n场景12 拒绝只在本轮生效：新一轮用户指令可重试同一请求")
    # 用户下一轮明确要求重试是合法的（比如换了网络/代理），不能带着旧状态
    class OneShot(FakeLLM):
        def __init__(self):
            super().__init__([])

        def stream_chat(self, messages, tools=None):
            self.seen.append([dict(m) for m in messages])
            last = str(messages[-1].get("content") or "")
            if "执行被拒绝" in last:
                yield txt("第一轮结论：目标拦截。")
            elif "系统提示" in last:
                # 无视收尾指令，原样重调 → 应被硬拒绝
                yield txt("再试")
                yield tc("http_probe", '{"url":"http://t/"}', "retry")
            else:
                yield txt("探测")
                yield tc("http_probe", '{"url":"http://t/"}', "go")

    runner = FakeRunner()
    llm = OneShot()
    events: list[str] = []
    a = Agent(FakeCfg(), FakeSession(), runner, TOOLS, llm,
              on_text=lambda s: None, on_event=events.append)
    await a.send("第一轮")
    n_first = len(runner.calls)
    check(n_first == LOOP_REPEAT_LIMIT,
          f"第一轮：{LOOP_REPEAT_LIMIT} 次执行 + 第 4 次被拒（未执行），实={n_first}")
    check(bool(a._refused), "第一轮结束时拒绝集已登记该指纹")
    await a.send("换了个代理，再试一次")
    # 第二轮开头会清空拒绝集：同一请求的第一发直接执行（否则 len 不会增长）
    check(len(runner.calls) > n_first, "第二轮同一请求被正常执行（拒绝状态已清）")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
