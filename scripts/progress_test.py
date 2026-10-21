"""轮次穷尽判定与自动轮询的回归测试。

复现的真实问题：会话里每轮之间要**手工回车**才继续。跑一个站点十几轮，
人得一直守着敲回车；而"什么时候算测完"也只能靠人自己看。

改法：`/poll [轮数]`（会话内）与 `--poll`（非交互）自动连续跑轮，
**穷尽了才停**。判据是连续 2 轮无推进（无新资产、无新发现、无下一步建议）。

覆盖：
  1. RoundOutcome 的"有推进 / 空转"语义
  2. 穷尽判定：单轮空转不停、连续两轮才停、中间有产出就清零
  3. 有下一步建议 → 不算空转（说明还有得测）
  4. **到上限 ≠ 已穷尽**（措辞必须分开，否则用户以为测完了）
  5. 穷尽优先于上限；0 = 不限；idle_limit=0 = 关掉穷尽判定
  6. poll_until_done 驱动：轮次计数、history、回调、存盘次数
  7. KeyboardInterrupt 必须穿透（不能被驱动层吞掉）
  8. /poll 与 --poll 的接线（命令表 / help / 补全 / CLI / 配置项）
  9. 功能：Repl._poll 真跑——剧本模式与 Agent 模式各一遍

运行：.venv/Scripts/python.exe scripts/test_progress.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _srcs import cli_source, module_source  # noqa: E402

from core.progress import (  # noqa: E402
    DEFAULT_MAX_ROUNDS,
    IDLE_LIMIT,
    STOP_CAPPED,
    STOP_EXHAUSTED,
    Exhaustion,
    RoundOutcome,
    poll_until_done,
)
from core.session import Session  # noqa: E402
from core.state import Asset  # noqa: E402


class FakeTurn:
    def __init__(self, suggestions=None):
        self.suggestions = list(suggestions or [])


class Cfg:
    def __init__(self, tmp: Path, max_rounds: int = 12):
        self.output_dir = str(tmp)
        self.data_dir = str(tmp)
        self.max_rounds = max_rounds

    class llm:
        enabled = False
        api_key = ""
        model = "x"
        base_url = "http://x"
        deep_model = ""
        model_warnings: list = []

    class rag:
        poc_dir = "./poc"

    @property
    def scan(self):
        outer = self

        class _S:
            readonly = True
            timeout = 5
            concurrency = 2
            auto_max_rounds = outer.max_rounds

        return _S()


def add_asset(sess, n=1):
    for i in range(n):
        sess.result.assets.append(
            Asset(kind="path", value=f"/p{len(sess.result.assets)}")
        )


async def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    print("场景1 一轮算不算「有推进」")
    check(RoundOutcome(no=1, new_assets=2).produced, "有新资产 → 有推进")
    check(RoundOutcome(no=1, new_findings=1).produced, "有新发现 → 有推进")
    check(RoundOutcome(no=1, new_model=1).produced,
          "建模阶段建出条目也算推进（它的产出既不是资产也不是发现）")
    check(not RoundOutcome(no=1).produced, "什么都没有 → 没推进")
    check(RoundOutcome(no=1).idle, "什么都没新增 → 空转")
    # 这一条是实测纠正的：Planner._suggest() 是**阶段驱动**的兜底文本，
    # 迭代阶段恒为"继续迭代或导出报告"，**每轮都非空**。最初把"无建议"
    # 也算作空转条件，结果穷尽永远判不出来、只会跑到上限。
    check(RoundOutcome(no=1, suggestions=["继续迭代或导出报告（/report）"]).idle,
          "**有建议但零新增仍然算空转**（建议是旁白，不是硬状态）")
    check(not RoundOutcome(no=1, new_assets=1, suggestions=["a"]).idle,
          "有产出就不空转")
    line = RoundOutcome(no=3, new_assets=1, new_findings=2, elapsed=1.25).line()
    check("第 3 轮" in line and "+1 资产" in line and "+2 发现" in line,
          f"进度行信息齐全，实={line!r}")
    check("无推进" in RoundOutcome(no=3).line(), "空转那轮明确标出来")
    check("建模项" in RoundOutcome(no=3, new_model=2).line(), "有建模项时也显示")

    print("\n场景2 穷尽判定：连续 N 轮空转")
    ex = Exhaustion()
    check(IDLE_LIMIT == 2, f"默认连击阈值 {IDLE_LIMIT}（单轮可能是'在整理'）")
    check(ex.observe(RoundOutcome(no=1)) == "", "第 1 轮空转**不停**")
    check(ex.idle_streak == 1, "记下 1 次空转")
    check(ex.observe(RoundOutcome(no=2)) == STOP_EXHAUSTED, "连续第 2 轮空转 → 停")
    check(ex.stop_round == 2, "记录停在第 2 轮")
    check(ex.stop_kind == STOP_EXHAUSTED, "停因是穷尽")

    ex2 = Exhaustion()
    ex2.observe(RoundOutcome(no=1))
    ex2.observe(RoundOutcome(no=2, new_assets=3))       # 又挖到东西了
    check(ex2.idle_streak == 0, "中间产出过一轮 → 连击清零（不算'连续'空转）")
    check(ex2.observe(RoundOutcome(no=3)) == "", "清零后要重新数两轮")
    check(ex2.observe(RoundOutcome(no=4)) == STOP_EXHAUSTED, "再连续两轮才停")

    ex3 = Exhaustion()
    ex3.observe(RoundOutcome(no=1, new_model=1))
    check(ex3.idle_streak == 0, "建模有产出 → 不累积空转")
    ex3.observe(RoundOutcome(no=2, suggestions=["继续迭代或导出报告"]))
    ex3.observe(RoundOutcome(no=3, suggestions=["继续迭代或导出报告"]))
    check(ex3.stop_kind == STOP_EXHAUSTED, "只有建议、始终零新增 → 照样判穷尽")

    print("\n场景3 到上限 ≠ 已穷尽（措辞必须分开）")
    ex4 = Exhaustion(max_rounds=3)
    check(ex4.observe(RoundOutcome(no=1, new_assets=5)) == "", "第 1 轮有产出，继续")
    check(ex4.observe(RoundOutcome(no=2, new_assets=5)) == "", "第 2 轮有产出，继续")
    kind = ex4.observe(RoundOutcome(no=3, new_assets=5))
    check(kind == STOP_CAPPED, f"每轮都有产出也会到上限，实={kind}")
    v = ex4.verdict()
    check("上限" in v and "不是测完了" in v, f"到上限要说清'不是测完了'，实={v!r}")
    check("已穷尽" not in v, "到上限**不能**说成已穷尽")
    check("auto_max_rounds" in v, "告诉用户去哪儿调上限")

    ex5 = Exhaustion(max_rounds=2)
    ex5.observe(RoundOutcome(no=1))
    kind = ex5.observe(RoundOutcome(no=2))
    check(kind == STOP_EXHAUSTED, "同一轮同时命中时，**穷尽优先于上限**")
    check("已穷尽" in ex5.verdict(), f"穷尽措辞，实={ex5.verdict()!r}")

    print("\n场景4 0 = 不限 / 关闭穷尽判定")
    ex6 = Exhaustion(max_rounds=0)
    for i in range(1, 30):
        check_stop = ex6.observe(RoundOutcome(no=i, new_assets=1))
        if check_stop:
            break
    check(ex6.stop_kind == "", "上限 0 = 不限轮数（有产出就一直在跑）")
    ex7 = Exhaustion(idle_limit=0)
    stopped = [ex7.observe(RoundOutcome(no=i)) for i in range(1, 5)]
    check(all(s == "" for s in stopped), "idle_limit=0 → 关掉穷尽判定（只受上限约束）")

    print("\n场景5 poll_until_done 驱动")
    script = [
        RoundOutcome(no=1, new_assets=3, elapsed=0.1),
        RoundOutcome(no=2, new_findings=1, elapsed=0.1),
        RoundOutcome(no=3, elapsed=0.1),
        RoundOutcome(no=4, elapsed=0.1),
    ]
    seen: list[int] = []
    rounds: list[RoundOutcome] = []
    saves = []

    async def run_round(no: int) -> RoundOutcome:
        seen.append(no)
        return script[no - 1]

    ex8 = Exhaustion()
    kind, history = await poll_until_done(
        run_round, ex=ex8,
        on_round=rounds.append,
        checkpoint=lambda: saves.append(1),
    )
    check(kind == STOP_EXHAUSTED, f"驱动层返回穷尽，实={kind}")
    check(seen == [1, 2, 3, 4], f"逐轮调用且轮次号连续，实={seen}")
    check(len(history) == 4, f"history 记录了每一轮，实={len(history)}")
    check(len(rounds) == 4 and len(saves) == 4, "每轮回调进度与存盘各一次")
    check(history[0] is script[0], "history 里是原对象（不复制，便于追查）")

    async def boom(no: int) -> RoundOutcome:
        raise KeyboardInterrupt

    try:
        await poll_until_done(boom, ex=Exhaustion())
        check(False, "KeyboardInterrupt 必须穿透")
    except KeyboardInterrupt:
        check(True, "KeyboardInterrupt 不被驱动层吞掉（Ctrl-C 要立刻生效）")

    async def capped(no: int) -> RoundOutcome:
        return RoundOutcome(no=no, new_assets=1)

    kind2, hist2 = await poll_until_done(capped, ex=Exhaustion(max_rounds=3))
    check(kind2 == STOP_CAPPED and len(hist2) == 3,
          f"每轮都有产出时靠上限收住，实={kind2}/{len(hist2)}")
    check(DEFAULT_MAX_ROUNDS == 12, f"默认上限 {DEFAULT_MAX_ROUNDS}")

    print("\n场景6 /poll 与 --poll 接线")
    from core.repl import COMMANDS, HELP, Repl

    check("/poll" in COMMANDS, "/poll 在补全候选里")
    check("/poll" in HELP, "/poll 在 /help 文本里")
    check("穷尽" in HELP, "/help 写明了停止条件")
    repl_src = module_source("core.repl")
    check("poll_until_done" in repl_src, "REPL 用的是共享驱动（不是自己写循环）")
    cli_src = cli_source()
    check('"--poll"' in cli_src, "CLI 有 --poll")
    check("poll_until_done" in cli_src, "CLI 也用同一个驱动")
    check("_poll_rounds" in cli_src and "_auto_rounds" in cli_src,
          "固定轮数与跑到穷尽是两个驱动（--auto N 行为不变）")
    from core.config_loader import ScanConfig

    check(getattr(ScanConfig(), "auto_max_rounds", None) == 12, "配置项存在且默认 12")

    print("\n场景7 Repl._poll 真跑（剧本模式）")
    tmp = Path(tempfile.mkdtemp())
    repl = Repl(Cfg(tmp), Session(target="http://t.test"), agent=False, probes=[])
    plan = [FakeTurn() for _ in range(5)]      # 第 5 个不该被用到
    calls = []

    async def fake_advance():
        calls.append(len(calls) + 1)
        # 前两轮各挖到点东西，第 3 轮起什么都没有 → 连击到 2 就停
        if len(calls) <= 2:
            add_asset(repl.session, 2)
        return plan[len(calls) - 1]

    repl._advance_and_run = fake_advance
    await repl._poll("")
    check(len(calls) == 4, f"第 4 轮判定穷尽后停止，实跑了 {len(calls)} 轮")
    check(len(repl.session.result.assets) == 4, "资产累加正确")
    check(len(plan) == 5, "第 5 轮没被执行")

    print("\n场景8 Repl._poll 到上限（措辞不能混）")
    tmp2 = Path(tempfile.mkdtemp())
    repl2 = Repl(Cfg(tmp2, max_rounds=2), Session(target="http://t.test"),
                 agent=False, probes=[])
    n2 = []

    async def always_productive():
        n2.append(1)
        add_asset(repl2.session, 1)
        return FakeTurn()

    repl2._advance_and_run = always_productive
    await repl2._poll("")
    check(len(n2) == 2, f"到上限 2 轮就停（即使每轮都有产出），实={len(n2)}")
    # 用 /poll 3 覆盖配置上限
    n3 = []

    async def productive3():
        n3.append(1)
        add_asset(repl2.session, 1)
        return FakeTurn()

    repl2._advance_and_run = productive3
    await repl2._poll("/poll 3")
    check(len(n3) == 3, f"/poll 3 覆盖配置里的上限，实={len(n3)}")
    await repl2._poll("/poll abc")
    check(True, "轮数不是整数时安全返回（不崩）")
    repl2.session.target = ""
    await repl2._poll("")
    check(True, "没有目标时安全返回")

    print("\n场景9 Repl._poll 真跑（Agent 模式分支）")
    tmp3 = Path(tempfile.mkdtemp())
    # 这里只测 `_poll` 的 **Agent 分支**。`agent_on` 是只读属性（= agent is not
    # None），所以放个只有 `history` 的占位对象把它点亮——不真的建 Agent
    # （那要走 LLMClient，与本用例无关，还会让测试依赖配置）。
    # `history` 必须有：`_save()` 每轮都会 `session.sync_history(agent.history)`。
    class AgentStub:
        history: list = []

    repl3 = Repl(Cfg(tmp3), Session(target="http://t.test"), agent=False, probes=[])
    repl3.agent = AgentStub()
    check(repl3.agent_on, "占位对象已把 agent_on 点亮（用例前提）")
    agent_rounds = []

    async def fake_agent(text):
        agent_rounds.append(text)
        if len(agent_rounds) == 1:
            add_asset(repl3.session, 1)      # 第一轮有产出
        return ""

    repl3._run_agent = fake_agent
    await repl3._poll("")
    # 第 1 轮有产出 → 第 2、3 轮空转 → 第 3 轮判定穷尽
    check(len(agent_rounds) == 3, f"Agent 分支同样跑到穷尽，实={len(agent_rounds)} 轮")
    check(all("继续" in t for t in agent_rounds), "自动轮询的提示语一致")
    check(repl3.session.result.assets, "Agent 分支的产出被记进会话")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
