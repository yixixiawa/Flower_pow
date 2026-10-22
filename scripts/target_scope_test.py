"""``/reset`` 与 ``/target`` 目标作用域的回归测试。

要守住的两条语义：

1. **``/reset`` 是"砸了换把新的"**——不管当前处于什么状态，一律丢弃旧
   ``Session``、换一把全新的空会话、删掉盘上快照。它不是"清对话历史、
   保留资产与发现"那种半吊子。
2. **换目标 = 换被测对象**——``/target`` 设成**与当前不同**的目标时，
   上一目标的资产/发现/指纹/凭证/对话历史/runner 运行期缓存必须一起清空。
   留着就会串线：上一个目标的资产进下一个目标的报告，上一个目标的
   HTTP 响应被贴成新目标的 PoC。

另外守住一条**不能过度**的边界：同形态不同主机（子域名、多主机业务）
不能被拦，同目标重复设定也不能毁掉进度。

运行：.venv/Scripts/python.exe scripts/target_scope_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.repl import COMMANDS, HELP  # noqa: E402
from core.repl import Repl  # noqa: E402
from core.session import Phase, Session, Turn  # noqa: E402
from core.state import Asset, Fingerprint  # noqa: E402


class FakeCfg:
    """最小配置——只提供 ``/reset`` 与 ``/target`` 会碰到的字段。"""

    class llm:
        enabled = False
        api_key = ""
        model = "test"
        base_url = "http://llm"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.output_dir = data_dir


class FakeAgent:
    """最小 Agent 替身——只验证"被 reset 了"和"session 引用换了"。"""

    def __init__(self, session):
        self.session = session
        self.reset_calls = 0
        self.history_len = 3

    def reset(self):
        self.reset_calls += 1
        self.history_len = 0


class FakeRunner:
    """最小 runner 替身——记录 ``reset_target_scope`` 被调了几次。"""

    def __init__(self):
        self.reset_calls = 0

    def reset_target_scope(self):
        self.reset_calls += 1


def make_repl(tmp: Path, session: Session) -> Repl:
    """造一个不触网、不调模型的 Repl（agent=False 走剧本模式构造）。"""
    repl = Repl.__new__(Repl)
    repl.cfg = FakeCfg(str(tmp))
    repl.session = session
    repl._planner = None
    repl.kickoff = False
    repl.runner = None
    repl.agent = None
    repl.llm = None
    repl.tools = []
    repl.probes = []
    repl.reader = None
    return repl


def fill_session(s: Session) -> None:
    """给会话塞满"与目标绑定"的数据——每一项都该在切换时被清掉。"""
    s.result.assets.append(Asset(kind="port", value="80"))
    from core.state import Category, Evidence, Finding, Severity

    s.result.findings.append(
        Finding(
            poc_id="x1",
            name="旧目标的漏洞",
            severity=Severity.HIGH,
            category=Category.CONTENT_MATCH,
            matched_at="http://old.test/x",
            evidence=Evidence(url="http://old.test/x", poc_id="x1"),
        )
    )
    s.result.fingerprints.append(Fingerprint(target="old.test", server="nginx"))
    s.result.notes.append("旧目标的备注")
    s.result.errors.append("旧目标的错误")
    s.credentials["token"] = "old-token"
    s.turns.append(Turn(no=1, phase=Phase.RECON, actions=["x"],
                        new_assets=1, new_findings=1, elapsed=1.0))
    s.model.resources.append("旧目标的接口")


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp(prefix="target_scope_"))

    print("场景1 命令注册与帮助文本")
    check("/reset" in COMMANDS, "/reset 在命令表里")
    check("/target" in COMMANDS, "/target 在命令表里")
    check("/fp" not in COMMANDS, "/fp 已下线")
    check("/login" not in COMMANDS, "/login 已下线")
    check("彻底重置" in HELP, "HELP 说明了 /reset 的彻底语义")
    check("清空" in HELP, "HELP 说明了 /target 切换会清空")

    print("\n场景2 /target 换目标 → 全清")
    s = Session(target="http://old.test")
    fill_session(s)
    repl = make_repl(tmp, s)
    repl.agent = FakeAgent(s)
    repl.runner = FakeRunner()

    repl._set_target("http://new.test")
    check(repl.session.target == "http://new.test", "目标已换成新目标")
    check(len(repl.session.result.assets) == 0, "资产清空")
    check(len(repl.session.result.findings) == 0, "发现清空")
    check(len(repl.session.result.fingerprints) == 0, "指纹清空")
    check(len(repl.session.result.notes) == 0, "备注清空")
    check(len(repl.session.result.errors) == 0, "错误日志清空")
    check(repl.session.credentials == {}, "凭证清空")
    check(len(repl.session.turns) == 0, "轮次记录清空")
    check(len(repl.session.model.resources) == 0, "业务模型清空")
    check(repl.agent.reset_calls == 1, "Agent 对话历史被 reset")
    check(repl.runner.reset_calls == 1, "runner 运行期缓存被清")
    check(repl.session.result.target == "http://new.test", "result.target 也指向新目标")

    print("\n场景3 /target 同一目标 → 不动")
    s2 = Session(target="http://same.test")
    fill_session(s2)
    repl2 = make_repl(tmp, s2)
    repl2.agent = FakeAgent(s2)
    repl2.runner = FakeRunner()
    repl2._set_target("http://same.test")
    check(len(repl2.session.result.assets) == 1, "同目标重复设定不毁进度")
    check(repl2.agent.reset_calls == 0, "同目标不 reset Agent")
    check(repl2.runner.reset_calls == 0, "同目标不清 runner 缓存")

    print("\n场景4 目标规范化（补 scheme / 去尾斜杠）")
    s3 = Session(target="")
    repl3 = make_repl(tmp, s3)
    repl3._set_target("example.com")
    check(repl3.session.target == "http://example.com", "补上 http://")
    s4 = Session(target="")
    repl4 = make_repl(tmp, s4)
    repl4._set_target("http://example.com/")
    check(repl4.session.target == "http://example.com", "去掉尾斜杠")

    print("\n场景5 /reset → 全新空会话 + 删盘上快照")
    sessions_dir = tmp / "sessions"
    s5 = Session(target="http://old.test", session_id="oldone")
    fill_session(s5)
    p5 = s5.save(sessions_dir)
    check(p5 is not None and p5.exists(), "旧会话已落盘")
    repl5 = make_repl(tmp, s5)
    repl5.agent = FakeAgent(s5)
    repl5.runner = FakeRunner()
    old_agent = repl5.agent

    repl5._reset()
    check(repl5.session is not s5, "换成了新的 Session 对象")
    check(repl5.session.target == "", "新会话没有目标")
    check(repl5.session.phase == Phase.RECON, "新会话回到 RECON 阶段")
    check(len(repl5.session.result.assets) == 0, "新会话无资产")
    check(len(repl5.session.result.findings) == 0, "新会话无发现")
    check(repl5.session.credentials == {}, "新会话无凭证")
    check(repl5.agent is old_agent, "Agent 对象本身没换（只换它持有的 session）")
    check(repl5.agent.session is repl5.session, "agent.session 指向新 Session")
    check(repl5.agent.reset_calls == 1, "Agent 被 reset（对话历史清空）")
    check(repl5.runner.reset_calls == 1, "runner 运行期缓存被清")
    check(repl5._planner is None, "规划器被清掉（它持有旧 session 引用）")
    check(not p5.parent.exists(), "盘上旧会话快照已删除")

    print("\n场景6 /reset 在没有盘上快照时也不报错")
    s6 = Session(target="http://x.test", session_id="nosnap")
    repl6 = make_repl(tmp, s6)
    repl6.agent = FakeAgent(s6)
    repl6.runner = FakeRunner()
    repl6._reset()
    check(repl6.session.target == "", "照样换成空会话")

    print("\n场景7 /reset 在无 Agent（剧本模式）下也不报错")
    s7 = Session(target="http://x.test")
    repl7 = make_repl(tmp, s7)
    repl7.agent = None
    repl7.runner = None
    repl7._reset()
    check(repl7.session.target == "", "剧本模式下也能重置")

    print("\n场景8 /target 切换时删掉旧目标的盘上快照吗")
    # 不删：/target 只清内存，换目标后仍可 /resume 回旧会话看历史
    # （这是有意为之——删掉的是"数据"，不是"存档"）
    s8 = Session(target="http://old.test", session_id="keepme")
    fill_session(s8)
    p8 = s8.save(sessions_dir)
    repl8 = make_repl(tmp, s8)
    repl8.agent = FakeAgent(s8)
    repl8.runner = FakeRunner()
    repl8._set_target("http://new.test")
    check(p8 is not None and p8.parent.exists(), "换目标不删旧快照（还能 /resume 回去）")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
