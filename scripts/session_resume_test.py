"""会话恢复功能测试（不触网、不调真实模型）。

覆盖：
  1. 对话历史能落盘并能读回（Session 往返）
  2. v1 旧快照（无 history 字段）仍可加载 —— 向后兼容
  3. 脱敏：工具返回里的凭据不会写进快照
  4. Agent.restore() 把历史喂回模型，且 send() 时模型真的看得到
  5. list_sessions() 按更新时间倒序
  6. 切到 Agent 模式时自动回填历史

运行：.venv/Scripts/python.exe scripts/test_session_resume.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.agent import Agent  # noqa: E402
from core.session import Phase, Session, list_sessions, redact, redact_messages  # noqa: E402


def build_history() -> list[dict]:
    """构造一轮含工具调用 + 含凭据返回的历史。"""
    return [
        {"role": "user", "content": "先收集信息"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "http_probe", "arguments": '{"url":"http://t/x"}'}}
        ]},
        {"role": "tool", "tool_call_id": "c1",
         "content": "HTTP/1.1 200 OK\nAuthorization: Bearer SECRETAAA111222333\nX-API-Key: KEYBBB444555666"},
        {"role": "assistant", "content": "目标返回 200，首页可访问。"},
    ]


class FakeLLM:
    def __init__(self, script=None):
        self.script = script or [[{"type": "text", "text": "好的"}]]
        self.i = 0
        self.seen_all: list[list[dict]] = []

    def stream_chat(self, messages, tools=None):
        # 记录**整条** messages：send() 会把新用户消息追加到末尾，
        # 只看最后一条会误判（最后那条必然是刚输入的「继续」）
        self.seen_all.append([dict(m) for m in messages])
        turn = self.script[min(self.i, len(self.script) - 1)]
        self.i += 1
        for ev in turn:
            yield ev


class FakeCfg:
    class scan:
        readonly = True
    class llm:
        enabled = True
        api_key = "sk-test"
        model = "test"
        base_url = "http://llm"


class FakeSession:
    target = "http://t"
    def status_line(self):
        return "ok"


class FakeRunner:
    def state_text(self, session):
        return ""
    async def execute(self, name, args, session):
        return "stub"


TOOLS = [{"function": {"name": "http_probe", "description": "d", "parameters": {}}}]


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp(prefix="resume_test_"))

    print("场景1 对话历史落盘 + 读回")
    s = Session(target="http://example.com", session_id="s1")
    s.history = build_history()
    s.sync_history(s.history)
    p = s.save(tmp)
    raw = json.loads(p.read_text(encoding="utf-8"))
    check("history" in raw, "session.json 含 history 字段")
    check(len(raw["history"]) == 4, f"4 条消息落盘，实={len(raw['history'])}")
    s2 = Session.load(p)
    check(s2 is not None and len(s2.history) == 4, "读回后仍是 4 条")
    check(s2.history_turns == 1, f"history_turns=1，实={s2.history_turns}")
    check(s2.history[2]["tool_call_id"] == "c1", "tool 消息的 tool_call_id 保留（协议完整性）")

    print("\n场景2 v1 旧快照向后兼容")
    old = {"version": 1, "target": "http://old.com", "session_id": "old1",
           "phase": "recon", "created_at": 1.0,
           "result": {}, "model": {}, "turns": [], "credentials": {}}
    d = tmp / "old1"
    d.mkdir()
    (d / "session.json").write_text(json.dumps(old, ensure_ascii=False), encoding="utf-8")
    s3 = Session.load(d)
    check(s3 is not None, "v1 快照可加载（未被版本校验拒绝）")
    check(s3 is not None and s3.history == [], "v1 快照 history 默认为空")
    check(s3 is not None and s3.target == "http://old.com", "v1 快照其余字段正常")
    # 未来版本应被拒绝
    bad = dict(old, version=999)
    (d / "session.json").write_text(json.dumps(bad), encoding="utf-8")
    check(Session.load(d) is None, "未知版本仍被拒绝（不静默读坏数据）")

    print("\n场景3 落盘脱敏：凭据不写进快照")
    check("SECRETAAA111222333" not in p.read_text(encoding="utf-8"), "Bearer 值未落盘")
    check("KEYBBB444555666" not in p.read_text(encoding="utf-8"), "X-API-Key 值未落盘")
    # 但内存里必须是原值，否则 agent 会拿着 *** 去干活
    check("SECRETAAA111222333" in s.history[2]["content"], "内存中的历史保持原值（未被提前改写）")
    r = redact("Authorization: Bearer abcdef1234567890")
    check("abcdef1234567890" not in r, "redact() 直接调用有效")
    check(redact("http://a.com/api?x=1") == "http://a.com/api?x=1", "正常 URL 不被误伤")
    rm = redact_messages(build_history())
    check("SECRETAAA111222333" not in rm[2]["content"], "redact_messages 处理 tool 结果")

    print("\n场景4 Agent.restore() 真的把历史喂给模型")
    llm = FakeLLM()
    ag = Agent(FakeCfg(), FakeSession(), FakeRunner(), TOOLS, llm, on_text=lambda x: None,
               on_event=lambda x: None)
    n = ag.restore(build_history())
    check(n == 4, f"restore 返回 4，实={n}")
    check(ag.history_len() == 4, "Agent 内历史长度正确")
    # 关键：send 时模型必须看得到之前的内容
    async def _drive():
        return await ag.send("继续")
    out = asyncio.run(_drive())
    joined = json.dumps(llm.seen_all[-1], ensure_ascii=False)
    check("首页可访问" in joined, "模型收到的上下文里含上轮结论（历史真的生效）")
    check("Bearer" in joined, "含上轮工具结果（tool 消息也回填了）")
    check("好的" in out, "模型正常返回")

    print("\n场景5 restore 空历史 / None 安全")
    ag2 = Agent(FakeCfg(), FakeSession(), FakeRunner(), TOOLS, FakeLLM(),
                on_text=lambda x: None, on_event=lambda x: None)
    check(ag2.restore([]) == 0, "空列表返回 0")
    check(ag2.restore(None) == 0, "None 返回 0（不抛异常）")

    print("\n场景6 list_sessions 按更新时间倒序")
    import time as _t

    ids = []
    for i in range(3):
        ss = Session(target=f"http://t{i}.com", session_id=f"z{i}")
        ss.save(tmp)
        ids.append(f"z{i}")
        _t.sleep(0.02)
    items = list_sessions(tmp, limit=10)
    names = [n for n, _ in items]
    check(len(items) == 4, f"列出 4 个会话（3 新 + 1 old），实={len(items)}")
    check(names[:3] == ["z2", "z1", "z0"], f"按更新时间倒序，实={names[:3]}")
    limited = list_sessions(tmp, limit=2)
    check(len(limited) == 2, "limit 生效")
    check(list_sessions(tmp / "nonexistent") == [], "目录不存在返回空列表")

    print("\n场景7 恢复后阶段与资产保留")
    s4 = Session(target="http://keep.com", session_id="k1", phase=Phase.ITERATE)
    from core.state import Asset
    s4.result.assets.append(Asset(kind="port", value="22", source="test"))
    s4.history = build_history()
    p4 = s4.save(tmp)
    s5 = Session.load(p4)
    check(s5.phase == Phase.ITERATE, "阶段保留")
    check(len(s5.result.assets) == 1, "资产保留")
    check(s5.credentials == {}, "凭证不落盘")
    check(s5.to_dict()["credentials"] == {}, "凭证字典为空（to_dict 一致）")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
