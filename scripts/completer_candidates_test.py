"""命令名 / 参数补全 + 对话标题索引的回归（纯逻辑，不触终端）。

补全是**纯逻辑**（`complete` 返回值），不需要真实 TTY；
标题索引走 Session 快照往返与脱敏。

终端行为级回归（输入区不漂移 / ANSI 兜底 / 按键分发）在
`completer_terminal_test.py`；提示符拆分与折行布局在 `completer_editing_test.py`。

运行：.venv/Scripts/python.exe scripts/completer_candidates_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 补全数据与终端测试共用一份，避免两边改了不同步
from _terminal_sim import ARGS, CMDS  # noqa: E402
from core.completer import Completer, PromptReader, available  # noqa: E402
from core.session import ConversationTurn, Session  # noqa: E402


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")
    c = Completer(CMDS, ARGS)

    print("场景1 命令名补全")
    check(c.complete("/stat")[0] == "/status", "唯一前缀补全")
    new, cands, _ = c.complete("/re")
    check(sorted(cands) == ["/report", "/resume"], f"多候选返回全部，实={cands}")
    check(new == "/re", f"多候选时公共前缀为空则不改变输入，实={new!r}")
    check(c.complete("/zzz") == ("/zzz", [], 0), "无匹配时原样返回")
    check(c.complete("/help")[0] == "/help", "已完整命令幂等")
    check(len(c.complete("/")[1]) == len(CMDS), "只打斜杠列出全部命令")

    print("\n场景2 参数补全（本轮修的重点）")
    # 这里验证的就是当初写错的 bug：/report 曾被补成 /report/report
    check(c.complete("/report")[0] == "/report", "命令名后不加斜杠内容")
    new, cands, _ = c.complete("/report m")
    check(new == "/report md", f"/report m -> /report md，实={new!r}")
    check(cands == ["md"], "参数候选正确")
    check(c.complete("/assets e")[0] == "/assets endpoint", "资产类型前缀补全")
    check(c.complete("/login a")[0] == "/login admin@juice-sh.op", "邮箱前缀补全")
    check(c.complete("/title 1")[0] == "/title 1", "编号幂等")

    print("\n场景3 多候选与空格保留")
    new, cands, _ = c.complete("/report ")
    check(sorted(cands) == ["all", "html", "json", "md"], f"参数空前缀列全部，实={cands}")
    # md/all 无公共前缀 → 输入保持不变，但空格不能丢
    check(new == "/report ", f"无公共前缀时保留尾部空格，实={new!r}")
    new2, cands2, _ = c.complete("/phase ")
    check(new2 == "/phase ", f"phase 无公共前缀保留空格，实={new2!r}")
    new3, cands3, _ = c.complete("/agent ")
    check(new3 == "/agent o", f"on/off 公共前缀 o，实={new3!r}")

    print("\n场景4 空格数量（参数本身可能含空格，如邮箱不含但路径含）")
    new4, _, _ = c.complete("/login admin")
    check(new4 == "/login admin@juice-sh.op", f"含空格账号补全，实={new4!r}")

    print("\n场景5 交互层在非TTY 下优雅降级")
    # 管道输入时必须退回 input()，否则会读到 EOF 直接崩
    r = PromptReader(c)
    check(isinstance(r.enabled, bool), "enabled 是 bool")
    check(r.enabled == available(), f"enabled 与 available() 一致（{r.enabled}）")
    # 直接验证降级路径：enabled=False 时 read 走 input()
    r.enabled = False
    import builtins

    calls = []

    def fake_input(prompt=""):
        calls.append(prompt)
        return "/help"

    orig = builtins.input
    builtins.input = fake_input
    try:
        out = r.read("[agent] > ")
        check(out == "/help", "非TTY 时退回 input() 并正常返回")
        check(calls and "[agent]" in calls[0], "提示符原样传给 input")
    finally:
        builtins.input = orig

    print("\n场景6 对话标题索引落盘往返")
    tmp = Path(tempfile.mkdtemp())
    s = Session(target="http://t", session_id="ct")
    check(s.conversations == [], "新会话标题列表为空")
    c1 = s.add_conversation("信息收集与指纹识别", ["recon_fingerprint"])
    c2 = s.add_conversation("重点验证越权", ["record_finding"])
    check(c1.no == 1 and c2.no == 2, "编号自增")
    p = s.save(tmp)
    s2 = Session.load(p)
    check(len(s2.conversations) == 2, f"读回 2 条，实={len(s2.conversations)}")
    check(s2.conversations[0].title == "信息收集与指纹识别", "标题正确")
    check(s2.conversations[1].tools == ["record_finding"], "工具清单保留")

    print("\n场景7 标题脱敏（与对话历史同一套规则）")
    s3 = Session(target="http://t", session_id="ct3")
    s3.add_conversation(
        "登录成功 Authorization: Bearer SECRETVALUE123456", []
    )
    raw = s3.to_dict()
    txt = str(raw)
    check("SECRETVALUE123456" not in txt, "标题里的凭据已脱敏")

    print("\n场景8 v1 旧快照仍可加载")
    import json

    old_dir = tmp / "old"
    old_dir.mkdir()
    (old_dir / "session.json").write_text(
        json.dumps({"version": 1, "target": "http://old", "session_id": "o1",
                    "phase": "recon", "result": {}, "model": {}, "turns": []}),
        encoding="utf-8",
    )
    s4 = Session.load(old_dir)
    check(s4 is not None, "v1 快照可加载")
    check(s4 is not None and s4.conversations == [], "v1 无标题字段时为空")

    print("\n场景9 ConversationTurn 单体往返")
    ct = ConversationTurn(no=3, title="标题", at=123.0, tools=["a", "b"])
    d = ct.to_dict()
    ct2 = ConversationTurn.from_dict(d)
    check(ct2.no == 3 and ct2.title == "标题" and ct2.tools == ["a", "b"], "往返一致")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
