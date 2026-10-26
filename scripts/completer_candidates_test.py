"""命令名 / 参数补全 + 对话标题索引的回归（纯逻辑，不触终端）。

补全是**纯逻辑**（`complete` 返回值），不需要真实 TTY；
标题索引走 Session 快照往返与脱敏。

交互层的**行为级**回归（按键真的走一遍 prompt_toolkit）在
`completer_pt_test.py`——那里用 prompt_toolkit 自己的管道输入驱动真实的
``PromptSession``，验证 Tab 补全与 Ctrl+C 双语义真的成立。

运行：.venv/Scripts/python.exe scripts/completer_candidates_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 补全夹具用的一组命令名与参数候选。
# 注意：``/login`` 与 ``/fp`` 已从真实命令表下线，这里也不再用它们做样本——
# 夹具里留着一条现实里不存在的命令，测试就成了自证的假通过。
CMDS = ["/help", "/status", "/report", "/resume", "/quit", "/target",
        "/agent", "/assets", "/title", "/chats"]
ARGS = {
    "report": ["md", "html", "json", "all"],
    "assets": ["port", "path", "api", "endpoint"],
    "phase": ["recon", "model", "exploit", "iterate"],
    "agent": ["on", "off"],
    "target": ["http://a.example.com/x", "http://b.example.com/y"],
    "title": ["1", "2", "3"],
}

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
    check(c.complete("/target http://a")[0] == "/target http://a.example.com/x",
          "URL 前缀补全")
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

    print("\n场景4 空格数量（参数本身可能含空格，如 URL 路径含空格）")
    new4, _, _ = c.complete("/target http://a")
    check(new4 == "/target http://a.example.com/x", f"含空格参数补全，实={new4!r}")

    print("\n场景5 补全候选的 start_position（prompt_toolkit 接口）")
    # 命令级：/re 的 tail 长度是 3 → start_position=-3，替换 "/re" 为 "/report"
    from prompt_toolkit.document import Document

    comps = list(c.get_completions(Document("/re", 3), None))
    check(len(comps) == 2, f"/re 出两个候选，实={len(comps)}")
    check(all(x.start_position == -3 for x in comps),
          f"命令级 start_position=-3（替换 tail），实={[x.start_position for x in comps]}")
    # 参数级：/report m 的 tail 长度是 1 → start_position=-1，替换 "m" 为 "md"
    comps2 = list(c.get_completions(Document("/report m", 9), None))
    check(len(comps2) == 1 and comps2[0].text == "md",
          f"/report m 补出 md，实={[x.text for x in comps2]}")
    check(comps2[0].start_position == -1,
          f"参数级 start_position=-1，实={comps2[0].start_position}")

    print("\n场景6 交互层在非TTY 下优雅降级")
    # 管道输入时必须退回 input()，否则会读到 EOF 直接崩
    r = PromptReader(c)
    check(isinstance(r.enabled, bool), "enabled 是 bool")
    check(r.enabled == available(), f"enabled 与 available() 一致（{r.enabled}）")

    print("\n场景7 对话标题索引落盘往返")
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

    print("\n场景8 标题脱敏（与对话历史同一套规则）")
    s3 = Session(target="http://t", session_id="ct3")
    s3.add_conversation(
        "登录成功 Authorization: Bearer SECRETVALUE123456", []
    )
    raw = s3.to_dict()
    txt = str(raw)
    check("SECRETVALUE123456" not in txt, "标题里的凭据已脱敏")

    print("\n场景9 v1 旧快照仍可加载")
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

    print("\n场景10 ConversationTurn 单体往返")
    ct = ConversationTurn(no=3, title="标题", at=123.0, tools=["a", "b"])
    d = ct.to_dict()
    ct2 = ConversationTurn.from_dict(d)
    check(ct2.no == 3 and ct2.title == "标题" and ct2.tools == ["a", "b"], "往返一致")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
