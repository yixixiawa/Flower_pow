"""``sessions`` 历史列表的回归测试。

要守住的东西：**历史会话列表永远能列出来**。

以前 ``list_sessions`` 里逐条 ``Session.load``，而 ``load`` 内部
``Phase(...)`` / ``int(...)`` / ``float(...)`` 遇到坏字段直接抛异常，
一条坏快照就能让整个 ``/sessions`` / ``flower_pow sessions`` 报错退出——
用户看到的是"历史会话全都没了"，也就无从挑选要恢复哪一个。

覆盖：
  1. 坏快照只跳过自己，不影响其余会话（含：未知阶段、JSON 截断、非字典）
  2. ``updated_at`` 快照往返（列表显示的时间必须是"最后更新"）
  3. 老快照没写 ``updated_at`` → 用文件 mtime 兜底
  4. ``limit=None`` 全量 / ``limit=N`` 截断；``latest_session`` 跳过坏的最新一条
  5. ``/sessions`` 带编号与标题，``/resume #N`` 按编号选中
  6. 裸命令 ``sessions`` 也能命中（不会被当成自然语言喂给模型）
  7. MCP ``sessions`` 服务返回标题/阶段/可读时间/对话轮数
  8. 相对 ``data_dir`` 按配置文件所在目录解析（与 CWD 无关）

运行：.venv/Scripts/python.exe scripts/session_list_test.py
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.repl import Repl  # noqa: E402
from core.session import Phase, Session  # noqa: E402
from core.session.store import latest_session, list_sessions  # noqa: E402

OK = 0
FAIL = 0


def check(cond: bool, msg: str) -> None:
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  ok   {msg}")
    else:
        FAIL += 1
        print(f"  FAIL {msg}")


def make(base: Path, name: str, *, target: str = "http://a.test",
         title: str = "", history: int = 0, age: float = 0.0,
         raw: dict | None = None) -> Path:
    """手写一份快照目录（不走 Session.save，便于造坏数据）。"""
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    data = raw if raw is not None else {
        "version": 2,
        "target": target,
        "session_id": name,
        "phase": "recon",
        "created_at": time.time() - 3600,
        "updated_at": time.time() - age,
        "result": {"target": target, "assets": [], "findings": []},
        "model": {},
        "turns": [],
        "credentials": {},
        "history": [{"role": "user", "content": f"q{i}"} for i in range(history)],
        "conversations": ([{"no": 1, "title": title, "at": time.time(), "tools": []}]
                          if title else []),
    }
    f = d / "session.json"
    f.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    # 让 mtime 有确定的先后顺序
    ts = time.time() - age
    os.utime(f, (ts, ts))
    return d


class FakeCfg:
    """最小配置——``/sessions`` 只用到 ``data_dir``。"""

    class llm:
        enabled = False
        api_key = ""
        model = "test"
        base_url = "http://llm"

    class scan:
        evidence_dir = ""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.output_dir = data_dir


def scenario_broken_snapshots(tmp: Path) -> None:
    print("\n场景1 坏快照只跳过自己")
    base = tmp / "s1"
    make(base, "20260101_正常甲", target="http://a.test", age=10)
    make(base, "20260102_正常乙", target="http://b.test", age=20)
    # 未知阶段：字段级容错应把它读成 RECON 而不是抛异常
    make(base, "20260103_阶段未知", raw={
        "version": 2, "target": "http://c.test", "phase": "recon_v0",
        "created_at": time.time(), "result": {},
    })
    # JSON 截断（写到一半被杀）
    bad = base / "20260104_截断"
    bad.mkdir(parents=True)
    (bad / "session.json").write_text('{"version": 2, "target": "htt', encoding="utf-8")
    # session.json 不是字典
    (base / "20260105_列表").mkdir(parents=True)
    (base / "20260105_列表" / "session.json").write_text("[1,2,3]", encoding="utf-8")

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        items = list_sessions(base, limit=None)
    names = [n for n, _s in items]
    check(len(items) == 3, f"3 条可读（阶段未知也容错读出来），实={len(items)} {names}")
    check("20260103_阶段未知" in names, "未知阶段按 RECON 兜底，仍然列出")
    unknown = dict(items).get("20260103_阶段未知")
    check(unknown is not None and unknown.phase is Phase.RECON,
          "未知阶段退回 Phase.RECON")
    check("20260104_截断" not in names and "20260105_列表" not in names,
          "读不出来的两条被跳过")
    check("跳过 2 个" in err.getvalue(), f"stderr 有一行汇总提示，实={err.getvalue()!r}")


def scenario_updated_at(tmp: Path) -> None:
    print("\n场景2 updated_at 往返 / 老快照兜底")
    base = tmp / "s2"
    s = Session(target="http://a.test")
    s.add_conversation("第一轮标题")
    f = s.save(base)
    check(f.is_file(), "快照落盘")
    loaded = Session.load(f)
    check(loaded is not None, "快照能读回")
    assert loaded is not None
    check(abs(loaded.updated_at - s.updated_at) < 0.01,
          f"updated_at 跟着快照回来，实={loaded.updated_at} vs {s.updated_at}")

    # 老快照（没有 updated_at 字段）→ 用文件 mtime
    old = make(base, "20260101_老快照", raw={
        "version": 1, "target": "http://old.test", "phase": "recon",
        "created_at": 1700000000, "result": {},
    })
    mtime = time.time() - 5000
    os.utime(old / "session.json", (mtime, mtime))
    got = Session.load(old)
    check(got is not None and abs(got.updated_at - mtime) < 2,
          f"缺 updated_at 时用 mtime 兜底，实={getattr(got, 'updated_at', None)}")


def scenario_limit_and_latest(tmp: Path) -> None:
    print("\n场景3 全量 / 截断 / latest 跳过坏快照")
    base = tmp / "s3"
    make(base, "20260101_甲", age=30)
    make(base, "20260102_乙", age=20)
    make(base, "20260103_丙", age=10)
    check(len(list_sessions(base, limit=None)) == 3, "limit=None 返回全部")
    check(len(list_sessions(base, limit=2)) == 2, "limit=2 截断到 2 条")
    check(list_sessions(base, limit=None)[0][0] == "20260103_丙",
          "按 mtime 倒序（最近的在前）")

    # 最新那条坏了，latest_session 要往前找，而不是说"没有会话"
    newest = base / "20260104_坏"
    newest.mkdir()
    (newest / "session.json").write_text("{oops", encoding="utf-8")
    os.utime(newest / "session.json", (time.time(), time.time()))
    with contextlib.redirect_stderr(io.StringIO()):
        got = latest_session(base)
    check(got is not None and got.session_id == "20260103_丙",
          f"latest_session 跳过坏的最新一条，实={getattr(got, 'session_id', None)}")


def scenario_repl_listing(tmp: Path) -> None:
    print("\n场景4 /sessions 编号与 /resume #N")
    base = tmp / "s4"
    make(base, "20260101_甲", target="http://a.test", title="甲任务", age=30, history=4)
    make(base, "20260102_乙", target="http://b.test", title="乙任务", age=20, history=8)
    cfg = FakeCfg(str(tmp / "s4root"))
    (tmp / "s4root").mkdir(exist_ok=True)
    import shutil

    shutil.copytree(base, tmp / "s4root" / "sessions")

    repl = Repl(cfg, Session(target="http://cur.test"), agent=False, probes=[])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        repl._sessions("")
    out = buf.getvalue()
    check("#1" in out and "#2" in out, f"列表带序号，实={out[:120]!r}")
    check("乙任务" in out or "20260102_乙" in out, "显示会话名/标题")
    check("2026-01-02" not in out or ":" in out, "显示可读更新时间")
    check("资产" in out and "发现" in out and "对话" in out, "显示资产/发现/对话条数")

    # 全量 vs 只看 1 条
    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        repl._sessions("1")
    out2 = buf2.getvalue()
    check("#2" not in out2, "「/sessions 1」只列最近 1 条")
    check("还有 1 个" in out2, "提示还有更早的会话")

    # 按编号恢复
    with contextlib.redirect_stdout(io.StringIO()):
        repl._resume("#2")
    check(repl.session.session_id == "20260101_甲",
          f"/resume #2 命中第二条，实={repl.session.session_id}")

    # 唯一片段也能命中
    with contextlib.redirect_stdout(io.StringIO()):
        repl._resume("乙")
    check(repl.session.session_id == "20260102_乙",
          f"/resume <片段> 命中唯一会话，实={repl.session.session_id}")

    # 裸命令 sessions 能被分发
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        asyncio.run(repl._handle("sessions"))
    check("可恢复会话" in buf3.getvalue(), "裸命令 sessions 直接列出会话（不喂给模型）")


def scenario_mcp_payload(tmp: Path) -> None:
    print("\n场景5 MCP sessions 服务的可读字段")
    from types import SimpleNamespace

    from mcp_server import services

    base = tmp / "s5" / "sessions"
    make(base, "20260101_甲", target="http://a.test", title="甲任务", age=10, history=6)
    cfg = SimpleNamespace(data_dir=str(tmp / "s5"))
    data = services.sessions(cfg, limit=0)  # type: ignore[arg-type]
    check("error" not in data, f"没有报错，实={data}")
    items = data.get("items") or []
    check(len(items) == 1, f"limit=0 返回全部，实={len(items)}")
    if items:
        it = items[0]
        check(it.get("title") == "甲任务", f"带标题，实={it.get('title')!r}")
        check(it.get("phase") == "recon", f"带阶段，实={it.get('phase')!r}")
        check(bool(it.get("updated_at_text")), f"带可读时间，实={it.get('updated_at_text')!r}")
        check(it.get("history_turns") == 6, f"带对话轮数，实={it.get('history_turns')}")
        check("total" in data and data["total"] == 1, "返回 total 便于判断是否被截断")


def scenario_relative_data_dir(tmp: Path) -> None:
    print("\n场景6 相对 data_dir 跟配置文件走")
    from core.config_loader import load_config

    proj = tmp / "proj"
    proj.mkdir()
    (proj / "config.yaml").write_text(
        "output_dir: ./output\ndata_dir: ./data\n", encoding="utf-8"
    )
    other = tmp / "elsewhere"
    other.mkdir()
    old = Path.cwd()
    try:
        os.chdir(other)
        cfg = load_config(str(proj / "config.yaml"))
    finally:
        os.chdir(old)
    check(Path(cfg.data_dir) == (proj / "data").resolve(),
          f"data_dir 指向配置文件同级目录，实={cfg.data_dir}")
    check(Path(cfg.output_dir) == (proj / "output").resolve(),
          f"output_dir 同理，实={cfg.output_dir}")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        scenario_broken_snapshots(tmp)
        scenario_updated_at(tmp)
        scenario_limit_and_latest(tmp)
        scenario_repl_listing(tmp)
        scenario_mcp_payload(tmp)
        scenario_relative_data_dir(tmp)
    total = OK + FAIL
    print(f"\n{OK}/{total} 通过")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
