"""空会话清理的测试。

用户的实际困扰：``/resume`` 里一串会话点进去，好几个都提示
"该会话没有对话历史……模型将从零开始"——那些都是"进来看看就退出"留下的空壳。

本测试覆盖三层防线：

1. **不再产生**：空会话不落盘（``repl._save`` 撞上 ``is_empty`` 返回 None）
2. **旧的要收**：``purge_empty_sessions`` 清掉历史遗留的空壳
3. **点名恢复要拦**：``/resume <空会话>`` 直接删掉并说明，而不是载入一个空状态

判定核心是"从严"——误删不可逆，"多留一个空壳"只是难看。所以大部分用例
都在验"有任意一项内容就必须保留"。

运行：.venv/Scripts/python.exe scripts/test_empty_session.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/：取 _cli_src

from _srcs import cli_source, module_source  # noqa: E402

from core.session import (  # noqa: E402
    Phase,
    Session,
    list_sessions,
    purge_empty_sessions,
)
from core.state import Asset  # noqa: E402


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    def fake_dir(root: Path, name: str, payload: dict) -> Path:
        """在 root 下手写一个会话目录（模拟历史遗留快照）。"""
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "session.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        return d

    # ── 场景1 判定：真正空的才算空 ────────────────────────────────
    print("场景1 is_empty —— 只有「完全没内容」才算空")
    check(Session(target="").is_empty(), "全新裸会话 = 空")
    check(not Session(target="http://x.test").is_empty(), "设了目标 ≠ 空")

    s = Session(target="")
    s.history = [{"role": "user", "content": "测一下"}]
    check(not s.is_empty(), "说过一句话 ≠ 空（历史里有 user 消息）")

    # 只有 system 消息（开场白）不算用户内容——那是模型自己说的
    s2 = Session(target="")
    s2.history = [{"role": "system", "content": "我是渗透测试操作员……"}]
    check(s2.is_empty(), "只有 system 开场白仍算空（不是用户说的）")

    s3 = Session(target="")
    s3.credentials["token"] = "abc"
    check(not s3.is_empty(), "登录过（有凭证）≠ 空——下次还得用")

    s4 = Session(target="")
    s4.result.assets.append(Asset(kind="port", value="80"))
    check(not s4.is_empty(), "拿到过资产 ≠ 空")

    s5 = Session(target="")
    s5.result.notes.append("随手记了一笔")
    check(not s5.is_empty(), "有笔记 ≠ 空")

    s6 = Session(target="")
    s6.set_phase(Phase.EXPLOIT)
    check(not s6.is_empty(), "推进过阶段 ≠ 空（说明有人在操作）")

    s7 = Session(target="")
    s7.add_conversation("聊了一轮", [])
    check(not s7.is_empty(), "有对话标题条目 ≠ 空")

    # ── 场景2 空会话不落盘（第一道防线）──────────────────────────
    print("\n场景2 空会话不写盘")
    base = Path(tempfile.mkdtemp())

    class _Rep:
        def __init__(self, sess):
            self.session = sess
            self.agent_on = False
            self.agent = None
            self.cfg = type("C", (), {"data_dir": str(base)})()

        _save = None  # 占位，下面绑定真实实现
        _sessions_dir = None  # 占位，下面绑定真实实现

    from core.repl import Repl

    rep = _Rep(Session(target=""))
    rep._save = Repl._save.__get__(rep)
    # _save 依赖 _sessions_dir（快照根目录单点定义），假对象也要绑上
    rep._sessions_dir = Repl._sessions_dir.__get__(rep)
    out = rep._save()
    check(out is None, f"空会话 _save 返回 None，实={out!r}")
    check(not any(base.iterdir()), "空会话一个目录都没留下")

    # 有内容就正常落盘
    rep2 = _Rep(Session(target="http://x.test"))
    rep2._save = Repl._save.__get__(rep2)
    rep2._sessions_dir = Repl._sessions_dir.__get__(rep2)
    p = rep2._save()
    check(p is not None and p.is_file(), f"有目标则正常落盘，实={p}")

    # ── 场景3 清扫历史遗留空壳（第二道防线）──────────────────────
    print("\n场景3 purge_empty_sessions —— 清掉磁盘上的旧空壳")
    base2 = Path(tempfile.mkdtemp())
    fake_dir(base2, "1791665980", {"version": 2, "target": "", "phase": "recon"})
    fake_dir(base2, "1791665847", {"version": 2, "target": "", "phase": "recon"})
    fake_dir(
        base2,
        "1791554001",
        {
            "version": 2,
            "target": "http://192.168.10.131:3000",
            "phase": "recon",
            "result": {"assets": [{"kind": "port", "value": "3000"}]},
        },
    )
    fake_dir(
        base2,
        "1791556497",
        {
            "version": 2,
            "target": "",
            "phase": "recon",
            "history": [{"role": "user", "content": "在吗"}],
        },
    )
    gone = sorted(purge_empty_sessions(base2))
    check(gone == ["1791665847", "1791665980"], f"只删了 2 个真空壳，实={gone}")
    check(not (base2 / "1791665980").exists(), "空壳目录确实没了")
    check((base2 / "1791554001").is_dir(), "有资产的会话没被动（误删不可逆）")
    check((base2 / "1791556497").is_dir(), "说过话的会话没被动")
    check(len(list_sessions(base2)) == 2, f"剩余 2 个可恢复，实={len(list_sessions(base2))}")

    # 幂等：再扫一遍没得删，返回空表
    check(purge_empty_sessions(base2) == [], "重复调用幂等（第二次返回空表）")

    # ── 场景4 只认带 session.json 的目录 ─────────────────────────
    print("\n场景4 不碰没有 session.json 的目录")
    base3 = Path(tempfile.mkdtemp())
    (base3 / "random_dir").mkdir()          # 同名但不是会话目录
    (base3 / "random_dir" / "note.txt").write_text("别删我")
    purge_empty_sessions(base3)
    check((base3 / "random_dir" / "note.txt").is_file(), "没有 session.json 的目录保持原样")

    # 读不出来的快照也不动——可能是手改坏了，交给用户自己看
    (base3 / "broken").mkdir()
    (base3 / "broken" / "session.json").write_text("{ 这不是 json", encoding="utf-8")
    purge_empty_sessions(base3)
    check((base3 / "broken").is_dir(), "坏快照一律不删（保守优先）")

    # ── 场景5 目录名与 session_id 不一致时按目录名删 ─────────────
    print("\n场景5 旧数字目录（名 != 内部 id 的形态）")
    base4 = Path(tempfile.mkdtemp())
    fake_dir(
        base4,
        "1789000000",
        {"version": 2, "target": "", "phase": "recon", "session_id": "完全不同的id"},
    )
    gone4 = purge_empty_sessions(base4)
    check(gone4 == ["1789000000"], f"以磁盘目录名为准删除，实={gone4}")
    check(not (base4 / "1789000000").exists(), "目录已删（没去找内部那个假 id）")

    # ── 场景6 点名恢复空会话 → 删掉并拦截 ────────────────────────
    print("\n场景6 /resume <空会话> 应删除而不是载入")
    base5 = Path(tempfile.mkdtemp())
    fake_dir(base5, "1791665980", {"version": 2, "target": "", "phase": "recon"})
    prev = Session.load(base5 / "1791665980")
    check(prev is not None and prev.is_empty(), "载入的这个确实是空的")
    check(prev.delete(base5), "delete() 返回 True")
    check(not (base5 / "1791665980").exists(), "目录已被删除")

    # delete 对不存在的目录返回 False（不抛异常）
    check(not prev.delete(base5), "重复 delete 返回 False 而不是崩")

    # 有内容的会话 delete 也没问题，但场景里我们只删空的
    keep = Session(target="http://x.test")
    keep.save(base5)
    check(keep.delete(base5), "非空会话也能主动删（/clean 之外的手工路径）")

    # ── 场景7 /clean 命令已注册 ──────────────────────────────────
    print("\n场景7 /clean 注册齐全（COMMANDS + HELP + 分发）")
    from core.repl import COMMANDS, HELP
    check("/clean" in COMMANDS, "COMMANDS 里有 /clean")
    check("/clean" in HELP, "HELP 里能查到 /clean")
    src = module_source("core.repl")
    check('"/clean", "/purge"' in src or "'/clean'" in src or '("/clean", "/purge")' in src,
          "分发分支存在（/clean 与 /purge 都能进）")
    check("def _clean_sessions" in src, "_clean_sessions 实现存在")

    # ── 场景8 恢复流程里带了清扫 ─────────────────────────────────
    print("\n场景8 恢复前自动清扫（repl 与 CLI 两条路）")
    check("purge_empty_sessions(base)" in src, "repl._resume 调了清扫")
    cli = cli_source()
    check("purge_empty_sessions" in cli, "CLI --resume / sessions 也用上了")
    check("--clean" in cli, "flower_pow sessions 有 --clean 开关")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
