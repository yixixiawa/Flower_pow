# -*- coding: utf-8 -*-
"""MCP 客户端接入（``flower_pow mcp install``）回归测试。

覆盖：
  1. **指纹固定向量**——两个被 WorkBuddy 真实接受过的条目，哈希必须一字节不差。
     这是本模块唯一不能漂的东西：算错就等于"配了但静默不加载"。
  2. 指纹语义：args 排序无关、env 只取键名、值不参与
  3. install：空目录新建 / 幂等不重写 / 保留别人的 server / 换解释器标 updated + 备份
  4. 坏 JSON：报 RegistryError 且**原文件不被改**（最危险的失败模式）
  5. 信任表：写入、旧指纹清理、坏审批表重建、uninstall 全清
  6. inspect / pick_clients / 干跑不写盘
  7. CLI：``mcp`` 是 group 而不是单命令，且无参仍是启动 server 的形状

运行：.venv/Scripts/python.exe scripts/mcp_registry_test.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server import registry as R  # noqa: E402

ok = 0
total = 0


def check(name: str, cond: bool) -> None:
    global ok, total
    total += 1
    if cond:
        ok += 1
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name}")


def make_client(root: Path, key: str = "workbuddy") -> R.Client:
    return R.Client(
        key=key,
        label="Test",
        config=root / "mcp.json",
        approvals=root / "mcp-approvals.json",
        restart_hint="restart",
    )


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    print("场景1 指纹固定向量（客户端真实接受过的值）")
    rea_fp = R.fingerprint(
        "cmd.exe", ["/d", "/c", "npx", "-y", "rea-agents@6.8.0", "mcp"]
    )
    check(
        "rea 条目指纹与 WorkBuddy approvals 里的一致",
        rea_fp
        == "dbcc62076ac0f1a304a98a1f5b18923c0922575a18ed6ad19f8f7b1b2d21b27c",
    )
    fp_fixed = R.fingerprint(
        r"D:\anyworkspace\python\flower_pow\.venv\Scripts\python.exe",
        [r"D:\anyworkspace\python\flower_pow\flower_pow.py", "mcp"],
    )
    check(
        "flower_pow 条目指纹与已信任值一致",
        fp_fixed
        == "0d9d06e67f41748093f4ede306607923bc0f3cfbbdcf307cbbe02f80a2114f2c",
    )

    print("\n场景2 指纹语义")
    a = R.fingerprint("py", ["b.py", "mcp"])
    b = R.fingerprint("py", ["mcp", "b.py"])
    check("args 顺序不影响指纹", a == b)
    c = R.fingerprint("py", ["b.py", "mcp"], {"KEY": "v1"})
    d = R.fingerprint("py", ["b.py", "mcp"], {"KEY": "v2"})
    check("env 值不参与指纹", c == d)
    e = R.fingerprint("py", ["b.py", "mcp"], {"KEY": "v1", "OTHER": "x"})
    check("env 多一个键 → 指纹变（要求重新信任）", c != e)
    check("command 不同 → 指纹不同", R.fingerprint("py2", ["b.py", "mcp"]) != a)
    check("trust_key 形如 <fp>::<name>", R.trust_key("n", "f") == "f::n")

    print("\n场景3 条目形状")
    entry = R.entry_for("/usr/bin/python3", "/opt/fp/flower_pow.py")
    check("args 固定为 [script, mcp]", entry["args"] == ["/opt/fp/flower_pow.py", "mcp"])
    check("不带 env 时不写 env 字段", "env" not in entry)
    check(
        "带 env 时原样写入",
        R.entry_for("py", "s.py", {"A": "1"})["env"] == {"A": "1"},
    )

    print("\n场景4 install 基本流")
    tmp = Path(tempfile.mkdtemp())
    c = make_client(tmp)
    res = R.install(c, "flower_pow", entry)
    check("空目录 → created", res.action == "created")
    check("配置文件已生成", c.config.is_file())
    check("条目写进去了", read(c.config)["mcpServers"]["flower_pow"] == entry)
    check("首次安装没有备份（本来就没文件）", res.backup is None)
    check("信任表已登记", res.trusted)
    check(
        "approvals 键是 <指纹>::flower_pow",
        R.trust_key("flower_pow", res.fingerprint) in read(c.approvals),
    )
    check(
        "登记值是毫秒时间戳",
        read(c.approvals)[R.trust_key("flower_pow", res.fingerprint)] > 1_600_000_000_000,
    )
    check("没有遗留 .tmp", not list(tmp.glob("*.tmp")))

    print("\n场景5 幂等与共存")
    before = c.config.read_text(encoding="utf-8")
    mtime = c.config.stat().st_mtime_ns
    res2 = R.install(c, "flower_pow", entry)
    check("重复安装 → unchanged", res2.action == "unchanged")
    check("内容一字未变", c.config.read_text(encoding="utf-8") == before)
    check("文件未被重写（mtime 不变）", c.config.stat().st_mtime_ns == mtime)
    check("unchanged 不产备份", res2.backup is None)
    check("重复安装仍报告已信任", res2.trusted)

    data = read(c.config)
    data["mcpServers"]["other"] = {"command": "x", "args": []}
    c.config.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    R.install(c, "flower_pow", entry)
    check(
        "安装不动别人的 server",
        read(c.config)["mcpServers"]["other"] == {"command": "x", "args": []},
    )

    print("\n场景6 换解释器 → updated + 备份 + 清旧指纹")
    new_entry = R.entry_for("/new/python", "/new/flower_pow.py")
    res3 = R.install(c, "flower_pow", new_entry, stamp="T1")
    check("配置变化 → updated", res3.action == "updated")
    check("产生备份", res3.backup is not None and res3.backup.is_file())
    check("备份文件名带时间戳", ".bak-T1" in str(res3.backup))
    ap = read(c.approvals)
    keys = [k for k in ap if k.split("::")[-1] == "flower_pow"]
    check("旧指纹被清掉，只剩当前一条", len(keys) == 1)
    check("剩下的是新指纹", keys[0] == R.trust_key("flower_pow", res3.fingerprint))

    print("\n场景7 坏 JSON：报错且不改盘")
    bad = Path(tempfile.mkdtemp()) / "mcp.json"
    bad.write_text('{"mcpServers": {"a": 1,}', encoding="utf-8")
    raw_before = bad.read_text(encoding="utf-8")
    raised = False
    try:
        R.install(R.Client("x", "X", bad), "flower_pow", entry)
    except R.RegistryError:
        raised = True
    check("坏 JSON → RegistryError", raised)
    check("原文件一个字节都没动", bad.read_text(encoding="utf-8") == raw_before)
    check("没有写出 .tmp 残留", not list(bad.parent.glob("*.tmp")))

    bad2 = Path(tempfile.mkdtemp()) / "mcp.json"
    bad2.write_text('{"mcpServers": []}', encoding="utf-8")
    raised2 = False
    try:
        R.install(R.Client("x", "X", bad2), "flower_pow", entry)
    except R.RegistryError:
        raised2 = True
    check("mcpServers 不是对象 → 拒绝改写", raised2)

    empty = Path(tempfile.mkdtemp()) / "mcp.json"
    empty.write_text("", encoding="utf-8")
    res4 = R.install(R.Client("x", "X", empty), "flower_pow", entry)
    check("空文件按空配置处理（不是错误）", res4.action == "created")

    print("\n场景8 审批表损坏 / 干跑 / status")
    broken_ap = Path(tempfile.mkdtemp())
    cb = make_client(broken_ap, "broken")
    cb.approvals.write_text("not json", encoding="utf-8")
    res5 = R.install(cb, "flower_pow", entry, stamp="B1")
    check("坏审批表不阻塞安装", res5.trusted)
    check("坏审批表被备份后重建", (broken_ap / "mcp-approvals.json.bak-B1").is_file())

    dry_dir = Path(tempfile.mkdtemp())
    cd = make_client(dry_dir, "dry")
    res6 = R.install(cd, "flower_pow", entry, dry_run=True)
    check("干跑返回 created", res6.action == "created")
    check("干跑不写配置文件", not cd.config.exists())
    check("干跑不写审批表", not cd.approvals.exists())
    check("干跑报告未信任（现状）", res6.trusted is False)

    st = R.inspect(c, "flower_pow")
    check("inspect：已注册", st.registered)
    check("inspect：指纹与安装时一致", st.fingerprint == res3.fingerprint)
    check("inspect：客户端认这个指纹", st.trusted)
    check("inspect：healthy", st.healthy)
    st_missing = R.inspect(make_client(Path(tempfile.mkdtemp()), "m"), "nope")
    check("inspect：未注册时 registered=False", not st_missing.registered)
    check("inspect：未注册不健康", not st_missing.healthy)

    print("\n场景9 uninstall")
    res7 = R.uninstall(c, "flower_pow", stamp="U1")
    check("条目被删", res7.removed_entry)
    check("配置里已无该条目", "flower_pow" not in read(c.config)["mcpServers"])
    check("别的 server 仍在", "other" in read(c.config)["mcpServers"])
    check("信任记录被删", res7.removed_trusts == 1)
    check("审批表里无残留", not [k for k in read(c.approvals) if k.endswith("::flower_pow")])
    check("删除也备份", res7.backup is not None)
    res8 = R.uninstall(c, "flower_pow")
    check("重复卸载不报错", res8.removed_entry is False and res8.removed_trusts == 0)

    print("\n场景10 客户端选择")
    home = Path(tempfile.mkdtemp())
    allc = R.pick_clients("all", home)
    check("all 展开出三个客户端", len(allc) == 3)
    keys = {x.key for x in allc}
    check("包含 workbuddy/claude/cursor", keys == {"workbuddy", "claude", "cursor"})
    wb = R.pick_clients("workbuddy", home)[0]
    check("WorkBuddy 配置在 ~/.workbuddy/mcp.json", wb.config == home / ".workbuddy" / "mcp.json")
    check("WorkBuddy 有审批表", wb.approvals == home / ".workbuddy" / "mcp-approvals.json")
    cl = R.pick_clients("claude,cursor", home)
    check("逗号分隔生效", [x.key for x in cl] == ["claude", "cursor"])
    check("Claude/Cursor 无审批机制", all(x.approvals is None for x in cl))
    bad_pick = False
    try:
        R.pick_clients("vscode", home)
    except R.RegistryError:
        bad_pick = True
    check("未知客户端 → RegistryError", bad_pick)

    print("\n场景11 CLI 装配")
    from cli import app as typer_app

    groups = {g.name for g in typer_app.registered_groups}
    check("`mcp` 注册成了子命令组", "mcp" in groups)
    cmd_names = {getattr(c.callback, "__name__", "") for c in typer_app.registered_commands}
    check("旧的单命令 mcpserve 已退场", "mcpserve" not in cmd_names)
    from cli.mcpsrv import mcp_app

    sub = {getattr(c.callback, "__name__", "") for c in mcp_app.registered_commands}
    check("install / status / uninstall 三个子命令齐了",
          {"mcp_install", "mcp_status", "mcp_uninstall"} <= sub)

    # 最要紧的兼容性：客户端配置里写的是 [flower_pow.py, "mcp"]，没有子命令。
    # 这条形状下必须**起得来 server**（而不是打印帮助就退出），否则所有已信任
    # 配置会一起失效。
    try:
        import mcp  # noqa: F401
    except ModuleNotFoundError:
        print("  - 跳过：本环境没装 mcp，无法起 server")
    else:
        import subprocess
        import time

        root = Path(__file__).resolve().parent.parent
        proc = subprocess.Popen(
            [sys.executable, "flower_pow.py", "mcp"],
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2.0)
        alive = proc.poll() is None
        proc.terminate()
        try:
            _out, errb = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            _out, errb = proc.communicate()
        check("无参 `mcp` 进入 stdio 常驻（没退化成打帮助）", alive)
        check(
            "stdio 模式不往 stdout 写东西（协议不能被污染）",
            not (_out or b"").strip(),
        )
        # stderr 里的启动提示不在这里断言：进程是被 terminate 强杀的，
        # TextIOWrapper 里没 flush 的部分会丢，读到的内容不稳定。
        # 它的存在由 cli/mcpsrv._serve 的代码路径保证（只 print 到 err）。

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
