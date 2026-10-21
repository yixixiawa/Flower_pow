"""文件增删改（沙箱）与报告就地覆盖的回归测试。

复现的真实问题：报告导出每次都生成**新文件**（``report_x.md`` →
``_2.md`` → ``_3.md``），改一轮导一次就堆出一串近似重复的报告，用户还得猜
哪份是最新的；智能体也没法"接着上一份改"，只能整篇重写。

两件事一起做，而且互相依赖：
  * ``core/fsops.py`` 给模型增删改文件的手；
  * 导出改成**就地覆盖同一份文件**，并允许用 ``edit_file`` 只改一段。

覆盖：
  1. 路径闸门：绝对路径 / ``..`` / UNC / 盘符 / 数据流 / 保留设备名 / 尾点 / 符号链接
  2. 扩展名**白名单**（不是黑名单）
  3. 写：新建 / 覆盖 / 拒绝覆盖 / 自动建目录 / 大小上限 / 原子无残留
  4. 读：内容 / 分段 / 截断 / 不存在
  5. 改：精确一次成功 / 没找到 / 歧义拒绝 / count=0 全替 / 空片段拒绝
  6. 删：文件成功 / 目录拒绝 / 不存在拒绝
  7. 列目录
  8. **报告就地覆盖**：同一路径、内容更新、不产生 _2；overwrite=False 仍防覆盖
  9. 工具注册 + handler 行为（拒绝是返回值不是异常）+ 删除留痕
 10. ``readonly`` 不阻断本地产物写入；``fs_ops_enabled=false`` 整体关闭

运行：.venv/Scripts/python.exe scripts/test_fsops.py
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import ScanConfig  # noqa: E402
from core.fsops import (  # noqa: E402
    ALLOWED_EXTS,
    MAX_WRITE_BYTES,
    FileOpDenied,
    FileSandbox,
    is_reparse_point,
    sandbox_for,
)
from core.session import Session  # noqa: E402
from core.state import Category, Evidence, Finding, Severity  # noqa: E402
from core.tools import ToolRunner  # noqa: E402
from core.tools import BUILTINS  # noqa: E402


class FakeCfg:
    """``cfg.scan`` 用真的 ScanConfig——假对象比真对象更容易骗过测试。"""

    def __init__(self, root: Path, **scan_kw) -> None:
        self.output_dir = str(root)
        self.scan = ScanConfig(**scan_kw)

    class rag:
        poc_dir = "./poc"


def mk_finding() -> Finding:
    at = "https://demo.example.com/x"
    return Finding(
        poc_id="p-1", name="测试发现", severity=Severity.MEDIUM,
        category=Category.HEADER_CHECK, matched_at=at,
        evidence=Evidence(url=at, poc_id="p-1"),
        verdict="true_positive", confidence=0.9,
    )


def main() -> int:
    ok = total = skipped = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    def skip(label):
        nonlocal skipped
        skipped += 1
        print(f"  SKIP {label}")

    def denied(fn, *a, **kw) -> str:
        """跑一下，返回拒绝信息；没被拒绝返回空串。"""
        try:
            fn(*a, **kw)
        except FileOpDenied as exc:
            return str(exc)
        except Exception as exc:  # noqa: BLE001
            return f"<非 FileOpDenied: {type(exc).__name__}: {exc}>"
        return ""

    tmp = Path(tempfile.mkdtemp())
    root = tmp / "output"
    root.mkdir()
    sb = FileSandbox(root=root)

    print("场景1 路径闸门（全部必须拒绝）")
    cases = [
        ("../../.env", "上级目录"),
        ("..", "纯上级"),
        ("a/../../b.md", "夹在中间的 .."),
        ("/etc/passwd", "绝对路径"),
        ("C:/Windows/win.ini", "盘符"),
        ("c:report.md", "盘符相对"),
        ("//server/share/a.md", "UNC"),
        ("a.md:stream", "数据流"),
        ("con.md", "保留设备名"),
        ("LPT1.md", "保留设备名"),
        ("report.md.", "尾部点（Windows 会静默归一）"),
        ("a.md .", "点+空格结尾"),
        ("", "空路径"),
        ("   ", "空白路径"),
        ("a\x00b.md", "含 NUL"),
    ]
    for rel, why in cases:
        msg = denied(sb.resolve, rel)
        check(bool(msg), f"拒绝 {why}：{rel!r}", "没被拒绝！")
    # 合法的要放行，别把闸门焊死
    check(sb.resolve("a.md").name == "a.md", "正常相对路径放行")
    check(sb.resolve("sub/dir/a.md").name == "a.md", "多级相对路径放行")
    check(sb.resolve("./a.md").name == "a.md", "带 ./ 前缀放行")
    check(sb.resolve("a b.md").name == "a b.md", "文件名中间的空格放行")
    # 首尾空白归一掉，而不是当成"另一个文件"——归一比报错更安全：
    # 否则 "a.md " 在 Windows 上会变成 a.md，正好绕过扩展名白名单
    check(sb.resolve(" a.md ").name == "a.md", "首尾空白被归一，不产生怪名文件")

    # 符号链接 / 目录联接。Windows 上 ``Path.is_symlink()`` **看不见目录联接**
    # （实测 symlink_to 创建出来的东西 is_symlink() 就是 False），
    # 所以两种都试，并且用重解析点属性判断——这是真踩到的坑。
    (tmp / "outside").mkdir(exist_ok=True)
    link = root / "link"
    made = ""
    try:
        link.symlink_to(tmp / "outside", target_is_directory=True)
        if is_reparse_point(link):
            made = "symlink"
    except (OSError, NotImplementedError, AttributeError):
        pass
    if not made:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(tmp / "outside")],
            capture_output=True, text=True,
        )
        if link.exists() and is_reparse_point(link):
            made = "junction"
    if made:
        kind = "符号链接" if made == "symlink" else "目录联接"
        check(bool(denied(sb.resolve, "link/a.md")), f"拒绝穿过{kind}")
        check(bool(denied(sb.write, "link/a.md", "x")), f"不允许经{kind}写入")
        check(all(i["name"] != "link" for i in sb.list_dir()), "列目录时跳过重解析点")
    else:
        skip("符号链接/目录联接逃逸（本环境创建不出重解析点）")
    # 不管上面能不能创建，都要验证**闸门确实接在 resolve() 里**——
    # 否则"能创建的环境里才拦得住"这种事永远不会在测试里暴露。
    import core.fsops as _F

    _orig_reparse = _F.is_reparse_point
    _F.is_reparse_point = lambda p: p.name == "linked"
    try:
        check(bool(denied(sb.resolve, "linked/a.md")),
              "中间片段被判为重解析点时 resolve 拒绝（闸门已接线）")
        check(bool(denied(sb.write, "linked/a.md", "x")), "写入路径同样过闸门")
    finally:
        _F.is_reparse_point = _orig_reparse

    print("\n场景2 扩展名走白名单")
    check(".md" in ALLOWED_EXTS and ".html" in ALLOWED_EXTS, "报告类产物在白名单里")
    for ext in (".py", ".exe", ".dll", ".bat", ".ps1", ".sh", ".js",
                ".env", ".pem", ".key", ".lic"):
        check(ext not in ALLOWED_EXTS, f"{ext} 不在白名单（防产物目录变成代码投放点）")
    for bad in ("evil.py", "run.exe", ".env", "key.pem", "noext"):
        check(bool(denied(sb.write, bad, "x")), f"拒绝写 {bad}")

    print("\n场景3 写：新建 / 覆盖 / 上限 / 原子")
    p = sb.write("a.md", "hello")
    check(p.read_text(encoding="utf-8") == "hello", "新建成功")
    check(sb.write("a.md", "world").read_text(encoding="utf-8") == "world", "覆盖成功")
    check(bool(denied(sb.write, "a.md", "x", overwrite=False)), "overwrite=false 时拒绝覆盖")
    p2 = sb.write("sub/deep/b.md", "nested")
    check(p2.exists() and "sub" in str(p2), "自动创建子目录")
    big = "x" * (MAX_WRITE_BYTES + 10)
    check(bool(denied(sb.write, "big.md", big)), f"超过 {MAX_WRITE_BYTES} 字节被拒")
    check(bool(denied(sb.write, "sub", "x")), "目标是不带扩展名的目录时被拒")
    parts = list(root.rglob("*.part")) + list(root.rglob(".fs-*"))
    check(parts == [], f"原子写没留下临时文件，实={parts}")

    print("\n场景4 读")
    sb.write("lines.md", "L1\nL2\nL3\nL4\nL5")
    check(sb.read("lines.md").startswith("L1"), "读全文")
    check(bool(denied(sb.read, "nope.md")), "读不存在的文件被拒")
    check(bool(denied(sb.read, "../x.md")), "读越界被拒")

    print("\n场景5 改：精确替换，含糊就拒绝")
    sb.write("e.md", "标题\n\n正文 AAA\n\n结尾 AAA\n")
    _f, n = sb.edit("e.md", "正文 AAA", "正文 BBB")
    t = sb.read("e.md")
    check(n == 1 and "正文 BBB" in t and "结尾 AAA" in t, "精确替换只动指定那处")
    # 歧义场景用**新文件**：上面那次替换已经把重复的 AAA 消耗掉一个了
    sb.write("dup.md", "AAA\n中间\nAAA\n")
    msg = denied(sb.edit, "dup.md", "AAA", "X")
    check("出现了 2 次" in msg, f"同一片段出现 2 次时拒绝并说明，实={msg[:70]!r}")
    check(sb.read("dup.md").count("AAA") == 2, "被拒绝时文件一字未改")
    _f, n = sb.edit("dup.md", "AAA", "CCC", count=0)
    check(n == 2 and sb.read("dup.md").count("CCC") == 2, "count=0 表示全部替换")
    check("没找到" in denied(sb.edit, "dup.md", "zzz", "x"), "找不到片段时明确提示")
    check(bool(denied(sb.edit, "dup.md", "", "x")), "空 old_text 被拒（否则处处插入）")
    check(bool(denied(sb.edit, "dup.md", "CCC", "CCC")), "新旧相同时被拒")
    check(bool(denied(sb.edit, "nope.md", "a", "b")), "改不存在的文件被拒")
    check(bool(denied(sb.edit, "dup.md", "CCC", "x" * (MAX_WRITE_BYTES + 1))),
          "改完超上限被拒")
    check(sb.read("dup.md").count("CCC") == 2, "超上限那次也放弃了，文件未被改")

    print("\n场景6 删：只删文件，不删目录")
    sb.write("doomed.md", "bye")
    f, size = sb.delete("doomed.md")
    check(not f.exists() and size == 3, "删除文件成功并返回原大小")
    (root / "keepdir").mkdir(exist_ok=True)
    msg = denied(sb.delete, "keepdir")
    check("拒绝删除目录" in msg, f"拒绝删目录，实={msg[:50]!r}")
    check((root / "keepdir").exists(), "目录确实还在")
    check(bool(denied(sb.delete, "nope.md")), "删不存在的文件被拒")
    check(bool(denied(sb.delete, "../.env")), "删越界被拒")

    print("\n场景7 列目录")
    (root / "sub").mkdir(exist_ok=True)
    items = sb.list_dir("")
    names = {i["name"] for i in items}
    check("sub" in names, f"列出子目录，实={sorted(names)[:5]}")
    check(any(i["dir"] for i in items), "标注了目录")
    check(any(i["size"] > 0 for i in items), "标注了文件大小")
    check(all(not i["path"].startswith("/") for i in items), "返回的是相对路径")
    check(len(sb.list_dir("sub")) >= 1, "能列子目录")
    check(bool(denied(sb.list_dir, "../")), "列越界目录被拒")

    print("\n场景8 报告就地覆盖（本需求的核心）")
    from output.report import report_paths, write_markdown

    s = Session(target="https://demo.example.com")
    s.result.add_findings([mk_finding()])
    a = write_markdown(s.result, root)
    # 名字格式是 report_<日期>_<主域名>：日期在前、主域名在后。
    # 下划线个数（2 个）顺带验证没有 _2 后缀——日期里的下划线也算在内，
    # 加了序号的会变成 3 个。
    import time as _time

    day = _time.strftime("%Y%m%d", _time.localtime(s.result.started_at))
    check(a.name == f"report_{day}_example.com.md",
          f"名字 = report_<日期>_<主域名>，实={a.name}")
    check(a.name.count("_") == 2, f"没有 _2 后缀，实={a.name}")
    a.write_text("被改坏了", encoding="utf-8")           # 冒充"上一份报告"
    b = write_markdown(s.result, root)
    check(b == a, f"**第二次导出写回同一路径**，实={b} vs {a}")
    check("渗透测试结果" in b.read_text(encoding="utf-8"), "内容被真正重写（不是留着旧内容）")
    twins = [p for p in root.iterdir() if p.name.startswith(a.stem + "_")]
    check(twins == [], f"没有堆出 _2/_3 副本，实={twins}")

    c = write_markdown(s.result, root, overwrite=False)
    check(c != a and "_2" in c.name, f"overwrite=false 仍另存为新文件，实={c.name}")
    plan = report_paths(s.result, root)
    check(plan["md"] == a and plan["html"].suffix == ".html",
          "report_paths 给出三种格式的确定路径")

    print("\n场景9 工具注册与 handler")
    names = [b.name for b in BUILTINS]
    for t in ("list_files", "read_file", "write_file", "edit_file", "delete_file"):
        check(t in names, f"注册了 {t}")
    spec = [b for b in BUILTINS if b.name == "edit_file"][0]
    check(set(spec.params.get("required") or []) >= {"path", "old_text", "new_text"},
          "edit_file 必填参数齐全")
    er = [b for b in BUILTINS if b.name == "export_report"][0]
    check("overwrite" in er.params["properties"], "export_report 暴露了 overwrite")

    runner = ToolRunner(FakeCfg(root), [], str(tmp))
    sess = Session(target="https://demo.example.com")

    out = asyncio.run(runner.execute("write_file", {"path": "n.md", "content": "N"}, sess))
    check("已新建" in out, f"handler 写成功，实={out[:40]!r}")
    out = asyncio.run(runner.execute("write_file", {"path": "n.md", "content": "N2"}, sess))
    check("已覆盖" in out, f"handler 覆盖时说清是覆盖，实={out[:40]!r}")
    out = asyncio.run(runner.execute("read_file", {"path": "n.md"}, sess))
    check("N2" in out, "handler 读回来")
    out = asyncio.run(runner.execute("list_files", {}, sess))
    check("n.md" in out, "handler 列目录")
    out = asyncio.run(runner.execute(
        "edit_file", {"path": "n.md", "old_text": "N2", "new_text": "N3"}, sess))
    check("已就地修改" in out, f"handler 就地改，实={out[:40]!r}")
    out = asyncio.run(runner.execute("delete_file", {"path": "n.md"}, sess))
    check("已删除" in out, f"handler 删除，实={out[:40]!r}")
    check(any("删除产物文件" in n for n in sess.result.notes), "删除在会话里留痕")

    out = asyncio.run(runner.execute("read_file", {"path": "../../.env"}, sess))
    check("已拒绝" in out, f"handler 把越界当**返回值**而不是异常，实={out[:40]!r}")
    check(not out.startswith("【执行失败】"), "不伪装成崩溃")
    out = asyncio.run(runner.execute("write_file", {"path": "x.py", "content": "x"}, sess))
    check("已拒绝" in out, "handler 拒绝写 .py")

    out = asyncio.run(runner.execute("export_report", {"fmt": "md"}, sess))
    check("覆盖" in out or "新建" in out, f"export_report 说明新建/覆盖，实={out[:60]!r}")
    check("整篇重新生成" in out,
          "**覆盖时要提醒**：edit_file 的局部改动会被这次导出替换掉")
    out2 = asyncio.run(runner.execute("export_report", {"fmt": "md"}, sess))
    check("整篇重新生成" in out2, "第二次导出（确实是覆盖）仍有提醒")

    print("\n场景10 readonly 不阻断；开关能整体关掉")
    rcfg = FakeCfg(root, readonly=True, fs_ops_enabled=True)
    rrunner = ToolRunner(rcfg, [], str(tmp))
    out = asyncio.run(rrunner.execute(
        "write_file", {"path": "ro.md", "content": "ok"}, Session(target="https://x.test")))
    check("已新建" in out, f"readonly=true 时本地产物仍可写（readonly 管的是目标），实={out[:40]!r}")

    off = FakeCfg(root, fs_ops_enabled=False)
    msg = denied(sandbox_for, off)
    check("已关闭" in msg, f"fs_ops_enabled=false 时沙箱直接拒绝，实={msg[:50]!r}")
    orunner = ToolRunner(off, [], str(tmp))
    out = asyncio.run(orunner.execute(
        "write_file", {"path": "off.md", "content": "x"}, Session(target="https://x.test")))
    check("已拒绝" in out, "关闭后 handler 也拒绝（不是抛异常）")
    check(not (root / "off.md").exists(), "关闭时确实没写出文件")

    print(f"\n{ok}/{total} 通过" + (f"（跳过 {skipped} 项）" if skipped else ""))
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
