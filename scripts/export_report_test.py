"""export_report 与工具参数类型归一的回归测试。

复现的真实问题（``scripts/_repro_export.py`` / ``_repro_bool.py`` 曾验证）：

1. **非法 fmt 静默"成功"**：``fmt="markdown"`` 不在枚举里时，三个
   ``if fmt in (...)`` 全落空，一个文件都没写，却照样返回「报告已导出：」。
   模型以为报告已经产出，用户什么都找不到——这是"无法输出报告"的根因。
2. **模型把布尔传成字符串**：``"false"`` 在 Python 里恒为真，
   ``overwrite="false"`` 真的去覆盖、``undo="false"`` 真的去撤销误报标记。
   修复是 schema 感知的 ``normalize_args``，在 ``execute()`` 单一收口。
3. **overwrite=false 时 [新建]/[覆盖] 标反**：``before`` 查的是覆盖模式路径，
   实际却写到 ``_2``——新建的文件被标成"覆盖"。
4. **overwrite=false 时三格式主干错位**：三个 writer 各自找空位，
   json 占掉 ``_2`` 后 md 可能跳到 ``_3``，报告与 JSON 快照对不上号。
5. **notes 重复累积**：每导一次就往 ``result.notes`` 塞一条一模一样的会话头。

覆盖：
  1. fmt 校验：非法值报错并列出合法值；大小写/首尾空格归一；缺省 = all
  2. 参数类型归一：布尔字符串 / 数字字符串 / 枚举大小写；认不出来的原样下传
  3. [新建]/[覆盖] 标注与实际行为一致（含 overwrite=false 另存）
  4. overwrite=false 时三格式共用主干（含"只有一个格式占了 _2"的错位场景）
  5. notes 不重复累积，哨兵前缀不进交付物
  6. overwrite 字符串 "false" 真的另存新文件；undo 字符串 "false" 不撤销
  7. plan_reports 一次性定路径
  8. set_target 工具同步 result.target → 报告名含主域名
     （复刻截图事故：文件名退化成 report_<日期>_target）
  9. export_report 兜底同步 session.target → result.target

运行：.venv/Scripts/python.exe scripts/test_export_report.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session  # noqa: E402
from core.state import Category, Evidence, Finding, Severity  # noqa: E402
from core.tools import ToolRunner  # noqa: E402
from core.tools import normalize_args  # noqa: E402
from output.report import plan_reports, write_json  # noqa: E402


class FakeCfg:
    """``cfg.scan`` 用真的 ScanConfig——假对象比真对象更容易骗过测试。"""

    def __init__(self, root: Path, **scan_kw) -> None:
        self.output_dir = str(root)
        self.scan = ScanConfig(**scan_kw)

    class rag:
        poc_dir = "./poc"


def mk_session() -> Session:
    sess = Session(target="https://demo.example.com")
    at = "https://demo.example.com/api/v1/users"
    sess.result.add_findings([
        Finding(
            poc_id="api-missing-auth", name="接口未鉴权", severity=Severity.HIGH,
            category=Category.API_AUTHZ, matched_at=at,
            evidence=Evidence(url=at, poc_id="api-missing-auth", status_code=200),
            verdict="true_positive", confidence=0.9,
        )
    ])
    return sess


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp())
    root = tmp / "output"
    root.mkdir()
    sess = mk_session()
    runner = ToolRunner(FakeCfg(root), [], str(tmp))

    def run(tool, args):
        return asyncio.run(runner.execute(tool, args, sess))

    print("场景1 fmt 校验：非法值必须报错，不能静默'成功'")
    out = run("export_report", {"fmt": "markdown"})
    check("【参数不合法】" in out, "非法 fmt 报错", f"实={out[:60]!r}")
    check("md / html / json / all" in out, "报错里列出合法值")
    check("一个文件都没有导出" in out, "明说没有产出任何文件")
    check(not list(root.iterdir()), "非法 fmt 没写任何文件")
    out = run("export_report", {"fmt": "MD"})
    check("报告已导出" in out and ".md" in out, "fmt='MD' 大小写归一后正常导出")
    out = run("export_report", {"fmt": "md "})
    check("报告已导出" in out, "fmt='md ' 首尾空格归一后正常导出")
    out = run("export_report", {"fmt": ""})
    check("报告已导出" in out and ".html" in out, "空 fmt 回落到 all")
    out = run("export_report", {})
    check("报告已导出" in out, "不传 fmt 默认 all")

    print("场景2 参数类型归一（normalize_args 单测）")
    n = normalize_args("export_report", {"fmt": "md", "overwrite": "false"})
    check(n["overwrite"] is False, "overwrite 'false' → False")
    n = normalize_args("export_report", {"overwrite": "0"})
    check(n["overwrite"] is False, "overwrite '0' → False")
    n = normalize_args("export_report", {"overwrite": "true"})
    check(n["overwrite"] is True, "overwrite 'true' → True")
    n = normalize_args("export_report", {"fmt": "MD"})
    check(n["fmt"] == "md", "枚举大小写归一 'MD' → 'md'")
    n = normalize_args("dismiss_finding", {"ref": "1", "undo": "false"})
    check(n["undo"] is False, "undo 'false' → False（不会误撤销）")
    n = normalize_args("recon_ports", {"top": "100"})
    check(n["top"] == 100, "数字字符串 '100' → 100")
    n = normalize_args("export_report", {"fmt": "markdown"})
    check(n["fmt"] == "markdown", "认不出来的枚举值原样下传（交给 handler 报错）")
    n = normalize_args("export_report", {"overwrite": "也许吧"})
    check(n["overwrite"] == "也许吧", "认不出来的布尔值原样下传（不瞎猜）")

    print("场景3 [新建]/[覆盖] 标注与实际行为一致")
    d3 = tmp / "s3"
    d3.mkdir()
    s3 = mk_session()
    r3 = ToolRunner(FakeCfg(d3), [], str(tmp))

    def run3(args):
        return asyncio.run(r3.execute("export_report", args, s3))

    out = run3({"fmt": "all"})
    check(out.count("[新建]") == 3, "首次导出三个 [新建]", f"实={out[:80]!r}")
    check("[覆盖]" not in out, "首次导出不出现 [覆盖]")
    out = run3({"fmt": "all"})
    check(out.count("[覆盖]") == 3, "再次导出三个 [覆盖]", f"实={out[:80]!r}")
    check("[新建]" not in out, "覆盖导出不出现 [新建]")
    out = run3({"fmt": "all", "overwrite": False})
    check(out.count("[新建]") == 3, "overwrite=false 另存为 [新建]（修复前标反为覆盖）",
          f"实={out[:80]!r}")
    check("[覆盖]" not in out, "overwrite=false 不出现 [覆盖]")
    names = sorted(p.name for p in d3.iterdir())
    check(any("_2." in n for n in names), "overwrite=false 产生了 _2 副本")

    print("场景4 overwrite=false 时三格式主干一致（含错位场景）")
    # 错位场景：只导出 md（overwrite=false）→ _2.md；再导出 all，
    # 修复前 json 会写 _2.json 而 md 跳 _3.md，主干对不上。
    d4 = tmp / "s4"
    d4.mkdir()
    s4 = mk_session()
    r4 = ToolRunner(FakeCfg(d4), [], str(tmp))
    asyncio.run(r4.execute("export_report", {"fmt": "all"}, s4))
    asyncio.run(r4.execute("export_report", {"fmt": "md", "overwrite": False}, s4))
    asyncio.run(r4.execute("export_report", {"fmt": "all", "overwrite": False}, s4))
    stems: dict[str, set[str]] = {}
    for p in d4.iterdir():
        stems.setdefault(p.stem, set()).add(p.suffix)
    full = [s for s, exts in stems.items() if exts == {".json", ".md", ".html"}]
    check(len(full) >= 2, f"至少两组主干三格式齐全（实={sorted(stems)}）")
    lonely = [
        (s, exts) for s, exts in stems.items()
        if exts != {".json", ".md", ".html"} and s != full[0]
    ]
    # 除了最初的整组和手动单导的 _2.md，不允许出现"半组"
    semi = [s for s, exts in lonely if exts & {".json", ".html"}]
    check(not semi, f"没有 json/html 落单的错位主干（实={semi}）")

    print("场景5 notes 不重复累积，哨兵不进交付物")
    d5 = tmp / "s5"
    d5.mkdir()
    s5 = mk_session()
    r5 = ToolRunner(FakeCfg(d5), [], str(tmp))
    for _ in range(3):
        asyncio.run(r5.execute("export_report", {"fmt": "all"}, s5))
    heads = [n for n in s5.result.notes if "交互式会话" in n]
    check(len(heads) == 1, f"导出 3 次后会话头只有 1 条（实={len(heads)}）")
    md = next(d5.glob("*.md")).read_text(encoding="utf-8")
    check("\x00" not in md, "报告里没有哨兵字符")
    check("交互式会话" in md, "会话头出现在报告的[执行说明]里")
    check("重复" not in md.split("执行说明")[-1] or "重复 1 次" not in md,
          "执行说明里没有「重复 N 次」噪音")

    print("场景6 模型把布尔传成字符串（端到端）")
    d6 = tmp / "s6"
    d6.mkdir()
    s6 = mk_session()
    r6 = ToolRunner(FakeCfg(d6), [], str(tmp))
    asyncio.run(r6.execute("export_report", {"fmt": "md"}, s6))
    base = sorted(p.name for p in d6.iterdir())
    out = asyncio.run(r6.execute(
        "export_report", {"fmt": "md", "overwrite": "false"}, s6))
    after = sorted(p.name for p in d6.iterdir())
    check(len(after) > len(base), "overwrite='false' 真的另存新文件（没被覆盖）")
    check("[新建]" in out, "标注为 [新建]")
    # undo='false' 不得撤销误报标记
    f = s6.result.findings[0]
    asyncio.run(r6.execute(
        "dismiss_finding", {"ref": "1", "reason": "复核为误报"}, s6))
    asyncio.run(r6.execute("dismiss_finding", {"ref": "1", "undo": "false"}, s6))
    check(f.dismissed, "undo='false' 不撤销误报标记")
    # write_file overwrite='false' 不得覆盖
    asyncio.run(r6.execute(
        "write_file", {"path": "a.md", "content": "1"}, s6))
    asyncio.run(r6.execute(
        "write_file", {"path": "a.md", "content": "2", "overwrite": "false"}, s6))
    content = (d6 / "a.md").read_text(encoding="utf-8")
    check(content == "1", "write_file overwrite='false' 不覆盖已有文件")

    print("场景7 plan_reports 一次性定路径")
    d7 = tmp / "s7"
    d7.mkdir()
    s7 = mk_session()
    p1 = plan_reports(s7.result, d7, overwrite=True)
    check(len({p.stem for p in p1.values()}) == 1, "覆盖模式三格式共用主干")
    write_json(s7.result, d7, "", path=p1["json"])  # json 先占位
    p2 = plan_reports(s7.result, d7, overwrite=False)
    check(len({p.stem for p in p2.values()}) == 1, "非覆盖模式三格式仍共用主干")
    check(all(p.stem != p1["json"].stem for p in p2.values()),
          "避开已被占用的主干，不劈叉")

    print("场景8 set_target 工具必须同步 result.target（报告命名读的是它）")
    # 复刻截图事故：聊天里让模型设目标 → set_target(url) → export_report。
    # 修复前 _h_set_target 只改 session.target，result.target 还是空串，
    # 文件名退化成 report_<日期>_target，主域名完全没用上。
    d8 = tmp / "s8"
    d8.mkdir()
    s8 = Session(target="")  # 会话创建时还没设目标
    r8 = ToolRunner(FakeCfg(d8), [], str(tmp))
    out = asyncio.run(r8.execute("set_target", {"url": "www.ftitle.studio"}, s8))
    check("目标已设定" in out, "set_target 正常返回")
    check(s8.result.target == "http://www.ftitle.studio",
          f"result.target 已同步（实={s8.result.target!r}）")
    out = asyncio.run(r8.execute("export_report", {"fmt": "md"}, s8))
    names8 = [p.name for p in d8.iterdir()]
    check(any("ftitle.studio" in n for n in names8),
          f"报告名含主域名（实={names8}）")
    check(not any(n.endswith("_target.md") for n in names8),
          "没有退化成 report_*_target.md")

    print("场景9 export_report 兜底同步（防御未来新增赋值路径漏同步）")
    d9 = tmp / "s9"
    d9.mkdir()
    s9 = Session(target="")
    s9.target = "https://api.ftitle.studio"  # 模拟只改了 session.target 的路径
    check(s9.result.target == "", "前置：result.target 为空")
    r9 = ToolRunner(FakeCfg(d9), [], str(tmp))
    asyncio.run(r9.execute("export_report", {"fmt": "md"}, s9))
    names9 = [p.name for p in d9.iterdir()]
    check(any("ftitle.studio" in n for n in names9),
          f"导出兜底把 session.target 补进了命名（实={names9}）")
    check(s9.result.target == "https://api.ftitle.studio",
          "导出后 result.target 已被兜底同步")

    print(f"\n结果：{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
