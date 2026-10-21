"""外部工具大输出落盘（spill）的回归测试。

复现的真实事故：模型用 curl 抓回一个 101KB 的库文件，输出被截断在
6000 字符，剩余部分**没有任何查看手段**——模型只好反复试
``curl -w %{json}`` / ``%{stdout}`` / ``%{http_code}``…… 连打十几次，
换取值就是新指纹，死循环检测也拦不住，一轮轮空转烧额度。

修复：``external_tool`` 输出超长时把**完整内容落盘**到
``output/tool-output/``，截断提示里给出路径和 ``read_file`` 分页用法。
内置工具**不落盘**（它们的输出是自己设计的分页视图，落盘会让
read_file 读 spill 文件再被截断再 spill，无限派生垃圾文件）。

覆盖：
  1. external_tool 超长 → 落盘 + 提示含路径与 read_file 用法 + 文件内容完整
  2. 超长单行被折行（单行几万字符的库文件/JSON 才有分页的意义）
  3. spill 文件能被 read_file 正常分页读取（.txt 在沙箱白名单内）
  4. 内置工具超长 → 纯截断、**不落盘**（防无限派生）
  5. read_file 自身超长 → 不落盘、提示换 start_line 翻页
  6. 落盘失败（目录建不了）→ 退化为纯截断，不报错不崩
  7. 连续多次 spill 文件名不撞

运行：.venv/Scripts/python.exe scripts/test_output_spill.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session  # noqa: E402
from core.tools import MAX_TOOL_OUTPUT, ToolRunner  # noqa: E402


class FakeCfg:
    def __init__(self, root: Path, **scan_kw) -> None:
        self.output_dir = str(root)
        self.scan = ScanConfig(**scan_kw)

    class rag:
        poc_dir = "./poc"


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
    sess = Session(target="https://demo.example.com")
    runner = ToolRunner(FakeCfg(root), [], str(tmp))

    print("场景1 external_tool 超长 → 完整落盘 + 出路提示")
    # 模拟 curl 拉回 101KB：多行 + 一条超长行（库文件常见形态）
    big = "\n".join(f"line {i} " + "x" * 50 for i in range(200))
    big += "\n" + ("PAYLOAD_" + "y" * 30000 + "_TAIL_FLAG")

    async def fake_ext(session, **kw):
        return big

    runner._h_external_tool = fake_ext  # 实例属性盖掉类方法
    out = asyncio.run(runner.execute("external_tool", {"tool": "curl", "args": []}, sess))
    check("完整输出已保存到" in out, "截断提示给出了落盘路径")
    check("read_file" in out and "start_line" in out, "提示里给了 read_file 分页用法")
    check("curl -w" in out, "明确劝阻再用 -w 碰运气")
    spills = list((root / "tool-output").glob("*.txt"))
    check(len(spills) == 1, f"落盘了一个文件，实={len(spills)}")
    content = spills[0].read_text(encoding="utf-8")
    # 折行只插入换行：去掉换行后必须与原输出**逐字符一致**
    check(
        content.replace("\n", "") == big.replace("\n", ""),
        "落盘内容完整（折行不丢字符）",
    )
    check("_TAIL_FLAG" in content, "尾部内容（被截断的部分）在文件里")
    check(out.index("完整输出已保存到") > MAX_TOOL_OUTPUT,
          "回灌给模型的部分仍被截断在上限内（上下文保护没破）")

    print("场景2 超长单行被折行，read_file 才有分页意义")
    check(all(len(ln) <= 2000 for ln in content.splitlines()),
          "落盘文件每行 ≤ 2000 字符")

    print("场景3 spill 文件能被 read_file 分页读取")
    rel = f"tool-output/{spills[0].name}"
    page1 = asyncio.run(runner.execute(
        "read_file", {"path": rel, "start_line": 1, "max_lines": 3}, sess))
    check("line 0" in page1, "第一页能读到开头")
    # 翻到尾部（超长行折成的段）确认能看到 flag
    total_lines = len(content.splitlines())
    tail_page = asyncio.run(runner.execute(
        "read_file",
        {"path": rel, "start_line": total_lines - 2, "max_lines": 3}, sess))
    check("_TAIL_FLAG" in tail_page, "翻页能读到被截断的尾部")

    print("场景4 内置工具超长 → 纯截断、不落盘")
    before = set((root / "tool-output").glob("*.txt"))

    async def fake_builtin(session, **kw):
        return "z" * (MAX_TOOL_OUTPUT + 5000)

    runner._h_fake_big = fake_builtin
    out = asyncio.run(runner.execute("fake_big", {}, sess))
    check("结果过长已截断" in out, "内置工具超长仍有截断提示")
    check("完整输出已保存到" not in out, "内置工具**不落盘**（防派生垃圾）")
    after = set((root / "tool-output").glob("*.txt"))
    check(after == before, "没有产生新的 spill 文件")

    print("场景5 read_file 自身超长 → 不落盘、提示翻页")
    big_md = root / "big.md"
    big_md.write_text("\n".join(f"row {i} " + "q" * 80 for i in range(500)),
                      encoding="utf-8")
    out = asyncio.run(runner.execute(
        "read_file", {"path": "big.md", "start_line": 1, "max_lines": 400}, sess))
    check("完整输出已保存到" not in out, "read_file 结果不落盘")
    check("start_line" in out, "截断提示指了翻页这个出路")
    after = set((root / "tool-output").glob("*.txt"))
    check(after == before, "read_file 没有派生新 spill 文件")

    print("场景6 落盘失败 → 退化为纯截断，不崩")
    bad = ToolRunner(FakeCfg(Path("Z:/不存在的盘/肯定建不了")), [], str(tmp))

    async def fake_ext2(session, **kw):
        return "w" * (MAX_TOOL_OUTPUT + 100)

    bad._h_external_tool = fake_ext2
    out = asyncio.run(bad.execute("external_tool", {"tool": "curl", "args": []}, sess))
    check("结果过长已截断" in out, "落盘失败仍返回截断文本")
    check("落盘失败" in out, "如实说明落盘失败", f"实={out[-40:]!r}")

    print("场景7 连续 spill 文件名不撞")
    out2 = asyncio.run(runner.execute("external_tool", {"tool": "curl", "args": []}, sess))
    check("完整输出已保存到" in out2, "第二次 spill 成功")
    spills = list((root / "tool-output").glob("*.txt"))
    check(len(spills) == 2, f"两次 spill 两个文件，实={len(spills)}")

    print(f"\n结果：{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
