"""read_file 的 grep 定位模式回归测试。

背景：Agent 曾把 267 行的 app.js 当文档逐页通读（7 次调用），根因是
read_file 只有 start_line 没有定位手段。这个测试锁死 grep 行为：
命中行 + 上下文、context 边界、正则无效、翻页尾部引导语。
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.session import Session
from core.tools import ToolRunner
from core.tools.args import normalize_args

PASS = 0


def check(cond: bool, msg: str, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  OK   {msg}")
    else:
        print(f"  FAIL {msg}" + (f"（实={detail}）" if detail else ""))
        raise SystemExit(1)


class FakeCfg:
    class scan:
        readonly = False
        fs_ops_enabled = True
        evidence_dir = ""

    class rag:
        poc_dir = ""

    def __init__(self, root: Path):
        self.output_dir = str(root)
        self.data_dir = str(root)


JS = "\n".join(
    [f"// filler-{i}" for i in range(1, 60)]
    + ["function postData(payload) {",
       "  return fetch('/api/order', {method: 'POST', body: payload});",
       "}"]
    + [f"// tail-{i}" for i in range(60, 200)]
)


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "app.js").write_text(JS, encoding="utf-8")
    r = ToolRunner(FakeCfg(tmp), [], str(tmp))
    sess = Session(target="https://demo.example.com")

    print("场景1 grep 定位：一次拿到函数体，不用翻页")
    out = asyncio.run(r.execute("read_file", {"path": "app.js", "grep": "postData"}, sess))
    check("1 处命中" in out, "命中计数正确", out[:80])
    check("function postData" in out, "命中行在结果里")
    check("fetch('/api/order'" in out, "默认 context=3 覆盖函数体（第 61 行）")
    check("--- 第 60 行命中 ---" in out, "带行号锚点", out[:120])

    print("\n场景2 context 边界：0/1/超限")
    out0 = asyncio.run(r.execute(
        "read_file", {"path": "app.js", "grep": "postData", "context": 0}, sess))
    check("fetch('/api/order'" not in out0, "context=0 只给命中行本身（0 是合法值，不能被 or 吞掉）")
    out1 = asyncio.run(r.execute(
        "read_file", {"path": "app.js", "grep": "postData", "context": 1}, sess))
    check("fetch('/api/order'" in out1 and "// filler-58" not in out1,
          "context=1 只带前后各 1 行")
    out_big = asyncio.run(r.execute(
        "read_file", {"path": "app.js", "grep": "postData", "context": 999}, sess))
    check("// filler-40" in out_big and "// filler-39" not in out_big,
          "context 超限截到 20（命中行 60，边界取到第 40 行），不报错")

    print("\n场景3 异常输入")
    check("未找到" in asyncio.run(r.execute(
        "read_file", {"path": "app.js", "grep": "no-such-thing"}, sess)), "无命中时说清")
    check("grep 正则无效" in asyncio.run(r.execute(
        "read_file", {"path": "app.js", "grep": "["}, sess)), "非法正则不崩")
    n = normalize_args("read_file", {"path": "a", "grep": "x", "context": "5"})
    check(n["grep"] == "x" and n["context"] == 5,
          "normalize_args 认识 grep/context（schema 与 handler 同步的证据）", str(n))

    print("\n场景4 翻页模式尾部引导语")
    outp = asyncio.run(r.execute(
        "read_file", {"path": "app.js", "start_line": 1, "max_lines": 5}, sess))
    check("不要逐页翻" in outp and 'grep="' in outp, "尾部提示引导用 grep 定位")

    print(f"\n结果：{PASS} 项断言全过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
