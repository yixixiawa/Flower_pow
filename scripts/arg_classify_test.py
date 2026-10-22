"""_classify_arg 参数归类回归测试。

背景：external.py 的 _looks_like_target 与 base.py 的 _looks_like_path
判断标准重叠、答案不互斥（http://x/y 两个都说是），合并为 _classify_arg。
这个测试锁死**合并前后的行为等价**：旧 _validate_argv 的分支顺序是
先 target 后 path，新实现必须逐例一致。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.tools.pathscan import _NOISE_EXACT
from core.tools.runner.base import _classify_arg

PASS = TOTAL = 0


def check(cond: bool, msg: str, detail: str = "") -> None:
    global PASS, TOTAL
    TOTAL += 1
    if cond:
        PASS += 1
        print(f"  OK   {msg}")
    else:
        print(f"  FAIL {msg}" + (f"（实={detail}）" if detail else ""))
        raise SystemExit(1)


def main() -> int:
    print("场景1 target：URL 与纯主机")
    # 注意 "a.b" / "notes.md" 这类**含点但不含分隔符**的值归 target——
    # 旧 _validate_argv 就是先查 target，它们到不了 path 分支。
    # 行为保持优先于"直觉上它像个文件名"。
    for a in ("http://x.com/y", "https://a.b.c:8443/p?q=1", "192.168.1.1",
              "example.com", "a.b", "notes.md"):
        check(_classify_arg(a) == "target", f"{a!r} → target", _classify_arg(a))

    print("\n场景2 path：路径前缀 / 盘符 / 含分隔符 / 已知扩展名")
    for a in ("/etc/passwd", "./rel.txt", "../up.json", "~/x",
              "C:\\Windows\\x", "dir/sub/file", "back\\\\win", "dir/notes.md"):
        check(_classify_arg(a) == "path", f"{a!r} → path", _classify_arg(a))

    print("\n场景3 other：模板 id / 关键词 / 空值")
    for a in ("cve-2021-44228", "http-missing-security-headers", "", "keyword"):
        check(_classify_arg(a) == "other", f"{a!r} → other", _classify_arg(a))

    print("\n场景4 target 优先于 path（与旧 _validate_argv 分支顺序一致）")
    # http://x/y 含 / ，但 scheme 在先 → target，不会被当成路径拒绝
    check(_classify_arg("http://x/y") == "target", "带 scheme 的 URL 永远先是 target")
    # 含点的路径（./a.b/c）target 判定要求不含 / → 落 path
    check(_classify_arg("./a.b/c") == "path", "含点的路径仍归 path")

    print("\n场景5 _NOISE_EXACT 源码无重复条目（集合会自动去重，重复写是噪音）")
    import re as _re
    src = Path(__file__).resolve().parent.parent.joinpath(
        "core", "tools", "pathscan.py").read_text(encoding="utf-8")
    m = _re.search(r"_NOISE_EXACT = \{(.*?)\}", src, _re.S)
    items = _re.findall(r'"([^"]+)"', m.group(1))
    dupes = sorted({x for x in items if items.count(x) > 1})
    check(not dupes, f"无重复字面量（实={dupes}）")
    check(len(_NOISE_EXACT) == len(set(_NOISE_EXACT)), "运行时集合本身无重复")

    print(f"\n结果：{PASS}/{TOTAL} 通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
