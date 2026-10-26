"""一条命令跑完 scripts/ 下全部回归测试。

用法：
  .venv/Scripts/python.exe scripts/run_tests.py            # 全部
  .venv/Scripts/python.exe scripts/run_tests.py throttle   # 只跑名字含 throttle 的

收集规则：文件名以 `_test.py` 结尾。下划线开头、不带 `_test` 后缀的公共
测试设施不会被当成一个测试来跑。

为什么需要它：全量回归原本要手写
  for f in scripts/*_test.py; do python "$f" < /dev/null; done
其中 `< /dev/null` 漏一次就会挂在补全测试的等待输入上——表现得像"卡死"而不是失败。
本脚本固定重定向 stdin、加单脚本超时、汇总断言项数，把这两个坑焊死。
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
TIMEOUT = 300  # 单个脚本上限（秒），超时判失败而不是无限等

_ITEMS = re.compile(r"(\d+)\s*/\s*(\d+)\s*通过")


def run_one(path: Path) -> tuple[bool, str, int, int, float]:
    """跑一个脚本，返回 (是否通过, 结论文字, 通过项, 总项, 耗时秒)。"""
    t0 = time.time()
    try:
        p = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,   # 补全测试会读 stdin，必须堵死
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, f"超时（>{TIMEOUT}s）", 0, 0, time.time() - t0

    out = (p.stdout or "") + (p.stderr or "")
    hits = _ITEMS.findall(out)
    ok_n, all_n = (int(hits[-1][0]), int(hits[-1][1])) if hits else (0, 0)
    fails = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("FAIL")]
    if p.returncode != 0 or fails:
        detail = fails[0] if fails else f"退出码 {p.returncode}"
        return False, detail, ok_n, all_n, time.time() - t0
    verdict = f"{ok_n}/{all_n} 通过" if all_n else "通过（未报告项数）"
    return True, verdict, ok_n, all_n, time.time() - t0


def main(argv: list[str]) -> int:
    kw = argv[1] if len(argv) > 1 else ""
    tests = sorted(HERE.glob("*_test.py"))
    if kw:
        tests = [t for t in tests if kw.lower() in t.name.lower()]
    if not tests:
        print(f"没找到匹配的 *_test.py（关键字={kw!r}）")
        return 1

    print(f"待跑 {len(tests)} 个脚本，单脚本超时 {TIMEOUT}s\n")
    ok_files = ok_items = all_items = 0
    bad: list[tuple[str, str]] = []
    t0 = time.time()
    for t in tests:
        good, verdict, o, a, dt = run_one(t)
        ok_files += int(good)
        ok_items += o
        all_items += a
        print(f"  {'OK  ' if good else 'FAIL'} {t.name:<32} {verdict}  ({dt:>5.1f}s)")
        if not good:
            bad.append((t.name, verdict))

    print()
    for name, v in bad:
        print(f"失败：{name} —— {v}")
    print(
        f"合计 {len(tests)} 文件 / {ok_files} 个全过 / 断言 {ok_items}/{all_items} 项"
        f"，用时 {time.time() - t0:.1f}s"
    )
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
