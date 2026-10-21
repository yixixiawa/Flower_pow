"""拦截降速重试的端到端验证——用假 dirsearch 脚本模拟 WAF 行为。

不依赖网络：生成一个 Python 脚本冒充 dirsearch，按环境变量决定
「第一次全拦、第二次放行」，验证 runner 是否真的从 -t 10 切到 -t 1。
"""

import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.dirsearch_runner import (  # noqa: E402
    build_argv,
    looks_blocked,
    run_with_throttle_retry,
)

# ── 假 dirsearch：第一次输出 429/403（WAF），第二次输出正常 200 ──
FAKE = r'''#!__PYTHON__
import json, os, sys
out = None
threads = None
for i, a in enumerate(sys.argv):
    if a == "-o" and i + 1 < len(sys.argv): out = sys.argv[i + 1]
    if a == "-t" and i + 1 < len(sys.argv): threads = sys.argv[i + 1]
marker = os.environ["FAKE_DIRSEARCH_MARKER"]
first = not os.path.exists(marker)
if first:
    open(marker, "w").close()
mode = os.environ.get("FAKE_MODE", "block-then-pass")
if mode == "block-then-pass":
    rows = ([{"url": "http://t/x%d" % i, "statusCode": 429, "contentLength": 100} for i in range(30)]
            + [{"url": "http://t/cdn-cgi/challenge", "statusCode": 403, "contentLength": 80} for _ in range(5)]
            ) if first else [{"url": "http://t/admin", "statusCode": 200, "contentLength": 500},
                             {"url": "http://t/login", "statusCode": 200, "contentLength": 400}]
elif mode == "always-block":
    rows = [{"url": "http://t/cdn-cgi/challenge", "statusCode": 403, "contentLength": 80} for _ in range(20)]
elif mode == "always-pass":
    rows = [{"url": "http://t/admin", "statusCode": 200, "contentLength": 500}]
else:
    rows = []
json.dump({"results": rows}, open(out, "w"))
print("THREADS_USED=%s FIRST=%s" % (threads, first))
'''


def make_fake(tmp: Path) -> Path:
    # 用 replace 而非 format：fake 脚本里有大量 JSON 花括号，format 会把它们当占位符
    p = tmp / "fakedirsearch.py"
    p.write_text(FAKE.replace("__PYTHON__", sys.executable), encoding="utf-8")
    cmd = tmp / "fakedirsearch.cmd"
    cmd.write_text(f'@"{sys.executable}" "{p}" %*\n', encoding="utf-8")
    return cmd


async def main() -> int:
    ok = 0
    total = 0

    def check(cond, label, extra="") -> None:
        """与其余 20 个回归脚本一致的断言入口。"""
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        exe = str(make_fake(tmp))
        marker = str(tmp / "marker")

        # 1. 首次被拦 → 应降速到 1 并重试成功
        os.environ["FAKE_DIRSEARCH_MARKER"] = marker
        os.environ["FAKE_MODE"] = "block-then-pass"
        ev: list[dict] = []
        oc = await run_with_throttle_retry(
            exe, targets=["http://t"], dictionary_size=120, threads=10,
            timeout=60, max_retries=1, on_event=lambda k, v: ev.append({"kind": k, **v}),
        )
        good = (
            oc.attempts == [10, 1]
            and oc.throttled
            and oc.total == 2
            # 降速重试成功了，block_reasons 里不该出现"无拦截特征"
            and oc.block_reasons
            and not any("无拦截特征" in r for r in oc.block_reasons)
        )
        check(good, "场景1 首次拦截→降速重试")
        print(f"        线程尝试={oc.attempts} 降速={oc.throttled} 命中={oc.total}")
        print(f"        理由={oc.block_reasons}")
        print(f"        事件={[e['kind'] for e in ev]}")

        # 2. 一直被拦 → 单线程后如实返回，不无限重试
        os.environ["FAKE_DIRSEARCH_MARKER"] = str(tmp / "m2")
        os.environ["FAKE_MODE"] = "always-block"
        ev2: list[dict] = []
        oc2 = await run_with_throttle_retry(
            exe, targets=["http://t"], dictionary_size=120, threads=10,
            timeout=60, max_retries=1, on_event=lambda k, v: ev2.append({"kind": k, **v}),
        )
        good2 = (
            oc2.attempts == [10, 1]
            and "dirsearch_still_blocked" in {e["kind"] for e in ev2}
            and "dirsearch_throttle" in {e["kind"] for e in ev2}
            # 两次都是同一个原因，不该重复记两条
            and len(oc2.block_reasons) == len(set(oc2.block_reasons))
            and not any("无拦截特征" in r for r in oc2.block_reasons)
        )
        check(good2, "场景2 持续拦截→单线程后停止")
        print(f"        线程尝试={oc2.attempts}")
        print(f"        事件={[e['kind'] for e in ev2]}")
        print(f"        理由={oc2.block_reasons}")

        # 3. 首次就通过 → 不应重试
        os.environ["FAKE_DIRSEARCH_MARKER"] = str(tmp / "m3")
        os.environ["FAKE_MODE"] = "always-pass"
        ev3: list[dict] = []
        oc3 = await run_with_throttle_retry(
            exe, targets=["http://t"], dictionary_size=120, threads=10,
            timeout=60, max_retries=1, on_event=lambda k, v: ev3.append({"kind": k, **v}),
        )
        good3 = oc3.attempts == [10] and not oc3.throttled and oc3.total == 1
        check(good3, "场景3 首次通过→不重试")
        print(f"        线程尝试={oc3.attempts} 降速={oc3.throttled} 命中={oc3.total}")

        # 4. argv 校验：-t 1 时必须带降速三件套
        a1 = build_argv("dirsearch", ["http://t"], threads=1)
        a10 = build_argv("dirsearch", ["http://t"], threads=10)
        good4 = (
            a1[a1.index("-t") + 1] == "1"
            and "--delay" in a1 and "--max-rate" in a1 and "--retries" in a1
            and "--delay" not in a10
        )
        check(good4, "场景4 argv 降速参数")
        print(f"        -t 1  : {' '.join(a1[a1.index('-t'):])}")
        print(f"        -t 10 : {' '.join(a10[a10.index('-t'):a10.index('-t')+3])}...")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
