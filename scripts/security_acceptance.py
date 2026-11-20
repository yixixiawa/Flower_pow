"""安全验收入口：按需求出结论，不看"pytest 是否全绿"。

用法::

    .venv/Scripts/python.exe scripts/security_acceptance.py
    .venv/Scripts/python.exe scripts/security_acceptance.py --only REQ-REDIRECT
    .venv/Scripts/python.exe scripts/security_acceptance.py --init-baseline
    .venv/Scripts/python.exe scripts/security_acceptance.py --json

退出码：0 = SECURITY_PASS；1 = FAIL / INCONCLUSIVE。

**只有**同时满足下列条件才会给 SECURITY_PASS：
必要测试全部执行、断言全过、负向路径覆盖、所有出网请求经统一 Gateway、
无已知策略旁路、结果有可追溯的执行记录（报告落盘）。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.acceptance import catalog, harness, report  # noqa: E402
from scripts.acceptance.model import (  # noqa: E402
    FAIL,
    INCONCLUSIVE,
    NOT_TESTED,
    PASS_STATES,
    SECURITY_PASS,
)


def _print_summary(suite) -> None:
    print()
    print(f"{'需求':<22}{'等级':<6}{'状态':<20}用例")
    print("-" * 72)
    for req in catalog.REQUIREMENTS:
        mine = [r for r in suite.results if r.spec.req == req.id]
        passed = sum(1 for r in mine if r.status in PASS_STATES)
        st = suite.requirement_status.get(req.id, NOT_TESTED)
        print(f"{req.id:<22}{req.severity:<6}{st:<20}{passed}/{len(mine)}")
    print("-" * 72)
    total = len(suite.results)
    ok = sum(1 for r in suite.results if r.status in PASS_STATES)
    bad = sum(1 for r in suite.results if r.status == FAIL)
    unknown = sum(1 for r in suite.results if r.status in (NOT_TESTED, INCONCLUSIVE))
    print(f"用例 {ok}/{total} 通过；失败 {bad}；未测/不确定 {unknown}；"
          f"耗时 {suite.duration:.1f}s")
    bad_cases = [r for r in suite.results
                 if r.status in (FAIL, INCONCLUSIVE, NOT_TESTED)]
    if bad_cases:
        print("未通过用例：")
        for r in bad_cases:
            print(f"  - [{r.status}] {r.spec.id} {r.spec.name}")
            print(f"      {r.reason}")
    if suite.integrity:
        print("完整性检查失败：")
        for e in suite.integrity:
            print(f"  - {e}")
    print()
    print(f"整体判定：{suite.overall}")
    for reason in suite.reasons:
        print(f"  - {reason}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="flower_pow 安全验收")
    ap.add_argument("--only", default="", help="只跑某个需求/用例 ID（调试用）")
    ap.add_argument("--init-baseline", action="store_true", help="生成断言数基线后退出")
    ap.add_argument("--json", action="store_true", help="把 JSON 报告打到 stdout")
    ap.add_argument("--no-report", action="store_true", help="不写报告文件")
    ap.add_argument("--out", default=str(ROOT / "reports"), help="报告目录")
    args = ap.parse_args(argv)

    if args.init_baseline:
        path = catalog.write_baseline()
        print(f"断言数基线已写入：{path}（{len(catalog.CASES)} 个用例）")
        return 0

    suite = harness.run_all(only=args.only)

    if args.json:
        print(json.dumps(report.render_json(suite, catalog.REQUIREMENTS),
                         ensure_ascii=False, indent=2))
    else:
        _print_summary(suite)

    if not args.no_report:
        md, js = report.write_report(suite, catalog.REQUIREMENTS, Path(args.out))
        print()
        print(f"报告：{md}")
        print(f"      {js}")

    print(f"SECURITY_ACCEPTANCE: {suite.overall}")
    return 0 if suite.overall == SECURITY_PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
