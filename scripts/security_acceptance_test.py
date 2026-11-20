"""安全验收机制自身的测试（元测试）。

验证的不是"产品安全"，而是**验收结论不能被造出来**：

* 用例谎报成功（观测与预期不符）→ FAIL；
* 断言数低于基线 → FAIL；
* 没执行 → NOT_TESTED，且整体不得判 SECURITY_PASS；
* P0 失败 → 整体 FAIL；P1 失败 → 整体也不得标完整通过；
* 删掉需求/负向用例/安全用例 → 完整性检查报错；
* 报告必须包含验收规则要求的全部列。

运行：.venv/Scripts/python.exe scripts/security_acceptance_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.acceptance import catalog, harness, report  # noqa: E402
from scripts.acceptance.gateway import GatewayTracer  # noqa: E402
from scripts.acceptance.model import (  # noqa: E402
    FAIL,
    INCONCLUSIVE,
    INTEGRATION_PASS,
    NOT_TESTED,
    SECURITY_PASS,
    UNIT_PASS,
    CaseResult,
    CaseSpec,
    Requirement,
    grade_requirement,
)

PASS = 0
FAILED: list[str] = []


def ok(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name}")


_REQ = Requirement(
    "R-TEST", "元测试需求", "P0", "测试边界", ("policy/api_policy.py",),
)
_SPEC = CaseSpec(
    "C-TEST", "R-TEST", "元测试用例", "security",
    "scripts.acceptance.cases_policy:unknown_command_denied",
    expect={"http_sent": False}, negative=True, min_assertions=1,
)


def test_lying_case_fails() -> None:
    """用例自己说"全过"，但观测显示请求真的发出去了 → 必须 FAIL。"""
    r = CaseResult(
        spec=_SPEC, executed=True, assertions_total=1, assertions_passed=1,
        http_sent=True,
    )
    harness._evaluate(r, 0)
    ok(r.status == FAIL, f"观测与预期不符必须 FAIL，实际 {r.status}")
    ok("观测与预期不符" in r.reason, f"失败原因应说明预期不符：{r.reason}")


def test_assertion_drop_fails() -> None:
    """删掉断言、把总数降到基线以下 → 必须 FAIL。"""
    r = CaseResult(
        spec=_SPEC, executed=True, assertions_total=2, assertions_passed=2,
    )
    harness._evaluate(r, 5)
    ok(r.status == FAIL, f"断言数低于基线必须 FAIL，实际 {r.status}")
    ok("基线" in r.reason, "失败原因应指向基线")


def test_not_tested_never_passes() -> None:
    r = CaseResult(spec=_SPEC)  # 没有执行
    harness._evaluate(r, 0)
    ok(r.status == NOT_TESTED, f"未执行必须是 NOT_TESTED，实际 {r.status}")

    suite = harness.evaluate_suite(
        [r], [_REQ], GatewayTracer(), [], [], time.time(),
    )
    ok(suite.overall == INCONCLUSIVE,
       f"P0 未执行时整体不得通过，实际 {suite.overall}")
    ok(suite.requirement_status["R-TEST"] == NOT_TESTED,
       "需求级也不得把 NOT_TESTED 升级")


def test_p0_fail_blocks_all() -> None:
    r = CaseResult(
        spec=_SPEC, executed=True, assertions_total=1, assertions_passed=0,
        failed_labels=["负向断言失败"],
    )
    harness._evaluate(r, 0)
    ok(r.status == FAIL, "断言失败应为 FAIL")
    suite = harness.evaluate_suite(
        [r], [_REQ], GatewayTracer(), [], [], time.time(),
    )
    ok(suite.overall == FAIL, f"P0 失败整体必须 FAIL，实际 {suite.overall}")


def test_p1_fail_not_full_pass() -> None:
    req = Requirement("R-P1", "P1 需求", "P1", "边界", ("x.py",))
    spec = CaseSpec(
        "C-P1", "R-P1", "P1 用例", "security",
        "scripts.acceptance.cases_policy:unknown_command_denied",
        expect={}, negative=True, min_assertions=1,
    )
    r = CaseResult(
        spec=spec, executed=True, assertions_total=1, assertions_passed=0,
        failed_labels=["boom"],
    )
    harness._evaluate(r, 0)
    suite = harness.evaluate_suite(
        [r], [req], GatewayTracer(), [], [], time.time(),
    )
    ok(suite.overall == FAIL, "P1 失败也不得标完整通过")
    ok(any("P1" in x for x in suite.reasons), "结论应明确是 P1 问题")


def test_grade_requires_security_case() -> None:
    ok(grade_requirement(["unit"], [UNIT_PASS]) == UNIT_PASS,
       "只有单元用例 → UNIT_PASS")
    ok(grade_requirement(["unit", "security"], [UNIT_PASS, SECURITY_PASS])
       == SECURITY_PASS, "有安全用例且全过 → SECURITY_PASS")
    ok(grade_requirement(["security"], [NOT_TESTED]) == NOT_TESTED,
       "未测不得升级")
    ok(grade_requirement(["security"], [INCONCLUSIVE]) == INCONCLUSIVE,
       "不确定不得升级")
    ok(grade_requirement(["integration", "security"],
                         [INTEGRATION_PASS, SECURITY_PASS]) == SECURITY_PASS,
       "集成 + 安全全过 → SECURITY_PASS")


def test_integrity_catches_deletion() -> None:
    orig_req = catalog.REQUIREMENTS
    orig_cases = catalog.CASES
    try:
        # 只留一条"纯单元、非负向"的用例：必须报缺负向、缺安全用例
        catalog.REQUIREMENTS = [
            Requirement("R-ONLY", "只剩单元测试", "P0", "边界", ("x.py",)),
        ]
        catalog.CASES = [
            CaseSpec(
                "C-ONLY", "R-ONLY", "只有单元", "unit",
                "scripts.acceptance.cases_policy:unknown_command_denied",
                expect={}, negative=False, min_assertions=1,
            ),
        ]
        errs = catalog.check_integrity()
        joined = "\n".join(errs)
        ok("缺少负向用例" in joined, "删掉负向用例必须被完整性检查发现")
        ok("缺少 SECURITY" in joined, "删掉安全用例必须被完整性检查发现")
        ok("必需需求缺失" in joined, "删掉需求必须被完整性检查发现")
    finally:
        catalog.REQUIREMENTS = orig_req
        catalog.CASES = orig_cases


def test_skip_marker_detected() -> None:
    # 标记串拼出来，避免本文件自己触发"跳过标记"扫描（反作弊扫描会读源码）
    skip_marker = "pytest.mark." + "skip"
    unittest_marker = "unittest." + "skip('x')"
    ok(catalog._SKIP_RE.search(skip_marker) is not None,
       "必须能识别 pytest 跳过标记")
    ok(catalog._SKIP_RE.search(unittest_marker) is not None,
       "必须能识别 unittest 跳过标记")
    ok(catalog._SKIP_RE.search("def test_ok():\n    assert True") is None,
       "正常用例不应被误报")


def test_baseline_complete() -> None:
    base, missing = catalog.load_baseline()
    ok(not missing, f"基线必须覆盖全部用例，缺 {missing[:5]}")
    ok(len(base) == len(catalog.CASES),
       f"基线条目数应等于用例数（{len(base)} vs {len(catalog.CASES)}）")
    ok(all(base.get(c.id, 0) >= c.min_assertions for c in catalog.CASES),
       "基线不得低于用例声明的最低断言数")


def test_real_catalog_integrity() -> None:
    errs = catalog.check_integrity()
    ok(not errs, f"当前目录必须完整性通过，实际：{errs[:3]}")
    ids = [c.id for c in catalog.CASES]
    ok(len(ids) == len(set(ids)), "用例 ID 必须唯一")
    ok(all(c.req in {r.id for r in catalog.REQUIREMENTS} for c in catalog.CASES),
       "每条用例都必须挂在存在的需求下")


def test_report_columns() -> None:
    r = CaseResult(
        spec=_SPEC, executed=True, assertions_total=1, assertions_passed=1,
    )
    harness._evaluate(r, 0)
    req = Requirement("R-TEST", "元测试需求", "P0", "测试边界",
                      ("policy/api_policy.py",))
    suite = harness.evaluate_suite(
        [r], [req], GatewayTracer(), [], [], time.time(),
    )
    md = report.render_markdown(suite, [req])
    for col in (
        "测试需求 ID", "对应源代码文件", "测试案例名称", "测试类型",
        "实际执行情况", "预期结果", "实际结果", "HTTP 是否实际发出",
        "失败原因", "尚未覆盖的风险", "最终验收状态",
    ):
        ok(col in md, f"报告必须包含列：{col}")
    ok("SECURITY_ACCEPTANCE" not in md, "报告不应把内部标记当正文列")


def test_no_ungoverned_blocks_gateway() -> None:
    """全程出现绕过 Gateway 的发送 → REQ-GATEWAY 必须 FAIL（不论用例怎么说）。"""
    spec = CaseSpec(
        "C-GW", "REQ-GATEWAY", "出口", "security",
        "scripts.acceptance.cases_policy:unknown_command_denied",
        expect={"http_sent": True}, negative=False, min_assertions=0,
    )
    r = CaseResult(
        spec=spec, executed=True, assertions_total=0, assertions_passed=0,
        http_sent=True,
    )
    harness._evaluate(r, 0)
    tracer = GatewayTracer()
    tracer.sends.append({"governed": False, "method": "GET", "url": "http://x/"})
    req = Requirement("REQ-GATEWAY", "统一出口", "P0", "边界", ("core/proxy.py",))
    suite = harness.evaluate_suite([r], [req], tracer, [], [], time.time())
    ok(suite.overall == FAIL, "存在未治理出口时整体必须 FAIL")
    ok(suite.requirement_status["REQ-GATEWAY"] == FAIL,
       "REQ-GATEWAY 必须被事实判 FAIL")


def main() -> int:
    test_lying_case_fails()
    test_assertion_drop_fails()
    test_not_tested_never_passes()
    test_p0_fail_blocks_all()
    test_p1_fail_not_full_pass()
    test_grade_requires_security_case()
    test_integrity_catches_deletion()
    test_skip_marker_detected()
    test_baseline_complete()
    test_real_catalog_integrity()
    test_report_columns()
    test_no_ungoverned_blocks_gateway()
    print(f"\n验收机制自测 {PASS}/{PASS} 通过"
          + (f"（另有 {len(FAILED)} 项失败）" if FAILED else ""))
    for name in FAILED:
        print(f"  - {name}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
