"""安全测试验收机制（第七轮整改）：**回归全绿 ≠ 安全通过**。

为什么单独立一套
----------------
``scripts/run_tests.py`` 的结论是"断言有没有过"。它回答不了四个问题：

1. 这条安全边界**到底测没测**（没测和测了通过，输出都是"0 失败"）；
2. 拒绝路径测没测（只测"该放行的放行了"，永远发现不了越权）；
3. 被拦的请求**是不是真的没发出去**（只看函数返回值，拦截逻辑写在
   发送之后也能"通过"）；
4. 结果能不能追溯（谁在什么代码版本上跑的、哪些项没覆盖）。

本模块是验收的**判定器**，不含任何被测代码的调用逻辑：

* :class:`Case` / :class:`Assertion` —— 一条测试用例的结构化记录；
* :class:`Requirement` —— 一条安全需求（可含多条用例、多种类型）；
* :class:`AcceptanceReport` —— 总体结论与可追溯执行记录；
* :func:`render_markdown` —— 固定 11 字段的验收报告；
* :func:`verify_baseline` —— 反作弊：用例被删/预期被改/断言被削弱即告警。

六级状态（**不得把 NOT_TESTED / INCONCLUSIVE 自动转成 PASS**）
--------------------------------------------------------------
=============== ==================================================
UNIT_PASS       单元逻辑测试通过（只证明函数返回值）
INTEGRATION_PASS 跨模块集成通过（证明模块之间接上了）
SECURITY_PASS   安全边界与绕过测试通过（必须含拒绝路径 + 真实网络观测）
FAIL            至少一项必要断言失败
NOT_TESTED      没有执行必要测试
INCONCLUSIVE    执行了，但证据不足以判断（断言缺项/HTTP 未观测/基线被改）
=============== ==================================================

总体验收（四、最终验收规则）
----------------------------
``SECURITY_PASS`` 需要同时满足：必要用例全部执行、断言全过、负向路径覆盖、
网络出口全部纳管、无已知旁路、有可追溯执行记录。任一 P0 用例 FAIL →
总体 FAIL；任一 P1 用例 FAIL → 同样不得判 SECURITY_PASS（``full_pass``
为 False）。判定逻辑在 :meth:`AcceptanceReport.verdict`，不允许调用方
自己拼结论。
"""

from __future__ import annotations

import hashlib
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


class TestStatus:
    """六级验收状态（字符串枚举，直接进报告）。"""

    UNIT_PASS = "UNIT_PASS"
    INTEGRATION_PASS = "INTEGRATION_PASS"
    SECURITY_PASS = "SECURITY_PASS"
    FAIL = "FAIL"
    NOT_TESTED = "NOT_TESTED"
    INCONCLUSIVE = "INCONCLUSIVE"

    ALL = (
        UNIT_PASS, INTEGRATION_PASS, SECURITY_PASS,
        FAIL, NOT_TESTED, INCONCLUSIVE,
    )
    PASS_LIKE = (UNIT_PASS, INTEGRATION_PASS, SECURITY_PASS)

    @classmethod
    def is_pass(cls, status: str) -> bool:
        return status in cls.PASS_LIKE


class Kind:
    """测试类型。安全用例必须覆盖拒绝路径才算 SECURITY_PASS。"""

    UNIT = "unit"
    INTEGRATION = "integration"
    SECURITY = "security"

    ALL = (UNIT, INTEGRATION, SECURITY)


class Severity:
    """失败影响面。P0 失败 → 整体 FAIL；P1 失败 → 不得判完整通过。"""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"

    ALL = (P0, P1, P2)


@dataclass(slots=True)
class Assertion:
    """一条断言。``passed=None`` 表示**没能验证**（证据不足，不是通过）。"""

    name: str
    expected: str
    actual: str = ""
    passed: bool | None = None
    detail: str = ""


@dataclass
class Case:
    """一条测试用例的结构化结果。

    ``probe_http=True`` 的用例必须给出 ``http_sent`` 观测，否则判
    INCONCLUSIVE——"函数返回了拒绝"不等于"请求没发出去"。
    """

    req_id: str
    name: str
    kind: str
    sources: list[str]
    expected: str
    severity: str = Severity.P1
    probe_http: bool = False
    negative_covered: bool = False
    executed: bool = False
    assertions: list[Assertion] = field(default_factory=list)
    http_sent: bool | None = None          # 是否真的有请求到达服务端
    network_side_effect: bool | None = None  # 被拒路径是否产生任何网络副作用
    gateway: str = ""                      # 实际经过的出口（如 core.gateway）
    audit_ok: bool | None = None           # 拒绝事件是否写入审计
    error: str = ""                        # 用例执行异常（= FAIL）
    residual: str = ""                     # 尚未覆盖的风险

    # ── 构造便捷方法 ────────────────────────────────────────────
    def check(
        self, name: str, expected: str, actual: Any, passed: bool | None,
        detail: str = "",
    ) -> Assertion:
        a = Assertion(
            name=name, expected=expected, actual=str(actual),
            passed=passed, detail=detail,
        )
        self.assertions.append(a)
        return a

    def fail(self, reason: str) -> None:
        """记一条失败断言并保留原因（用例继续跑完，便于一次看全）。"""
        self.check("用例执行", "无异常", reason, False, detail=reason)

    # ── 判定 ────────────────────────────────────────────────────
    @property
    def status(self) -> str:
        if self.error:
            return TestStatus.FAIL
        if not self.executed:
            return TestStatus.NOT_TESTED
        if not self.assertions:
            return TestStatus.INCONCLUSIVE
        if any(a.passed is False for a in self.assertions):
            return TestStatus.FAIL
        if any(a.passed is None for a in self.assertions):
            return TestStatus.INCONCLUSIVE
        if self.probe_http and self.http_sent is None:
            # 只看了返回值，没有网络观测 → 不足以判安全通过
            return TestStatus.INCONCLUSIVE
        if self.kind == Kind.UNIT:
            return TestStatus.UNIT_PASS
        if self.kind == Kind.INTEGRATION:
            return TestStatus.INTEGRATION_PASS
        if not self.negative_covered:
            # 安全用例没覆盖拒绝路径 → 不能算安全通过
            return TestStatus.INCONCLUSIVE
        if self.audit_ok is False:
            # 拒绝未留痕：可追溯性不成立
            return TestStatus.INCONCLUSIVE
        return TestStatus.SECURITY_PASS

    @property
    def failures(self) -> list[Assertion]:
        return [a for a in self.assertions if a.passed is False]


@dataclass
class Requirement:
    """一条安全需求。``requires_security`` 的需求必须至少一条安全用例通过。"""

    req_id: str
    title: str
    sources: list[str]
    cases: list[Case] = field(default_factory=list)
    requires_security: bool = True
    residual: str = ""

    @property
    def status(self) -> str:
        if not self.cases:
            return TestStatus.NOT_TESTED
        statuses = [c.status for c in self.cases]
        if TestStatus.FAIL in statuses:
            return TestStatus.FAIL
        if TestStatus.NOT_TESTED in statuses:
            return TestStatus.NOT_TESTED
        if TestStatus.INCONCLUSIVE in statuses:
            return TestStatus.INCONCLUSIVE
        if self.requires_security and TestStatus.SECURITY_PASS not in statuses:
            # 只有单元/集成通过，缺安全边界验证 → 不足以判该需求安全通过
            return TestStatus.INCONCLUSIVE
        if TestStatus.SECURITY_PASS in statuses:
            return TestStatus.SECURITY_PASS
        # 不需要安全用例的需求：全绿即可，取最强结论
        if TestStatus.INTEGRATION_PASS in statuses:
            return TestStatus.INTEGRATION_PASS
        return TestStatus.UNIT_PASS

    @property
    def severity(self) -> str:
        """需求内最严重的失败用例等级（无失败为 P2）。"""
        worst = Severity.P2
        for c in self.cases:
            if c.status == TestStatus.FAIL:
                if c.severity == Severity.P0:
                    return Severity.P0
                if c.severity == Severity.P1:
                    worst = Severity.P1
        return worst


@dataclass
class AcceptanceReport:
    """一次验收运行的完整记录。"""

    requirements: list[Requirement] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: _now())
    finished_at: str = ""
    policy_hash: str = ""
    baseline_version: str = ""
    baseline_violations: list[str] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)

    # ── 汇总 ────────────────────────────────────────────────────
    @property
    def cases(self) -> list[Case]:
        return [c for r in self.requirements for c in r.cases]

    def cases_by_status(self, status: str) -> list[Case]:
        return [c for c in self.cases if c.status == status]

    @property
    def p0_failures(self) -> list[Case]:
        return [c for c in self.cases if c.status == TestStatus.FAIL and c.severity == Severity.P0]

    @property
    def p1_failures(self) -> list[Case]:
        return [c for c in self.cases if c.status == TestStatus.FAIL and c.severity == Severity.P1]

    @property
    def untested(self) -> list[Case]:
        return self.cases_by_status(TestStatus.NOT_TESTED)

    @property
    def inconclusive(self) -> list[Case]:
        return self.cases_by_status(TestStatus.INCONCLUSIVE)

    def verdict(self) -> str:
        """总体验收结论。**只有一种情形能叫 SECURITY_PASS**。

        * 任一 P0 用例 FAIL → FAIL（整体安全验收不通过）；
        * 任一带 P1 的 FAIL → FAIL（不得标记为完整安全通过）；
        * 存在 NOT_TESTED / INCONCLUSIVE → 不得判通过，分别报
          NOT_TESTED / INCONCLUSIVE；
        * 需求未全部 SECURITY_PASS（含基线被改）→ FAIL；
        * 否则 SECURITY_PASS。
        """
        if self.baseline_violations:
            return TestStatus.FAIL
        if self.p0_failures or self.p1_failures:
            return TestStatus.FAIL
        if any(c.status == TestStatus.FAIL for c in self.cases):
            return TestStatus.FAIL
        if self.untested:
            return TestStatus.NOT_TESTED
        if self.inconclusive:
            return TestStatus.INCONCLUSIVE
        if not self.requirements:
            return TestStatus.NOT_TESTED
        if any(r.status != TestStatus.SECURITY_PASS for r in self.requirements):
            return TestStatus.FAIL
        return TestStatus.SECURITY_PASS

    @property
    def full_pass(self) -> bool:
        """完整安全通过：结论 SECURITY_PASS 且无任何 P1/P0 失败。"""
        return (
            self.verdict() == TestStatus.SECURITY_PASS
            and not self.p0_failures
            and not self.p1_failures
            and not self.baseline_violations
        )

    # ── 执行记录（可追溯性）─────────────────────────────────────
    def stamp_environment(self, **extra: Any) -> None:
        self.environment = {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "cwd": extra.get("cwd", ""),
            "git_commit": extra.get("git_commit", ""),
            "git_dirty": extra.get("git_dirty", None),
            "target": extra.get("target", ""),
            **{k: v for k, v in extra.items() if k not in ("cwd", "git_commit", "git_dirty", "target")},
        }
        self.finished_at = _now()

    # ── 序列化 ──────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict(),
            "full_pass": self.full_pass,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "environment": self.environment,
            "policy_hash": self.policy_hash,
            "baseline_version": self.baseline_version,
            "baseline_violations": self.baseline_violations,
            "summary": {s: len(self.cases_by_status(s)) for s in TestStatus.ALL},
            "requirements": [
                {
                    "req_id": r.req_id,
                    "title": r.title,
                    "sources": r.sources,
                    "status": r.status,
                    "severity": r.severity,
                    "residual": r.residual,
                    "cases": [
                        {
                            "name": c.name,
                            "kind": c.kind,
                            "severity": c.severity,
                            "status": c.status,
                            "executed": c.executed,
                            "expected": c.expected,
                            "http_sent": c.http_sent,
                            "network_side_effect": c.network_side_effect,
                            "gateway": c.gateway,
                            "audit_ok": c.audit_ok,
                            "negative_covered": c.negative_covered,
                            "error": c.error,
                            "residual": c.residual,
                            "assertions": [
                                {
                                    "name": a.name, "expected": a.expected,
                                    "actual": a.actual, "passed": a.passed,
                                    "detail": a.detail,
                                }
                                for a in c.assertions
                            ],
                        }
                        for c in r.cases
                    ],
                }
                for r in self.requirements
            ],
        }


# ── 反作弊：基线校验 ──────────────────────────────────────────────
# "禁止通过删除失败测试、降低断言强度、跳过测试或修改预期结果来制造 PASS"
# 这条规则靠自觉守不住，必须机械可查：基线记录**每条用例的 ID、预期结果、
# 断言数量与断言名集合的指纹**。运行结果与基线不一致（用例消失、预期文本
# 被改、断言被删）即记 violation，总体直接 FAIL——改测试制造 PASS 的路被
# 堵死，要改就得显式更新基线并在报告里留痕。


def case_fingerprint(case: Case) -> str:
    """用例指纹：预期结果 + 断言名集合的 sha1（改预期/删断言都会变）。"""
    payload = "|".join([
        case.req_id,
        case.name,
        case.expected,
        ",".join(sorted(a.name for a in case.assertions)),
    ])
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def build_baseline(report: AcceptanceReport, version: str) -> dict[str, Any]:
    """由一次运行生成基线（只在人工确认后显式调用）。"""
    return {
        "version": version,
        "policy_hash": report.policy_hash,
        "cases": {
            c.name: {
                "req_id": c.req_id,
                "fingerprint": case_fingerprint(c),
                "assertions": len(c.assertions),
            }
            for c in report.cases
        },
    }


def verify_baseline(report: AcceptanceReport, baseline: dict[str, Any]) -> list[str]:
    """比对基线与本次运行，返回 violation 列表（空 = 未被篡改）。"""
    violations: list[str] = []
    expected: dict[str, Any] = dict(baseline.get("cases") or {})
    current = {c.name: c for c in report.cases}
    for name, meta in expected.items():
        c = current.get(name)
        if c is None:
            violations.append(f"用例被删除：{name}")
            continue
        if case_fingerprint(c) != meta.get("fingerprint"):
            violations.append(
                f"用例预期/断言被修改：{name}"
                f"（基线 {meta.get('assertions')} 条断言，当前 {len(c.assertions)} 条）"
            )
        if len(c.assertions) < int(meta.get("assertions") or 0):
            violations.append(f"断言被削弱：{name}")
    return violations


# ── 报告渲染（固定 11 字段）────────────────────────────────────────
_COLUMNS = [
    "测试需求 ID",
    "对应源代码文件",
    "测试案例名称",
    "测试类型",
    "实际执行情况",
    "预期结果",
    "实际结果",
    "HTTP 请求是否实际发出",
    "失败原因",
    "尚未覆盖的风险",
    "最终验收状态",
]


def _yn(v: bool | None) -> str:
    if v is None:
        return "未观测"
    return "是" if v else "否"


def _actual_of(case: Case) -> str:
    if case.error:
        return f"执行异常：{case.error}"
    if not case.executed:
        return "未执行"
    failed = case.failures
    if failed:
        return "；".join(f"{a.name}：{a.actual}" for a in failed)[:300]
    return f"{len(case.assertions)} 项断言全部通过"


def _reason_of(case: Case) -> str:
    if case.error:
        return case.error[:300]
    failed = case.failures
    if failed:
        return "；".join(f"{a.name} 期望 {a.expected}，实际 {a.actual}" for a in failed)[:300]
    if case.status == TestStatus.INCONCLUSIVE:
        if case.probe_http and case.http_sent is None:
            return "缺少网络观测（未确认请求是否真的发出）"
        if case.kind == Kind.SECURITY and not case.negative_covered:
            return "未覆盖拒绝路径"
        if case.audit_ok is False:
            return "拒绝事件未写入审计"
        return "证据不足"
    return "—"


def render_markdown(report: AcceptanceReport) -> str:
    """渲染验收报告：结论 + 需求汇总 + 11 字段明细 + 执行记录。"""
    verdict = report.verdict()
    lines: list[str] = [
        "# 安全测试验收报告",
        "",
        f"- 总体结论：**{verdict}**",
        f"- 完整安全通过（full_pass）：**{_yn(report.full_pass)}**",
        f"- 执行时间：{report.started_at} → {report.finished_at or '（未完成）'}",
        f"- 策略代码指纹（policy/）：`{report.policy_hash or '未计算'}`",
        f"- 基线版本：{report.baseline_version or '未比对'}",
        "",
    ]
    if report.baseline_violations:
        lines += ["## 基线违规（改测试制造 PASS）", ""]
        lines += [f"- {v}" for v in report.baseline_violations]
        lines.append("")

    lines += ["## 需求汇总", "", "| 需求 ID | 需求 | 状态 | 失败等级 | 用例数 |", "|---|---|---|---|---|"]
    for r in report.requirements:
        lines.append(
            f"| {r.req_id} | {r.title} | {r.status} | {r.severity} | {len(r.cases)} |"
        )
    counts = {s: len(report.cases_by_status(s)) for s in TestStatus.ALL}
    lines += [
        "",
        "状态计数："
        + "，".join(f"{k}={v}" for k, v in counts.items()),
        "",
        "## 用例明细",
        "",
        "| " + " | ".join(_COLUMNS) + " |",
        "|" + "---|" * len(_COLUMNS),
    ]
    for r in report.requirements:
        for c in r.cases:
            row = [
                c.req_id,
                "<br>".join(f"`{s}`" for s in c.sources),
                c.name,
                c.kind,
                "已执行" if c.executed else "未执行",
                c.expected,
                _actual_of(c),
                _yn(c.http_sent),
                _reason_of(c),
                c.residual or r.residual or "—",
                c.status,
            ]
            lines.append("| " + " | ".join(x.replace("|", "\\|") for x in row) + " |")

    lines += [
        "",
        "## 执行记录（可追溯）",
        "",
        "```json",
        _json_dump(report.environment),
        "```",
        "",
    ]
    if report.untested or report.inconclusive:
        lines += ["## 未完成项（不得视为通过）", ""]
        for c in report.untested:
            lines.append(f"- NOT_TESTED：{c.req_id} / {c.name}")
        for c in report.inconclusive:
            lines.append(f"- INCONCLUSIVE：{c.req_id} / {c.name} —— {_reason_of(c)}")
        lines.append("")
    return "\n".join(lines)


def _json_dump(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def summarize_lines(report: AcceptanceReport) -> list[str]:
    """终端输出用的紧凑摘要。"""
    out = [f"验收结论：{report.verdict()}（full_pass={report.full_pass}）"]
    for r in report.requirements:
        mark = "OK  " if r.status == TestStatus.SECURITY_PASS else "FAIL"
        out.append(f"  {mark} {r.req_id} {r.title} → {r.status}")
    for c in report.p0_failures:
        out.append(f"  [P0] {c.req_id} / {c.name} —— {_reason_of(c)}")
    for c in report.p1_failures:
        out.append(f"  [P1] {c.req_id} / {c.name} —— {_reason_of(c)}")
    for c in report.untested:
        out.append(f"  [NOT_TESTED] {c.req_id} / {c.name}")
    for c in report.inconclusive:
        out.append(f"  [INCONCLUSIVE] {c.req_id} / {c.name} —— {_reason_of(c)}")
    return out


def policy_hash(root: "Any") -> str:
    """policy/ 目录内容指纹：报告能对应到具体一份策略代码。"""
    from pathlib import Path

    base = Path(root) / "policy"
    h = hashlib.sha1()
    for py in sorted(base.glob("*.py")):
        h.update(py.name.encode("utf-8"))
        h.update(py.read_bytes())
    return h.hexdigest()[:16]


def run_cases(cases: Iterable[tuple[Requirement, Case, Any]]) -> None:
    """执行用例函数并吞异常（异常记 FAIL，不中断整轮验收）。

    ``cases`` 的每项是 ``(requirement, case, fn)``，``fn(case)`` 负责
    填断言与观测字段。异常写 ``case.error``——**执行崩溃不能变成"没跑就
    不算失败"**，否则一个坏用例能把整条需求洗成 NOT_TESTED。
    """
    for _req, case, fn in cases:
        try:
            fn(case)
            case.executed = True
        except Exception as exc:  # noqa: BLE001
            case.executed = True
            case.error = f"{type(exc).__name__}: {exc}"
