"""验收报告：Markdown（给人看）+ JSON（可追溯）。

Markdown 的列与用户验收规则第五节逐项对应：
测试需求 ID / 对应源代码文件 / 测试案例名称 / 测试类型 / 实际执行情况 /
预期结果 / 实际结果 / HTTP 是否实际发出 / 失败原因 / 尚未覆盖的风险 /
最终验收状态。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from scripts.acceptance.model import (
    FAIL,
    INCONCLUSIVE,
    NOT_TESTED,
    PASS_STATES,
    SECURITY_PASS,
    CaseResult,
    Requirement,
)


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _expect_text(r: CaseResult) -> str:
    if not r.spec.expect:
        return "（无结构化预期）"
    bits = []
    for k, v in r.spec.expect.items():
        if isinstance(v, dict):
            bits.append(f"{k}={json.dumps(v, ensure_ascii=False)}")
        else:
            bits.append(f"{k}={v!r}")
    return "；".join(bits)


def _actual_text(r: CaseResult) -> str:
    bits = []
    if r.values:
        bits.append("观测 " + json.dumps(r.values, ensure_ascii=False, default=str))
    if r.network_hits:
        bits.append("网络 " + "、".join(r.network_hits[:4]))
    if r.audit_events:
        denies = [e for e in r.audit_events if e.get("event") == "deny"]
        bits.append(f"审计 {len(r.audit_events)} 条（deny {len(denies)}）")
    if not bits:
        bits.append("无观测数据")
    return "；".join(bits)


def _exec_text(r: CaseResult) -> str:
    if not r.executed:
        return "未执行"
    return f"已执行：断言 {r.assertions_passed}/{r.assertions_total} 通过"


def _http_text(r: CaseResult) -> str:
    if r.http_sent:
        return f"是（{len(r.http_hops)} 跳）"
    return "否"


def _risk_text(r: CaseResult) -> str:
    if r.risk:
        return r.risk
    if r.status == NOT_TESTED:
        return "该路径没有实际执行，无法证明任何安全属性"
    if r.status == INCONCLUSIVE:
        return "结果不足以判断，不能视为通过"
    if r.status == FAIL:
        return "该边界存在未修复缺陷"
    return "无已知未覆盖项（本地隔离环境内验证）"


def _status_badge(s: str) -> str:
    return {
        SECURITY_PASS: "**SECURITY_PASS**",
        "INTEGRATION_PASS": "INTEGRATION_PASS",
        "UNIT_PASS": "UNIT_PASS",
        FAIL: "**FAIL**",
        NOT_TESTED: "**NOT_TESTED**",
        INCONCLUSIVE: "**INCONCLUSIVE**",
    }.get(s, s)


def render_markdown(
    suite, requirements: list[Requirement], *, generated_at: float | None = None,
) -> str:
    reqs = {r.id: r for r in requirements}
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(generated_at or time.time()))
    lines: list[str] = []
    lines.append("# flower_pow 安全验收报告")
    lines.append("")
    lines.append(f"- 生成时间：{ts}")
    lines.append(f"- 耗时：{suite.duration:.1f}s")
    lines.append(f"- 整体判定：{_status_badge(suite.overall)}")
    for r in suite.reasons:
        lines.append(f"  - {r}")
    lines.append("")
    lines.append(
        "判定口径：UNIT_PASS / INTEGRATION_PASS / SECURITY_PASS 三档，"
        "NOT_TESTED 与 INCONCLUSIVE **不会**被算作通过；任何 P0 需求非 "
        "SECURITY_PASS，整体验收即不通过。"
    )
    lines.append("")

    # ── 需求总表 ─────────────────────────────────────────────────
    lines.append("## 一、需求级验收")
    lines.append("")
    lines.append("| 测试需求 ID | 需求 | 等级 | 用例数 | 通过 | 失败 | 未测/不确定 | 最终状态 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for req in requirements:
        mine = [r for r in suite.results if r.spec.req == req.id]
        passed = sum(1 for r in mine if r.status in PASS_STATES)
        failed = sum(1 for r in mine if r.status == FAIL)
        unknown = sum(1 for r in mine if r.status in (NOT_TESTED, INCONCLUSIVE))
        st = suite.requirement_status.get(req.id, NOT_TESTED)
        lines.append(
            f"| {req.id} | {_cell(req.title)} | {req.severity} | {len(mine)} | "
            f"{passed} | {failed} | {unknown} | {_status_badge(st)} |"
        )
    lines.append("")

    # ── 用例明细 ─────────────────────────────────────────────────
    lines.append("## 二、用例明细")
    lines.append("")
    lines.append(
        "| 测试需求 ID | 对应源代码文件 | 测试案例名称 | 测试类型 | 实际执行情况 | "
        "预期结果 | 实际结果 | HTTP 是否实际发出 | 失败原因 | 尚未覆盖的风险 | 最终验收状态 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in suite.results:
        req = reqs.get(r.spec.req)
        sources = ", ".join(r.spec.sources or (req.sources if req else ()))
        lines.append(
            "| "
            + " | ".join([
                r.spec.req,
                _cell(sources),
                _cell(f"{r.spec.id} {r.spec.name}"),
                r.spec.kind,
                _cell(_exec_text(r)),
                _cell(_expect_text(r)),
                _cell(_actual_text(r)),
                _http_text(r),
                _cell(r.reason if r.status in (FAIL, INCONCLUSIVE, NOT_TESTED) else "—"),
                _cell(_risk_text(r)),
                _status_badge(r.status),
            ])
            + " |"
        )
    lines.append("")

    # ── 出口证据 ─────────────────────────────────────────────────
    lines.append("## 三、网络出口与旁路证据")
    lines.append("")
    tr = suite.tracer_summary
    lines.append(f"- 统一 Gateway 签发参数：{tr.get('issued', 0)} 次")
    lines.append(f"- httpx 客户端构造：{tr.get('clients', 0)} 次")
    lines.append(f"- 实际网络发送（含重定向每一跳）：{tr.get('sends', 0)} 次")
    bad_c = tr.get("ungoverned_clients") or []
    bad_s = tr.get("ungoverned_sends") or []
    lines.append(f"- 绕过 Gateway 的客户端：{len(bad_c)} 个 {bad_c if bad_c else ''}")
    lines.append(f"- 绕过 Gateway 的发送：{len(bad_s)} 次 {bad_s[:5] if bad_s else ''}")
    lines.append("")
    lines.append("所有验收请求只打本机 mock（127.0.0.1 的两个端口），未向任何生产目标发送请求。")
    lines.append("")

    # ── 完整性 ───────────────────────────────────────────────────
    lines.append("## 四、完整性与反作弊检查")
    lines.append("")
    if suite.integrity:
        for e in suite.integrity:
            lines.append(f"- ❌ {e}")
    else:
        lines.append("- ✅ 需求清单完整、每条需求都有负向 + SECURITY 用例、无跳过标记、断言数基线齐全")
    if suite.baseline_missing:
        lines.append("- ❌ 断言数基线缺失：" + "、".join(suite.baseline_missing[:10]))
    lines.append("")

    # ── 结论 ─────────────────────────────────────────────────────
    lines.append("## 五、结论")
    lines.append("")
    if suite.overall == SECURITY_PASS:
        lines.append(
            "全部 P0/P1 需求取得 SECURITY_PASS：必要测试已执行、负向路径覆盖、"
            "所有出网请求经统一 Gateway、未发现已知策略旁路。"
        )
    elif suite.overall == FAIL:
        lines.append(
            "**验收不通过。** 存在失败项或完整性问题，按规则不得标记为安全通过；"
            "不得通过删除失败测试、降低断言强度或修改预期结果来翻案。"
        )
    else:
        lines.append(
            "**结果不足以判定通过。** 存在未执行或结论不确定的必要测试，"
            "需补齐后重跑。"
        )
    lines.append("")
    lines.append(
        "> 说明：本报告由 `scripts/security_acceptance.py` 生成。"
        "结构化预期存放在 `scripts/acceptance/catalog.py`，与用例代码分离；"
        "断言数低于 `baseline.json` 直接判 FAIL。"
    )
    return "\n".join(lines) + "\n"


def render_json(suite, requirements: list[Requirement]) -> dict[str, Any]:
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(suite.started_at)),
        "overall": suite.overall,
        "reasons": suite.reasons,
        "duration_s": round(suite.duration, 1),
        "integrity": suite.integrity,
        "baseline_missing": suite.baseline_missing,
        "gateway": suite.tracer_summary,
        "requirements": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "status": suite.requirement_status.get(r.id, NOT_TESTED),
                "cases": [
                    {
                        "id": c.spec.id,
                        "name": c.spec.name,
                        "kind": c.spec.kind,
                        "status": c.status,
                        "executed": c.executed,
                        "assertions": [c.assertions_passed, c.assertions_total],
                        "http_sent": c.http_sent,
                        "network_hits": c.network_hits,
                        "audit_events": len(c.audit_events),
                        "reason": c.reason,
                        "expect": c.spec.expect,
                        "values": c.values,
                    }
                    for c in suite.results if c.spec.req == r.id
                ],
            }
            for r in requirements
        ],
    }


def write_report(
    suite, requirements: list[Requirement], out_dir: Path,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(suite.started_at))
    md = out_dir / f"security_acceptance_{ts}.md"
    js = out_dir / f"security_acceptance_{ts}.json"
    md.write_text(render_markdown(suite, requirements, generated_at=suite.started_at),
                  encoding="utf-8")
    js.write_text(
        json.dumps(render_json(suite, requirements), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return md, js


__all__ = ["render_markdown", "render_json", "write_report"]
