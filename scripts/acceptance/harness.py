"""用例执行与判定：用例只采集事实，判定在这里。

判定顺序（任何一步不过就停，不会"后面还有通过项"而翻案）::

    没执行            → NOT_TESTED
    执行异常          → INCONCLUSIVE（结果不足以判断）
    断言数低于基线    → FAIL（防"删断言/跳过"制造通过）
    有断言失败        → FAIL
    观测与结构化预期不符 → FAIL
    全过              → 按用例类型给 UNIT/INTEGRATION/SECURITY_PASS

结构化预期写在 :mod:`catalog` 里，与用例代码分离：改测试代码改不动预期。
"""

from __future__ import annotations

import asyncio
import importlib
import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scripts.acceptance import catalog as catalog_mod
from scripts.acceptance.gateway import GatewayTracer
from scripts.acceptance.mocknet import MockNet
from scripts.acceptance.model import (
    FAIL,
    INCONCLUSIVE,
    KIND_STATUS,
    NOT_TESTED,
    PASS_STATES,
    SECURITY_PASS,
    CaseResult,
    CaseSpec,
    Requirement,
    grade_requirement,
    worst_requirement_status,
)


# ── 用例上下文 ────────────────────────────────────────────────────


class Ctx:
    """传给用例函数的上下文。断言与配置都在这里，用例不碰框架内部。"""

    def __init__(self, spec: CaseSpec, net: MockNet, tmp: Path) -> None:
        self.spec = spec
        self.net = net
        self.tmp = tmp
        self.values: dict[str, Any] = {}
        self.failed: list[str] = []
        self.total = 0
        self.risk = ""

    # ── 断言 ─────────────────────────────────────────────────────
    def check(self, cond: Any, label: str) -> None:
        self.total += 1
        if not cond:
            self.failed.append(label)

    # ── 结构化观测 ───────────────────────────────────────────────
    def set(self, key: str, value: Any) -> None:
        self.values[key] = value

    def note_risk(self, text: str) -> None:
        self.risk = text

    # ── 网络观测（用例内的局部视图）────────────────────────────────
    def mark(self) -> tuple[int, int]:
        """记录当前 mock 计数，供用例自己观察"这一段"打到了谁。"""
        return self.net.snapshot()

    def hits(self, mark: tuple[int, int]):
        return self.net.delta(mark)

    # ── 配置 / 运行器 / 会话 ─────────────────────────────────────
    def cfg(
        self,
        env: str = "isolated_test",
        *,
        default_env: str = "unknown",
        audit: bool = True,
        environments: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ):
        from core.config_loader import Config

        cfg = Config()
        cfg.scan.timeout = 5.0
        cfg.scan.follow_redirects = follow_redirects
        cfg.scan.proxy = None
        cfg.scan.verify_tls = False
        cfg.scan.no_proxy = []
        cfg.scan.proxy_autodetect = False
        cfg.llm.enabled = False
        cfg.rag.enabled = False
        cfg.data_dir = str(self.tmp / "data")
        cfg.output_dir = str(self.tmp / "out")
        # 探测器（只拿得到 ScanConfig）的审计目录与网关判定依赖这两个字段
        cfg.scan.audit_dir = cfg.data_dir
        cfg.policy.default_environment = default_env
        cfg.policy.audit = audit
        cfg.policy.environments = (
            dict(environments) if environments is not None else self.net.bindings()
        )
        if env:
            cfg.policy.environments[self.net.a.binding] = env
        return cfg

    def runner(self, cfg):
        from core.tools.runner import ToolRunner

        return ToolRunner(cfg, root=self.tmp)

    def session(self, cfg, target: str | None = None, session_id: str = ""):
        from core.session import Session

        return Session(
            target=target or self.net.target,
            session_id=session_id or None,
        )

    # ── 审计 ─────────────────────────────────────────────────────
    def audit_path(self, cfg) -> Path:
        return Path(cfg.data_dir) / "policy" / "audit.jsonl"

    def events(self, cfg) -> list[dict[str, Any]]:
        p = self.audit_path(cfg)
        if not p.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


# ── 快照 ──────────────────────────────────────────────────────────


@dataclass
class _Snapshot:
    sends: tuple[int, int]
    net: tuple[int, int]


def _snapshot(tracer: GatewayTracer, net: MockNet) -> _Snapshot:
    return _Snapshot(tracer.snapshot(), net.snapshot())


def _resolve(path: str, r: CaseResult) -> Any:
    if path == "http_sent":
        return r.http_sent
    if path == "gateway.all_governed":
        return r.gateway_ok
    if path == "network.count":
        return len(r.network_hits)
    if path == "network.hosts":
        return sorted(r.network_hosts)
    if path == "network.any":
        return bool(r.network_hits)
    if path == "audit.count":
        return len(r.audit_events)
    if path == "assertions":
        return r.assertions_total
    if path.startswith("values."):
        return r.values.get(path[len("values."):], "<missing>")
    if path.startswith("audit."):
        return path
    raise KeyError(path)


def _subset(event: dict[str, Any], want: dict[str, Any]) -> bool:
    return all(event.get(k) == v for k, v in want.items())


def _compare(expect: dict[str, Any], r: CaseResult) -> list[str]:
    bad: list[str] = []
    for path, want in expect.items():
        if path == "audit.any":
            hits = [e for e in r.audit_events
                    if isinstance(want, dict) and _subset(e, want)]
            if not hits:
                bad.append(f"审计中未找到事件 {want}（实际 {len(r.audit_events)} 条）")
            continue
        if path == "audit.none":
            hits = [e for e in r.audit_events
                    if isinstance(want, dict) and _subset(e, want)]
            if hits:
                bad.append(f"审计中出现了不该有的事件 {want}")
            continue
        if path == "audit.last_event":
            if not r.audit_events or r.audit_events[-1].get("event") != want:
                bad.append(f"最后一条审计事件应为 {want}")
            continue
        actual = _resolve(path, r)
        if actual != want:
            bad.append(f"预期 {path}={want!r}，实际 {actual!r}")
    return bad


# ── 单用例执行 ────────────────────────────────────────────────────


def _load_fn(fn: str) -> Callable[[Ctx], None]:
    mod_name, _, func = fn.partition(":")
    mod = importlib.import_module(mod_name)
    return getattr(mod, func)


def run_case(
    spec: CaseSpec,
    net: MockNet,
    tracer: GatewayTracer,
    baseline: dict[str, int],
) -> CaseResult:
    r = CaseResult(spec=spec)
    tmp = Path(tempfile.mkdtemp(prefix=f"acc_{spec.id}_"))
    before = _snapshot(tracer, net)
    ctx = Ctx(spec, net, tmp)
    try:
        fn = _load_fn(spec.fn)
        fn(ctx)
        r.executed = True
    except Exception as exc:  # noqa: BLE001 —— 用例自身崩了 = 结果不足以判断
        r.executed = True
        r.error = f"{type(exc).__name__}: {exc}"
    finally:
        after = _snapshot(tracer, net)
        sends, clients = tracer.delta(before.sends)
        hits = net.delta(before.net)

        r.assertions_total = ctx.total
        r.assertions_passed = ctx.total - len(ctx.failed)
        r.failed_labels = list(ctx.failed)
        r.values = dict(ctx.values)
        r.risk = ctx.risk

        r.http_sent = bool(sends)
        r.http_hops = [f"{s['method']} {s['url']}" for s in sends]
        r.network_hits = [rec.line() for rec in hits]
        r.network_hosts = sorted({rec.host for rec in hits})
        bad = [s for s in sends if not s["governed"]]
        r.ungoverned_sends = [f"{s['method']} {s['url']}" for s in bad]
        r.gateway_ok = not bad

        # 审计：本用例的 temp 目录是独立的，直接读全量
        audit_path = tmp / "data" / "policy" / "audit.jsonl"
        r.audit_file_ok = audit_path.exists() or not _wrote_audit_expected(spec)
        if audit_path.exists():
            for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r.audit_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        _evaluate(r, baseline.get(spec.id, 0))
        shutil.rmtree(tmp, ignore_errors=True)
    return r


def _wrote_audit_expected(spec: CaseSpec) -> bool:
    return any(k.startswith("audit.") for k in spec.expect)


def _evaluate(r: CaseResult, baseline_assertions: int) -> None:
    spec = r.spec
    if not r.executed:
        r.status = NOT_TESTED
        r.reason = "用例没有执行"
        return
    if r.error:
        r.status = INCONCLUSIVE
        r.reason = f"用例执行异常，结果不足以判断：{r.error}"
        return

    required = max(spec.min_assertions, baseline_assertions)
    if r.assertions_total < required:
        r.status = FAIL
        r.reason = (
            f"断言数 {r.assertions_total} 低于基线 {required}——"
            "删除断言/跳过校验不能算通过"
        )
        return
    if r.failed_labels:
        r.status = FAIL
        r.reason = "断言失败：" + "；".join(r.failed_labels[:4])
        return

    mismatch = _compare(spec.expect, r)
    if mismatch:
        r.status = FAIL
        r.reason = "观测与预期不符：" + "；".join(mismatch[:4])
        return

    r.status = KIND_STATUS.get(spec.kind, INCONCLUSIVE)
    r.reason = "全部断言通过，且实际观测符合结构化预期"


# ── 整体验收 ──────────────────────────────────────────────────────


@dataclass
class SuiteResult:
    results: list[CaseResult]
    requirement_status: dict[str, str]
    overall: str
    reasons: list[str]
    tracer_summary: dict[str, Any]
    integrity: list[str]
    started_at: float
    duration: float
    baseline_missing: list[str] = field(default_factory=list)

    def by_requirement(self) -> dict[str, list[CaseResult]]:
        out: dict[str, list[CaseResult]] = {}
        for r in self.results:
            out.setdefault(r.spec.req, []).append(r)
        return out


def evaluate_suite(
    results: list[CaseResult],
    requirements: list[Requirement],
    tracer: GatewayTracer,
    integrity: list[str],
    baseline_missing: list[str],
    started_at: float,
) -> SuiteResult:
    by_req: dict[str, list[CaseResult]] = {r.id: [] for r in requirements}
    for res in results:
        by_req.setdefault(res.spec.req, []).append(res)

    req_status = {
        rid: grade_requirement(
            [c.spec.kind for c in cases], [c.status for c in cases],
        )
        for rid, cases in by_req.items()
    }

    # 全程出现绕过 Gateway 的发送 → 出口需求直接 FAIL（事实优先于用例）
    if any(not s["governed"] for s in tracer.sends):
        for rid in list(req_status):
            if rid == "REQ-GATEWAY":
                req_status[rid] = FAIL

    reasons: list[str] = []
    if integrity:
        reasons.extend(f"完整性检查失败：{x}" for x in integrity)

    p0_bad = [rid for rid in req_status
              if _sev(rid, requirements) == "P0" and req_status[rid] != SECURITY_PASS]
    p1_bad = [rid for rid in req_status
              if _sev(rid, requirements) == "P1" and req_status[rid] != SECURITY_PASS]

    if integrity:
        overall = FAIL
    elif any(req_status[rid] == FAIL for rid in p0_bad):
        overall = FAIL
        reasons.append("存在 P0 安全问题：" + "、".join(
            rid for rid in p0_bad if req_status[rid] == FAIL))
    elif p0_bad:
        overall = INCONCLUSIVE
        reasons.append("P0 需求未取得 SECURITY_PASS（NOT_TESTED/INCONCLUSIVE）："
                       + "、".join(p0_bad))
    elif any(req_status[rid] == FAIL for rid in p1_bad):
        overall = FAIL
        reasons.append("存在 P1 问题，不得标记为完整安全通过：" + "、".join(
            rid for rid in p1_bad if req_status[rid] == FAIL))
    elif p1_bad:
        overall = INCONCLUSIVE
        reasons.append("P1 需求未完成验收：" + "、".join(p1_bad))
    else:
        overall = SECURITY_PASS
        reasons.append("全部 P0/P1 需求取得 SECURITY_PASS，且无已知策略旁路")

    return SuiteResult(
        results=results,
        requirement_status=req_status,
        overall=overall,
        reasons=reasons,
        tracer_summary=tracer.summary(),
        integrity=integrity,
        started_at=started_at,
        duration=time.time() - started_at,
        baseline_missing=baseline_missing,
    )


def _sev(req_id: str, requirements: list[Requirement]) -> str:
    for r in requirements:
        if r.id == req_id:
            return r.severity
    return "P0"


def run_all(only: str = "", keep_going: bool = True) -> SuiteResult:
    """跑全部用例。``only`` 用于按需求/用例 ID 过滤（调试用）。"""
    started = time.time()
    net = MockNet()
    tracer = GatewayTracer()
    tracer.install()
    baseline, baseline_missing = catalog_mod.load_baseline()

    integrity = catalog_mod.check_integrity()
    results: list[CaseResult] = []
    try:
        for spec in catalog_mod.CASES:
            if only and only not in spec.id and only not in spec.req:
                continue
            res = run_case(spec, net, tracer, baseline)
            results.append(res)
            if not keep_going and res.status == FAIL:
                break
    finally:
        tracer.uninstall()
        net.close()

    # 目录里声明了、但没有跑到的用例 → 显式补一条 NOT_TESTED
    ran = {r.spec.id for r in results}
    for spec in catalog_mod.CASES:
        if only and only not in spec.id and only not in spec.req:
            continue
        if spec.id not in ran:
            r = CaseResult(spec=spec)
            r.status = NOT_TESTED
            r.reason = "用例未被执行（中断或收集失败）"
            results.append(r)

    suite = evaluate_suite(
        results, catalog_mod.REQUIREMENTS, tracer, integrity, baseline_missing, started,
    )
    return suite


__all__ = ["Ctx", "SuiteResult", "run_all", "run_case", "evaluate_suite"]
