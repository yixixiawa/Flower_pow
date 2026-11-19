"""``_VerifyMixin``：验证 + 探针 + 研判 + 知识库沉淀。

HTTP 验证 → 高危探针（SQLi/RCE/文件读/上传）→ LLM 研判 → 入库。
**探针放在研判之前**：模型只该看探针拿回来的事实，不该自己编 payload。"""

from __future__ import annotations

import time
from pathlib import Path
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)
from detectors.exploit import ExploitProbeDetector, ops_from_assets
from detectors.http_detector import FingerprintDetector, HttpDetector


class _VerifyMixin:
    async def _phase4_verify(self, result: ScanResult, verbose: bool) -> None:
        t0 = time.perf_counter()
        selected: list[POC] = getattr(self, "_selected", [])
        if not selected:
            result.phases["verify"] = 0.0
            return

        base = result.target.rstrip("/") + "/"
        det = HttpDetector(self.cfg.scan)
        try:
            # 先建立软 404 基线——这一步直接决定误报率
            await det.probe_soft404(base)
            findings, errors = await det.run_many(
                selected, base, getattr(self, "_scores", None)
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"验证阶段异常: {type(exc).__name__}: {exc}")
            result.phases["verify"] = round(time.perf_counter() - t0, 2)
            return
        finally:
            await det.aclose()

        result.add_findings(findings)
        result.errors.extend(errors)
        result.pocs_executed = len(selected)
        result.findings.sort(key=lambda f: (f.severity.rank, f.rag_score), reverse=True)
        if verbose:
            self._log(
                f"[3/5] 验证 {result.pocs_executed} 条 POC → {len(findings)} 条原始命中",
                verbose,
            )
        result.phases["verify"] = round(time.perf_counter() - t0, 2)

        # 4.5) 一次性高危探针：SQL 注入（只取版本号）/ RCE / 任意文件读
        #     与 POC 库验证分开，是因为它需要"按接口填参数 + 命中即停"的动态逻辑，
        #     而且必须先有接口清单（OpenAPI 或 JS 端点）才有意义。
        await self._phase4b_exploit(result, verbose)

        # 4.6) 第二次独立验证：完整性 → 反向验证 → 独立复测 → 定级
        #      **必须放在研判之前**：模型只该看已经取证过的事实，不该替我们
        #      决定"这条到底算不算漏洞"（它的置信度不是概率，见 quality.py）。
        await self._phase4c_second_pass(result, verbose)

    async def _phase4b_exploit(self, result: ScanResult, verbose: bool) -> None:
        """一次性高危探针。

        **每个接口每类漏洞只尝试一次**：命中就停，没命中就跳过，
        请求出错/被 WAF 拦截则跳过该接口，累计出错达阈值自动跳过剩余扫描。
        SQL 注入只取数据库版本号，不做拖库——这是"证明存在"与"造成破坏"的分界。
        """
        t0 = time.perf_counter()
        cfg = self.cfg.scan
        kinds: list[str] = []
        for name, flag in (
            ("sqli", "sqli_probe_enabled"),
            ("rce", "rce_probe_enabled"),
            ("fileread", "file_read_probe_enabled"),
            ("upload", "file_upload_probe_enabled"),
        ):
            if getattr(cfg, flag, False):
                kinds.append(name)
        if not kinds:
            result.phases["exploit"] = 0.0
            return

        base = result.target.rstrip("/") + "/"
        limit = max(1, int(getattr(cfg, "probe_max_ops", 40) or 40))
        ops = ops_from_assets(result.assets, limit)
        if len(ops) == 1 and ops[0].source == "fallback" and verbose:
            self._log(
                "      未拿到接口清单（无 OpenAPI / JS 端点），只对站点根做一次探测",
                verbose,
            )

        det = ExploitProbeDetector(cfg, self._poc_map, approver=self.approver)
        try:
            findings, stats = await det.run(base, ops, kinds=tuple(kinds), verbose=False)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"高危探针异常: {type(exc).__name__}: {exc}")
            result.phases["exploit"] = round(time.perf_counter() - t0, 2)
            return
        finally:
            await det.aclose()

        result.add_findings(findings)
        result.notes.extend(det.notes)
        if verbose:
            total_err = sum(s.get("error", 0) for s in stats.values())
            self._log(
                f"      高危探针 {','.join(kinds)}：{len(ops)} 个接口各尝试 1 次 → "
                f"命中 {len(findings)}、出错跳过 {total_err}、共发 {det.checked} 次请求",
                verbose,
            )
        result.phases["exploit"] = round(time.perf_counter() - t0, 2)

    # ── 阶段 4.6：第二次独立验证 ─────────────────────────────────
    async def _phase4c_second_pass(self, result: ScanResult, verbose: bool) -> None:
        """对全部原始命中做独立取证，产出 ``evidence_score`` 与三档定级。

        为什么不能只看一次命中：软 404、通用 200 页面、一次网络抖动都能
        让"命中"成立而"漏洞"不成立。这一步用**同一 site 的基线**与**第二次
        请求**把它们区分开（见 :mod:`detectors.second_pass`）。

        异常处理原则：二次验证是增强，失败一律降级为「待人工复核」，
        绝不把已经拿到的发现丢掉。
        """
        t0 = time.perf_counter()
        if not result.findings:
            result.phases["second_pass"] = 0.0
            return
        if not getattr(self.cfg.scan, "second_pass_enabled", True):
            result.notes.append(
                "第二次独立验证已关闭：命中只凭首次响应定级，"
                "缺基线对照与独立复测的项都会落到待人工复核"
            )
            result.phases["second_pass"] = 0.0
            return

        from detectors.second_pass import SecondPassVerifier

        det = HttpDetector(self.cfg.scan)
        try:
            verifier = SecondPassVerifier(
                det,
                base_url=result.target,
                poc_lookup=self._poc_map,
                retest_enabled=bool(getattr(self.cfg.scan, "second_pass_retest", True)),
            )
            stats = await verifier.run(result.findings)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"二次验证异常: {type(exc).__name__}: {exc}")
            result.phases["second_pass"] = round(time.perf_counter() - t0, 2)
            return
        finally:
            await det.aclose()

        result.notes.append(
            f"二次验证：确认 {stats['confirmed']} / 待复核 {stats['needs_review']}"
            f" / 误报 {stats['rejected']}（独立复测 {stats['retested']} 条，"
            f"按非破坏性原则跳过 {stats['retest_skipped']} 条）"
        )
        if verbose:
            self._log(
                f"[3.5/5] 二次验证 {stats['checked']} 条 → 确认 {stats['confirmed']}"
                f"、待复核 {stats['needs_review']}、误报 {stats['rejected']}",
                verbose,
            )
        result.phases["second_pass"] = round(time.perf_counter() - t0, 2)

    # ── 阶段 5：降误报研判 ───────────────────────────────────────
    async def _phase5_triage(self, result: ScanResult, verbose: bool) -> None:
        t0 = time.perf_counter()
        if not result.findings:
            result.phases["triage"] = 0.0
            return

        if not self.llm.available:
            result.notes.append("LLM 未配置：不做研判，定级完全依据客观证据评分")
            if verbose:
                self._log("[4/5] 跳过 LLM 研判（未配置 API Key）", verbose)
            result.phases["triage"] = round(time.perf_counter() - t0, 2)
            # 没有研判就没有模型补充判断，沉淀完全靠证据评分把关
            # （require_triage）——未研判项 confidence=0，会被严格挡下。
            if self.cfg.rag.knowledge_enabled and result.findings:
                self._ingest_knowledge(result, verbose, require_triage=True)
            return

        if verbose:
            self._log(f"[4/5] LLM 研判 {len(result.findings)} 条命中…", verbose)
        verdicts = self.llm.triage(result.findings)
        if not verdicts:
            result.notes.append("LLM 研判失败或返回空：保留全部命中，定级沿用证据评分")
        else:
            confirmed, rejected = self.llm.apply_triage(result.findings, verdicts)
            # **不再从 findings 里删除**：误报也是复核记录的一部分。
            # 状态已经落到 REJECTED，报告正文/数量统计自然不会带它。
            result.notes.append(
                f"LLM 研判：确认 {len(confirmed)} 条，判为误报 {len(rejected)} 条，"
                f"待复核 {len(result.needs_review_findings())} 条"
                f"（证据分不因模型置信度改变；0.95 不是 95% 的概率）"
            )
            if rejected and verbose:
                self._log(f"      模型判误报 {len(rejected)} 条（已转待复核/误报档）", verbose)
            for f in rejected[:5]:
                result.notes.append(
                    f"模型判误报: {f.poc_id} —— {f.rationale or '模型判定为误报'}"
                )

        result.findings.sort(key=lambda f: (f.severity.rank, f.confidence), reverse=True)
        result.phases["triage"] = round(time.perf_counter() - t0, 2)

        # ── 知识库沉淀 ────────────────────────────────────────────
        # 放在研判**之后**：只有 CONFIRMED 的发现才值得入库，
        # 放在前面会把待复核项与误报喂回召回，形成正反馈污染。
        self._ingest_knowledge(result, verbose)

    def _ingest_knowledge(
        self,
        result: ScanResult,
        verbose: bool,
        *,
        require_triage: bool = False,
    ):
        """把本次确认过的发现沉淀进知识库（见 :mod:`kb.knowledge`）。

        ``require_triage`` 用于「本次没跑研判」的场景（见
        :func:`kb.knowledge.finding_to_record` 同名参数）。
        返回 :class:`kb.knowledge.IngestReport`，失败返回 ``None``。

        失败**不影响**扫描结果——沉淀是附加价值，不能因为它拖累主流程。
        """
        if not self.cfg.rag.knowledge_enabled or not result.findings:
            return None
        try:
            from kb.knowledge import KnowledgeStore
            from core.state import Severity

            db = Path(self.cfg.rag.knowledge_db)
            ks = KnowledgeStore.open(
                db, self.cfg.rag.dim, max_entries=self.cfg.rag.knowledge_max_entries
            )
            conf = self.cfg.rag.knowledge_min_confidence
            rep = ks.ingest_findings(
                result.findings,
                result.target,
                min_severity=Severity.parse(self.cfg.rag.knowledge_min_severity),
                min_confidence=conf,
                boost_terms=self.cfg.rag.boost_terms,
                require_triage=require_triage,
            )
            ks.save()
            result.notes.append(f"知识库沉淀：{rep.line()}")
            if verbose:
                self._log(f"[5/5] {rep.line()}", verbose)
            return rep
        except Exception as exc:  # noqa: BLE001
            msg = f"知识库沉淀失败（不影响本次结果）：{type(exc).__name__}: {exc}"
            result.notes.append(msg)
            if verbose:
                self._log(f"      {msg}", verbose)
            return None

    # ── 报告 ──────────────────────────────────────────────────────
