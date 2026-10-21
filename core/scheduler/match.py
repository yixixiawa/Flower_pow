"""``_MatchMixin``：RAG 召回 + 基线合并 + 情报增强。

把资产指纹喂进检索器召回 POC，与「已确认基线」合并去重，
再用外部 CVE 情报（CVSS / KEV / EPSS）给候选排序。"""

from __future__ import annotations

import time
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)
from detectors.poc_loader import filter_executable, load_poc_map
from kb.intel import get_intel
from kb.retriever import RetrievalResult, Retriever
from core.scheduler.helpers import _profile_text


class _MatchMixin:
    async def _phase3_match(self, result: ScanResult, verbose: bool) -> list[POC]:
        t0 = time.perf_counter()
        if not result.fingerprints or result.fingerprints[0].http_status is None:
            result.phases["match"] = round(time.perf_counter() - t0, 2)
            return []

        poc_map, load_errors = load_poc_map(self.cfg.rag.poc_dir)
        self._poc_map = poc_map
        result.pocs_loaded = len(poc_map)
        result.errors.extend(load_errors)

        candidates, skip_reasons = filter_executable(
            list(poc_map.values()), readonly=self.cfg.scan.readonly
        )
        result.notes.extend(skip_reasons[:5])

        if not candidates:
            result.errors.append("POC 库为空或全部被过滤")
            result.phases["match"] = round(time.perf_counter() - t0, 2)
            return []

        # ── RAG 召回 ────────────────────────────────────────────
        selected: list[POC] = []
        scores: dict[str, float] = {}
        retr: RetrievalResult | None = None

        if self.cfg.rag.enabled:
            retriever, errs = Retriever.from_config(self.cfg.rag, poc_map, verbose)
            result.errors.extend(errs)
            if retriever is None:
                result.notes.append("RAG 索引不可用，降级为全量 POC 按严重度排序")
            else:
                retr = retriever.retrieve(result)
                result.rag_enabled = True
                selected = [r.poc for r in retr.results]
                for r in retr.results:
                    scores[r.poc.id] = r.final_score

                # LLM 重排
                if selected:
                    profile = _profile_text(result)
                    retr = retriever.rerank_with_llm(
                        retr, result.target, profile, self.llm
                    )
                    selected = [r.poc for r in retr.results]
                    for r in retr.results:
                        scores[r.poc.id] = r.final_score

                if verbose:
                    self._log(
                        f"[2/5] RAG 召回：{len(candidates)} 条候选 → 命中 {len(selected)} 条"
                        f"（跳过 {retr.skipped_low_score} 条低分）",
                        verbose,
                    )
                    for r in retr.results[:6]:
                        self._log(
                            f"      {r.final_score:.3f}  {r.poc.id:<30} {r.poc.name}",
                            verbose,
                        )

        # ── 降级路径：全量按严重度 ─────────────────────────────
        if not selected:
            selected = sorted(
                candidates, key=lambda p: p.severity.rank, reverse=True
            )[: self.cfg.rag.top_k]
            result.notes.append("RAG 未命中或已禁用，使用按严重度排序的兜底 POC 集")

        # ── 基线 POC 并入 ──────────────────────────────────────
        # 必须在**降级路径之后**执行，不能只靠 kb/retriever：RAG 被禁用
        # 或索引损坏时会走降级分支，那时基线集不会生效，就会漏掉
        # .git/config 泄露、响应头缺失这类与技术栈无关的必查项。
        selected = self._merge_baseline(selected, candidates, verbose)

        # ── CVE 情报增强 ───────────────────────────────────────
        self._enrich_with_intel(selected, result, verbose)

        result.pocs_selected = len(selected)
        self._selected = selected
        self._scores = scores
        result.phases["match"] = round(time.perf_counter() - t0, 2)
        return selected

    def _merge_baseline(
        self, selected: list[POC], candidates: list[POC], verbose: bool
    ) -> list[POC]:
        """把通用基线 POC 并入执行集。

        判据与技术栈无关的必查项：
        * ``always_run: true`` 显式声明
        * ``header_check`` 类——判断"某个响应头在不在"与目标是什么技术
          栈毫无关系，任何 Web 目标都该查
        * 命中 kb/retriever._BASELINE_IDS

        这个函数是 :meth:`Retriever._add_baseline` 的同构实现，
        放在调度器这层是为了让**降级路径**（RAG 禁用 / 索引损坏）也能覆盖到。
        两处判据刻意保持一致，改一处就要改另一处——所以判据来源统一走
        POC 的 ``always_run`` 字段与 category，不各自硬编码 ID。
        """
        from kb.retriever import _BASELINE_IDS  # 单一事实来源

        have = {p.id for p in selected}
        added: list[str] = []
        for p in candidates:
            if p.id in have or p.intrusive:
                continue
            if p.always_run or p.id in _BASELINE_IDS or p.category is Category.HEADER_CHECK:
                selected.append(p)
                added.append(p.id)
        if added and verbose:
            self._log(f"      并入通用基线 POC：{', '.join(added)}", verbose)
        return selected

    def _enrich_with_intel(
        self, pocs: list[POC], result: ScanResult, verbose: bool
    ) -> None:
        """用 pocindex 情报给 CVE 类 POC 补客观风险指标（CVSS/KEV/EPSS）。"""
        cve_pocs = [p for p in pocs if p.cve]
        if not cve_pocs:
            return
        try:
            intel = get_intel(f"{self.cfg.data_dir}/intel")
            found = 0
            for p in cve_pocs:
                for cve in p.cve:
                    info = intel.lookup(cve)
                    if not info:
                        continue
                    found += 1
                    tags = intel.enrich(cve)
                    p.tags = list({*p.tags, *tags})
                    if info.kev:
                        p.tags = [*p.tags, "actively-exploited"]
                        p.description += f"\n\n⚠ 该 CVE 已被列入 CISA KEV（存在在野利用）。"
                    if info.cvss is not None:
                        p.description += f"\n外部情报：{info.summary_line()}"
                    break
            if found and verbose:
                self._log(f"      CVE 情报增强：{found}/{len(cve_pocs)} 条命中", verbose)
        except Exception as exc:  # noqa: BLE001 —— 情报是增强项，失败不阻塞
            result.errors.append(f"CVE 情报获取失败（已跳过增强）: {type(exc).__name__}")

    # ── 阶段 4：批量验证 ──────────────────────────────────────────
