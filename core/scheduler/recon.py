"""``_ReconMixin``：主流程 + 侦察 + 公开性核验。

``scan`` 是整条流水线的编排入口，``_phase2_recon`` 负责端口/路径/
子域/JAvas 采集。公开性核验放在这里是因为它要在侦察之后立刻做——
站点自己公开的目录后面就别当漏洞扫了。"""

from __future__ import annotations

import time
from urllib.parse import urlparse
from collectors.js_analyze import JsAnalyzer
from collectors.path_scan import PathScanner
from collectors.port_scan import PortScanner
from collectors.subdomain_extract import SubdomainCollector
from core.config_loader import Config, sessions_dir
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)
from detectors.http_detector import FingerprintDetector, HttpDetector
from detectors.js_logic import JsLogicDetector
from core.scheduler.helpers import _is_ip


class _ReconMixin:
    async def scan(self, target: str, verbose: bool = True) -> ScanResult:
        result = ScanResult(
            target=target,
            session_id=f"{int(time.time())}",
            llm_enabled=self.llm.available,
        )

        if verbose:
            self._log(f"目标：{target}")
            self._log(
                f"LLM：{self.llm.model_for('fast')}"
                + (
                    f" / 深度任务 {self.llm.model_for('deep')}"
                    if self.cfg.llm.deep_model
                    else ""
                )
                + f" @ {self.cfg.llm.base_url}"
                if self.llm.available
                else "LLM：未配置（DEEPSEEK_API_KEY 缺失）→ 跳过重排与研判"
            )
            # 模型名被静默降级时必须说出来：调用不会报错，用户无从察觉
            for w in self.cfg.llm.model_warnings:
                self._log(f"⚠ {w}")

        try:
            await self._phase2_recon(result, verbose)
            await self._phase3_match(result, verbose)
            await self._phase4_verify(result, verbose)
            await self._phase5_triage(result, verbose)
            await self._phase5b_public_check(result, verbose)
        finally:
            result.finished_at = time.time()
            # 记录实际使用的模型与调用量。放在 finally 里是因为
            # "扫描中途失败"恰恰是最需要知道用了哪个模型的场景。
            result.llm_stats = self.llm.stats()
            # 无论成败都落盘会话快照——失败的排查也靠它
            result.save(sessions_dir(self.cfg))

        return result

    # ── 阶段 5b：公开性核验（回源取证，降误报）────────────────────
    async def _phase5b_public_check(self, result: ScanResult, verbose: bool) -> None:
        """回源站根目录核验命中，判定为"站点自己公开的资源"就自动排除。

        为什么放在研判**之后**：研判是"这条命中技术上成不成立"，
        公开性核验是"就算技术成立，它是不是有意公开的"。后者需要已经有一份
        像样的命中清单，而且只值得为剩下的这些花几次请求。

        为什么自动排除是安全的：只有证据够强（站点自己挂了链接 / 明确自述演示站）
        才动手，弱的只写进 notes 提示人工确认——删掉一条真实漏洞的代价远大于
        多留一条误报。被排除的项会进报告的「误报复核」附录，可撤销。
        """
        if not getattr(self.cfg.scan, "auto_dismiss_public", True):
            return
        todo = result.active_findings()
        if not todo:
            return

        t0 = time.perf_counter()
        from detectors.public_check import PublicResourceChecker

        checker = PublicResourceChecker(self.cfg.scan, verbose=verbose)
        try:
            verdicts = await checker.check_many(result.target, todo)
            result.notes.extend(checker.notes)
        except Exception as exc:  # noqa: BLE001
            # 核验失败绝不能影响主流程（报告该出还得出）
            result.errors.append(f"公开性核验失败：{type(exc).__name__}: {exc}")
            result.phases["public_check"] = time.perf_counter() - t0
            return
        finally:
            await checker.aclose()

        by_key = {(f.poc_id, f.matched_at): f for f in result.findings}
        n_pub = n_suspect = 0
        for v in verdicts:
            if not v.auto_dismissible:
                if v.confidence in ("suspect", "weak"):
                    n_suspect += 1
                    result.notes.append(
                        f"疑似公开资源（证据不足，未自动排除，建议人工确认）：{v.describe()}"
                    )
                continue
            f = by_key.get((v.poc_id, v.matched_at))
            if f is None or not f.active:
                continue
            dismiss_finding(f, v.reason_text())
            n_pub += 1

        if n_pub:
            result.notes.append(
                f"公开性核验：{n_pub} 条命中判定为站点自己公开的资源，已自动排除为误报"
                f"（见报告「已排除的发现（误报复核）」附录，可让 Agent 用 dismiss_finding 撤销）"
            )
        result.phases["public_check"] = time.perf_counter() - t0
        if verbose and (n_pub or n_suspect):
            self._log(
                f"    公开性核验：自动排除 {n_pub} 条 / 疑似待确认 {n_suspect} 条",
                verbose,
            )

    # ── 阶段 2：探活 + 指纹 + 侦察 ────────────────────────────────    
    async def _phase2_recon(self, result: ScanResult, verbose: bool) -> None:
        t0 = time.perf_counter()
        base = result.target.rstrip("/") + "/"
        host = urlparse(base).hostname or ""

        # 1) 指纹（决定 RAG query，必须第一个做）
        fp_det = FingerprintDetector(self.cfg.scan)
        try:
            fp = await fp_det.fingerprint(base)
            result.fingerprints.append(fp)
            if fp.http_status is None:
                result.errors.append(f"目标不可达: {fp.target}")
                self._log("[!] 目标不可达，终止后续阶段", verbose)
                result.phases["recon"] = time.perf_counter() - t0
                return
            result.notes.append(f"指纹：{fp.summary()}")
            if verbose:
                self._log(f"[1/6] 指纹识别：{fp.summary()}", verbose)
        finally:
            await fp_det.aclose()

        # 2) 端口扫描
        if self.cfg.scan.port_scan_enabled and host:
            try:
                assets = await PortScanner(self.cfg.scan).run(host, verbose)
                result.assets.extend(assets)
                web_ports = [a.value for a in assets if a.meta.get("web")]
                if web_ports and verbose:
                    self._log(f"      开放 Web 端口：{', '.join(web_ports)}", verbose)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"端口扫描失败: {type(exc).__name__}: {exc}")

        # 3) 子域枚举（被动，不发请求给目标；产出扩大探测面 + 丰富 RAG 语料）
        if host and not _is_ip(host):
            try:
                sc = SubdomainCollector(self.cfg.scan, verbose)
                try:
                    sub_assets = await sc.assets(base, verbose, passive_only=True)
                    result.assets.extend(sub_assets)
                    if sub_assets:
                        srcs = sorted({a.meta.get("source", "") for a in sub_assets})
                        result.notes.append(
                            f"子域枚举: 被动源发现 {len(sub_assets)} 个子域"
                            f"（{', '.join(s for s in srcs if s)}）"
                        )
                        if verbose:
                            self._log(
                                f"[3/6] 子域枚举：{len(sub_assets)} 个"
                                f"（来源 {'/'.join(s for s in srcs if s)}）",
                                verbose,
                            )
                    elif sc.notes:
                        # **失败必须可见**：所有被动源都挂了时若只写"未发现"，
                        # 会把"工具失效"伪装成"该域真的没资产"——实网踩过。
                        result.notes.extend(f"子域枚举: {n}" for n in sc.notes[:4])
                        if verbose:
                            self._log("[3/6] 子域枚举：未发现", verbose)
                    elif verbose:
                        self._log("[3/6] 子域枚举：未发现", verbose)
                finally:
                    await sc.aclose()
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"子域枚举失败: {type(exc).__name__}: {exc}")

        # 4) JS 静态分析（只读，最先出高价值资产）
        if self.cfg.scan.js_analyze_enabled:
            try:
                js = JsAnalyzer(self.cfg.scan)
                try:
                    assets = await js.run(base, verbose)
                    result.assets.extend(assets)
                    secrets = result.assets_of("secret")
                    internals = result.assets_of("internal")
                    endpoints = result.assets_of("endpoint")
                    if verbose and (secrets or internals or endpoints):
                        self._log(
                            f"      JS 资产：端点 {len(endpoints)}、"
                            f"疑似密钥 {len(secrets)}、内网地址 {len(internals)}",
                            verbose,
                        )
                    for s in secrets:
                        result.notes.append(f"JS 中发现疑似硬编码凭据: {s.value[:40]}")
                finally:
                    await js.aclose()
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"JS 分析失败: {type(exc).__name__}: {exc}")

        # 5) 目录爆破（默认关闭，见 ScanConfig.path_scan_enabled）
        if self.cfg.scan.path_scan_enabled:
            try:
                ps = PathScanner(self.cfg.scan)
                try:
                    assets = await ps.run(base, verbose)
                    result.assets.extend(assets)
                    if verbose and assets:
                        self._log(f"      路径爆破发现 {len(assets)} 个有效路径", verbose)
                finally:
                    await ps.aclose()
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"路径爆破失败: {type(exc).__name__}: {exc}")

        # 6) JS 逻辑审计（前端权限判断 / 调试开关 / 前端算价 / JS 接口未鉴权）
        #    放在侦察阶段是因为它的产出既含发现，也含 endpoint 资产——
        #    后者是阶段 4.5 一次性探针的输入，必须早于探针拿到。
        if getattr(self.cfg.scan, "js_logic_enabled", True):
            try:
                jl = JsLogicDetector(self.cfg.scan, self._poc_map)
                try:
                    assets, findings = await jl.run(base, verbose)
                    result.assets.extend(assets)
                    result.add_findings(findings)
                    result.notes.extend(jl.notes)
                    if verbose and (findings or assets):
                        self._log(
                            f"      JS 逻辑审计：{jl.stats.get('js_files', 0)} 份 JS、"
                            f"接口 {jl.stats.get('endpoints_found', 0)} 个、"
                            f"未鉴权命中 {jl.stats.get('unauth_hits', 0)} 个、"
                            f"逻辑缺陷 {len(findings)} 项",
                            verbose,
                        )
                finally:
                    await jl.aclose()
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"JS 逻辑审计失败: {type(exc).__name__}: {exc}")

        # JS 里的端点作为资产补进指纹语料（强化后续 RAG 召回）
        for a in result.assets_of("endpoint")[:20]:
            result.fingerprints[0].tech.extend([])  # 不污染 tech，保留语义干净

        result.phases["recon"] = round(time.perf_counter() - t0, 2)

    # ── 阶段 3：RAG 检索 + 重排 ───────────────────────────────────
