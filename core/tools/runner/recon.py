"""侦察类工具：发请求、指纹、端口、路径、JS、SQLi 探针、OpenAPI、子域名。

这些 handler 只做"取回事实"，判断留给模型；探针的命中判定一律走
``detectors/`` 下的检测器，不在这里另写一套匹配规则。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.state import Finding
from core.tools.runner.base import _BODY_PREVIEW


class ReconMixin:
    """见模块说明。"""

    # ── 侦察类 ────────────────────────────────────────────────────

    async def _h_http_request(
        self, session, url: str = "", method: str = "GET",
        headers: dict[str, str] | None = None, body: str = "",
    ) -> str:
        from detectors.http_detector import HttpDetector

        target = self._normalize_target(url) if url else self._target_of(session)
        det = HttpDetector(self.cfg.scan)
        try:
            ev = await det.send_request(target, method=method or "GET", headers=headers, body=body or "")
        finally:
            await det.aclose()
        if ev.error:
            return f"请求失败：{ev.error}"
        # 记下这次真实报文：模型随后登记手工发现时，报告 PoC 段才有响应可贴
        self._remember_exchange(ev)
        # 响应无变化检测：**在拼装返回文本之前**，用结构化信号
        # (status_code, body_size, body_hash) 判定——不能对完整返回文本
        # 做 md5，那里面混着 elapsed_ms，每次请求耗时都不同，"完全相同"
        # 永远不成立（真实教训：18 连发端点检测一次都没触发）。
        # 命中抛 ToolBlocked，由 execute 既有的 except 转【已拦截】回灌。
        self._check_endpoint_signal(
            target, ev.status_code, ev.body_size, ev.body_excerpt or ""
        )
        hdrs = "\n".join(
            f"  {k}: {v}"
            for k, v in list(ev.response_headers.items())
            if k in ("server", "content-type", "set-cookie", "location", "x-powered-by",
                     "access-control-allow-origin", "www-authenticate", "content-length")
        )
        body_txt = (ev.body_excerpt or "").strip()
        # 只有**真的切了**才写「截断」：预览没超上限时也写「截断 N 字符」，
        # 会让下游把完整响应判成残缺版（回填/报告都会跟着标错）。
        shown = body_txt[:_BODY_PREVIEW]
        mark = (
            f"截断 {len(shown)} 字符" if len(shown) < len(body_txt) else f"{len(shown)} 字符"
        )
        return (
            f"{method} {target}\n"
            f"状态码：{ev.status_code}  耗时：{ev.elapsed_ms}ms  正文大小：{ev.body_size}B\n"
            f"关键响应头：\n{hdrs or '  （无）'}\n"
            f"正文（{mark}）：\n{shown}"
        )

    async def _h_recon_fingerprint(self, session, url: str = "") -> str:
        from detectors.http_detector import FingerprintDetector

        target = self._target_of(session, url)
        det = FingerprintDetector(self.cfg.scan)
        try:
            fp = await det.fingerprint(target if target.endswith("/") else target + "/")
        finally:
            await det.aclose()
        if fp.http_status is None:
            return f"目标不可达：{fp.target}"
        session.result.fingerprints = [f for f in session.result.fingerprints if f.target != fp.target]
        session.result.fingerprints.append(fp)
        return f"指纹：{fp.summary()}"

    async def _h_recon_ports(self, session, host: str = "", top: int = 0) -> str:
        from collectors.port_scan import PortScanner

        if host:
            norm = self._normalize_target(host)
            h = urlparse(norm).hostname or host
        else:
            h = urlparse(self._target_of(session)).hostname or ""
        if not h:
            return "无法确定主机名"
        old = self.cfg.scan.port_scan_top
        if top:
            self.cfg.scan.port_scan_top = max(1, min(int(top), 2000))
        try:
            assets = await PortScanner(self.cfg.scan).run(h, False)
        finally:
            self.cfg.scan.port_scan_top = old
        added = self._merge_assets(session, assets)
        ports = [a.value for a in assets][:40]
        return f"开放端口 {len(ports)} 个（新增资产 {added}）：{', '.join(ports) or '无'}"

    async def _h_recon_paths(self, session, url: str = "") -> str:
        from collectors.path_scan import PathScanner

        target = self._target_of(session, url)
        base = target.rstrip("/") + "/"
        ps = PathScanner(self.cfg.scan)
        try:
            assets = await ps.run(base, False)
        finally:
            await ps.aclose()
        added = self._merge_assets(session, assets)
        lines = [f"路径探测：命中 {len(assets)} 个（新增资产 {added}）"]
        for a in assets[:30]:
            lines.append(f"  {a.value[:110]}" + (f"  [{a.meta.get('title','')[:30]}]" if a.meta.get("title") else ""))
        return "\n".join(lines)

    async def _h_recon_js(self, session, url: str = "") -> str:
        from collectors.js_analyze import JsAnalyzer

        target = self._target_of(session, url)
        js = JsAnalyzer(self.cfg.scan)
        try:
            assets = await js.run(target.rstrip("/") + "/", False)
        finally:
            await js.aclose()
        added = self._merge_assets(session, assets)
        by: dict[str, list[str]] = {}
        for a in assets:
            by.setdefault(a.kind, []).append(a.value)
        # 接口按"像不像接口"排序：放宽提取后导航目录名（/gi、/bwc、/tzgg）
        # 会和真接口混在一起，只靠前 40 条展示时噪声会盖住值钱的那批。
        if by.get("endpoint"):
            from detectors.js_logic import ep_rank

            by["endpoint"].sort(key=ep_rank)
        lines = [f"JS 静态分析：{len(assets)} 项（新增 {added}）"]
        # endpoint 给足展示位：放宽提取后接口是主角，只列 12 条会让人
        # 以为"就挖到这么点"；密钥/内网/map 本来就少，各给 8 条够看。
        cap = {"endpoint": 40, "secret": 8, "internal": 8, "map": 8}
        for k, v in by.items():
            lines.append(f"  {k}（{len(v)}）：")
            for x in v[: cap.get(k, 10)]:
                lines.append(f"    {x[:120]}")
            if len(v) > cap.get(k, 10):
                lines.append(f"    … 另有 {len(v) - cap.get(k, 10)} 条")
        return "\n".join(lines)

    async def _h_js_audit(self, session, url: str = "", probe_api: bool = True) -> str:
        """JS 页面内容审计：前端逻辑漏洞 + JS 接口未鉴权探测。"""
        from detectors.js_logic import JsLogicDetector

        target = self._target_of(session, url)
        base = target.rstrip("/") + "/"
        det = JsLogicDetector(self.cfg.scan, self.poc_map)
        # 临时开关而不改配置对象：cfg 是共享的 pydantic 模型，
        # 直接改会污染后续所有工具调用。
        old = getattr(self.cfg.scan, "js_logic_probe_api", True)
        self.cfg.scan.js_logic_probe_api = bool(probe_api)
        try:
            assets, findings = await det.run(base, verbose=False)
        finally:
            self.cfg.scan.js_logic_probe_api = old
            await det.aclose()
        added_a = self._merge_assets(session, assets)
        added_f = self._merge_findings(session, findings)

        lines = [
            f"JS 内容审计：{base}",
            f"  JS 来源 {det.stats.get('js_files', 0)} 份、"
            f"提取接口 {det.stats.get('endpoints_found', 0)} 个"
            + (
                f"、未鉴权探测 {det.stats.get('endpoints_probed', 0)} 个 → "
                f"命中 {det.stats.get('unauth_hits', 0)} 个"
                if probe_api
                else "（未做接口探测）"
            ),
            f"  并入会话：新增资产 {added_a}、新增发现 {added_f}",
        ]
        by: dict[str, list[Finding]] = {}
        for f in findings:
            by.setdefault(f.poc_id, []).append(f)
        if by:
            lines.append("  发现明细：")
            for pid, fs in sorted(by.items()):
                lines.append(
                    f"    [{fs[0].severity.label}] {pid} × {len(fs)} —— {fs[0].name}"
                )
                lines.append(f"      例：{fs[0].matched_at[:100]}")
        else:
            lines.append("  未发现前端逻辑缺陷（也可能是页面为纯静态/JS 未下载到）")
        for n in det.notes:
            lines.append(f"  注：{n}")
        return "\n".join(lines)

    async def _h_sqli_probe(self, session, url: str = "", limit: int = 0) -> str:
        """SQL 注入一次性探针：只取数据库版本号。"""
        from detectors.exploit import ExploitProbeDetector, ops_from_assets

        target = self._target_of(session, url)
        base = target.rstrip("/") + "/"
        lim = self._probe_limit(limit)
        ops = ops_from_assets(session.result.assets, lim)
        det = ExploitProbeDetector(self.cfg.scan, self.poc_map, approver=self.approver)
        try:
            findings, stats = await det.run(base, ops, kinds=("sqli",), verbose=False)
        finally:
            await det.aclose()
        return self._probe_report("SQL 注入（只取版本号）", session, det, findings, stats, ops)

    async def _h_exploit_probe(
        self, session, url: str = "", kinds: str = "rce,fileread", limit: int = 0
    ) -> str:
        """RCE / 任意文件读 / 任意文件上传一次性探针。"""
        from detectors.exploit import ExploitProbeDetector, ops_from_assets

        target = self._target_of(session, url)
        base = target.rstrip("/") + "/"
        lim = self._probe_limit(limit)
        ops = ops_from_assets(session.result.assets, lim)
        want = tuple(k.strip() for k in (kinds or "rce,fileread").split(",") if k.strip())
        if "all" in want:
            want = ("rce", "fileread", "upload")
        det = ExploitProbeDetector(self.cfg.scan, self.poc_map, approver=self.approver)
        try:
            findings, stats = await det.run(base, ops, kinds=want, verbose=False)
        finally:
            await det.aclose()
        return self._probe_report("高危探针", session, det, findings, stats, ops)

    def _probe_limit(self, limit: int) -> int:
        n = int(limit or 0) or int(getattr(self.cfg.scan, "probe_max_ops", 40) or 40)
        return max(1, min(n, 500))

    def _probe_report(
        self, title: str, session, det, findings: list[Finding],
        stats: dict[str, dict[str, int]], ops: list[Any],
    ) -> str:
        """把一次性探针的结果整理成给模型看的文本。"""
        added = self._merge_findings(session, findings)
        lines = [
            f"{title}：接口 {len(ops)} 个，每接口只尝试一次",
            f"  发起请求 {det.checked} 次；并入会话新增发现 {added} 项",
        ]
        for kind, st in stats.items():
            lines.append(
                f"  {kind}：尝试 {st['attempted']}、命中 {st['hit']}、"
                f"未命中 {st['miss']}、出错跳过 {st['error']}、"
                f"中止后跳过 {st.get('skipped', 0)}"
            )
        for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True)[:12]:
            lines.append(f"  [{f.severity.label}] {f.poc_id} → {f.matched_at[:90]}")
        if not findings:
            lines.append("  未命中：所有接口一次探测均未取得证据，已按策略跳过（不再重试）")
        for n in det.notes:
            lines.append(f"  注：{n}")
        return "\n".join(lines)

    async def _h_recon_openapi(self, session, url: str = "") -> str:
        from collectors.openapi import OpenApiCollector

        target = self._target_of(session, url)
        oa = OpenApiCollector(self.cfg.scan, verbose=False)
        try:
            assets = await oa.run(target.rstrip("/") + "/", verbose=False)
            spec = oa.spec_url
        finally:
            await oa.aclose()
        added = self._merge_assets(session, assets)
        if not assets:
            return "未发现 OpenAPI/Swagger 文档"
        no_auth = [a for a in assets if not a.meta.get("auth")]
        admin = [a for a in assets if a.meta.get("admin")]
        hv = [a for a in assets if a.meta.get("high_value")]
        lines = [
            f"接口文档：{spec}",
            f"共 {len(assets)} 个操作（新增资产 {added}）：免鉴权 {len(no_auth)}、"
            f"后台类 {len(admin)}、高价值 {len(hv)}",
        ]
        for a in assets[:25]:
            flags = []
            if not a.meta.get("auth"):
                flags.append("免鉴权")
            if a.meta.get("admin"):
                flags.append("后台")
            if a.meta.get("high_value"):
                flags.append("高价值")
            if a.meta.get("has_id"):
                flags.append("含ID")
            lines.append(
                f"  {a.meta.get('method','GET'):6} {a.meta.get('path','')[:70]}"
                + (f"  [{'/'.join(flags)}]" if flags else "")
            )
        if len(assets) > 25:
            lines.append(f"  …（其余 {len(assets)-25} 条见资产列表）")
        return "\n".join(lines)

    async def _h_recon_subdomains(
        self, session, domain: str = "", passive_only: bool = True
    ) -> str:
        from collectors.subdomain_extract import SubdomainCollector

        target = self._target_of(session, domain)
        sc = SubdomainCollector(self.cfg.scan, verbose=False)
        try:
            cands = await sc.run(target, verbose=False, passive_only=passive_only)
            base = sc.main_domain(target)
            notes = list(sc.notes)
        finally:
            await sc.aclose()
        if not cands:
            return "\n".join(
                [f"子域枚举：{base or target} 未发现子域"] + [f"  注：{n}" for n in notes]
            )
        assets = [c.to_asset(base) for c in cands]
        added = self._merge_assets(session, assets)
        # 来源分布：被动源的算"实测到的"，permutation 的单独算"猜的"。
        # 刻意**不硬编码 crt.sh**——被动源已扩到多个，写死一个名字会
        # 让别的源拿到的子域被误报成"猜测"。
        by_source: dict[str, int] = {}
        for c in cands:
            by_source[c.source] = by_source.get(c.source, 0) + 1
        lines = [
            f"子域枚举：主域 {base} → {len(cands)} 个候选（新增资产 {added}）",
            "  来源：" + "、".join(f"{k} {v}" for k, v in by_source.items()),
        ]
        for c in cands[:30]:
            lines.append(f"  {c.host[:70]}  [{c.source}]")
        if len(cands) > 30:
            lines.append(f"  …（其余 {len(cands)-30} 条见资产列表）")
        if notes:
            lines += [f"  注：{n}" for n in notes[:4]]
        return "\n".join(lines)
