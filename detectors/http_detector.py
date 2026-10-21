"""HTTP 类检测器：把 POC 声明翻译成实际的HTTP 请求 + 匹配判断。

一条 POC 的验证流程：

    对 request.paths 中每个路径发一个请求
        ↓
    是不是软 404？（基线比对，见 base.py）
        ↓ 是 → 丢弃
        ↓ 否
    状态码在expect_status 里？或规则命中？（允许"500 页面泄露堆栈也算"）
        ↓
    全部 match 规则求值
        ↓ true → 生成 Finding（带完整 Evidence）

``header_check`` 类走单独分支：它只关心响应头，不走路径列表，
且**不参与软 404 抑制**（响应头缺失与路径是否存在无关）。
"""

from __future__ import annotations

from core.config_loader import ScanConfig
from core.state import Category, Finding, POC
from detectors.base import Detector


class HttpDetector(Detector):
    """通用 HTTP 检测器——覆盖 POC 库里的绝大多数类别。"""

    name = "http"

    def __init__(self, cfg: ScanConfig) -> None:
        super().__init__(cfg)

    # ── 响应头检查 ────────────────────────────────────────────────
    async def _verify_header(self, poc: POC, base_url: str, rag_score: float) -> list[Finding]:
        # HSTS 只在 HTTPS 下有意义，纯 HTTP 目标上跳过，避免产生无意义告警
        if poc.id == "hdr-missing-hsts" and not base_url.startswith("https"):
            return []

        ev = await self.send_request(base_url, poc)
        if ev.error or not ev.response_headers:
            return []
        # 响应头规则基于同一份响应头统一判定（AND / any_of 由 POC.rules_match 处理）
        if not poc.rules_match("", ev.response_headers):
            return []
        f = self.make_finding(poc, ev, rag_score, extra_tags=["header"])
        f.description = (
            f"{poc.description}\n\n判定依据：{self.rule_hit_reason(poc, ev)}"
            if poc.description
            else f"判定依据：{self.rule_hit_reason(poc, ev)}"
        )
        return [f]

    # ── 通用 HTTP 验证 ────────────────────────────────────────────
    async def _verify_http(self, poc: POC, base_url: str, rag_score: float) -> list[Finding]:
        """按paths 逐个探测。

        **同一 POC 的多路径命中合并为一条发现**，命中位置列出全部路径。
        实测踩坑：`.env` POC 探测 `.env` 与 `.env.local` 两个路径，
        两者都命中时会报出两条内容相同的"严重"漏洞，报告里显得像
        发现了两个不同问题，实际只是同一个问题出现了两处。
        合并后报告可读性显著更好，数量也不虚高。
        """
        hits: list[tuple[str, Evidence, str]] = []

        for path in poc.request.search_paths:
            url = self.build_url(base_url, poc, path)
            ev = await self.send_request(url, poc, body=poc.request.body)
            if ev.error or ev.status_code is None:
                continue

            # 软 404 抑制：与随机路径基线高度相似的一律丢
            if self.is_soft404(ev):
                continue

            if poc.rules:
                # 有规则时以规则为准：允许状态码不符但内容命中（如 500 泄露堆栈）
                if not self.rules_match(poc, ev):
                    continue
            elif not self.status_ok(poc, ev):
                continue

            hits.append((url, ev, self.rule_hit_reason(poc, ev)))

        if not hits:
            return []

        # 以第一条命中作为主证据，其余仅记录 URL
        main_url, main_ev, basis = hits[0]
        f = self.make_finding(poc, main_ev, rag_score)
        f.matched_at = " | ".join(u for u, _, _ in hits[:6])
        if len(hits) > 1:
            f.tags = [*f.tags, f"multi-path:{len(hits)}"]
        f.description = (
            f"{poc.description}\n\n判定依据：{basis}"
            f"（HTTP {main_ev.status_code}"
            + (f"，共{len(hits)} 个路径命中：{f.matched_at}" if len(hits) > 1 else "")
            + "）"
        )
        return [f]

    # ── 统一入口 ──────────────────────────────────────────────────
    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list[Finding]:
        base = base_url.rstrip("/") + "/"
        if poc.category is Category.HEADER_CHECK:
            return await self._verify_header(poc, base, rag_score)
        return await self._verify_http(poc, base, rag_score)


class FingerprintDetector(Detector):
    """指纹识别器——产出 :class:`Fingerprint`，供 RAG 检索用。

    单独成类是因为它的产物不是Finding 而是目标画像，
    且需要读取较大的响应体（技术栈线索常在 JS/CSS 里）。
    """

    name = "fingerprint"

    _TITLE_RE = r"<title[^>]*>(.*?)</title>"

    TECH_HINTS: dict[str, tuple[str, ...]] = {
        "php": ("php", "x-powered-by: php", ".php"),
        "java": ("java", "jsessionid", "tomcat", "jetty", "weblogic", "jboss", "jsp"),
        "spring": ("spring", "whitelabel", "actuator"),
        "python": ("python", "django", "flask", "fastapi", "gunicorn", "werkzeug"),
        "nodejs": ("node", "express", "next.js", "nuxt", "koa"),
        "dotnet": ("asp.net", "aspnet", "aspx", ".net", "iis"),
        "go": ("gin", "go1.", "gorilla"),
        "vue": ("vue", "__vue__", "vue.js", "nuxt"),
        "react": ("react", "react-dom", "_reactroot", "next.js"),
        "jquery": ("jquery",),
        "wordpress": ("wp-content", "wp-includes"),
        "nginx": ("nginx",),
        "apache": ("apache",),
        "iis": ("microsoft-iis", "asp.net"),
        "tomcat": ("tomcat",),
        "swagger": ("swagger", "swagger-ui", "openapi.json", "knife4j"),
        "graphql": ("graphql", "/graphql"),
        "nacos": ("nacos",),
        "jenkins": ("jenkins",),
    }

    async def fingerprint(self, base_url: str):
        from core.state import Fingerprint

        base = base_url.rstrip("/") + "/"
        fp = Fingerprint(target=base)
        ev = await self.send_request(base)
        fp.http_status = ev.status_code
        fp.headers = ev.response_headers
        if ev.error:
            return fp

        fp.server = (
            ev.response_headers.get("server")
            or ev.response_headers.get("x-powered-by")
            or ""
        )
        import re

        if m := re.search(self._TITLE_RE, ev.body_excerpt, re.IGNORECASE | re.DOTALL):
            fp.title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

        blob = f"{fp.server} {fp.title} {ev.body_excerpt}".lower()
        for tech, hints in self.TECH_HINTS.items():
            if any(h in blob for h in hints):
                fp.tech.append(tech)
        return fp

    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list[Finding]:
        """指纹类POC 不作为验证项返回，产物由 :meth:`fingerprint` 给出。"""
        return []