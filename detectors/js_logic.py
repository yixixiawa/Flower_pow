"""JS 页面内容审计：从前端 JS 里找**逻辑漏洞**与**未鉴权接口**。

为什么单独做一层
----------------
``collectors/js_analyze`` 做的是"资产提取"（端点、密钥、内网地址），
它回答的是"这里有什么"。而前端真正值钱的漏洞藏在**逻辑**里：

* 权限判断写在前端（``role === 'admin'``）——改一个 localStorage 就是管理员
* 调试开关没关（``bypassAuth: true``、``isMock: true``）
* 订单金额在前端算完再提交——改 JS 就能改价
* 后台接口路径直接写进前端 bundle
* 路由守卫声明了 ``requiresAuth`` 却没有 ``beforeEach`` 真正去拦

这些**只在 JS 里成立**，对后端发再多请求也测不出来。所以本模块先抓 JS 内容
做静态分析，再**基于分析结果**去打一次请求做验证（JS 里发现的接口，不带任何
凭证访问一次，看能不能拿到业务数据）。

两条边界
--------
1. **不执行 JS。** 全部是正则匹配，不 eval、不渲染、不加载第三方资源。
2. **验证只发 GET。** 与 api_authz 一致——探测不该改动业务数据。
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from collectors.js_analyze import (
    _INLINE_JS_RE,         # 内联 <script>
    _SCRIPT_SRC_RE,        # <script src=...>
    _SECRET_PATTERNS,      # 硬编码凭据
    JsAnalyzer,            # 复用模块图爬虫（import 追踪）
    _around,
    extract_base_url,
    extract_endpoints,
)
from core.state import Asset, Category, Evidence, Finding, POC, RequestSpec, Severity
from detectors.api_authz import biz_ok
from detectors.base import Detector

# 静态资源后缀的判别已收敛到 collectors.js_analyze._looks_like_path
# （单一事实来源），这里只留"后台类路径优先"的排序词表。
_ADMIN_RE = re.compile(r"admin|manage|sys(?:tem|config)|internal|后台", re.I)
# 传统后端接口的文件后缀——带这些的路径确定是接口，不是页面路由
_API_EXT_RE = re.compile(r"\.(?:aspx?|php\d?|do|action|jsp|ashx|cgi)$", re.I)


def ep_rank(v: str) -> tuple[int, int, int, int]:
    """接口路径的排序权重（小的排前面）。

    放宽提取后单段目录名（``/gi``、``/bwc``、``/tzgg`` 这类导航链接）
    会和真接口混在一起。**不能靠丢**——丢就可能丢掉 ``/dorm`` 这种真接口，
    只能靠排序把它们沉底：后台类优先 → 带接口后缀的优先 → 段数多的优先。
    """
    segs = [x for x in v.split("/") if x]
    return (
        0 if _ADMIN_RE.search(v) else 1,
        0 if _API_EXT_RE.search(v) else 1,
        -len(segs),
        len(v),
    )


@dataclass(frozen=True)
class LogicRule:
    """一条前端逻辑审计规则。"""

    id: str
    name: str
    severity: Severity
    rx: re.Pattern[str]
    advice: str
    group: str = "js_logic"


# ── 规则表 ────────────────────────────────────────────────────────
#
# 每条规则都刻意收窄：**宁可漏报也不刷屏**。前端 bundle 动辄几 MB，
# 稍宽的正则一次能匹配出上千条，报告就没法看了。

_LOGIC_RULES: tuple[LogicRule, ...] = (
    LogicRule(
        id="js-client-authz",
        name="前端权限判断（可被篡改）",
        severity=Severity.HIGH,
        # 三条写法都覆盖：直接比较变量、从本地存储取出来比较、模板里判断
        rx=re.compile(
            r"""(?:role|userType|userRole|userLevel|identity)\s*(?:===|==|!==|!=)\s*"""
            r"""['"](?:admin|superadmin|root|administrator|system)['"]"""
            r"""|(?:getItem|get)\(\s*['"](?:role|userType|userRole|userLevel)['"]\s*\)"""
            r"""\s*(?:===|==|!==|!=)\s*['"](?:admin|superadmin|root)['"]"""
            r"""|(?:v-if|ng-if)\s*=\s*['"][^'"]{0,60}(?:isAdmin|role\s*===)""",
            re.I,
        ),
        advice="权限判断必须在服务端做。前端的 role 比较只是 UI 显隐，攻击者改一个变量即可绕过。",
    ),
    LogicRule(
        id="js-client-authz-storage",
        name="权限标志存在浏览器本地存储",
        severity=Severity.HIGH,
        rx=re.compile(
            r"""(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"]"""
            r"""(?:role|isAdmin|userType|userRole|admin|permission|auth|level)['"]""",
            re.I,
        ),
        advice="把权限/角色写进 localStorage 等于把鉴权交给用户。改为服务端依据 token 解析角色。",
    ),
    LogicRule(
        id="js-debug-switch",
        name="前端调试/后门开关未关闭",
        severity=Severity.MEDIUM,
        rx=re.compile(
            r"""(?:bypassAuth|skipAuth|SKIP_AUTH|noAuth|__DEBUG__|VUE_APP_DEBUG|"""
            r"""enableDebug|debugMode|isMock|mockData|testMode|isTest)\s*[:=]\s*"""
            r"""(?:true|1|['"]true['"])""",
            re.I,
        ),
        advice="生产构建必须剔除调试开关。bypassAuth / mock 类开关一旦生效等于全局鉴权失效。",
    ),
    LogicRule(
        id="js-crypto-key",
        name="前端硬编码加密/签名密钥",
        severity=Severity.MEDIUM,
        rx=re.compile(
            r"""(?:aesKey|secretKey|signKey|md5Key|appSecret|encryptKey|cryptoKey)"""
            r"""\s*[:=]\s*['"][A-Za-z0-9_\-]{8,64}['"]"""
            r"""|CryptoJS\.(?:AES|DES|TripleDES|RC4)\.(?:encrypt|decrypt)\s*\("""
            r"""|CryptoJS\.enc\.Utf8\.parse\(\s*['"][^'"]{8,}['"]""",
            re.I,
        ),
        advice="前端没有秘密。对称密钥放在前端等于公开，签名/加密必须放到服务端。",
    ),
    LogicRule(
        id="js-client-price",
        name="金额在前端计算（可被篡改）",
        severity=Severity.MEDIUM,
        rx=re.compile(
            r"""(?:price|unitPrice|goodsPrice)\s*\*\s*(?:count|num|quantity|qty)"""
            r"""|(?:totalPrice|payAmount|totalFee|orderAmount|totalAmount)"""
            r"""\s*[:=]\s*[^;{}\n]{0,60}\*\s*\w""",
            re.I,
        ),
        advice="服务端必须重新计算金额并与前端传入值比对，不能直接信任前端算出的总价。",
    ),
    LogicRule(
        id="js-comment-secret",
        name="注释里的凭据/待办",
        severity=Severity.LOW,
        rx=re.compile(
            r"""(?://|/\*|<!--)\s*[^\n]{0,120}"""
            r"""(?:password|passwd|pwd\s*[:=]|token|secret|accessKey|密钥|密码"""
            r"""|测试账号|上线前删除|临时账号|admin\s*[:=]\s*\S{3,20})""",
            re.I,
        ),
        advice="清理注释里的测试凭据与待办项；构建时开启注释剥离与敏感词扫描。",
    ),
    LogicRule(
        id="js-sourcemap",
        name="Source Map 泄露（可还原源码）",
        severity=Severity.MEDIUM,
        rx=re.compile(r"sourceMappingURL\s*=\s*(\S+)", re.I),
        advice="生产环境不要发布 .map 文件，或在构建时关闭 sourceMap。",
    ),
)


@dataclass(slots=True)
class JsSource:
    """一份 JS 内容（外链文件或内联脚本）。"""

    name: str        # URL 或 (inline)
    text: str


class JsLogicDetector(Detector):
    """JS 内容审计 + 基于分析结果的未鉴权验证。"""

    name = "js_logic"

    def __init__(self, cfg, poc_map: dict[str, POC] | None = None) -> None:
        super().__init__(cfg)
        self.poc_map = poc_map or {}
        self.notes: list[str] = []
        self.stats: dict[str, int] = {}
        self.sources: list[JsSource] = []

    # ── 1. 收集 JS 内容 ───────────────────────────────────────────
    async def collect(self, base: str, verbose: bool = False) -> list[JsSource]:
        """抓首页 → 抽 script src + 内联脚本 → 下载 JS 正文。

        下载复用 :class:`JsAnalyzer` 的模块图爬虫：只取 HTML 里的
        ``<script src>`` 会漏掉所有路由懒加载 chunk（``*-api-*.js`` 就是
        这样被漏掉的），那里的接口比首页 bundle 更值钱。
        """
        # 首页用 JS 的抓取上限：SPA 的 index.html 里常有整段内联脚本，
        # 4KB 截断会把后面的 <script src> 声明一起截掉。
        cap = int(getattr(self.cfg, "js_max_bytes", 2_000_000) or 2_000_000)
        page = await self.send_request(base, capture_limit=cap)
        if page.error or not page.body_excerpt:
            self.notes.append(f"首页抓取失败：{page.error or '空响应'}")
            return []

        out: list[JsSource] = []
        html = page.body_excerpt

        for m in _INLINE_JS_RE.finditer(html):
            txt = m.group(1) or ""
            if len(txt.strip()) > 40:
                out.append(JsSource("(inline)", txt))

        urls: list[str] = []
        for m in _SCRIPT_SRC_RE.finditer(html):
            src = m.group(1).strip()
            if src.startswith(("http://", "https://")):
                urls.append(src)
            elif src.startswith("//"):
                urls.append(f"https:{src}")
            else:
                urls.append(urljoin(base, src))
        seen: set[str] = set()
        urls = [u for u in urls if not (u in seen or seen.add(u))]

        if verbose and urls:
            print(f"[js-logic] 下载 {len(urls)} 个 JS 入口（含 import 追踪）")

        crawler = JsAnalyzer(self.cfg)
        try:
            crawled = await crawler._crawl(urls, verbose)
        finally:
            await crawler.aclose()
        for url, text in crawled:
            out.append(JsSource(url, text))

        self.sources = out
        return out

    # ── 2. 静态分析 ───────────────────────────────────────────────
    def analyze(self, sources: list[JsSource]) -> list[Finding]:
        findings: list[Finding] = []
        for src in sources:
            for rule in _LOGIC_RULES:
                hits = _collect_hits(rule.rx, src.text, limit=3)
                if hits:
                    findings.append(self._mk_logic(rule, src, hits))
            # 硬编码凭据：复用 js_analyze 的密钥模式（单一事实来源）
            secrets = self._find_secrets(src.text)
            if secrets:
                findings.append(
                    self._mk_logic(
                        LogicRule(
                            id="js-hardcoded-cred",
                            name="前端硬编码凭据",
                            severity=Severity.HIGH,
                            rx=re.compile(r"(?:none)"),
                            advice="立即吊销并轮换该凭据；前端不能携带任何长期有效的密钥。",
                        ),
                        src,
                        secrets,
                    )
                )
            # 文件级检查：路由守卫 / 鉴权头
            findings.extend(self._file_level_checks(src))
        return findings

    def _find_secrets(self, text: str) -> list[str]:
        out: list[str] = []
        for kind, rx in _SECRET_PATTERNS:
            for m in list(rx.finditer(text))[:2]:
                val = m.group(0)
                if any(ok in val for ok in ("process.env", "window.", "${")):
                    continue
                out.append(f"[{kind}] {_clip(val)}")
            if len(out) >= 3:
                break
        return out[:3]

    def _file_level_checks(self, src: JsSource) -> list[Finding]:
        """整文件级别的判定（不是正则单条命中，而是"有 A 无 B"）。"""
        text = src.text
        low = text.lower()
        out: list[Finding] = []

        # 路由守卫：声明了 requiresAuth 却没有全局前置守卫
        if "requiresauth" in low and "beforeeach" not in low and "router" in low:
            out.append(
                self._mk_logic(
                    LogicRule(
                        id="js-router-guard",
                        name="路由声明 requiresAuth 但未见全局守卫",
                        severity=Severity.MEDIUM,
                        rx=re.compile(r"(?:none)"),
                        advice=(
                            "前端路由守卫只是 UI 层拦截，本身就不可靠；此处连守卫都缺失。"
                            "必须在服务端对每个接口做鉴权。"
                        ),
                    ),
                    src,
                    ["requiresAuth 出现但未见 router.beforeEach 守卫"],
                )
            )

        # 大量接口调用却完全不带鉴权头
        calls = len(re.findall(r"axios\.|fetch\s*\(|\$\.ajax|request\s*\(", text))
        if calls >= 3 and not re.search(r"authorization|bearer\s|interceptors|x-token", low):
            out.append(
                self._mk_logic(
                    LogicRule(
                        id="js-no-auth-header",
                        name="前端请求未携带任何鉴权头",
                        severity=Severity.LOW,
                        rx=re.compile(r"(?:none)"),
                        advice=(
                            "确认鉴权是否依赖 Cookie（可以）还是压根没有鉴权（不可以）。"
                            "若为前者请确认 Cookie 带 HttpOnly + SameSite。"
                        ),
                    ),
                    src,
                    [f"该文件中约 {calls} 处请求调用，未见 Authorization / 拦截器设置"],
                )
            )
        return out

    # ── 3. 提取接口 + 未鉴权验证 ──────────────────────────────────
    def endpoints(self, sources: list[JsSource]) -> list[tuple[str, str]]:
        """从 JS 里抽接口路径，返回 ``(路径, 来源文件)``。

        提取走 :func:`extract_endpoints`（结构判别，无业务前缀白名单），
        连 ``o("monitor/online/query",t)`` 这种压缩形态也收，
        并按 JS 里的 ``baseURL`` 拼成可直接访问的路径。
        """
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for src in sources:
            base = extract_base_url(src.text)
            for v in extract_endpoints(src.text, base):
                if v in seen:
                    continue
                seen.add(v)
                out.append((v, src.name))
        # 后台类接口优先——它们的未授权后果最严重；同档内按"像不像接口"排
        out.sort(key=lambda x: ep_rank(x[0]))
        return out

    async def probe_endpoints(
        self, base: str, endpoints: list[tuple[str, str]], verbose: bool = False
    ) -> list[Finding]:
        """对 JS 里发现的接口打**一次**免凭证 GET，看能不能拿到业务数据。"""
        if not getattr(self.cfg, "js_logic_probe_api", True):
            self.notes.append("js_logic：js_logic_probe_api=false，跳过接口未鉴权探测")
            return []
        limit = max(1, int(getattr(self.cfg, "js_logic_max_endpoints", 60) or 60))
        eps = endpoints[:limit]
        findings: list[Finding] = []
        sem = asyncio.Semaphore(max(2, min(6, self.cfg.concurrency)))

        async def one(path: str, origin: str) -> Finding | None:
            async with sem:
                url = base.rstrip("/") + "/" + path.lstrip("/")
                ev = await self.send_request(url)
                if ev.error or ev.status_code is None or ev.status_code >= 400:
                    return None
                body = ev.body_excerpt or ""
                if self.is_soft404(ev) or len(body) < 20:
                    return None
                if not biz_ok(body):
                    return None
                poc = self._poc(
                    "js-unauth-api", "JS 中提取的接口未鉴权可访问", Severity.HIGH
                )
                return Finding(
                    poc_id=poc.id,
                    name=poc.name,
                    severity=Severity.HIGH,
                    category=Category.JS_LOGIC,
                    description=(
                        f"命中 1 处：GET {path}（发现于 {origin}）\n"
                        f"{poc.description or poc.name}\n"
                        f"不带任何凭证请求返回 HTTP {ev.status_code} 且响应含真实业务数据。\n"
                        f"响应片段：{_clip(body, 200)}"
                    ),
                    remediation=poc.remediation or (
                        "为接口补上鉴权守卫；前端 JS 里暴露的接口路径不能作为"
                        "「没人知道就不用鉴权」的理由。"
                    ),
                    matched_at=url,
                    evidence=ev,
                    detector=self.name,
                    tags=[*poc.tags, "js-logic", "unauthenticated", "one-shot"],
                )

        rs = await asyncio.gather(*(one(p, o) for p, o in eps), return_exceptions=True)
        for r in rs:
            if isinstance(r, Finding):
                findings.append(r)
        self.stats["endpoints_found"] = len(endpoints)
        self.stats["endpoints_probed"] = len(eps)
        self.stats["unauth_hits"] = len(findings)
        if verbose:
            print(
                f"[js-logic] JS 接口 {len(endpoints)} 个，探测 {len(eps)} 个，"
                f"未鉴权命中 {len(findings)} 个"
            )
        return findings

    # ── 对外入口 ──────────────────────────────────────────────────
    async def run(
        self, base_url: str, verbose: bool = False
    ) -> tuple[list[Asset], list[Finding]]:
        """完整跑一遍：抓 JS → 静态分析 → 接口未鉴权验证。"""
        base = base_url.rstrip("/") + "/"
        # 先建软 404 基线：否则"任何路径都返回 200 首页"的站点会把
        # 每个 JS 接口都判成未授权可访问。
        await self.probe_soft404(base)
        sources = await self.collect(base, verbose)
        if not sources:
            return [], []

        findings = self.analyze(sources)
        eps = self.endpoints(sources)
        # 提取数与被探测数分开记：不探测时也要能看到"挖到多少接口"，
        # 否则 stats 里的 endpoints_found 会一直是 None，日志看起来像没跑。
        self.stats["endpoints_found"] = len(eps)
        assets: list[Asset] = []

        # 端点资产：即使没有 OpenAPI 文档，也能喂给一次性高危探针。
        # 上限与探测上限共用同一配置——资产里少了，下游探针自然也够不着。
        asset_cap = max(1, int(getattr(self.cfg, "js_logic_max_endpoints", 60) or 60))
        for path, origin in eps[:asset_cap]:
            assets.append(
                Asset(
                    kind="endpoint",
                    value=path,
                    meta={"source_file": origin, "from": "js_logic"},
                    source="js_logic",
                )
            )
        # 逻辑缺陷资产（供报告与 RAG 画像使用）
        for f in findings:
            assets.append(
                Asset(
                    kind="js_logic",
                    value=f.poc_id,
                    meta={"name": f.name, "severity": f.severity.value,
                          "matched_at": f.matched_at},
                    source="js_logic",
                )
            )

        if getattr(self.cfg, "js_logic_probe_api", True):
            findings.extend(await self.probe_endpoints(base, eps, verbose))

        self.stats["js_files"] = len(sources)
        self.stats["logic_findings"] = len(findings)
        return assets, findings

    # ── 小工具 ────────────────────────────────────────────────────
    def _poc(self, pid: str, name: str, sev: Severity) -> POC:
        p = self.poc_map.get(pid)
        if p is not None:
            return p
        return POC(
            id=pid,
            name=name,
            category=Category.JS_LOGIC,
            severity=sev,
            description=name,
            request=RequestSpec(paths=[""]),
        )

    def _mk_logic(self, rule: LogicRule, src: JsSource, hits: list[str]) -> Finding:
        poc = self._poc(rule.id, rule.name, rule.severity)
        return Finding(
            poc_id=poc.id,
            name=rule.name,
            severity=rule.severity,
            category=Category.JS_LOGIC,
            description=(
                f"{poc.description or rule.name}\n\n"
                f"位置：{src.name}\n"
                f"命中 {len(hits)} 处：" + "；".join(hits) + "\n"
                f"上下文：{_clip(_around(src.text, _first_pos(rule.rx, src.text)), 200)}"
            ),
            remediation=poc.remediation or rule.advice,
            matched_at=src.name,
            evidence=Evidence(url=src.name, method="GET"),
            detector=self.name,
            tags=[*poc.tags, "js-logic", "static"],
        )

    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list[Finding]:
        return []


# ── 辅助 ──────────────────────────────────────────────────────────


def _collect_hits(rx: re.Pattern[str], text: str, limit: int = 3) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in rx.finditer(text):
        v = _clip(m.group(0), 100)
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= limit:
            break
    return out


def _first_pos(rx: re.Pattern[str], text: str) -> int:
    m = rx.search(text)
    return m.start() if m else 0


def _clip(s: str, n: int = 120) -> str:
    s = re.sub(r"\s+", " ", (s or "")).strip()
    return s[:n] + ("…" if len(s) > n else "")


__all__ = ["JsLogicDetector", "JsSource", "LogicRule", "ep_rank"]
