"""检测器基类：统一 ``send_request`` / ``verify`` 契约。

为什么要有基类
--------------
调度器只知道"给一个 POC 和一个目标，告诉我有没有发现"。具体怎么发请求、
怎么抑制软 404、怎么留证据，全部收敛在基类里。加新检测类型（比如
GraphQL 专用检测器）只需继承并实现 :meth:`Detector.verify`。

**软 404 抑制是这里最关键的一段逻辑。** 路径探测类误报的根源是：
目标对任何不存在的路径都返回同一个 200 页面（"系统升级中…"）。
如果不处理，一个 22 条 POC 的库能轻松报出上百条假漏洞。
做法是先探测一个随机不存在路径建立基线，之后任何与基线正文高度相似的
命中一律判为软 404。
"""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import httpx

from core.config_loader import ScanConfig
from core.state import Category, Evidence, Finding, MatchRule, POC

_SOFT404_EXTRA = (
    "does not exist", "no handler found", "whitelabel error page",
    "there is no resource", "content not found", "非法请求", "无效的请求",
    "page not found", "not found", "页面不存在", "找不到该页面",
)


def random_path(n: int = 16) -> str:
    """生成随机不存在路径，用于建立软 404 基线。"""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choices(alphabet, k=n))


def normalize_body(text: str, limit: int = 512) -> str:
    """把响应正文归一化，用于相似度比较。

    去掉空白差异与常见动态部分（时间戳、trace id、随机 nonce），
    否则同一页面两次请求会被判为不同内容。
    """
    t = (text or "").lower()
    t = re.sub(r"<script.*?</script>", " ", t, flags=re.DOTALL)
    t = re.sub(r"<!--.*?-->", " ", t, flags=re.DOTALL)
    t = re.sub(r"\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}", " ", t)
    t = re.sub(r"[0-9a-f]{16,}", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit]


def similarity(a: str, b: str) -> float:
    """基于 token 集合的 Jaccard 相似度——比 difflib 快且够用。"""
    sa, sb = set(a.split()), set(b.split())
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / float(len(sa | sb))


def _fallback_proxy(cfg: ScanConfig) -> str | None:
    """不知道目标主机时的代理决策——**跟着配置走**。

    调用 ``client()`` 却不给 url 的情形（例如只想拿客户端去做个无关请求），
    无法判断目标是不是内网。此时按配置里的代理走——因为默认语义就是
    "挂了代理就全部走代理"，用户要例外时用 ``scan.no_proxy`` 表达。
    """
    from core.proxy import normalize_proxy

    return normalize_proxy(getattr(cfg, "proxy", None) or "") or None


def persist_evidence(evdir: str, ev: Evidence, *, require_status: bool = True) -> str:
    """把**完整原始报文**落盘到证据目录，返回 artifact 相对路径（失败返回 ""）。

    文件布局与 Burp 导出一致（也是 ``output/report.py`` PoC 段的直接数据源）：
    请求行 + 请求头 + 请求体，``[RESPONSE]`` 分隔，状态行 + 响应头 + 响应体。

    抽成模块级函数而不是留在 :class:`Detector` 里，是因为**手工登记的发现**
    （``record_finding``）同样需要落盘——两个入口必须写同一种格式，
    否则报告里自动发现与手工发现的 PoC 会呈现两种样子。

    ``require_status=True``（探针路径）：没有状态码就不落盘——那时说明
    请求根本没成功，落盘一个"半截报文"只会让报告更难读。
    手工登记可以传 False：模型粘贴的是真实响应，哪怕它没抄状态行。

    落盘失败（磁盘满/权限）静默返回 ""——证据落盘是增强，
    不能因为写不了文件把调用方弄崩。
    """
    evdir = (evdir or "").strip()
    if not evdir or evdir.lower() == "off" or ev.artifact:
        return ""
    if require_status and ev.status_code is None:
        return ""
    try:
        import hashlib
        from pathlib import Path

        root = Path(evdir)
        root.mkdir(parents=True, exist_ok=True)
        # 必须含 URL：/users/1 与 /users/2 返回相同页面时，
        # 仅凭 method|status|正文前缀 会撞名互相覆盖
        digest = hashlib.sha1(
            f"{ev.method}|{ev.url}|{ev.status_code}|{(ev.full_body or ev.body_excerpt)[:512]}".encode(
                "utf-8", "ignore"
            )
        ).hexdigest()[:12]
        status = ev.status_code if ev.status_code is not None else 0
        name = f"{status}_{digest}.http"
        body = ev.full_body or ev.body_excerpt or ""
        # 留 16 字节余量：正文在工具结果里过过 strip、解码时还做过 errors=replace，
        # 少几个字节是常事。差 1 字节就写「仅保留前 N 字符」，报告读起来像残页，
        # 而真实情况是完整的（实测：880 字节的 /etc/passwd 因为行尾换行被标成截断）。
        truncated = ev.body_size > len(body.encode("utf-8", "replace")) + 16
        head = ev.request_line or f"{ev.method} {ev.url} HTTP/1.1"
        parts = [
            head,
            "",
            "[RESPONSE]",
            f"HTTP/1.1 {ev.status_code}" if ev.status_code is not None else "（未记录状态行）",
            *(f"{k}: {v}" for k, v in ev.response_headers.items()),
            "",
            body,
        ]
        if truncated:
            parts.append(f"\n[TRUNCATED] 原始响应体 {ev.body_size} 字节，"
                         f"仅保留前 {len(body)} 字符")
        (root / name).write_text("\n".join(parts), encoding="utf-8")
        # 报告引用一律用相对 output_dir 的路径（POSIX 斜杠——
        # Windows 的反斜杠进了 Markdown 会被当转义符）；自定义目录
        # 落在 output_dir 之外时退化为绝对路径（报告按两者都能读处理）。
        try:
            ev.artifact = (root / name).relative_to(root.parent).as_posix()
        except ValueError:
            ev.artifact = (root / name).as_posix()
        return ev.artifact
    except OSError:
        return ""


class Detector(ABC):
    """检测器基类。"""

    name = "base"

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self._sem = asyncio.Semaphore(max(1, cfg.concurrency))
        self._soft404_bodies: list[str] = []
        self._client: httpx.AsyncClient | None = None
        self._client_proxy: str | None = None

    # ── HTTP 客户端 ──────────────────────────────────────────────
    def client(self, url: str = "") -> httpx.AsyncClient:
        """取 HTTP 客户端。

        ``url`` 是这个客户端的**首个目标**，用于代理决策（默认全部走代理）。
        检测器实例通常只服务一个目标，所以第一次调用时定下的代理会被复用。
        若后续请求换了主机（跨主机的检测器），代理决策与已建好的客户端不一致，
        此时**重建客户端**——比"用错代理静默扫描"要安全得多。
        """
        from core.proxy import build_client_kwargs, resolve_proxy_for

        host = ""
        if url:
            try:
                from urllib.parse import urlparse

                host = urlparse(url if "://" in url else f"http://{url}").hostname or ""
            except Exception:  # noqa: BLE001
                host = ""
        wanted = resolve_proxy_for(self.cfg, host) if host else _fallback_proxy(self.cfg)

        if self._client is not None and self._client_proxy != wanted:
            # 目标主机或代理决策变了 → 旧客户端作废，重建。不能复用：
            # httpx 的 proxy 在客户端构造时就绑定了，改不了。
            old, self._client = self._client, None
            try:
                asyncio.get_running_loop().create_task(old.aclose())
            except RuntimeError:
                pass

        if self._client is None:
            # 代理决策统一收敛到 core/proxy.py：显式配置 > 自动探测到的代理。
            # 默认**全部目标都走代理**（内网也走），这样挂了 Burp/Clash
            # 就能看到全部流量——内网/本机也不拦截。
            self._client = httpx.AsyncClient(
                **build_client_kwargs(self.cfg, url or self._client_url_hint)
            )
            self._client_proxy = wanted
        return self._client

    _client_url_hint = ""

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._client_proxy = None

    async def __aenter__(self) -> "Detector":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ── 统一请求接口 ──────────────────────────────────────────────
    def build_url(self, base_url: str, poc: POC, path: str) -> str:
        """拼接 URL。

        **不能**用 ``urljoin(base, path)``：当 path 以 ``/`` 开头时 urljoin
        会把它当绝对路径，从而丢掉 base 的 path 前缀——部署在 ``/app/`` 的
        子路径站点会全跑偏。统一按"去重斜杠"拼接。
        """
        url = base_url + path.lstrip("/") if path else base_url
        if poc.request.params:
            qs = "&".join(f"{k}={v}" for k, v in poc.request.params.items())
            url = f"{url}{'&' if '?' in url else '?'}{qs}"
        return url

    async def send_request(
        self,
        url: str,
        poc: POC | None = None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        capture_limit: int | None = None,
    ) -> Evidence:
        """发一个请求并抓取证据。**任何网络异常都转为 Evidence.error，不抛出。**

        ``capture_limit`` 覆盖 ``cfg.max_body_capture``。默认 4KB 是给
        「报告里贴一段响应」用的；抓 JS 时按 4KB 截断，等于只扫了文件头
        的 license 注释——压缩 bundle 动辄几百 KB，接口路径全在后面。
        JS 分析传 ``cfg.js_max_bytes``（默认 2MB）。
        """
        method = (poc.request.method if poc else method) or method
        req_headers = dict(poc.request.headers if poc else {})
        req_headers.update(headers or {})

        ev = Evidence(url=url, method=method, request_headers=req_headers)
        if poc is not None:
            ev.poc_id = poc.id
            ev.poc_name = poc.name
            # 记录「本次探针实际要发什么」——GET 的 query 常被写在 paths 里，
            # 只记 URL 读者看不出 payload 长什么样，无法复现。
            ev.payload_sent = _payload_of(poc, url, method, body)
            # 预期特征：把匹配规则写成人话放进报告
            ev.expected = _expect_of(poc)
        started = time.perf_counter()
        try:
            resp = await self.client(url).request(
                method, url, headers=req_headers, content=body or None
            )
        except Exception as exc:  # noqa: BLE001
            ev.error = f"{type(exc).__name__}: {exc}"
            ev.elapsed_ms = int((time.perf_counter() - started) * 1000)
            return ev

        ev.elapsed_ms = int((time.perf_counter() - started) * 1000)
        ev.status_code = resp.status_code
        ev.response_headers = {k.lower(): v for k, v in resp.headers.items()}
        raw = resp.content or b""
        ev.body_size = len(raw)
        cap = capture_limit if capture_limit and capture_limit > 0 else self.cfg.max_body_capture
        ev.body_excerpt = raw[:cap].decode(
            "utf-8", errors="replace"
        )
        # 完整响应体（上限 64KB）：body_excerpt 只有 4KB，命中后要落盘
        # Burp 式完整报文（报告 PoC 段用），4KB 截断版不算"完整"。
        # 上限防的是 SSRF 拉回超大文件把内存撑爆——64KB 对报告足够。
        ev.full_body = raw[: max(cap, 65536)].decode(
            "utf-8", errors="replace"
        )

        u = urlparse(url)
        ev.request_line = f"{method} {u.path or '/'}"
        if u.query:
            ev.request_line += f"?{u.query}"
        ev.request_line += " HTTP/1.1"
        ev.request_line += f"\nHost: {u.netloc}"
        ev.request_line += f"\nUser-Agent: {self.cfg.user_agent}"
        for k, v in req_headers.items():
            ev.request_line += f"\n{k}: {v}"
        if body:
            ev.request_line += f"\n\n{body}"
        return ev

    # ── 软404 ────────────────────────────────────────────────────
    def learn_soft404(self, ev: Evidence) -> None:
        """用一次随机路径的响应建立基线。"""
        if ev.error or not ev.body_excerpt:
            return
        norm = normalize_body(ev.body_excerpt)
        if norm:
            self._soft404_bodies.append(norm)

    def is_soft404(self, ev: Evidence) -> bool:
        """判断响应是否属于软 404。"""
        if ev.status_code == 404:
            return True
        norm = normalize_body(ev.body_excerpt)
        for marker in _SOFT404_EXTRA:
            if marker in norm:
                return True
        for base in self._soft404_bodies:
            if similarity(norm, base) >= 0.85:
                return True
        return False

    # ── 匹配 ──────────────────────────────────────────────────────
    def rules_match(self, poc: POC, ev: Evidence) -> bool:
        """求值 POC 规则。组合语义（AND / any_of）由 POC.rules_match 统一处理。"""
        return poc.rules_match(ev.body_excerpt, ev.response_headers)

    @staticmethod
    def rule_hit_reason(poc: POC, ev: Evidence) -> str:
        """给报告生成一句"凭什么算命中"。"""
        if not poc.rules:
            return f"状态码 {ev.status_code} 属于期望集合 {poc.request.expect_status}"
        bits: list[str] = []
        for r in poc.rules:
            scope = f"header[{r.header}]" if r.target.value == "header" else "响应内容"
            if r.value_regex:
                bits.append(f"{scope} 匹配 {r.value_regex}")
            elif r.patterns:
                bits.append(f"{scope} 包含 {'/'.join(r.patterns[:3])}")
        return "；".join(bits) or "规则命中"

    def status_ok(self, poc: POC, ev: Evidence) -> bool:
        if ev.status_code is None:
            return False
        return ev.status_code in poc.request.expect_status

    # ── 发现构造 ──────────────────────────────────────────────────

    # 响应体落盘上限：超过就不值得全文进文件（报告里也读不动），
    # 截断处会在文件里标注原始大小。
    _EVIDENCE_BODY_CAP = 65536

    def _persist_evidence(self, ev: Evidence) -> None:
        """命中时把完整原始报文落盘到证据目录，``ev.artifact`` 记录路径。

        为什么在 ``make_finding`` 时落盘而不是 ``send_request``：那里还不知道
        这条响应会不会成为发现——一次扫描几百个请求全落盘，证据目录会爆炸；
        只有命中才值得留档，量天然可控。

        真正的写入逻辑在模块级 :func:`persist_evidence`——
        ``record_finding``（手工登记）也走它，两条路径写出的报文格式必须
        一致，否则报告里自动发现与手工发现的 PoC 会呈现两种样子。
        """
        persist_evidence((getattr(self.cfg, "evidence_dir", "") or ""), ev)

    def make_finding(
        self,
        poc: POC,
        ev: Evidence,
        rag_score: float = 0.0,
        extra_tags: list[str] | None = None,
    ) -> Finding:
        # 命中依据写进证据，报告里才能说清「凭什么算命中」而不是只丢个 URL
        if not ev.matched_pattern:
            ev.matched_pattern = self.rule_hit_reason(poc, ev)
        self._persist_evidence(ev)
        return Finding(
            poc_id=poc.id,
            name=poc.name,
            severity=poc.severity,
            category=poc.category,
            description=poc.description,
            remediation=poc.remediation,
            matched_at=ev.url,
            evidence=ev,
            references=list(poc.references),
            cve=list(poc.cve),
            detector=self.name,
            rag_score=rag_score,
            tags=[*poc.tags, *(extra_tags or [])],
        )

    async def probe_soft404(self, base_url: str) -> None:
        """对给定目标建立软 404 基线。"""
        ev = await self.send_request(base_url.rstrip("/") + "/" + random_path())
        self.learn_soft404(ev)

    # ── 子类实现 ──────────────────────────────────────────────────
    @abstractmethod
    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list[Finding]:
        """验证一条 POC，返回发现列表（可能为空）。"""

    async def run_many(
        self,
        pocs: list[POC],
        base_url: str,
        scores: dict[str, float] | None = None,
        concurrency: int | None = None,
    ) -> tuple[list[Finding], list[str]]:
        """并发跑一批 POC。返回 ``(findings, errors)``。

        单条 POC 抛异常不能拖垮整批——单条失败记进 errors 后继续。
        """
        sem = asyncio.Semaphore(concurrency or max(1, self.cfg.concurrency))
        scores = scores or {}

        async def one(p: POC) -> list[Finding]:
            async with sem:
                return await self.verify(p, base_url, scores.get(p.id, 0.0))

        results = await asyncio.gather(
            *(one(p) for p in pocs), return_exceptions=True
        )
        findings: list[Finding] = []
        errors: list[str] = []
        for p, r in zip(pocs, results):
            if isinstance(r, BaseException):
                errors.append(f"{p.id} 执行异常: {type(r).__name__}: {r}")
            else:
                findings.extend(r)
        return findings, errors

# ── POC 执行过程的可读化 ──────────────────────────────────────────

_OP_CN = {
    "contains": "响应包含",
    "all": "同时包含",
    "not_contains": "响应不含",
    "regex": "匹配正则",
    "missing": "响应头缺失",
    "absent": "响应头存在但不匹配",
}
_TARGET_CN = {"all": "响应任意位置", "body": "响应体", "header": "响应头",
              "status": "状态码"}


def _payload_of(poc: POC, url: str, method: str, body: str = "") -> str:
    """把「本次实际发出的 payload」拼成一行可读文本。

    只给 URL 读者看不出注入点长什么样——报告里必须原样给出 payload，
    否则对方无法复现。GET 的 query 已经包含在 url 里，但单独标出来更清楚。
    """
    bits: list[str] = [f"{method} {url}"]
    if body:
        bits.append(f"body: {body}")
    if poc.request.params:
        q = "&".join(f"{k}={v}" for k, v in poc.request.params.items())
        bits.append(f"query: {q}")
    # POC 常把注入 payload 写在 paths 里（例如 /search?q='))UNION...），
    # 这时 URL 本身已经包含 payload，额外说明它来自 POC 定义
    if poc.request.paths:
        bits.append(f"paths: {', '.join(poc.request.paths[:3])}")
    if poc.request.headers:
        keys = ", ".join(sorted(poc.request.headers)[:6])
        bits.append(f"headers: {keys}")
    return " | ".join(bits)


def _expect_of(poc: POC) -> str:
    """把匹配规则写成人话，作为「预期返回」。"""
    if not poc.rules:
        return "（该 POC 无匹配规则，由专用探测器动态判定）"
    parts: list[str] = []
    for i, r in enumerate(poc.rules, 1):
        op = _OP_CN.get(r.op.value if hasattr(r.op, "value") else str(r.op), "匹配")
        tgt = _TARGET_CN.get(
            r.target.value if hasattr(r.target, "value") else str(r.target), ""
        )
        pat = " / ".join(str(p) for p in (r.patterns or [])[:3])
        joiner = " 且 " if getattr(r, "match_all", False) else " 或 "
        parts.append(f"规则{i}：{tgt} {op} [{joiner.strip()}]{pat}")
    return "；".join(parts)[:400]
