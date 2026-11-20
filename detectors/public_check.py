"""公开资源核验：命中一条漏洞后**回源站根目录**判断它是不是「站点自己公开的东西」。

解决什么问题
------------
自动探针判不了"设计如此"。最典型的一类是**公开演示站点**：站点本身就建给人看，
其中"泄露"出来的配置文件、默认账号、接口文档、固件包全是有意公开的。
探针看到"敏感信息/未授权访问"照报不误——但这不是漏洞。

手工判定靠的是"人一眼看出来"，而人看出来的其实还是**证据**，只不过没被写成规则：

1. **根页面自述**——首页写着「演示站点 / 在线演示 / 仅供演示 / sandbox」；
2. **站点自己公开了这个资源**——首页或 sitemap.xml 里就有指向它的链接。
   这是最硬的证据：**站点自己把链接挂出来，那它就是公开的**，与探针怎么想无关；
3. **路径落在公开资料目录**——``/download/`` ``/firmware/`` ``/docs/`` ``/manual/``
   这类目录按语义就是给人下载的；
4. **主机名形如 ``demo.`` / ``test.`` / ``sandbox.``**——辅助信号，单独不足以定案。

反向证据同样重要：**robots.txt 明确 Disallow 了这条路径**，说明站点主动要求
不要抓取，那就**不该**判成公开（可能是真的没打算暴露）。

判定分级（不是二值）
--------------------
证据按强度加权，最后分四档。**只有 strong 才自动排除**，suspect / weak 都只
提示人工确认——自动删掉一条真实漏洞的代价，远大于多留一条误报。

| 档位 | 分数 | 处置 |
|---|---|---|
| `strong` | ≥ 3 | **自动判误报**。能达到 3 分只有两条路：站点自己公开挂了它的链接（资源级证据），或"自述演示站 + demo 主机名/公开目录"叠加 |
| `suspect` | = 2 | **不自动排除**，报"疑似公开，建议人工确认" |
| `weak` | = 1 | 只提示 |
| `none` | ≤ 0 | 正常漏洞，不动 |

> 门槛刻意不放在 2 分。「根页面自述演示站」单独就是 2 分，而这类措辞在
> **真实的产品营销页**上随处可见（"请申请演示环境"就命中 `演示环境`）。
> 拿一条可能来自营销页的措辞去自动删掉整站所有发现，是在用误删风险换省事。

两条工程约束
------------
* **网络失败绝不当成"公开"**。抓不到根页面时返回 `none` + 失败原因——
  判错的代价不对称：多留一条误报只是噪音，删掉一条真实漏洞是事故。
* **证据按 host 缓存**。根页面 / robots / sitemap 每个 host 只抓一次，
  几十条发现共用一份上下文，不会因为"每条都回源"把目标打一遍。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from core.config_loader import ScanConfig
from core.state import Finding

# ── 证据词表 ──────────────────────────────────────────────────────

# 强信号：根页面**明确自述**自己是演示/示例/测试站点。
# 注意不用裸词 "demo"——营销页上"预约演示""申请演示"随处可见，
# 单独一个 demo 词根本不能说明站点是公开的，必须成句。
_STRONG_SELF_DESC = (
    "演示站点", "演示站", "本站为演示", "仅为演示", "仅供演示", "演示环境",
    "在线演示", "在线体验", "演示地址", "示例站点", "测试站点", "样例站点",
    "示范站点", "demo site", "live demo", "public demo", "demo environment",
    "sandbox environment", "for demonstration", "is a demo",
)

# 中信号：语义上偏向"给人试用"，但也可能出现在正常产品页里，权重低一档。
_MEDIUM_SELF_DESC = (
    "沙箱", "sandbox", "playground", "试用环境", "体验环境",
    "示例数据", "样例数据", "demo account", "测试账号",
)

# 公开资料目录：按语义就是给人下载/查看的
_PUBLIC_DIR_RE = re.compile(
    r"/(?:downloads?|firmwares?|rom|docs?|manuals?|resources?|public|"
    r"assets?|static|templates?|examples?|samples?|pub|open|share)/",
    re.I,
)

# demo 型主机名前缀（辅助信号，单独不成立）
_DEMO_HOST_RE = re.compile(
    r"^(?:demo|test|sandbox|try|example|sample|beta|staging|preview)(?:[-.]|$)",
    re.I,
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LINK_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*["']([^"']+)["']""", re.I)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# 证据权重
W_LINKED = 3        # 站点自己公开链接了这个资源 / 出现在 sitemap
W_SELF_DESC = 2     # 根页面明确自述演示站点
W_WEAK_DESC = 1     # 沙箱 / 试用环境这类中等自述
W_PUBLIC_DIR = 1    # 路径落在公开资料目录
W_DEMO_HOST = 1     # 主机名是 demo./test. 这类
W_ROBOTS_DENY = -2  # robots 明确禁止抓取 → 反向证据

# 只有这个分数以上才**自动排除**。
#
# 为什么门槛定在 3 而不是 2：2 分 = 「根页面自述演示站」这一条单独成立。
# 而这类措辞在**真实的产品营销页**上随处可见（"请申请演示环境"就命中了
# `演示环境`）。拿一条可能来自营销页的措辞去自动删掉整站所有发现，
# 是在用误删的风险换省事——删掉一条真实漏洞的代价远大于多留一条误报。
#
# 达到 3 分只有两条路，两条都够硬：
#   * 站点自己公开挂了这个资源的链接（3，资源级证据，与探针怎么想无关）
#   * 自述演示站（2）+ demo 型主机名 / 公开资料目录（+1）
SCORE_STRONG = 3
SCORE_SUSPECT = 2

# 单个响应的读取上限——核验只看首页/sitemap 的头部就够了，
# 不设上限会被一个几百 MB 的下载响应拖死。
_MAX_BYTES = 256 * 1024


# ── 路径归一化 ────────────────────────────────────────────────────


def normalize_path(p: str) -> str:
    """URL 路径归一：去 query/fragment、补前导斜杠、去尾斜杠、统一小写。

    统一小写是刻意的：这里是"**站点是不是自己公开了它**"的匹配，
    路径大小写差异（``/Docs/`` vs ``/docs/``）在绝大多数站点上指向同一资源，
    按大小写敏感比较只会漏判、让我们把公开资源当漏洞报出来。
    """
    s = (p or "").strip()
    s = s.split("#", 1)[0].split("?", 1)[0]
    if "://" in s:
        s = urlparse(s).path
    s = "/" + s.lstrip("/")
    if len(s) > 1:
        s = s.rstrip("/")
    return s.lower() or "/"


def path_of(url: str) -> str:
    return normalize_path(url)


def host_of(url: str) -> str:
    s = (url or "").strip()
    if "://" not in s:
        s = "//" + s
    try:
        return (urlparse(s).hostname or "").lower()
    except ValueError:
        return ""


# ── 数据结构 ──────────────────────────────────────────────────────


@dataclass
class HostContext:
    """一个 host 的公开性证据（三条 GET 的结果，按 host 缓存复用）。"""

    base: str
    host: str = ""
    root_url: str = ""
    root_status: int = 0
    root_title: str = ""
    body_text: str = ""
    links: set[str] = field(default_factory=set)     # 根页面提到的同域路径
    sitemap_paths: set[str] = field(default_factory=set)
    robots_denied: list[str] = field(default_factory=list)
    fetched: bool = False
    # 根页面**真的拿到了**没有。和 ``fetched`` 分开记：``fetched`` 只表示
    # "尝试过了"，它是判断"要不要重抓"的；判定要不要下结论得看 ``root_ok``。
    # 合成一个字段的话，"抓过但失败了"和"压根没抓"就分不开，
    # 报告里会把"没查到"说成"查到没有"。
    root_ok: bool = False
    error: str = ""

    def link_hit(self, path: str) -> bool:
        return path in self.links or path in self.sitemap_paths

    def robots_blocks(self, path: str) -> bool:
        for rule in self.robots_denied:
            if _rule_matches(rule, path):
                return True
        return False

    def self_desc(self) -> tuple[str, int]:
        """返回 ``(命中的证据词, 权重)``，没命中返回 ``("", 0)``。"""
        text = f"{self.root_title} {self.body_text}".lower()
        for w in _STRONG_SELF_DESC:
            if w in text:
                return w, W_SELF_DESC
        for w in _MEDIUM_SELF_DESC:
            if w in text:
                return w, W_WEAK_DESC
        return "", 0


@dataclass
class PublicVerdict:
    """一条命中的公开性判定结果。"""

    poc_id: str
    matched_at: str
    is_public: bool
    score: int
    confidence: str                  # strong | medium | weak | none
    reasons: list[str] = field(default_factory=list)
    host: str = ""

    @property
    def auto_dismissible(self) -> bool:
        """是否达到"可以自动判误报"的证据强度。

        **只有 strong**。suspect（2 分）在报告里照实说"疑似公开，建议人工确认"，
        不替用户做决定。
        """
        return self.is_public and self.confidence == "strong"

    def reason_text(self) -> str:
        """写进 ``dismiss_reason`` 的一行说明（会进报告的复核附录）。"""
        if self.reasons:
            return "自动判定为公开资源（" + "；".join(self.reasons) + "）"
        return "自动判定为公开资源"

    def describe(self) -> str:
        mark = {"strong": "★强", "suspect": "中", "weak": "弱", "none": "—"}[self.confidence]
        body = "；".join(self.reasons) if self.reasons else "无公开特征"
        return f"[{mark} {self.score:+d}] {self.poc_id} @ {self.matched_at[:70]} — {body}"


def _rule_matches(rule: str, path: str) -> bool:
    """robots 的 Disallow 规则是否覆盖该路径（支持 ``*`` 与结尾 ``$``）。"""
    r = (rule or "").strip()
    if not r or r == "/":
        return bool(r)      # Disallow: / = 全站禁止
    rx = re.escape(r).replace(r"\*", ".*")
    if rx.endswith(r"\$"):
        rx = rx[:-2] + "$"
    try:
        return re.match("^" + rx, path, re.I) is not None
    except re.error:
        return False


# ── 解析 ──────────────────────────────────────────────────────────


def page_title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    return _TAG_RE.sub("", m.group(1)).strip() if m else ""


def page_text(html: str) -> str:
    """去 script/style 再剥标签，得到正文文本（用于关键词命中）。"""
    t = _SCRIPT_STYLE_RE.sub(" ", html or "")
    t = _TAG_RE.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


def page_links(html: str, root_host: str) -> set[str]:
    """根页面里指向**同域**的路径集合。

    只收同域：站外链接（友链、CDN、第三方）不能证明"这个站自己公开了它"。
    """
    out: set[str] = set()
    for raw in _LINK_RE.findall(html or ""):
        u = raw.strip()
        if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(f"https://{root_host}/", u) if root_host else u
        h = host_of(full)
        if root_host and h and h != root_host:
            continue
        out.add(path_of(full))
    return out


def sitemap_paths(xml: str) -> set[str]:
    return {path_of(loc) for loc in _LOC_RE.findall(xml or "")}


def robots_disallows(text: str) -> list[str]:
    """取 robots.txt 里的 Disallow 规则（不区分 UA——保守起见取并集）。"""
    rules: list[str] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() == "disallow" and v.strip():
            rules.append(v.strip())
    return rules


# ── 核验器 ────────────────────────────────────────────────────────


class PublicResourceChecker:
    """按 host 抓公开性证据，并对发现逐条给判定。"""

    def __init__(self, cfg: ScanConfig, verbose: bool = False) -> None:
        self.cfg = cfg
        self.verbose = verbose
        self._client: httpx.AsyncClient | None = None
        self._ctx: dict[str, HostContext] = {}
        self.notes: list[str] = []

    # ── HTTP ──────────────────────────────────────────────────────
    def client(self, url: str = "") -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            from core.proxy import build_client_kwargs

            # 核验发的是真实请求，代理决策必须走统一入口（默认全部走代理）
            self._client = httpx.AsyncClient(**build_client_kwargs(self.cfg, url))
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def _get_text(self, url: str) -> tuple[int, str]:
        """GET 并返回 ``(状态码, 文本)``。失败返回 ``(0, "")``，绝不抛。"""
        try:
            r = await self.client(url).get(url)
        except Exception:  # noqa: BLE001
            return 0, ""
        if r.status_code >= 400:
            return r.status_code, ""
        raw = r.content[:_MAX_BYTES] if r.content else b""
        enc = r.encoding or "utf-8"
        try:
            return r.status_code, raw.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return r.status_code, raw.decode("utf-8", errors="replace")

    # ── 证据采集 ──────────────────────────────────────────────────
    async def context(self, base_url: str) -> HostContext:
        """取（或复用）该 host 的证据。同一个 host 只抓一次。"""
        base = (base_url or "").rstrip("/")
        host = host_of(base)
        if host and host in self._ctx:
            return self._ctx[host]

        ctx = HostContext(base=base, host=host, root_url=base + "/")
        if not host:
            ctx.error = "无法从目标解析出主机名"
            ctx.fetched = True
            return ctx

        try:
            status, html = await self._get_text(ctx.root_url)
            ctx.root_status = status
            if status:
                ctx.root_ok = True
                ctx.root_title = page_title(html)
                ctx.body_text = page_text(html)[:8000]
                ctx.links = page_links(html, host)
            else:
                ctx.error = "根页面抓取失败"

            # robots + sitemap：拿不到就当没有，不影响主判定
            _rs, robots = await self._get_text(base + "/robots.txt")
            if robots:
                ctx.robots_denied = robots_disallows(robots)
            _ss, sm = await self._get_text(base + "/sitemap.xml")
            if sm:
                ctx.sitemap_paths = sitemap_paths(sm)
        except Exception as exc:  # noqa: BLE001
            ctx.error = f"{type(exc).__name__}: {exc}"
        finally:
            ctx.fetched = True
            if ctx.error and self.verbose:
                self.notes.append(f"公开性核验：{host} {ctx.error}")

        self._ctx[host] = ctx
        return ctx

    # ── 判定（纯函数，便于离线测试）────────────────────────────────
    def evaluate(self, ctx: HostContext, finding: Finding) -> PublicVerdict:
        """对单条发现给出公开性判定。**不发网络请求**。"""
        path = path_of(finding.matched_at or "")
        v = PublicVerdict(
            poc_id=finding.poc_id,
            matched_at=finding.matched_at or "",
            is_public=False,
            score=0,
            confidence="none",
            host=ctx.host,
        )
        if not ctx.fetched or not ctx.host:
            v.reasons.append(ctx.error or "未取得根目录信息，不判定")
            return v

        # 根页面拿不到 → 手上没有任何证据,不能"因为查不到所以算公开"。
        # 这条分支必须单独走:空 title/body 一路打分会算出 0 分,
        # 报告里就成了"无公开特征",把"没查到"说成"查到没有"——
        # 这两种结论对用户的意义完全不同。
        if not ctx.root_ok:
            v.reasons.append(ctx.error or "根页面抓取失败，无证据不判定")
            return v

        # 1) 站点自己公开链接了这个资源 —— 最硬的证据
        if ctx.link_hit(path):
            v.score += W_LINKED
            src = "sitemap" if path in ctx.sitemap_paths else "根页面"
            v.reasons.append(f"{src}中公开列出了该资源（站点自己发布的链接）")

        # 2) 根页面自述
        word, w = ctx.self_desc()
        if w:
            v.score += w
            v.reasons.append(f"根页面自述「{word}」")

        # 3) 公开资料目录
        if _PUBLIC_DIR_RE.search(path):
            v.score += W_PUBLIC_DIR
            v.reasons.append(f"路径位于公开资料目录（{path}）")

        # 4) demo 型主机名
        if _DEMO_HOST_RE.match(ctx.host.split(":")[0]):
            v.score += W_DEMO_HOST
            v.reasons.append(f"主机名形如演示/测试站（{ctx.host}）")

        # 5) 反向证据：robots 明确禁止抓取
        if ctx.robots_blocks(path):
            v.score += W_ROBOTS_DENY
            v.reasons.append("robots.txt 明确禁止抓取该路径（反向证据）")

        if v.score >= SCORE_STRONG:
            v.confidence, v.is_public = "strong", True
        elif v.score >= SCORE_SUSPECT:
            v.confidence, v.is_public = "suspect", False
        elif v.score >= 1:
            v.confidence, v.is_public = "weak", False
        else:
            v.confidence, v.is_public = "none", False
            if not v.reasons:
                v.reasons.append("无公开特征")
        return v

    async def check(self, base_url: str, finding: Finding) -> PublicVerdict:
        return self.evaluate(await self.context(base_url), finding)

    async def check_many(
        self, base_url: str, findings: list[Finding]
    ) -> list[PublicVerdict]:
        """一批发现共用一份 host 上下文——不会"每条都回源"把目标打一遍。"""
        ctx = await self.context(base_url)
        return [self.evaluate(ctx, f) for f in findings]


__all__ = [
    "PublicResourceChecker",
    "HostContext",
    "PublicVerdict",
    "normalize_path",
    "path_of",
    "host_of",
    "page_title",
    "page_text",
    "page_links",
    "sitemap_paths",
    "robots_disallows",
    "SCORE_STRONG",
    "SCORE_SUSPECT",
]
