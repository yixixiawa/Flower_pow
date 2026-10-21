"""JS 静态分析采集器（findsomething 逻辑）。

抓取页面里的 JS 文件并从中提取四类资产：

============  ====================================================
kind         提取内容
============  ====================================================
endpoint     后端接口路径（``/api/xxx``、``baseURL + "/user"``）
secret       硬编码凭据（AK/SK、token、密码、JWT、内网地址）
map          source map 引用（``.map``）——可还原完整源码
internal     内网地址（``10.x`` / ``192.168.x`` / ``*.internal``）
============  ====================================================

**这是纯只读操作**，不执行 JS、不发送任何构造请求，因此绝对安全，
是Web 漏扫里性价比最高的采集器之一——很多后台的接口路径只存在于前端 JS 里，
不扫JS 就永远发现不了。

三个曾经把结果压到个位数的硬限制（已全部放宽）
------------------------------------------------
1. **抓取按 4KB 截断**。``max_body_capture`` 本来是给"报告里贴一段响应"用的，
   拿它截 JS 等于只扫到文件头的 license 注释——压缩 bundle 几百 KB，接口全在后面。
   现在 JS 走 ``cfg.js_max_bytes``（默认 2MB）。
2. **接口路径吃前缀白名单**。旧规则只认 ``/api`` ``/v1`` ``/admin`` 等 11 个前缀，
   实际路径是 ``/role/getAll`` ``/oa/noticeType/getAll`` ``/monitor/log/query``
   ——一条都匹配不上。现在改成**结构判别**（多段、含字母、非静态资源），
   不再猜业务词。
3. **只看 HTML 里的 ``<script src>``**。路由懒加载的 ``*-api-*.js`` chunk 由
   ``import()`` 引入，从不下载，里面的接口自然挖不到。现在按模块图 BFS 跟进
   ``import`` / ``from`` / ``require`` / ``import()`` 的相对边。

正则来源：findsomething / nuclei 的公开规则集思路，
按本项目需要重写。
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from core.config_loader import ScanConfig
from core.state import Asset, Evidence
from detectors.base import Detector

# 从 HTML 中提取 script src
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']""", re.IGNORECASE
)
# 提取内联 script 里的 JS（有限长度）
_INLINE_JS_RE = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>", re.DOTALL | re.I)

# ── 提取规则 ─────────────────────────────────────────────────────

# 接口路径：带引号的、以 / 开头的路径。
# **不再带业务前缀白名单**——那 11 个词覆盖不到 /role/getAll、/oa/noticeType/getAll、
# /monitor/log/query 这类真实路径，是"只挖出 5 个接口"的直接原因。
# 结构约束交给 _looks_like_path（多段、含字母、非静态资源）。
_ENDPOINT_RE = re.compile(
    r"""["'](/[A-Za-z0-9_\-./{}:$]{2,119})["']""",
)

# 压缩后的调用形态：``o("monitor/online/query",t)``。路径**没有前导斜杠**，
# 上面那条绝对路径正则抓不到。只在"函数调用实参"位置出现才收，
# 且 callee 限 1~3 字符（压缩别名）+ 几个常见请求函数名。
_CALL_ARG_RE = re.compile(
    r"""(?:[\w$]{1,3}|axios\s*\.\s*\w+|\$\.(?:ajax|get|post)|fetch|request)\s*\(\s*"""
    r"""["'`]([A-Za-z0-9_\-./{}:$]{3,119})["'`]""",
    re.I,
)

# axios/fetch 调用里显式声明的 url/baseURL
_BASEURL_RE = re.compile(
    r"""base(?:URL|Url|_url)\s*[:=]\s*["'`]([^"'`\n]{1,120})["'`]""",
)

# 模块图的边：import x from "./a.js" / import"./a.js" / import("./a.js") / require("./a.js")
_IMPORT_EDGE_RE = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)"""
    r"""["']([^"'\s]{1,200})["']""",
    re.I,
)
# 打包器（Vite/Rollup 为主）的 chunk 清单：一个纯字符串数组
# ``["js/vue-router-a1.js","js/monitor-api-390a.js","css/index-b2.css"]``。
# 这些不是 import 语句，上面那条抓不到——而 ``monitor-api`` 正在这个数组里，
# 漏了它等于漏掉整个监控模块的接口。
_CHUNK_REF_RE = re.compile(r"""["']((?:[\w\-.]+/)+[\w\-.]+\.m?js)["']""")

# 静态资源后缀——路径里带这些的不是接口
_STATIC_SUFFIX_RE = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|css|less|scss|sass|map|png|jpe?g|gif|webp|avif|"
    r"bmp|svg|ico|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|flac|pdf|zip|gz|tgz|"
    r"7z|rar|docx?|xlsx?|pptx?|txt|html?|htm|xml|json|wasm)$",
    re.I,
)
# MIME 类型不是路径（``t("text/plain")`` 在压缩代码里到处都是）
_MIME_RE = re.compile(
    r"^(?:text|image|application|audio|video|font|multipart|message|model|"
    r"charset|content)/", re.I,
)

# 硬编码密钥模式（参考 nuclei/findsomething，误报低的那些）
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_ak", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aliyun_ak", re.compile(r"\bLTAI[0-9A-Za-z]{12,24}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("generic_secret",
     re.compile(r"""(?i)(?:api[_-]?key|secret[_-]?key|app[_-]?secret|access[_-]?key)"""
                r"""\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']""")),
    ("db_password",
     re.compile(r"""(?i)(?:pass(?:wd|word)?|pwd)\s*[:=]\s*["']([^"'\s]{6,64})["']""")),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@")),
]

# 内网地址
_INTERNAL_PATTERNS = (
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b[\w.\-]+\.(?:internal|local|corp|intranet)\b"),
)
# 已知的公共资源前缀，排除误报
_INTERNAL_ALLOW = ("127.0.0.1", "0.0.0.0", "localhost")


@dataclass(slots=True)
class JsFinding:
    kind: str                # Asset 分类：endpoint|secret|internal|map
    value: str
    context: str = ""
    # 密钥子类：aws_ak / jwt / db_password / generic_secret …
    sub_kind: str = ""


# ── 路径判别 ─────────────────────────────────────────────────────


def _looks_like_path(v: str, *, allow_relative: bool = False) -> bool:
    """判断一个字符串像不像接口路径。

    **结构判别，不猜业务词。** 只要满足"多段、含字母、不是静态文件"就收：
    放宽的是前缀白名单，收紧的是"一眼假的"——静态资源、MIME、版本号堆叠、
    随机串、时间戳目录。这样 /role/getAll 能进，main.js 进不来。
    """
    if not v or len(v) < 3 or len(v) > 120:
        return False
    if "//" in v or ".." in v:
        return False
    s = v.rstrip("/")
    if not s:
        return False
    if _STATIC_SUFFIX_RE.search(s) or _MIME_RE.match(s.lstrip("/")):
        return False

    if allow_relative:
        # 相对路径：不能是模块相对引用（那是 import 边，不是接口）
        if s.startswith(("/", "./", "../")):
            return False
        if "/" not in s:
            return False   # 单段单词太容易误命中（变量名、枚举值）
    else:
        if not s.startswith("/"):
            return False

    segs = [x for x in s.split("/") if x]
    if not segs or len(segs) > 10:
        return False
    # 单段过长 → 更像 base64 / hash / 哈希路由
    if any(len(x) > 60 for x in segs):
        return False
    # 至少一段含字母（挡掉 /2024/10/13 这类日期与纯数字 ID）
    if not any(re.search(r"[A-Za-z]", x) for x in segs):
        return False
    # 全 16 进制段 → hash 路由，不是接口
    if all(re.fullmatch(r"[0-9a-fA-F]{6,}", x) for x in segs if x):
        return False
    return True


def _in_import_context(text: str, pos: int) -> bool:
    """命中位置前面紧邻 from/import/require → 这是模块引用，不是接口。"""
    head = text[max(0, pos - 24) : pos]
    return bool(re.search(r"(?:\bfrom|\bimport|\brequire)\s*\(?\s*$", head))


def extract_base_url(text: str) -> str:
    """从 JS 里取 axios/请求库的 baseURL。取不到返回 ""。

    压缩 chunk 里的接口常写成 ``o("monitor/online/query",t)``，
    真正可访问的路径是 ``/api/monitor/online/query``——少了 baseURL 前缀，
    拿去探活只会得到 404。所以要把 base 找出来拼上。
    """
    for m in _BASEURL_RE.finditer(text):
        v = (m.group(1) or "").strip()
        if not v or v.startswith(("${", "http://", "https://")):
            # 完整 URL 的 base 不做拼接（跨域 API 的 host 拼接会破坏同源判定）
            if v.startswith(("http://", "https://")):
                p = urlparse(v)
                return (p.path or "").rstrip("/")
            continue
        if not v.startswith("/"):
            continue
        return v.rstrip("/")
    return ""


def extract_endpoints(text: str, base: str = "") -> list[str]:
    """从一个 JS 文本里抽全部接口路径（**宽松模式**）。

    三路并集：
      1. 带引号的绝对路径 ``"/role/getAll"``
      2. 函数调用实参里的相对多段路径 ``o("monitor/online/query",t)``
      3. 显式 url 字段 ``url:"/oa/notice/list"``（已被 1 覆盖，保留兜底）

    相对路径若找到 baseURL 会拼成绝对路径；拼不上就原样返回（带前导斜杠的
    形态更利于下游探活，但宁可不拼也不猜）。
    """
    base = (base or "").rstrip("/")
    out: list[str] = []
    seen: set[str] = set()

    def push(v: str, *, relative: bool) -> None:
        v = (v or "").strip()
        if not _looks_like_path(v, allow_relative=relative):
            return
        if relative:
            v = f"{base}/{v}" if base else f"/{v}"
        v = v.rstrip("/") or "/"
        if v in seen:
            return
        seen.add(v)
        out.append(v)

    for m in _ENDPOINT_RE.finditer(text):
        if _in_import_context(text, m.start()):
            continue
        push(m.group(1), relative=False)

    for m in _CALL_ARG_RE.finditer(text):
        if _in_import_context(text, m.start()):
            continue
        push(m.group(1), relative=True)

    return out


def _chunk_priority(url: str) -> tuple[int, int, int]:
    """JS 下载顺序：**接口模块优先**。

    预算（``js_max_files``）永远不够覆盖整个模块图——实测 cas-admin
    第 2 层就有 127 个候选。而真正藏着接口的是 ``*-api-*.js``
    这类模块名，vendor/ui/图标这类下下来基本是浪费。
    所以按"名字里带 api / admin / service"排前面，剩下的按 URL 长度
    （短的通常是入口 chunk，长的多是分包）。
    """
    name = url.rsplit("/", 1)[-1].lower()
    is_api = bool(re.search(r"(?:^|[-_.])(?:api|service|services|server)(?:[-_.]|$)", name))
    is_admin = "admin" in url.lower()
    return (0 if is_api else 1, 0 if is_admin else 1, len(url))


class JsAnalyzer(Detector):
    """JS 敏感信息提取。"""

    name = "js_analyze"

    def __init__(self, cfg: ScanConfig) -> None:
        super().__init__(cfg)

    # ── 提取 ──────────────────────────────────────────────────────
    def extract(self, js_text: str) -> list[JsFinding]:
        """从 JS 源码里提取资产。纯正则，无执行。"""
        out: list[JsFinding] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, value: str, ctx: str = "") -> None:
            value = (value or "").strip()
            if not value or len(value) > 300:
                return
            # Asset.kind 是分类（secret/endpoint/internal/map），报告层按它过滤。
            # 密钥的"子类"（aws_ak / jwt / db_password…）另存到 meta.sub_kind，
            # 不能混进 kind —— 否则 `assets_of("secret")` 一条都匹配不到。
            sub = ""
            if ":" in kind:
                kind, sub = kind.split(":", 1)
            k = (kind, value)
            if k in seen:
                return
            seen.add(k)
            out.append(
                JsFinding(kind=kind, value=value, context=ctx[:120], sub_kind=sub)
            )

        base = extract_base_url(js_text)
        for ep in extract_endpoints(js_text, base):
            add("endpoint", ep, _around(js_text, js_text.find(ep)))

        for kind, rx in _SECRET_PATTERNS:
            for m in rx.finditer(js_text):
                val = m.group(0)
                if any(ok in val for ok in ("process.env", "window.", "${")):
                    continue  # 模板占位符，不是真凭据
                add(f"secret:{kind}", val[:120], _around(js_text, m.start()))

        for rx in _INTERNAL_PATTERNS:
            for m in rx.finditer(js_text):
                if m.group(0) in _INTERNAL_ALLOW:
                    continue
                add("internal", m.group(0), _around(js_text, m.start()))

        return out

    # ── 模块图 ────────────────────────────────────────────────────
    @staticmethod
    def resolve_ref(rel: str, from_url: str) -> str:
        """把 JS 里的一个模块引用解析成绝对 URL。解析不了返回 ""。

        难点在**裸相对路径**：Vite/Rollup 的 chunk 清单写成 ``"js/x.js"``，
        它相对的不是当前文件目录（否则会变成 ``/cas-admin/js/js/x.js``），
        而是入口文件的**父目录**。判据是「当前目录名恰好等于路径首段」——
        ``/cas-admin/js/`` 对上 ``js/``，于是回退一级拼 ``/cas-admin/js/x.js``。
        这一条直接决定 ``monitor-api`` 能不能被下载到。
        """
        if not rel:
            return ""
        if rel.startswith(("data:", "node:", "npm:", "#")):
            return ""
        if rel.startswith(("http://", "https://")):
            return rel
        if rel.startswith("//"):
            return f"https:{rel}"
        if rel.startswith("/"):
            p = urlparse(from_url)
            return f"{p.scheme}://{p.netloc}{rel}"
        if rel.startswith("."):
            return urljoin(from_url, rel)
        if "/" not in rel:
            return ""                     # 裸模块名（vue / lodash）
        cur_dir = from_url.rsplit("/", 1)[0]
        head = rel.split("/", 1)[0]
        if cur_dir.endswith("/" + head):
            return cur_dir[: -(len(head) + 1)] + "/" + rel
        return urljoin(from_url, rel)

    def import_edges(self, js_text: str, from_url: str) -> list[str]:
        """从一份 JS 里取出它引用的**脚本边**，解析成绝对 URL。

        两个来源：import/require 语句 + 打包器的 chunk 清单数组。
        裸模块名与 CSS/图片等非脚本一律跳过。
        """
        out: list[str] = []
        seen: set[str] = set()
        rels = [m.group(1) for m in _IMPORT_EDGE_RE.finditer(js_text)]
        rels += [m.group(1) for m in _CHUNK_REF_RE.finditer(js_text)]
        for rel in rels:
            url = self.resolve_ref(rel.strip(), from_url)
            if not url:
                continue
            if not re.search(r"\.(?:m?js|jsx|ts|tsx)(?:\?[^#]*)?$", url, re.I):
                continue          # 只跟进脚本文件
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
        return out

    async def _collect_js_urls(self, html: str, base: str) -> list[str]:
        urls: list[str] = []
        for m in _SCRIPT_SRC_RE.finditer(html):
            src = m.group(1).strip()
            if src.startswith(("http://", "https://")):
                urls.append(src)
            elif src.startswith("//"):
                urls.append(f"https:{src}")
            else:
                urls.append(urljoin(base, src))
        # 去重 + 保序
        seen: set[str] = set()
        return [u for u in urls if not (u in seen or seen.add(u))]

    async def _crawl(
        self, seeds: list[str], verbose: bool = False
    ) -> list[tuple[str, str]]:
        """按模块图 BFS 下载 JS，返回 ``[(url, text)]``。

        ``cfg.js_max_files`` 是**总文件数**预算（跨层共享），
        ``cfg.js_max_depth`` 是层数。深度 0 = 只看 HTML 里声明的脚本。
        """
        budget = max(1, int(getattr(self.cfg, "js_max_files", 60) or 60))
        max_depth = max(0, int(getattr(self.cfg, "js_max_depth", 2) or 0))
        cap = int(getattr(self.cfg, "js_max_bytes", 2_000_000) or 2_000_000)
        sem = asyncio.Semaphore(max(2, self.cfg.concurrency // 2))

        got: dict[str, str] = {}
        frontier = sorted(dict.fromkeys(u for u in seeds if u), key=_chunk_priority)[:budget]
        depth = 1

        while frontier and len(got) < budget:
            async def one(url: str) -> tuple[str, str]:
                async with sem:
                    ev = await self.send_request(url, capture_limit=cap)
                    if ev.error or not ev.body_excerpt:
                        return url, ""
                    return url, ev.body_excerpt

            results = await asyncio.gather(*(one(u) for u in frontier), return_exceptions=True)
            nxt: list[str] = []
            for r in results:
                if isinstance(r, BaseException):
                    continue
                url, text = r
                if not text:
                    continue
                got[url] = text
                if depth < max_depth:
                    for edge in self.import_edges(text, url):
                        if edge not in got and edge not in nxt:
                            nxt.append(edge)
            if verbose and nxt:
                print(f"[collect] JS 模块图 第 {depth + 1} 层：+{len(nxt)} 个候选")
            room = budget - len(got)
            # 同层候选也要按"接口模块优先"排，否则预算会被 vendor 吃掉
            frontier = sorted(nxt, key=_chunk_priority)[:room] if room > 0 else []
            depth += 1

        return list(got.items())

    async def run(self, base_url: str, verbose: bool = False) -> list[Asset]:
        """抓取首页 → 找 JS（并跟进 import）→ 下载分析 → 产出 Asset。"""
        if not self.cfg.js_analyze_enabled:
            return []

        base = base_url.rstrip("/") + "/"
        # 首页也要用 JS 的抓取上限：SPA 的 index.html 里常有整段内联脚本，
        # 4KB 截断会把 <script src> 声明一起截掉，等于根本没发现 JS。
        cap = int(getattr(self.cfg, "js_max_bytes", 2_000_000) or 2_000_000)
        page = await self.send_request(base, capture_limit=cap)
        if page.error or not page.body_excerpt:
            return []

        assets: list[Asset] = []
        # 首页内联脚本也值得扫
        for blob in self.extract(page.body_excerpt):
            assets.append(
                Asset(kind=blob.kind, value=blob.value,
                      meta={"context": blob.context, "sub_kind": blob.sub_kind,
                            "source_file": "(inline)"},
                      source="js_analyze")
            )

        seeds = await self._collect_js_urls(page.body_excerpt, base)
        crawled = await self._crawl(seeds, verbose)
        if crawled and verbose:
            print(f"[collect] JS 分析：{len(crawled)} 个文件（含 import 追踪）")

        for url, text in crawled:
            found = self.extract(text)
            for m in re.finditer(r"sourceMappingURL=(\S+)", text):
                found.append(JsFinding("map", m.group(1).strip()))
            for blob in found:
                assets.append(
                    Asset(kind=blob.kind, value=blob.value,
                          meta={"file": url,
                                "context": f"{url} | {blob.context}",
                                "sub_kind": blob.sub_kind},
                          source="js_analyze")
                )

        return _dedup(assets)

    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list:
        """JS 资产的消费方是 RAG（提升召回）与报告，不做漏洞判定。"""
        return []


def _dedup(assets: list[Asset]) -> list[Asset]:
    """同名同类只留第一条（保留出现顺序= 页面加载顺序，优先级更高）。"""
    seen: set[tuple[str, str]] = set()
    out: list[Asset] = []
    for a in assets:
        k = (a.kind, a.value)
        if k in seen:
            continue
        seen.add(k)
        out.append(a)
    return out


def _looks_internal(host: str) -> bool:
    return any(r.match(host.lower()) for r in _INTERNAL_PATTERNS)


def _around(text: str, pos: int, span: int = 60) -> str:
    """截取命中位置附近的上下文，方便人工确认。"""
    if pos < 0:
        return ""
    start = max(0, pos - span // 2)
    return re.sub(r"\s+", " ", text[start : pos + span]).strip()


__all__ = [
    "JsAnalyzer",
    "JsFinding",
    "extract_endpoints",
    "extract_base_url",
]
