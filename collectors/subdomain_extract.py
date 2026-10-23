"""子域被动枚举采集器——第 1 轮信息收集的第一步。

为什么单独一个模块
------------------
``core/subdomain.py`` 负责"**给我一批域名，我并发扫完**"，起点是
*已经拿到手的* 一列主机名。但真实测试里第一步恰恰是**怎么把这一列主机名
拿到手**——这两件事的输入输出都不一样，混在一个模块里只会互相拖累。

本模块只做一件事：**给定一个主域，产出尽可能多的候选子域主机名（去重后）**。
拿到列表之后交给 ``core/subdomain.SubdomainScanner`` 去并发探活即可。

为什么做"多源"而不是"只查 crt.sh"
----------------------------------
最初这里只有 crt.sh 一个源。实网测试踩到 **crt.sh 整站 502**
（连根路径 ``https://crt.sh/`` 都返回 nginx 502），导致子域枚举**完全失效**：
被动枚举返回空、排列组合也返回空，最后只能拿用户手工提供的子域清单继续——

> 实例：``gdust.edu.cn`` 一役，crt.sh 持续 502，工具颗粒无收；
> 事后用 hackertarget 一查，同域拿到 **21 个子域**，其中 9 个是用户清单里没有的
> （``webvpn`` / ``jump`` / ``m`` / ``zikao`` / ``pxg`` / ``kjx`` …），
> 也就是**整整一批被漏掉的攻击面**。

结论：**单点数据源在实网里不可接受**。任何公网被动源都会挂、会限流、会被墙。
所以本模块改为**多源并发聚合 + 每源独立降级**（见 ``PASSIVE_SOURCES``）。

各源的坑（都踩过）
------------------
* **crt.sh**：
  1. **整站会 502。** 不只是查询接口，根路径也 502——是服务端挂，
     不是查询姿势错，重试无意义，直接换源。
  2. **返回体巨大。** 热门主域动辄几万条证书，必须限条数、只取
     ``name_value``，否则内存飙。
  3. **一条记录含多个域名。** ``name_value`` 换行分隔，不拆会把整串当主机名。
  4. **通配符要剥。** ``*.example.com`` 不剥星号既非法、又会把主域反复算进来。
* **hackertarget**：免费额度 **50 次/天**，超了返回
  ``API count exceeded`` 而不是 HTTP 错误——**必须看正文，不能只看状态码**。
  返回体是 ``hostname,ip`` 每行一条，取逗号前。
* **rapiddns**：返回的是 **HTML**，域名在结果表 ``<tbody>`` 的每行第一个
  ``<td>`` 里。**没有结果不是错误**（页面正文写 "Found 0 subdomain"），
  但**结构变了**要当成失败上报，不能静默返回空——否则失效能被伪装成"没资产"。
* **urlscan.io**：`q=domain:X` 的过滤**很松**，会混进完全无关的域名
  （实测查 ``example.com`` 混进 ``huffpost.com``）。所以必须逐条按后缀严格收敛，
  这道闸门在 ``_accept``，任何源都绕不过。
* **otx.alienvault**：限流严格（实测直接 429）；无记录时返回 404
  （那是"没数据"不是"失败"，不能算错误）。

主域抽取的坑
------------
``main_domain`` 曾经天真地"取最后两段"，于是：

    gdust.edu.cn   →  edu.cn     ← 错！多段公共后缀被当成了主域
    example.com.cn →  com.cn     ← 错！
    x.example.co.uk→  co.uk      ← 错！

后果是**双重**的：一是查询 ``%.edu.cn`` 会拉回全国高校的域名（几十万条、
必然超时/502，且污染结果）；二是排列组合会产出 ``dev.edu.cn`` 这类垃圾。
所以这里内置了一份**精简公共后缀表**做最长匹配（见 ``PUBLIC_SUFFIXES``）。

排列组合是"锦上添花"，不是主力
------------------------------
已知子域 ``api.example.com`` 很常见配上 ``dev.`` / ``staging.`` 等前缀。
但对已知子域做**前缀替换**（``api.`` → ``dev.api.`` 之类）命中率其实一般，
所以它排在被动枚举之后，且**产出会明确标注来源为 permutation**——
后续如果要做活跃探活筛选，可以据此把"猜出来的"和"被动源里来的"区分开。
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from core.state import Asset

# ── 被动枚举数据源 ────────────────────────────────────────────────────
#
# 全部是**公网被动源**：只查公开日志/搜索引擎的存量数据，
# **不向被测目标发任何请求**。所以这一步零攻击面、零被拉黑风险。
CRT_SH_URL = "https://crt.sh/"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}"
URLSCAN_URL = "https://urlscan.io/api/v1/search/"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

# 保留的历史常量名，供老调用方/文档引用。
PASSIVE_SOURCES = ("crt.sh", "hackertarget", "rapiddns", "urlscan", "otx")

# 多源合并时，同一主机名归给谁。**排在前面的优先**——
# crt.sh 是证书日志，可信度最高；hackertarget 次之；urlscan 噪音最大排后面。
SOURCE_PRIORITY = ("crt.sh", "hackertarget", "rapiddns", "urlscan", "otx")

# 每个源的硬超时。crt.sh 挂的时候是"连不上/一直转"，不设上限会拖死整轮侦察。
# 注意这里是**源级**超时，与 ``cfg.timeout``（单请求）是两回事：多源并发时
# 总耗时 ≈ 最慢的那个源，不会累加。
SOURCE_TIMEOUT = 15.0

# 单个主域最多留多少条子域。热门主域的证书日志能到几万条，
# 全量接住既没意义（绝大多数是 CM 内部签发机名）又会拖慢后续扫描。
MAX_SUBDOMAINS = 2000

# ── 精简公共后缀表（多段后缀，最长匹配）────────────────────────────────
#
# 刻意**不引 publicsuffixlist**：为一个字符串判断拉一个包（还带一份需要
# 定期更新的数据文件）不划算。这份表只收"现实里真会碰到、且真的会把主域
# 抽错"的多段后缀——覆盖中国高校/企业（.edu.cn / .com.cn 是最常踩的）
# 以及跨境业务常见地区。
#
# 单段后缀（``com`` / ``cn`` / ``org``）**不需要列**：最后两段规则天然正确。
# 表里没有的多段后缀会退回"取末两段"，方向是安全的（偏大只会多留候选，
# 不会漏掉真正的子域），只是主域会偏大——文档里已注明。
PUBLIC_SUFFIXES = frozenset({
    # 中国
    "edu.cn", "gov.cn", "org.cn", "com.cn", "net.cn", "ac.cn", "mil.cn",
    # 中国香港 / 中国澳门 / 中国台湾
    "com.hk", "edu.hk", "org.hk", "gov.hk", "net.hk", "idv.hk",
    "com.mo", "edu.mo", "gov.mo", "org.mo", "net.mo",
    "com.tw", "edu.tw", "org.tw", "gov.tw", "net.tw", "idv.tw",
    # 日韩
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "ac.kr", "go.kr", "re.kr", "pe.kr",
    # 东南亚
    "com.sg", "edu.sg", "gov.sg", "org.sg", "net.sg", "per.sg",
    "co.id", "ac.id", "go.id", "or.id", "web.id", "my.id", "sch.id", "net.id",
    "ac.th", "co.th", "go.th", "or.th", "in.th", "mi.th", "net.th",
    "com.vn", "edu.vn", "gov.vn", "org.vn", "net.vn", "int.vn", "ac.vn",
    "com.my", "edu.my", "gov.my", "org.my", "net.my", "mil.my", "name.my",
    "com.ph", "edu.ph", "gov.ph", "org.ph", "net.ph",
    # 英联邦
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "ltd.uk", "plc.uk", "nhs.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au", "csiro.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz", "gen.nz",
    "co.za", "org.za", "net.za", "gov.za", "web.za", "edu.za", "ac.za",
    # 南亚
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "ac.in", "edu.in", "gov.in", "res.in", "nic.in", "mil.in",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd",
    "com.np", "org.np", "edu.np", "gov.np",
    "com.lk", "org.lk", "edu.lk", "gov.lk",
    # 拉美 / 中东 / 非洲
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "edu.ar", "gob.ar",
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "edu.pe", "gob.pe",
    "com.ec", "com.uy", "com.ve", "com.bo", "com.py", "com.do", "com.gt",
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "web.tr",
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa", "pub.sa",
    "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke", "sc.ke",
    "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng",
    "com.gh", "com.ma", "co.ma", "com.tn", "com.dz",
    # 欧洲
    "co.at", "or.at", "ac.at", "gv.at", "priv.at",
    "co.hu", "org.hu", "edu.hu", "gov.hu",
    "co.ro", "org.ro", "com.ro", "nom.ro",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "waw.pl",
    "com.gr", "net.gr", "org.gr", "edu.gr", "gov.gr",
    "com.es", "org.es", "nom.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "edu.pt", "gov.pt", "int.pt", "nome.pt",
    "co.no", "co.se", "co.dk", "co.fi", "com.hr", "com.ba", "com.rs", "com.sk", "com.cy",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru", "edu.ru", "gov.ru", "ac.ru",
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua", "in.ua", "kiev.ua",
    "co.by", "com.by", "co.md", "com.md", "com.ge", "com.am", "com.az",
})

# 常见环境前缀——排列组合用。
# 刻意只放"真实存在率高"的短前缀，不堆砌（堆得越多，噪音越大）。
#
# 注意这里**只收环境语义**（dev/staging/prod…），不收服务语义（api/git/jenkins…）：
# 后者属于"给主域加前缀"的字典爆破，本模块刻意不做（见 ``permute()`` 说明）。
ENV_PREFIXES = (
    "dev", "test", "staging", "stage", "uat", "pre", "prod",
    "beta", "demo", "portal", "app", "web", "admin",
)

# 这些"前缀"本身就是完整体，不该再往前拼（否则出 ``dev.www.x.com`` 这类垃圾）。
_NO_STACK = {"www", "m", "mobile"}

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# 公共后缀最长可能的段数。真实 PSL 里最长的是 ``pvt.k12.ma.us`` 这类四段，
# 这里把上界放开到 4，将来往 PUBLIC_SUFFIXES 里加长后缀不用改逻辑。
_MAX_SUFFIX_LABELS = 4


def _suffix_span(labels: list[str]) -> int:
    """返回 ``labels`` 尾部属于**公共后缀**的段数（1 表示单段 TLD）。

    最长匹配：从长到短试，命中即返回。单段后缀（``com`` / ``cn``）
    不在表里但恒成立，所以兜底返回 1。
    """
    for n in range(min(_MAX_SUFFIX_LABELS, len(labels)), 1, -1):
        if ".".join(labels[-n:]) in PUBLIC_SUFFIXES:
            return n
    return 1


@dataclass
class SubdomainCandidate:
    """一个候选子域，带来源标注。

    ``source`` 的取值直接决定这个候选有多可信：

    * ``crt.sh`` / ``hackertarget`` / ``rapiddns`` / ``urlscan`` / ``otx``
      —— 被动源里真实出现过，**可信度高**（同一主机名按
      :data:`SOURCE_PRIORITY` 归给最可信的那个源）
    * ``permutation`` —— 由已知子域按前缀规则猜出来的，**需要探活验证**
    """

    host: str
    source: str = "crt.sh"

    def to_asset(self, base: str = "") -> Asset:
        return Asset(
            kind="subdomain",
            value=self.host,
            meta={
                "source": self.source,
                "base": base,
                # 是不是"猜"出来的——后续做活跃探活时用来排优先级
                "guessed": self.source == "permutation",
            },
            source="subdomain_extract",
        )


class _SourceFail(Exception):
    """单个被动源失败。**只描述这一次失败**，由聚合层转成 note。

    刻意区分于"返回空"：**"源挂了"和"源说没有"是两回事**。
    前者要显式告诉用户（否则失效能被伪装成"该域没资产"），
    后者静默即可。所以失败一律抛这个异常，而不是返回 ``set()``。
    """


class SubdomainCollector:
    """被动枚举（多源聚合）+ 排列组合，产出候选子域列表。"""

    def __init__(self, cfg, verbose: bool = False) -> None:
        self.cfg = cfg
        self.verbose = verbose
        self.notes: list[str] = []
        # 按**代理决策所依据的主机**分别缓存客户端。所有被动源都是公网服务，
        # 决策结果通常一致；但按主机分桶才能在将来接入内网源时不出错
        # （见 core/proxy.py 的"用错主机名会拿错主机做决策"警告）。
        self._clients: dict[str, httpx.AsyncClient] = {}

    def client(self, url: str = CRT_SH_URL) -> httpx.AsyncClient:
        host = urlparse(url).hostname or ""
        c = self._clients.get(host)
        if c is None or c.is_closed:
            from core.proxy import build_client_kwargs

            # 被动源是**公网服务**，不是被测目标——代理决策要用它自己的
            # 主机名，而不是被枚举的那个域名。用错的话，枚举内网域名时
            # 会拿内网主机名去决策，结果一个被动源都连不上。
            c = httpx.AsyncClient(**build_client_kwargs(self.cfg, url))
            self._clients[host] = c
        return c

    async def aclose(self) -> None:
        for c in self._clients.values():
            if not c.is_closed:
                await c.aclose()
        self._clients.clear()

    # ── 多源聚合 ──────────────────────────────────────────────────
    async def query_passive(
        self, domain: str, verbose: bool = False
    ) -> dict[str, set[str]]:
        """**并发**查所有被动源，返回 ``{源名: 子域集合}``。

        关键性质（都是为了"少一个源不该让整轮侦察失败"）：

        1. **并发**——总耗时 ≈ 最慢的那个源，不随源数累加。
           crt.sh 挂的时候是"一直转"，串行跑会把时间全耗在它身上。
        2. **每源独立降级**——任一源抛异常只让那一项变空集 + 记一条 note，
           其余源照常出结果。
        3. **源级硬超时**——``asyncio.wait_for`` 兜底，防止某个源
           既不回包也不断开（比 httpx 的读超时更彻底）。
        4. **失败必须可见**——失败走 note，绝不静默成"该域没资产"。

        返回的字典**按 :data:`SOURCE_PRIORITY` 保序**，便于调用方按可信度展示。
        """
        verbose = verbose or self.verbose

        async def one(name: str, fn) -> tuple[str, set[str]]:
            try:
                got = await asyncio.wait_for(fn(domain), timeout=SOURCE_TIMEOUT)
            except asyncio.TimeoutError:
                reason = f"超时（>{SOURCE_TIMEOUT:.0f}s）"
            except _SourceFail as exc:
                reason = str(exc)
            except Exception as exc:  # noqa: BLE001
                reason = f"不可达（{type(exc).__name__}）"
            else:
                if verbose:
                    print(f"      {name}：{len(got)} 个子域")
                return name, got
            self.notes.append(f"{name} {reason}，跳过该源")
            if verbose:
                print(f"      {name}：{reason}，跳过")
            return name, set()

        funcs = [(n, getattr(self, f"_src_{n.replace('.', '_')}")) for n in PASSIVE_SOURCES]
        pairs = await asyncio.gather(*(one(n, f) for n, f in funcs))
        return {n: g for n, g in pairs}

    @staticmethod
    def merge_sources(per_source: dict[str, set[str]]) -> tuple[set[str], dict[str, str]]:
        """合并多源结果，返回 ``(全部主机名, {主机名: 归属源})``。

        同一主机名出现在多个源时，按 :data:`SOURCE_PRIORITY` **归给最可信的那个**。
        这样后续展示/筛优先级时能一眼看出"这条是证书日志来的还是搜索引擎来的"。
        """
        origin: dict[str, str] = {}
        for name in SOURCE_PRIORITY:
            for host in per_source.get(name) or ():
                origin.setdefault(host, name)
        return set(origin), origin

    # ── 各被动源实现 ──────────────────────────────────────────────
    # 约定：**只抛异常表达失败**，不自己吞。是否降级由 query_passive 决定。
    # 非致命观察（如达上限）允许直接写 self.notes。

    async def _src_crt_sh(self, domain: str) -> set[str]:
        """证书透明日志。**这条挂了不代表没资产**——crt.sh 会整站 502。"""
        r = await self.client(CRT_SH_URL).get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=SOURCE_TIMEOUT,
        )
        if r.status_code != 200:
            raise _SourceFail(f"返回 HTTP {r.status_code}")
        try:
            rows = r.json()
        except Exception:  # noqa: BLE001
            # crt.sh 被限流时会返回 HTML 错误页而不是 JSON
            raise _SourceFail("返回体不是 JSON（可能被限流）") from None
        if not isinstance(rows, list):
            raise _SourceFail("返回体不是列表")

        found: set[str] = set()
        for row in rows[: MAX_SUBDOMAINS * 4]:   # 先按记录条数粗筛
            if not isinstance(row, dict):
                continue
            raw = str(row.get("name_value") or "")
            for line in raw.splitlines():
                found |= self._accept(line, domain)
                if len(found) >= MAX_SUBDOMAINS:
                    break
            if len(found) >= MAX_SUBDOMAINS:
                self.notes.append(f"crt.sh 子域数达上限 {MAX_SUBDOMAINS}，已截断")
                break
        return found

    async def _src_hackertarget(self, domain: str) -> set[str]:
        """SecurityTrails 家的免费接口。返回体是 ``主机名,IP`` 每行一条。

        **注意**：额度用尽（50 次/天）返回的是正文
        ``API count exceeded`` 而**不是** HTTP 错误——
        只看 ``status_code`` 会把它当成"这个域没有子域"，静默失真。
        """
        r = await self.client(HACKERTARGET_URL).get(
            HACKERTARGET_URL, params={"q": domain}, timeout=SOURCE_TIMEOUT
        )
        if r.status_code != 200:
            raise _SourceFail(f"返回 HTTP {r.status_code}")
        text = (r.text or "").strip()
        low = text.lower()
        if "api count exceeded" in low:
            raise _SourceFail("免费额度用尽（50 次/天）")
        if low.startswith("error") or "no records found" in low:
            # "no records found" 是**有效结论**：这个域确实没记录，不是失败
            return set()
        found: set[str] = set()
        for line in text.splitlines():
            found |= self._accept(line.split(",")[0], domain)
        return found

    async def _src_rapiddns(self, domain: str) -> set[str]:
        """RapidDNS。返回 HTML，结果在 ``<tbody>`` 每行第一个 ``<td>``。

        "找到 0 条"不是错误（正文写 ``Found 0 subdomain``），
        但**结构变了**必须当失败抛出去——否则选择器失效会被伪装成"没资产"。
        """
        url = RAPIDDNS_URL.format(domain=domain)
        r = await self.client(url).get(url, params={"full": "1"}, timeout=SOURCE_TIMEOUT)
        if r.status_code != 200:
            raise _SourceFail(f"返回 HTTP {r.status_code}")
        html = r.text or ""
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S)
        if not body:
            if "found 0 subdomain" in html.lower():
                return set()
            raise _SourceFail("结果表结构变化，无法解析")
        found: set[str] = set()
        for cell in re.findall(r"<td>([^<]+)</td>", body.group(1)):
            found |= self._accept(cell.strip(), domain)
            if len(found) >= MAX_SUBDOMAINS:
                break
        return found

    async def _src_urlscan(self, domain: str) -> set[str]:
        """urlscan.io 公开扫描结果。

        **`q=domain:X` 的过滤很松**——实测查 ``example.com`` 会混进
        ``huffpost.com`` 这类完全无关的域名。所以这里取到候选后
        **一定**要走 ``_accept`` 按后缀严格收敛，不能直接信服务端过滤。
        """
        r = await self.client(URLSCAN_URL).get(
            URLSCAN_URL,
            params={"q": f"domain:{domain}", "size": "100"},
            timeout=SOURCE_TIMEOUT,
        )
        if r.status_code != 200:
            raise _SourceFail(f"返回 HTTP {r.status_code}")
        try:
            payload = r.json()
        except Exception:  # noqa: BLE001
            raise _SourceFail("返回体不是 JSON") from None
        if not isinstance(payload, dict):
            raise _SourceFail("返回体不是对象")
        found: set[str] = set()
        for item in payload.get("results") or []:
            page = (item or {}).get("page") or {}
            for key in ("domain", "apexDomain"):
                found |= self._accept(str(page.get(key) or ""), domain)
            raw_url = str(page.get("url") or "")
            host = urlparse(raw_url).hostname or ""
            found |= self._accept(host, domain)
            if len(found) >= MAX_SUBDOMAINS:
                break
        return found

    async def _src_otx(self, domain: str) -> set[str]:
        """AlienVault OTX 被动 DNS。

        限流很严（实测直接 429）；**404 是"该域没记录"，不算失败**。
        """
        url = OTX_URL.format(domain=domain)
        r = await self.client(url).get(url, timeout=SOURCE_TIMEOUT)
        if r.status_code == 404:
            return set()
        if r.status_code != 200:
            raise _SourceFail(f"返回 HTTP {r.status_code}")
        try:
            payload = r.json()
        except Exception:  # noqa: BLE001
            raise _SourceFail("返回体不是 JSON") from None
        if not isinstance(payload, dict):
            raise _SourceFail("返回体不是对象")
        found: set[str] = set()
        for rec in payload.get("passive_dns") or []:
            found |= self._accept(str((rec or {}).get("hostname") or ""), domain)
            if len(found) >= MAX_SUBDOMAINS:
                break
        return found

    # ── 单源兼容出口 ──────────────────────────────────────────────
    async def query_crtsh(self, domain: str, verbose: bool = False) -> set[str]:
        """只查 crt.sh，失败静默降级为空集（保留给老调用方与测试）。

        新代码请用 :meth:`query_passive`——单源在实网里不可靠。
        """
        verbose = verbose or self.verbose
        try:
            found = await asyncio.wait_for(
                self._src_crt_sh(domain), timeout=SOURCE_TIMEOUT
            )
        except asyncio.TimeoutError:
            self.notes.append(f"crt.sh 超时（>{SOURCE_TIMEOUT:.0f}s），跳过被动枚举")
            if verbose:
                print(f"      crt.sh：超时（>{SOURCE_TIMEOUT:.0f}s），跳过")
            return set()
        except _SourceFail as exc:
            self.notes.append(f"crt.sh {exc}，跳过被动枚举")
            if verbose:
                print(f"      crt.sh：{exc}，跳过")
            return set()
        except Exception as exc:  # noqa: BLE001
            self.notes.append(f"crt.sh 不可达（{type(exc).__name__}），跳过被动枚举")
            if verbose:
                print(f"      crt.sh：请求失败（{type(exc).__name__}），跳过")
            return set()
        if verbose:
            print(f"      crt.sh：被动枚举到 {len(found)} 个子域")
        return found

    @staticmethod
    def _accept(line: str, domain: str) -> set[str]:
        """清洗单条 crt.sh 记录，返回其中属于 ``domain`` 的合法子域集合。

        处理三件事：剥通配符、按主域收敛、剔除非法标签。
        """
        s = (line or "").strip().lower().rstrip(".")
        if not s:
            return set()
        if s.startswith("*."):
            s = s[2:]                    # ``*.example.com`` → ``example.com``
        if s.startswith("."):
            s = s.lstrip(".")
        if not s or "@" in s or " " in s:
            return set()
        # 必须真的是 domain 的子域（或它自己）
        if s != domain and not s.endswith("." + domain):
            return set()
        # 逐标签校验，挡掉 ``a..b`` / ``-x.y`` 这类脏数据
        labels = s.split(".")
        if len(labels) < 2 or not all(_LABEL_RE.fullmatch(lb) for lb in labels):
            return set()
        # 主域自身不算"子域"，它已经是被测目标了
        if s == domain:
            return set()
        return {s}

    # ── 排列组合 ──────────────────────────────────────────────────
    def permute(self, domain: str, known: set[str]) -> set[str]:
        """由已知子域生成候选：只做"减前缀 / 换同级前缀"。

        两条规则，都刻意加了**互斥条件**，否则会产出一堆噪音
        （本地假 crt.sh 实测踩到）：

        * **减前缀**——``dev.api.example.com`` → ``api.example.com``。
          只在剩下的部分仍是合法子域（长度 ≥ 主域 + 1 段）时生成。
        * **换前缀**——``staging.example.com`` → ``test.example.com``。
          **仅当最左段是环境前缀、且其余部分恰好就是主域时**才做。
          不加这个条件，``admin.portal.example.com`` 会被当成
          "``admin`` + ``portal.example.com``" 而产出
          ``dev.portal.example.com`` / ``portal.portal.example.com``
          这类两层堆叠的垃圾——实测 6 个真子域被放大成 24 个噪音候选。

        刻意**不做**"给主域加服务前缀"的爆破：那是 wordlist 的活，
        塞进"被动枚举"里会让用户以为只是查了个日志，实际发了一堆猜测请求。
        """
        out: set[str] = set()
        for host in known:
            if not host.endswith("." + domain):
                continue
            prefix, _, rest = host.partition(".")
            # 方向一：砍掉最左一段（rest 必须仍是主域下的合法子域）
            if rest.endswith("." + domain):
                out.add(rest)
            # 方向二：换同级环境前缀 —— 仅当 rest 恰好是主域本身时。
            # ``dev.example.com`` 的 rest 是 ``example.com`` → 换；
            # ``admin.portal.example.com`` 的 rest 是 ``portal.example.com``
            # → 不换（rest 不是主域，换出来就是堆叠垃圾）。
            if rest == domain and prefix in ENV_PREFIXES and prefix not in _NO_STACK:
                for alt in ENV_PREFIXES:
                    if alt != prefix:
                        out.add(f"{alt}.{domain}")
        return {h for h in out if h.endswith("." + domain) and h != domain}

    # ── 采集器统一入口 ────────────────────────────────────────────
    async def run(
        self, base_url: str, verbose: bool = False, passive_only: bool = True
    ) -> list[SubdomainCandidate]:
        """产出候选子域列表（去重、保序：被动源按可信度在前、猜测在后）。

        ``base_url`` 可以是 ``https://a.example.com/`` 也可以是
        ``example.com``——内部统一收敛到主域。
        """
        verbose = verbose or self.verbose
        domain = self.main_domain(base_url)
        if not domain:
            self.notes.append(f"无法从 {base_url!r} 解析出主域，跳过子域枚举")
            return []

        if verbose:
            print(f"      子域枚举：主域 {domain}")

        per_source = await self.query_passive(domain, verbose)
        found, origin = self.merge_sources(per_source)
        live = [n for n in SOURCE_PRIORITY if per_source.get(n)]
        if verbose and found:
            detail = "、".join(f"{n} {len(per_source[n])}" for n in live)
            print(f"      被动枚举合计 {len(found)} 个子域（{detail}）")

        # 排序键：先按源可信度，同源内按字典序。
        def key(host: str) -> tuple[int, str]:
            try:
                return (SOURCE_PRIORITY.index(origin[host]), host)
            except ValueError:      # pragma: no cover - origin 必含 host
                return (len(SOURCE_PRIORITY), host)

        bodies = [SubdomainCandidate(h, origin[h]) for h in sorted(found, key=key)]

        if passive_only:
            return bodies

        guessed = self.permute(domain, found)
        fresh = guessed - found
        self.notes.append(f"排列组合新增 {len(fresh)} 个候选（未验证，需探活）")
        if verbose and fresh:
            print(f"      排列组合：+{len(fresh)} 个候选")
        bodies += [SubdomainCandidate(h, "permutation") for h in sorted(fresh)]
        return bodies

    @staticmethod
    def main_domain(raw: str) -> str:
        """从任意输入里抽出**注册域**（registrable domain），不做过度截断。

        刻意**不引 publicsuffixlist**——为一个字符串判断拉一个包（还带一份
        需要定期更新的数据文件）不划算。改用内置的精简公共后缀表
        :data:`PUBLIC_SUFFIXES` 做**最长匹配**，覆盖现实里真会踩的多段后缀。

        这里修的是一个真实事故：老实现无条件取末两段，于是

            gdust.edu.cn    →  edu.cn      查询 ``%.edu.cn`` 拉回全国高校域名
            example.com.cn  →  com.cn
            x.example.co.uk →  co.uk

        后果不止"名字难看"——按 ``edu.cn`` 收敛会把**别的学校的域名**
        当成自己的子域收进来（``_accept`` 走 ``endswith`` 收敛，挡不住），
        同时排列组合会基于 ``edu.cn`` 产出 ``dev.edu.cn`` 这类垃圾。

        表里没有的多段后缀仍退回"取末两段"，方向安全（偏大只会多留候选，
        不会漏掉真正的子域）。
        """
        s = (raw or "").strip().lower()
        if not s:
            return ""
        if "://" in s:
            s = urlparse(s).hostname or ""
        else:
            s = s.split("/")[0].split("?")[0]
            # 裸 ``host:port``（没有 scheme）时 ``urlparse`` 用不上，
            # 端口必须自己剥——否则 ``com:8080`` 会被当成非法标签整串丢弃。
            head, sep, tail = s.rpartition(":")
            if sep and tail.isdigit():
                s = head
        s = s.rstrip(".")
        if not s or "@" in s:
            return ""
        # IP 不做子域枚举
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
            return ""
        labels = [lb for lb in s.split(".") if lb]
        if len(labels) < 2:
            return ""
        # 逐标签校验：含空格 / 非法字符的畸形串在这里就该被挡掉，
        # 否则会从 ``"a b.com"`` 里抽出 ``"b.com"`` 这种"看似合理"的假主域。
        if not all(_LABEL_RE.fullmatch(lb) for lb in labels):
            return ""

        span = _suffix_span(labels)
        if len(labels) <= span:
            # 输入本身就是一个公共后缀（``edu.cn`` / ``co.uk``）——
            # 它不是可枚举的主域，直说"解析不出"比硬造一个更有用。
            return ""
        return ".".join(labels[-(span + 1):])

    # ── 便捷出口（供 planner / scheduler 直接用）──────────────────
    async def assets(
        self, base_url: str, verbose: bool = False, passive_only: bool = True
    ) -> list[Asset]:
        """直接产出 ``Asset(kind="subdomain")`` 列表。"""
        domain = self.main_domain(base_url)
        cands = await self.run(base_url, verbose, passive_only)
        return [c.to_asset(domain) for c in cands]


__all__ = [
    "SubdomainCollector",
    "SubdomainCandidate",
    "CRT_SH_URL",
    "HACKERTARGET_URL",
    "RAPIDDNS_URL",
    "URLSCAN_URL",
    "OTX_URL",
    "PASSIVE_SOURCES",
    "SOURCE_PRIORITY",
    "SOURCE_TIMEOUT",
    "PUBLIC_SUFFIXES",
    "MAX_SUBDOMAINS",
    "ENV_PREFIXES",
]
