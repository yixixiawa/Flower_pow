"""子域批量扫描——把一批域名并发跑完，汇总成一份报告。

为什么单独一个模块
------------------
``scan`` 只接单个URL（一次完整流水线：侦察 → RAG → 验证 → 研判 → 报告）。
但实际测试里更常见的是"给我一百个子域，全部扫一遍"——这不该由调用方
写for 循环拼命令，更不该开一百个进程。

**子域扫描有两个特有的坑，不处理就会得到一份看起来很完整、实际大面积漏报的
结果：**

1. **子域大多不可达。** 一个主域下几十个子域，真正在线的可能只有三五个。
   不可达的目标如果照常用超时 12s，串行下光等就能耗掉十几分钟。
2. **请求量放大得离谱。** 每个子域都会跑端口扫描 + 字典爆破 + 21 条 POC。
   100 个子域 = 数万次请求。**这既是服务端的压力，也可能让整个网段被拉黑**，
   所以必须显式给并发上限与逐域超时，且默认先做一次快速探活。

分三档策略（``--mode``）
------------------------
====== ==================================== ==========================
档位做什么                              适用
====== ==================================== ==========================
probe只做 HTTP 探活 + 指纹，不跑 POC      默认档。100+ 子域的常规做法
full  每个在线子域都跑完整流水线          只对少数高价值子域
pipeline 跑一次完整流水线（用 run_pipeline 先探后验）  需要报告逐域留档时
====== ==================================== ==========================

**默认档刻意不跑 POC。** 一百个子域全跑 POC 与"批量筛出值得深挖的子域"
是两件不同的事，混在一起只会得到几百条低危配置缺失，把真正的问题淹掉。
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.config_loader import Config
from core.state import Asset, ScanResult, Severity

# 域名正则：保守一些，宁可漏掉奇怪的也不误报路径片段。
# TLD 部分只收字母，所以 IPv4 匹配不到——**IP 单独用一条正则补**，
# 否则 http://127.0.0.1:8899 这类目标在抽取阶段就被漏掉（实测踩过）。
_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.I,
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
# ``127.0.0.1.1:80`` 这类连着点的畸形串会误当 IP，先排掉
_BAD_DOTTED_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){4,}")

# 公共 CDN / 统计 / 前端库——这类域名出现在页面里是**引用别人的资源**，
# 不是被测方的子域。留着只会让"扫我的子域"变成"扫一堆第三方 CDN"。
#
#刻意**不含** example.com / example.org / test.local 这类
# RFC 2606 文档保留域名：它们在真实场景里就是合法目标（本机靶场、
# 内网测试、CTF 复现），当成噪音会误伤用户自己的测试环境（实测踩过：
# `a.example.com` 被整条丢掉，一个子域都没剩下）。
_NOISE_SUFFIXES = (
    "w3.org", "schema.org", "google.com", "gstatic.com", "googleapis.com",
    "cloudflare.com", "bootstrapcdn.com", "jquery.com", "jsdelivr.net",
    "microsoft.com", "apple.com", "mozilla.org", "iana.org",
    "w3schools.com", "stackoverflow.com", "github.com", "gmail.com",
    "yahoo.com", "baidu.com", "qq.com", "163.com", "aliyun.com",
    "apache.org", "nginx.org", "python.org",
    # 前端 CDN 与统计
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "unpkg.com", "cdnjs.cloudflare.com", "at.alicdn.com", "staticfile.org",
    "sinaimg.cn", "gravatar.com", "fonts.googleapis.com", "fontawesome.com",
)

MAX_TARGETS = 500  # 硬上限。超过就报错而不是默默截断——静默截断会让用户
# 以为全扫完了，实际漏了一大半。


@dataclass
class SubScanEntry:
    """单个子域的扫描结果。"""

    host: str
    reachable: bool = False
    status: int = 0
    result: ScanResult | None = None
    error: str = ""
    elapsed: float = 0.0

    @property
    def findings_count(self) -> int:
        return len(self.result.findings) if self.result else 0

    @property
    def severity_counts(self) -> dict[str, int]:
        return self.result.counts() if self.result else {}


@dataclass
class SubScanReport:
    """批量扫描的汇总。"""

    root: str = ""
    entries: list[SubScanEntry] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    notes: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> list[SubScanEntry]:
        return [e for e in self.entries if e.reachable]

    @property
    def total_findings(self) -> int:
        return sum(e.findings_count for e in self.entries)

    def by_severity(self) -> dict[str, int]:
        agg: dict[str, int] = {s.value: 0 for s in Severity}
        for e in self.entries:
            for k, v in e.severity_counts.items():
                agg[k] = agg.get(k, 0) + v
        return agg

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.finished_at - self.started_at, 2),
            "summary": {
                "total": len(self.entries),
                "reachable": len(self.reachable),
                "findings": self.total_findings,
                "by_severity": self.by_severity(),
            },
            "entries": [
                {
                    "host": e.host,
                    "reachable": e.reachable,
                    "status": e.status,
                    "elapsed": round(e.elapsed, 2),
                    "error": e.error,
                    "findings": (
                        [f.to_dict() for f in e.result.findings] if e.result else []
                    ),
                    "assets": (
                        [a.to_dict() for a in e.result.assets] if e.result else []
                    ),
                }
                for e in self.entries
            ],
            "notes": self.notes,
        }


# ── 输入解析 ──────────────────────────────────────────────────────────


def normalize_host(raw: str, scheme: str = "http") -> str | None:
    """把任意文本里的域名片段规整成 ``http://host[:port]``。

    返回 ``None`` 表示**这不是一个可用的目标**（空、纯路径、协议伪 URL 等）。

    三个刻意取舍：

    * **IPv4 放行**。本地靶场与内网自建服务常直接用 IP，用户显式给了就不该拦。
    * **IPv6 放弃**。``[::1]:8080`` 这类字面量解析成本高、收益低，直接不认。
    * **接受 ``host:port``**。非标准端口上的子域极常见（``api.x.com:8080``），
      一律按无端口处理会漏掉整整一类目标（实测踩过）。
    """
    s = (raw or "").strip().lower()
    if not s:
        return None
    s = re.sub(r"^[a-z]+://", "", s)          # 去协议头
    s = s.split("/")[0]                        # 去路径
    s = s.split("?")[0]                        # 去查询串
    if not s or "@" in s:                    # 邮箱不是目标
        return None
    if s.startswith("["):                     # IPv6 字面量，放弃
        return None

    # 拆主机与端口。顺序很关键：先切端口再校验主机，
    # 反过来会让 "x.com:8080" 因为含冒号而整条被否掉。
    host, port = s, ""
    if ":" in s:
        maybe_host, _, maybe_port = s.rpartition(":")
        # 只有后半段全是数字才认作端口，否则 "a:b" 形态直接否掉
        if maybe_port.isdigit() and 0 < int(maybe_port) < 65536:
            host, port = maybe_host, maybe_port
        else:
            return None

    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    if host.startswith("-") or host.endswith("-") or "--" in host:
        return None
    # IPv4 放行：本地靶场 / 内网自建服务常直接用 IP，且用户显式给了它就不该拦。
    # 但它不参与"主域收敛"——`root=example.com` 时 IP 本来就不该被算作子域。
    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
    if not is_ip and not _HOST_RE.fullmatch(host):
        return None
    return f"{scheme}://{host}{':' + port if port else ''}"


def _is_noise(host: str, base: str = "") -> bool:
    """判断域名是否属于"公共资源/噪音"。

    **必须先按主域收敛、再判噪音**，否则会误伤：
    ``api.example.com`` 结尾是 ``example.com``，而噪音表里恰好有 ``example.com``，
    于是自己的子域被判成噪音丢掉——这是实测踩过的坑。
    所以只要它是 ``base`` 的子域，就一��不看噪音表。
    """
    if base and (host == base or host.endswith("." + base)):
        return False
    return any(host == n or host.endswith("." + n) for n in _NOISE_SUFFIXES)


def extract_hosts(text: str, root: str = "") -> list[str]:
    """从任意文本里抽取域名列表（去重、排序）。

    ``root`` 给了就只保留它自己的子域与本域——**这是必须有的收敛**。
    页面里随便一个外链（``cdn.jsdelivr.net``）都会被正则捞出来，
    不按主域收敛的话，"扫描我的子域"会变成"扫描整个互联网的抽样域名"。
    """
    root_host = ""
    if root:
        root_host = (re.sub(r"^[a-z]+://", "", root).split("/")[0]).lower()
        root_host = root_host.split(":")[0]

    found: set[str] = set()
    for m in _HOST_RE.findall(text or ""):
        h = m.lower().strip(".")
        # 至少两段且总长 ≥ 5，挡掉 "a.js" / "x.io" 这类文件名与短 TLD
        if len(h) < 5 or "." not in h:
            continue
        if _is_noise(h, root_host):
            continue
        # 有主域时只保留它的子域；IP 不参与（它不是任何主域的子域）
        if root_host and not (h == root_host or h.endswith("." + root_host)):
            continue
        found.add(h)

    # IP 单独一轮：只保留**显式出现**的，不参与主域收敛。
    # 不加 root 过滤是有意的——用户直接给 IP 就是要扫它。
    if not root_host:
        masked = _BAD_DOTTED_RE.sub(" ", text or "")
        for m in _IP_RE.findall(masked):
            ip = m.split(":")[0]
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                found.add(m)

    return sorted(found)


def parse_input(data: Any, root: str = "") -> tuple[list[str], list[str]]:
    """解析扩展导出的 JSON（或纯文本），返回 ``(目标URL列表, 提示信息)``。

    **刻意兼容 findSubDomain 的四段结构**（截图里的输出形态）：
    ``域名`` / ``IncompletePath`` / ``URL`` / ``邮箱``。
    其中「域名」与「URL」里的主机名是扫描目标；「IncompletePath``是路径不是主机
    （``/``、``/l/``、``/static/``），对端口/资产扫描无意义；「邮箱」本身不是
    目标，但**邮箱域名往往正是子域**，所以抽取、不丢弃。

    三种输入形态走三条独立分支，不互相借用逻辑——
    之前把文本分支接在结构化分支之后，导致字符串输入永远走不到那里（真bug）。
    """
    notes: list[str] = []

    # ── 形态 1：纯文本（findSubDomain 的复制内容、粘贴的整段结果）──
    if isinstance(data, str):
        hosts = extract_hosts(data, root)
        urls = _dedup_urls(hosts)
        if not urls:
            notes.append(
                "没能从文本里解析出域名。若是 findSubDomain 的输出，"
                "请确认复制完整，或改用 JSON 文件输入。"
            )
        return urls, notes

    # ── 形态 2：结构化对象（扩展导出 / findSubDomain JSON）──
    if isinstance(data, dict):
        hosts = _hosts_from_dict(data, notes, root)
        # **结构化输入同样要按主域收敛**。扩展已经在前端过滤过一遍，
        # 但工具不能假设"喂进来的都干净"——用户可能直接扔来 findSubDomain 的
        # 原始结果，里面全是跨站外链。不收敛就会扫到一堆第三方域名去。
        base = _base_host(root)
        if base:
            before = len(hosts)
            hosts = [h for h in hosts if _host_of(h) == base or _host_of(h).endswith("." + base)]
            dropped = before - len(hosts)
            if dropped:
                notes.append(f"按主域 {base} 收敛：排除 {dropped} 个不属于它的域名")
        urls = _dedup_urls(hosts)
        if not urls and (data.get("域名") or data.get("hosts") or data.get("URL")):
            notes.append("输入里没有任何可用的主机名")
        return urls, notes

    # ── 形态 3：字符串数组（最简单的一行一个域名）──
    if isinstance(data, (list, tuple)):
        base = _base_host(root)
        items = [str(x) for x in data]
        if base:
            items = [h for h in items if _host_of(h) == base or _host_of(h).endswith("." + base)]
        urls = _dedup_urls(items)
        if not urls and data:
            notes.append(f"输入了 {len(data)} 条，但没能解析出任何有效域名")
        return urls, notes

    return [], ["无法识别的输入类型：%s" % type(data).__name__]


def _base_host(root: str) -> str:
    """把用户给的 root 规整成裸主机名（小写、无端口、无路径）。"""
    if not root:
        return ""
    s = re.sub(r"^[a-z]+://", "", str(root).strip().lower()).split("/")[0]
    return s.split(":")[0]


def _host_of(x: Any) -> str:
    """取任意形态输入项里的裸主机名。"""
    if isinstance(x, dict):
        for k in ("host", "domain", "value", "name", "url"):
            if x.get(k):
                return _base_host(str(x[k]))
        return ""
    s = str(x)
    if "@" in s:                      # 邮箱
        s = s.split("@")[-1]
    return _base_host(s)


def _hosts_from_dict(data: dict, notes: list[str], root: str = "") -> list[str]:
    """从结构化字典里收集所有可能的主机名线索。"""
    hosts: list[str] = []

    def add(v: Any) -> None:
        if isinstance(v, str) and v.strip():
            hosts.append(v.strip())
        elif isinstance(v, dict):
            # 扩展可能给 {"host": ..., "sources": [...]}
            for k in ("host", "domain", "value", "name", "url"):
                if v.get(k):
                    add(str(v[k]))
                    return

    # 扩展的原生字段
    for key in ("hosts", "domains", "subdomains"):
        for v in data.get(key) or []:
            add(v)

    # findSubDomain 原始四段（中文键名）
    for key in ("域名", "domain"):
        for v in data.get(key) or []:
            add(v)
    for key in ("URL", "url", "urls"):
        for v in data.get(key) or []:
            add(v)
    for key in ("邮箱", "email", "emails", "emailDomains"):
        for v in data.get(key) or []:
            # **兼容两种形态**：带 @ 的完整邮箱、纯域名数组，
            # 以及扩展导出的 {domain: ..., sources: [...]} 对象。
            # 早期扩展输出的是 "x@x.com" 这种（还会拼出 x.com@x.com 的废数据），
            # 现在只给域名——两种都得认，否则会静默漏掉邮箱线索里的子域。
            if isinstance(v, str) and "@" in v:
                d = v.split("@")[-1].strip().lower()
                hosts.append(d)
                notes.append(f"从邮箱提取域名：{d}")
            else:
                before = len(hosts)
                add(v)
                if len(hosts) == before:
                    continue

    if data.get("IncompletePath") or data.get("incompletePath"):
        notes.append(
            "已忽略 IncompletePath（它是路径片段如 /static/，不是主机名，"
            "对端口与资产扫描无意义）"
        )
    if data.get("root") and not root:
        notes.append(f"输入自带主域：{data['root']}")
    return hosts


def _dedup_urls(hosts: list[str]) -> list[str]:
    """规整 + 去重，保持原有顺序（便于对照扩展里的排序）。"""
    urls: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        u = normalize_host(h)
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


# ── 扫描执行 ──────────────────────────────────────────────────────────


class SubdomainScanner:
    """并发扫描一批子域。"""

    def __init__(self, cfg: Config, *, concurrency: int = 8, per_host_timeout: float = 60.0) -> None:
        self.cfg = cfg
        self.concurrency = max(1, concurrency)
        self.per_host_timeout = per_host_timeout

    async def _probe_one(self, url: str) -> SubScanEntry:
        """只探活 + 指纹，不跑 POC。子域筛选的默认档。"""
        from collectors.js_analyze import JsAnalyzer
        from detectors.http_detector import FingerprintDetector

        entry = SubScanEntry(host=url)
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            fp = await asyncio.wait_for(
                # Detector 要的是 ScanConfig，不是整个 Config ——
                # 传错的话它在建并发信号量时就会 AttributeError（真踩过）
                FingerprintDetector(self.cfg.scan).fingerprint(url), timeout=12
            )
            entry.elapsed = loop.time() - t0
            # fingerprint() 即使请求失败也会返回对象（ev.error 非空时提前返回），
            # 所以判据是 http_status —— 0 或 3xx 之外的错误态都算没真响应。
            if not fp or not fp.http_status or fp.http_status >= 500:
                entry.reachable = False
                entry.error = "无有效响应"
                return entry
            entry.reachable = True
            entry.status = fp.http_status
            r = ScanResult(target=url, fingerprints=[fp])
            # 只抓当前页的 JS：子域页面的 JS 往往指向自己的 API。
            # 用 run() 而非 extract()——run 负责下载并遍历页面引用的脚本文件，
            # extract() 只对已拿到的文本做静态分析。
            try:
                js = JsAnalyzer(self.cfg.scan)
                assets = await asyncio.wait_for(js.run(url, False), timeout=15)
                r.assets.extend(assets or [])
            except Exception:  # noqa: BLE001 - JS 分析失败不影响探活结论
                pass
            r.finished_at = time.time()
            entry.result = r
        except asyncio.TimeoutError:
            entry.elapsed = loop.time() - t0
            entry.error = "探活超时"
        except Exception as exc:  # noqa: BLE001
            entry.elapsed = loop.time() - t0
            entry.error = f"{type(exc).__name__}: {exc}"[:120]
        return entry

    async def _full_one(self, url: str, verbose: bool = False) -> SubScanEntry:
        """跑完整流水线（侦察 → RAG → 验证 → 研判）。"""
        from core.scheduler import Scheduler

        entry = SubScanEntry(host=url)
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            res = await asyncio.wait_for(
                Scheduler(self.cfg).scan(url, verbose=verbose), timeout=self.per_host_timeout
            )
            entry.elapsed = loop.time() - t0
            entry.result = res
            entry.reachable = bool(res.fingerprints)
            entry.status = res.fingerprints[0].http_status if res.fingerprints else 0
        except asyncio.TimeoutError:
            entry.elapsed = loop.time() - t0
            entry.error = f"超过单域上限 {self.per_host_timeout:.0f}s"
        except Exception as exc:  # noqa: BLE001
            entry.elapsed = loop.time() - t0
            entry.error = f"{type(exc).__name__}: {exc}"[:120]
        return entry

    async def run(
        self,
        urls: list[str],
        mode: str = "probe",
        verbose: bool = True,
        on_progress=None,
    ) -> SubScanReport:
        rep = SubScanReport(root=urls[0] if urls else "", started_at=time.time())
        if not urls:
            rep.finished_at = time.time()
            rep.notes.append("没有可扫描的目标")
            return rep
        if len(urls) > MAX_TARGETS:
            rep.notes.append(
                f"目标数 {len(urls)} 超过上限 {MAX_TARGETS}，"
                f"仅处理前 {MAX_TARGETS} 个（请分批或收窄主域）"
            )
            urls = urls[:MAX_TARGETS]

        rep.notes.append(
            f"模式：{mode}；并发 {self.concurrency}；单域上限 {self.per_host_timeout:.0f}s"
        )
        sem = asyncio.Semaphore(self.concurrency)
        done = 0

        async def one(u: str) -> SubScanEntry:
            nonlocal done
            async with sem:
                e = await (
                    self._probe_one(u) if mode == "probe" else self._full_one(u, verbose)
                )
                done += 1
                if verbose:
                    mark = "✓" if e.reachable else "✗"
                    extra = f" {e.error}" if e.error else (
                        f" {e.findings_count} 项发现" if e.findings_count else ""
                    )
                    if on_progress:
                        on_progress(done, len(urls), e, mark + extra)
                    else:
                        print(f"  [{done}/{len(urls)}] {mark} {u}{extra}")
                return e

        # gather 而非 TaskGroup：单个任务抛异常不该让整批失败——
        # _probe_one/_full_one 内部已兜住异常，这里再兜一层是防 unforeseen。
        entries = await asyncio.gather(*(one(u) for u in urls), return_exceptions=True)
        for u, e in zip(urls, entries):
            if isinstance(e, BaseException):
                rep.entries.append(
                    SubScanEntry(host=u, error=f"任务异常：{type(e).__name__}")
                )
            else:
                rep.entries.append(e)

        rep.finished_at = time.time()
        return rep


__all__ = [
    "SubdomainScanner", "SubScanEntry", "SubScanReport",
    "parse_input", "extract_hosts", "normalize_host", "MAX_TARGETS",
]