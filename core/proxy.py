"""本机代理探测——决定请求该不该走代理、以及走哪个代理。

为什么需要这个模块
------------------
渗透测试机通常**同时**挂着两套代理，而它们的目标各不相同：

* **环境变量代理**（``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``ALL_PROXY``）
  ——常是上一层工具链（Burp、mitmproxy、公司网关）注入的拦截口，
  所有 HTTP(S) 流量都要经过它才能被看见/篡改。
* **Windows 系统代理**（注册表 ``Internet Settings``）
  ——常是 Clash / v2ray 这类分流工具的入口，自带 ``ProxyOverride`` 分流表。

业务上的真实需求是：**"我挂了代理，扫描流量就该走代理，
不然 Burp 里什么也看不到、Clash 的分流也白配了"**。

但这里有两个致命陷阱，不加约束直接把 ``trust_env`` 打开就会踩：

1. **内网目标不能送外部代理。** 被测目标常是物理机网口 IP
   （``192.168.x.x`` / ``10.x`` / ``172.16-31.x``）或 ``127.0.0.1``。
   把这类请求送给一个公网代理，轻则全部 502（代理回不来内网），
   重则**把内网拓扑泄露给第三方**。系统代理的 ``ProxyOverride``
   本身就带这份分流表，而裸环境变量没有——这正是差异所在。
2. **端口扫描根本无法走 HTTP 代理。** ``collectors/port_scan.py``
   用的是裸 TCP（``asyncio.open_connection``），HTTP 代理只能转发
   HTTP 语义的请求，不转发任意 TCP。所以端口探测必须直连，
   这一点在文档里要写清楚，否则用户会以为"开了代理端口就扫描不到"。

设计取舍
--------
* **优先级：显式配置 > 环境变量 > 系统代理。**
  用户在 ``config.yaml`` / ``POCS_PROXY`` 里写死的东西永远最高，
  它代表"我就是要走这个"，不做任何自动化判断覆盖它。
* **探测到代理 ≠ 对所有目标都走代理。** 落到具体请求时用
  :func:`resolve_proxy_for` 按主机再判一次：内网/本机一律直连。
* **探测过程绝不发网络请求。** 只读环境变量与注册表——
  在只读模式（``readonly=true``）下也必须能安全运行。
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

# 环境变量名（大小写两种都认；httpx / requests / curl 都这样）。
_ENV_KEYS = (
    ("http", ("HTTP_PROXY", "http_proxy")),
    ("https", ("HTTPS_PROXY", "https_proxy")),
    ("all", ("ALL_PROXY", "all_proxy")),
)
_NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")


# ── 数据模型 ──────────────────────────────────────────────────────────


@dataclass
class ProxyInfo:
    """一次探测的完整结论。"""

    proxy: str = ""                    # 归一化后的代理 URL，空串=没找到
    source: str = ""                   # env | env:http | system | config
    no_proxy: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)   # 原始取值，排查用
    notes: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.proxy)

    def describe(self) -> str:
        """给终端用的一行摘要。"""
        if not self.found:
            return "未检测到代理（直连）"
        bits = [f"{self.proxy}（来源 {self.source}）"]
        if self.no_proxy:
            bits.append(f"直连例外 {len(self.no_proxy)} 条")
        return "，".join(bits)


# ── 归一化 ────────────────────────────────────────────────────────────


def normalize_proxy(raw: str) -> str:
    """把各种写法的代理规整成带 scheme 的 URL。

    * ``127.0.0.1:7897`` → ``http://127.0.0.1:7897``（缺 scheme 是常态）
    * ``http://x:8080/`` → ``http://x:8080``（去尾斜杠）
    * ``socks5://x:1080`` 原样保留（httpx 支持 socks，需 httpx[socks]）
    * 空串 / 明显非法 → 空串
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if "://" not in s:
        # ``x:8080`` 与 ``127.0.0.1:7897`` 都补 http；不补的话 httpx 会当相对路径
        s = "http://" + s
    try:
        u = urlparse(s)
    except Exception:  # noqa: BLE001
        return ""
    if not u.hostname:
        return ""
    scheme = (u.scheme or "http").lower()
    if scheme not in ("http", "https", "socks4", "socks5", "socks5h"):
        # 未知 scheme 不当代理（可能是 ``file://`` 之类误填）
        return ""
    netloc = u.hostname
    if u.port:
        netloc = f"{u.hostname}:{u.port}"
    if u.username:
        cred = u.username + (f":{u.password}" if u.password else "")
        netloc = f"{cred}@{netloc}"
    return f"{scheme}://{netloc}"


# ── 内网 / 本机判定 ───────────────────────────────────────────────────


def is_local_host(host: str) -> bool:
    """主机是不是"本机或内网"——这类目标**永远不该走外部代理**。

    覆盖四种情况：

    * ``localhost`` / ``*.localhost`` / ``*.local``
    * 回环 ``127.0.0.0/8``、``::1``
    * 私有网段（``10/8``、``172.16/12``、``192.168/16``、``169.254/16``、
      ``fc00::/7``、``fe80::/10``）
    * 主机名里出现 ``.internal`` / ``.lan`` / ``.intranet`` 这类内网后缀

    无法解析成 IP 的公网域名返回 False（该走代理）。
    """
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False
    if h == "localhost" or h.endswith(".localhost"):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    if h.endswith(".intranet") or h.endswith(".corp") or h.endswith(".home"):
        return True
    # 去掉可能的端口
    if h.count(":") == 1:
        head, _, tail = h.rpartition(":")
        if tail.isdigit():
            h = head
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


def _match_no_proxy(host: str, patterns: list[str]) -> bool:
    """主机是否命中 NO_PROXY 例外表。

    支持 ``*``（全放行）、精确匹配、后缀匹配（``.example.com``）、
    CIDR（``192.168.0.0/16``）与裸网段前缀（``192.168.*``）。
    """
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False
    if h.count(":") == 1:
        head, _, tail = h.rpartition(":")
        if tail.isdigit():
            h = head
    for pat in patterns:
        p = (pat or "").strip().lower()
        if not p:
            continue
        if p == "*":
            return True
        if p.startswith("."):
            base = p[1:]
            if h == base or h.endswith(p):
                return True
            continue
        # CIDR
        if "/" in p:
            try:
                net = ipaddress.ip_network(p, strict=False)
                if ipaddress.ip_address(h) in net:
                    return True
            except ValueError:
                pass
            continue
        # 通配前缀 ``192.168.*`` / ``10.*``
        if p.endswith("*"):
            if h.startswith(p[:-1]):
                return True
            continue
        if h == p or h.endswith("." + p):
            return True
    return False


# ── 探测 ──────────────────────────────────────────────────────────────


def _read_env() -> tuple[str, str, list[str], dict[str, str]]:
    """读环境变量，返回 ``(proxy, source, no_proxy, raw)``。"""
    raw: dict[str, str] = {}
    no_proxy: list[str] = []
    for k in _NO_PROXY_KEYS:
        if os.environ.get(k):
            raw[k] = os.environ[k]
    if raw:
        no_proxy = [x for x in raw[next(iter(raw))].split(",") if x.strip()]

    # https 优先（渗透目标多为 https；httpx 对 https 请求取 https 代理）
    for scheme, keys in _ENV_KEYS:
        for k in keys:
            v = os.environ.get(k)
            if v and v.strip():
                raw[k] = v
                return normalize_proxy(v), f"env:{scheme}", no_proxy, raw
    return "", "", no_proxy, raw


def _read_system_windows() -> tuple[str, list[str], dict[str, str]]:
    """读 Windows 系统代理（注册表）。非 Windows 或读取失败返回空。"""
    if os.name != "nt":
        return "", [], {}
    try:
        import winreg  # noqa: PLC0415
    except ImportError:
        return "", [], {}
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
    except OSError:
        return "", [], {}

    raw: dict[str, str] = {}
    enabled = ""
    server = ""
    override = ""
    try:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                val, _ = winreg.QueryValueEx(key, name)
                raw[name] = str(val)
            except FileNotFoundError:
                continue
        enabled = raw.get("ProxyEnable", "")
        server = raw.get("ProxyServer", "")
        override = raw.get("ProxyOverride", "")
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass

    if enabled not in ("1", "True", "true"):
        # 系统代理没开。但 AutoConfigURL(PAC) 存在时无法可靠解析——
        # 明确记一条 note，而不是假装没有代理。
        return "", [], raw

    # ProxyServer 可能是 ``host:port`` 或 ``http=x;https=y`` 形式
    proxy_url = ""
    if "=" in server:
        parts = dict(
            p.split("=", 1) for p in server.split(";") if "=" in p
        )
        proxy_url = (
            parts.get("https") or parts.get("http") or next(iter(parts.values()), "")
        )
    else:
        proxy_url = server

    no_proxy = [x for x in override.split(";") if x.strip()]
    return normalize_proxy(proxy_url), no_proxy, raw


def detect_proxy(*, use_system: bool = True) -> ProxyInfo:
    """探测本机代理。**只读本地状态，不发任何网络请求。**

    优先级：环境变量 > 系统代理（Windows 注册表）。
    两者都没有则返回 ``found=False``。

    ``use_system=False`` 时只看环境变量——供"我不想让脚本读注册表"
    的场景显式关闭。
    """
    info = ProxyInfo()

    env_proxy, env_source, env_no, env_raw = _read_env()
    info.raw.update(env_raw)
    if env_proxy:
        info.proxy = env_proxy
        info.source = env_source
        info.no_proxy = env_no
        info.notes.append(
            f"环境变量代理 {env_proxy} 已启用；"
            "内网/本机目标仍会直连（见 resolve_proxy_for）"
        )
        return info

    if not use_system:
        return info

    sys_proxy, sys_no, sys_raw = _read_system_windows()
    info.raw.update(sys_raw)
    if sys_proxy:
        info.proxy = sys_proxy
        info.source = "system"
        info.no_proxy = sys_no
        info.notes.append(
            f"Windows 系统代理 {sys_proxy} 已启用；"
            f"系统分流表 {len(sys_no)} 条已并入直连例外"
        )
        return info

    if sys_raw.get("AutoConfigURL"):
        info.notes.append(
            "检测到 PAC 脚本（AutoConfigURL），本项目不解析 PAC，按无代理处理"
        )
    return info


def detect_and_apply(cfg, *, use_system: bool = True, verbose: bool = False) -> ProxyInfo:
    """探测代理并**回填到配置**（仅当配置里没显式设过）。

    这是"有代理就默认走代理"的落地点。三条规则：

    1. 配置里已显式设了 ``proxy`` → 尊重用户，什么都不做（记一条 note）。
    2. 探测到代理 → 写回 ``cfg.proxy``，后续所有客户端自动使用。
    3. 没探测到 → 保持 ``None``，退回原来的 ``trust_env=False`` 直连行为。

    返回探测结论供调用方打印/记录。
    """
    explicit = (getattr(cfg, "proxy", None) or "").strip()
    if explicit:
        info = ProxyInfo(
            proxy=normalize_proxy(explicit),
            source="config",
            notes=["配置已显式指定代理，跳过自动探测"],
        )
        return info

    info = detect_proxy(use_system=use_system)
    if info.found:
        cfg.proxy = info.proxy
    if verbose:
        print(f"[proxy] {info.describe()}")
        for n in info.notes:
            print(f"        {n}")
    return info


def resolve_proxy_for(cfg, host: str, *, force: bool = False) -> str | None:
    """**请求级**决策：这个主机该不该走代理、走哪个。

    这是比"探测"更细的一层——探测回答"本机有没有代理"，
    本函数回答"**这次请求**要不要用它"。规则：

    1. ``force=True``（用户显式 ``--proxy`` 或配置强制）→ 一律走。
    2. 主机是本机/内网（:func:`is_local_host`）→ **一律直连**，
       避免内网流量被送出外部，也避免 502 假死。
    3. 主机命中 ``NO_PROXY`` 例外表 → 直连。
    4. 其余 → 走配置里的代理（可能是探测回填的）。

    返回 ``None`` 表示直连；返回 URL 表示该用这个代理。
    """
    proxy = (getattr(cfg, "proxy", None) or "").strip()
    if not proxy:
        return None
    if force:
        return normalize_proxy(proxy)
    # 主机为空 = 调用方也说不上来目标是谁。此时**保守直连**：
    # 错发内网流量到外部代理的代价，远大于少走一次代理。
    if not (host or "").strip():
        return None
    if is_local_host(host):
        return None
    no_proxy = getattr(cfg, "no_proxy", None) or []
    if _match_no_proxy(host, list(no_proxy)):
        return None
    return normalize_proxy(proxy)


def build_client_kwargs(cfg, url: str = "", *, force: bool = False) -> dict:
    """给 httpx 构造客户端参数——把代理决策收敛到一处。

    所有 ``httpx.AsyncClient`` / ``httpx.Client`` 的构造点都应调它，
    避免"这个模块走代理、那个模块不走"的割裂（实测踩过：
    新增采集器时漏了代理，Burp 里就是看不到它的流量）。

    ``trust_env`` 的取值逻辑：

    * 决定走代理 → 显式传 ``proxy=``，同时 ``trust_env=False``
      （避免 httpx 再叠加一份环境代理，造成双重代理）。
    * 决定直连 → ``trust_env=False``，**完全无视**环境代理。
      这是刻意的：直连决策已经由本模块做过，不该让 httpx 再擅自反悔。
    """
    host = ""
    if url:
        try:
            host = urlparse(url if "://" in url else f"http://{url}").hostname or ""
        except Exception:  # noqa: BLE001
            host = ""
    kw: dict = {
        "timeout": cfg.timeout,
        "verify": cfg.verify_tls,
        "follow_redirects": getattr(cfg, "follow_redirects", True),
        "headers": {"User-Agent": cfg.user_agent},
        "trust_env": False,
    }
    chosen = resolve_proxy_for(cfg, host, force=force)
    if chosen:
        kw["proxy"] = chosen
    return kw


__all__ = [
    "ProxyInfo",
    "normalize_proxy",
    "is_local_host",
    "detect_proxy",
    "detect_and_apply",
    "resolve_proxy_for",
    "build_client_kwargs",
]
