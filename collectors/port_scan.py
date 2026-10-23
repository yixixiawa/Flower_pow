"""端口探测采集器。

两条实现路径，自动降级
----------------------
1. **原生 asyncio socket**（默认）——零依赖、可控并发、能区分
   ``closed``（明确 RST）与 ``filtered``（超时）。对Web 漏扫足够。
2. **nmap**（若PATH 中存在）——需要时用 ``-sV`` 拿服务指纹，
   识别率高于纯端口扫描，但慢 100 倍且需要管理员权限。

安全边界：只做 ``connect`` 扫描（发SYN 或完成三次握手），
**绝不使用** ``-sU`` UDP 全端口扫（对目标压力大且极易被 IDS 记录）。

**端口扫描怎么走代理**：本模块用裸 TCP（``asyncio.open_connection``），
HTTP 代理只转发 HTTP 语义的请求，不转发任意 TCP——**但 SOCKS5 的 CONNECT
命令可以**，HTTP 代理的 ``CONNECT`` 方法也可以。所以这里不再"始终直连"，
而是优先用 :mod:`core.tunnel` 建隧道：

* 代理是 ``socks5://`` → SOCKS5 握手 + CONNECT；
* 代理是 ``http://`` → 先试 HTTP CONNECT 隧道（Burp 场景），
  失败再试 SOCKS5（Clash mixed 端口场景）；
* 代理不支持隧道 → **自动降级直连**，不因为代理而让整个扫描失败。

隧道建立的成败直接映射为端口状态：连接成功 = ``open``，
代理回 "connection refused" = ``closed``，不可达/超时 = ``filtered``。
"""

from __future__ import annotations

import asyncio
import shutil
import socket
from dataclasses import dataclass, field

from core.config_loader import ScanConfig
from core.state import Asset
from core.tunnel import TunnelError, open_tunnel

# 常见 Web / 中间件端口——优先扫这些，命中即高价值
COMMON_PORTS: dict[int, str] = {
    80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt",
    8000: "http-alt", 8888: "http-alt", 8008: "http-alt", 9000: "http-alt",
    7001: "weblogic", 7002: "tomcat-alt", 8081: "http-alt", 8091: "http-alt",
    8161: "active-mq", 9001: "weblogic-admin", 4848: "glassfish",
    3000: "node-grafana", 5000: "flask", 8000: "flask",
    9200: "elasticsearch", 6379: "redis", 27017: "mongodb",
    3306: "mysql", 5432: "postgres", 1433: "mssql", 1521: "oracle",
    27017: "mongodb", 2375: "docker", 6443: "k8s-api",
    8161: "active-mq", 1099: "rmi", 4444: "rmi-alt",
    9999: "webmin", 10000: "webmin", 5984: "couchdb",
}

# nmap top ports 精简版（避免依赖外部文件）
TOP_PORTS: list[int] = sorted(set(
    [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
     1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200,
     27017, 3000, 5000, 6379, 11211, 27018]
    + list(COMMON_PORTS)
))


@dataclass(slots=True)
class PortResult:
    port: int
    state: str                # open | closed | filtered
    service: str = ""
    banner: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def is_web(self) -> bool:
        s = (self.service or "").lower()
        return self.port in {80, 443, 8080, 8443, 8000, 8888, 9000} or any(
            k in s for k in ("http", "https", "web")
        )


class PortScanner:
    """端口探测。"""

    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self.use_nmap = shutil.which("nmap") is not None
        self.notes: list[str] = []

    # ── 代理决策 ────────────────────────────────────────────────
    def _proxy_for(self, host: str) -> str | None:
        """本次端口扫描该用哪个代理（``None`` = 直连）。

        走与 HTTP 完全同一套决策（:func:`core.proxy.resolve_proxy_for`），
        所以"HTTP 走代理但端口扫描直连"的割裂不复存在。
        """
        from core.proxy import resolve_proxy_for

        return resolve_proxy_for(self.cfg, host)

    # ── 原生实现 ──────────────────────────────────────────────────
    async def _probe_port(
        self, host: str, port: int, timeout: float
    ) -> PortResult:
        """单个端口的 TCP connect 探测。

        区分 closed / filtered 很关键：closed 说明主机在线但端口没开（有效信息），
        filtered 多数是被防火墙丢包（也说明主机可能在线）。

        优先通过代理隧道探测；代理不支持隧道时降级直连。
        """
        proxy = self._proxy_for(host)
        if proxy:
            try:
                reader, writer = await open_tunnel(proxy, host, port, timeout)
            except TunnelError as exc:
                if exc.state == "unsupported":
                    # 代理不转发任意 TCP —— 记一次，之后本轮都直连
                    self.notes.append(
                        f"代理 {proxy} 不支持 TCP 隧道，端口扫描降级直连"
                    )
                    return await self._probe_direct(host, port, timeout)
                return PortResult(
                    port=port, state=exc.state, service=exc.detail[:80]
                )
            except (OSError, asyncio.CancelledError):
                return PortResult(port=port, state="error", service="隧道建立失败")

            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            return PortResult(
                port=port, state="open", service=COMMON_PORTS.get(port, ""),
                extra={"via": "proxy"},
            )

        return await self._probe_direct(host, port, timeout)

    async def _probe_direct(
        self, host: str, port: int, timeout: float
    ) -> PortResult:
        """直连的 TCP connect 探测。"""
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return PortResult(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed")
        except (socket.gaierror, OSError) as exc:
            return PortResult(port=port, state="error", service=str(exc)[:80])
        else:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            return PortResult(port=port, state="open", service=COMMON_PORTS.get(port, ""))

    async def scan(
        self, host: str, ports: list[int] | None = None, timeout: float = 1.5
    ) -> list[PortResult]:
        """并发探测一批端口。返回开放/过滤的端口（closed 的信息量低，不上报）。"""
        target_ports = ports or TOP_PORTS[: max(self.cfg.port_scan_top, 20)]
        sem = asyncio.Semaphore(max(10, self.cfg.concurrency * 4))
        tmo = min(self.cfg.timeout, timeout)

        async def one(p: int) -> PortResult:
            async with sem:
                return await self._probe_port(host, p, tmo)

        results = await asyncio.gather(*(one(p) for p in target_ports))
        return [r for r in results if r.state in {"open", "filtered"}]

    # ── nmap 实现（可选）─────────────────────────────────────────
    async def scan_nmap(
        self, host: str, ports: list[int] | None = None, timeout: int = 180
    ) -> list[PortResult]:
        """调nmap -sV 拿服务指纹。需要 nmap 在 PATH 中。

        只扫 TCP（``-sT``），不扫 UDP、不做脚本扫描、不做漏洞检测——
        我们自己有 POC 引擎，不需要 nmap 的 NSE。

        代理是 SOCKS 时给 nmap 传 ``--proxy``（它原生支持 SOCKS4/5 隧道）；
        代理是 HTTP 时不走 nmap——nmap 的 HTTP 代理支持有限，
        交给原生隧道实现更可靠。
        """
        import re

        if not self.use_nmap:
            return []
        port_arg = ",".join(str(p) for p in (ports or []))
        cmd = ["nmap", "-sT", "-sV", "--version-light", "-T4", "-Pn", "-n", host]
        if port_arg:
            cmd += ["-p", port_arg]
        proxy = self._proxy_for(host)
        if proxy:
            from core.tunnel import parse_proxy_endpoint

            ep = parse_proxy_endpoint(proxy)
            if ep and ep.scheme.startswith("socks"):
                cmd += ["--proxy", f"socks5://{ep.host}:{ep.port}"]
            else:
                # HTTP 代理 + nmap = 不可靠，走原生隧道
                return []

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return []

        out: list[PortResult] = []
        line_re = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s*(.*)$")
        for line in stdout.decode("utf-8", "replace").splitlines():
            m = line_re.match(line.strip())
            if not m:
                continue
            port, _, state, rest = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            service = rest.split()[0] if rest else ""
            out.append(
                PortResult(
                    port=port,
                    state="open" if state == "open" else state,
                    service=service if service != "unknown" else COMMON_PORTS.get(port, ""),
                    banner=rest,
                )
            )
        return out

    # ── 对外入口 ──────────────────────────────────────────────────
    async def run(self, host: str, verbose: bool = False) -> list[Asset]:
        """探测端口并转成 Asset 列表。"""
        if not self.cfg.port_scan_enabled:
            return []

        results: list[PortResult] = []
        if self.use_nmap:
            if verbose:
                print(f"[collect] 端口扫描：nmap -sV {host}")
            results = await self.scan_nmap(host)
        if not results:
            if verbose:
                print(
                    f"[collect] 端口扫描：原生 socket × "
                    f"{self.cfg.port_scan_top} 端口 {host}"
                )
            results = await self.scan(host)

        return [
            Asset(
                kind="port",
                value=f"{r.port}/{r.service or 'unknown'}",
                meta={"port": r.port, "state": r.state, "service": r.service,
                      "web": r.is_web},
                source="port_scan",
            )
            for r in results
            if r.state == "open"
        ]