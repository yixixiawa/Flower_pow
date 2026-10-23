"""**代理隧道**——把裸 TCP 连接通过代理转发出去。

为什么需要它
------------
HTTP 代理只转发 HTTP 语义的请求，端口扫描这种"裸 TCP connect"它转不了。
但 **SOCKS5 的 CONNECT 命令可以转发任意 TCP**，而且 **HTTP 代理的
``CONNECT`` 方法同样可以**（Burp / mitmproxy 就是靠它做 TCP 隧道的）。

Clash 的 **mixed 端口**（``127.0.0.1:7897`` 这类）同时接受
HTTP 代理语义与 SOCKS5，因此本模块按下面的顺序尝试：

1. 代理 scheme 是 ``socks5`` / ``socks5h`` → 直接走 SOCKS5 握手。
2. 代理 scheme 是 ``http`` / ``https`` → 先试 **HTTP CONNECT** 隧道
   （Burp 场景最常见，且能被抓包）；失败再试 **SOCKS5 握手**
   （Clash mixed 端口场景）；再失败 → 判定该代理不支持隧道。
3. 代理完全不支持隧道 → 抛 :class:`TunnelError`（``state="unsupported"``），
   由调用方**降级直连**——扫描不该因为代理不支持就整个失败。

SOCKS5 协议实现要点
--------------------
握手::

    → 05 01 00                     VER=5, METHODS=1, METHOD=0x00(无认证)
    ← 05 00                        VER=5, METHOD=0x00

请求（ATYP=0x03 域名 / 0x01 IPv4 / 0x04 IPv6）::

    → 05 01 00 03 <len> <host...> <port:2>
    ← 05 REP 00 ATYP BND.ADDR BND.PORT

回包 ``REP`` 的语义映射到端口状态：

===========  ==========================
REP          端口状态
===========  ==========================
0x00成功      open
0x05拒绝      closed
0x03/04/06    filtered（不可达/超时）
其他          error
===========  ==========================

超时统一映射为 ``filtered``——与直连扫描的语义保持一致。
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from dataclasses import dataclass
from urllib.parse import urlparse

# SOCKS5 常量
_VER = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

# 回包码 → 端口状态
_REP_TO_STATE = {
    0x00: "open",       # succeeded
    0x03: "filtered",  # network unreachable
    0x04: "filtered",  # host unreachable
    0x05: "closed",    # connection refused
    0x06: "filtered",  # TTL expired
}

# 代理端点 → 是否支持隧道。同一进程内缓存，避免每个端口重复试错。
_TUNNEL_CACHE: dict[tuple[str, int], bool] = {}


class TunnelError(Exception):
    """隧道建立失败。

    ``state`` 直接就是端口状态语义：``unsupported`` / ``closed`` /
    ``filtered`` / ``error``。
    """

    def __init__(self, state: str, detail: str = "") -> None:
        super().__init__(detail or state)
        self.state = state
        self.detail = detail


@dataclass(slots=True)
class ProxyEndpoint:
    host: str
    port: int
    scheme: str = "http"

    @property
    def key(self) -> tuple[str, int]:
        return (self.host, self.port)


def parse_proxy_endpoint(proxy: str) -> ProxyEndpoint | None:
    """把代理 URL 拆成 host/port/scheme。解析不了返回 ``None``。"""
    raw = (proxy or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlparse(raw)
    except Exception:  # noqa: BLE001
        return None
    if not u.hostname:
        return None
    scheme = (u.scheme or "http").lower()
    default_port = 1080 if scheme.startswith("socks") else 8080
    port = u.port or default_port
    return ProxyEndpoint(host=u.hostname, port=port, scheme=scheme)


# ── SOCKS5 ───────────────────────────────────────────────────────────


def _encode_addr(host: str) -> bytes:
    """把目标地址编成 SOCKS5 的 DST.ADDR 字段。"""
    h = (host or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        raw = h.encode("idna") if any(ord(c) > 127 for c in h) else h.encode("utf-8")
        return bytes([_ATYP_DOMAIN, len(raw)]) + raw
    if ip.version == 4:
        return bytes([_ATYP_IPV4]) + ip.packed
    return bytes([_ATYP_IPV6]) + ip.packed


async def _socks5_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    timeout: float,
) -> None:
    """在已建立的连接上跑 SOCKS5 握手与 CONNECT。失败抛 TunnelError。"""
    try:
        # 1) 握手：只声明"无认证"一种方法
        writer.write(bytes([_VER, 0x01, 0x00]))
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != _VER:
            raise TunnelError("unsupported", f"代理返回非 SOCKS5 版本 {resp[0]:#04x}")
        if resp[1] != 0x00:
            raise TunnelError("unsupported", f"代理要求认证（方法 {resp[1]:#04x}）")

        # 2) CONNECT 请求
        addr = _encode_addr(host)
        writer.write(
            bytes([_VER, _CMD_CONNECT, 0x00]) + addr + struct.pack("!H", port)
        )
        await writer.drain()

        head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if head[0] != _VER:
            raise TunnelError("unsupported", f"代理返回非 SOCKS5 响应 {head[0]:#04x}")
        rep = head[1]
        atyp = head[3]
        # 消耗 BND.ADDR 与 BND.PORT
        if atyp == _ATYP_IPV4:
            await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        elif atyp == _ATYP_IPV6:
            await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
        elif atyp == _ATYP_DOMAIN:
            ln = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(ln[0]), timeout=timeout)
        await asyncio.wait_for(reader.readexactly(2), timeout=timeout)

        if rep == 0x00:
            return
        state = _REP_TO_STATE.get(rep, "error")
        raise TunnelError(state, f"SOCKS5 回包 REP={rep:#04x}")
    except TunnelError:
        raise
    except asyncio.IncompleteReadError:
        raise TunnelError("unsupported", "代理提前关闭连接（非 SOCKS5 端点）") from None
    except asyncio.TimeoutError:
        raise TunnelError("filtered", "SOCKS5 握手超时") from None
    except OSError as exc:
        raise TunnelError("error", f"代理 IO 错误：{exc}") from None


async def _http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    timeout: float,
) -> None:
    """HTTP CONNECT 隧道（Burp / mitmproxy 走的就是这条路）。"""
    req = (
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    )
    writer.write(req.encode("latin-1", "replace"))
    await writer.drain()
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    except asyncio.IncompleteReadError:
        raise TunnelError("unsupported", "代理提前关闭连接（非 HTTP 代理端点）") from None
    except asyncio.LimitOverrunError:
        raise TunnelError("unsupported", "代理响应过长") from None
    except asyncio.TimeoutError:
        raise TunnelError("filtered", "HTTP CONNECT 响应超时") from None

    line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split(" ", 2)
    code = 0
    if len(parts) >= 2 and parts[1].isdigit():
        code = int(parts[1])
    if code == 200:
        return
    if code in (403, 502, 503):
        # 代理能解析请求但拒绝/回不到目标 —— 目标多半不可达或被策略拦
        raise TunnelError("filtered", f"HTTP CONNECT 返回 {code}")
    raise TunnelError("unsupported", f"HTTP CONNECT 返回 {code or line!r}")


# ── 对外入口 ──────────────────────────────────────────────────────────


async def open_tunnel(
    proxy: str,
    host: str,
    port: int,
    timeout: float = 1.5,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """通过代理建立到 ``host:port`` 的 TCP 隧道。

    返回 ``(reader, writer)``——调用方像用直连 socket 一样收发数据。
    失败抛 :class:`TunnelError`，``state`` 字段给出端口状态语义。
    """
    ep = parse_proxy_endpoint(proxy)
    if ep is None:
        raise TunnelError("unsupported", f"代理地址无法解析：{proxy!r}")

    cached = _TUNNEL_CACHE.get(ep.key)
    attempts: list[str]
    if ep.scheme.startswith("socks"):
        attempts = ["socks5"]
    elif cached is False:
        # 已经确认这个代理端点不支持隧道，别再浪费一轮
        raise TunnelError("unsupported", "该代理端点不支持 TCP 隧道")
    else:
        attempts = ["http", "socks5"]

    last: TunnelError | None = None
    for mode in attempts:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ep.host, ep.port), timeout=timeout
            )
        except asyncio.TimeoutError:
            last = TunnelError("filtered", "连接代理超时")
            continue
        except ConnectionRefusedError:
            last = TunnelError("error", "代理端口拒绝连接")
            continue
        except OSError as exc:
            last = TunnelError("error", f"连接代理失败：{exc}")
            continue

        try:
            if mode == "http":
                await _http_connect(reader, writer, host, port, timeout)
            else:
                await _socks5_connect(reader, writer, host, port, timeout)
        except TunnelError as exc:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
            last = exc
            if exc.state == "unsupported":
                continue  # 换下一种隧道方式
            raise

        _TUNNEL_CACHE[ep.key] = True
        return reader, writer

    _TUNNEL_CACHE[ep.key] = False
    raise last or TunnelError("unsupported", "代理不支持 TCP 隧道")


def reset_tunnel_cache() -> None:
    """清掉隧道能力缓存（测试用；或用户换了代理端口后重来）。"""
    _TUNNEL_CACHE.clear()


__all__ = [
    "TunnelError",
    "ProxyEndpoint",
    "parse_proxy_endpoint",
    "open_tunnel",
    "reset_tunnel_cache",
]
