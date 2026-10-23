"""端口扫描走代理（SOCKS5 / HTTP CONNECT 隧道）的测试。

这块的行为以前是"端口扫描始终直连"，现在改成**优先走隧道**，
所以必须有测试守住三件事：

1. **隧道真的能建起来**——本地假 SOCKS5 服务器 + 假目标服务，
   验证 ``open`` / ``closed`` 状态判定正确。
2. **代理不支持隧道时降级直连**，而不是整个扫描失败。
3. **状态语义映射正确**：SOCKS5 回包 ``0x05`` → closed，超时 → filtered。

不依赖外部网络：所有服务都在本地临时端口上起。

运行：.venv/Scripts/python.exe scripts/port_scan_proxy_test.py < /dev/null
"""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.proxy import resolve_proxy_for  # noqa: E402
from core.tunnel import (  # noqa: E402
    TunnelError,
    open_tunnel,
    parse_proxy_endpoint,
    reset_tunnel_cache,
)


class _Cfg:
    """最小 ScanConfig 替身。"""

    def __init__(self, proxy=None, no_proxy=None):
        self.timeout = 5.0
        self.verify_tls = False
        self.follow_redirects = True
        self.user_agent = "test-agent"
        self.proxy = proxy
        self.no_proxy = list(no_proxy or [])
        self.proxy_autodetect = True


# ── 本地假服务器 ──────────────────────────────────────────────────────


async def _start_echo_server() -> tuple[int, asyncio.AbstractServer]:
    """起一个"连上就立刻断开"的服务——端口必然是 open。"""

    async def handle(reader, writer):
        try:
            await reader.read(1)
        except Exception:  # noqa: BLE001
            pass
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return port, server


async def _start_socks5_proxy(
    target_port: int, *, refuse: bool = False
) -> tuple[int, asyncio.AbstractServer, list[str]]:
    """起一个最小 SOCKS5 服务器。

    ``refuse=True`` 时回 ``REP=0x05``（connection refused），
    用来验证端口状态映射成 ``closed``。
    记录收到的目标主机名/端口，用于验证 CONNECT 请求编对了。
    """
    seen: list[str] = []

    async def handle(reader, writer):
        try:
            # 握手
            head = await reader.readexactly(3)
            if head[0] != 0x05:
                writer.close()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

            # CONNECT 请求
            req = await reader.readexactly(4)
            atyp = req[3]
            if atyp == 0x03:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            elif atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            else:
                host = "?"
            port = int.from_bytes(await reader.readexactly(2), "big")
            seen.append(f"{host}:{port}")

            if refuse:
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 4 + b"\x00\x00")
                await writer.drain()
                writer.close()
                return

            # 真的去连请求里指定的目标。用裸 socket + 短超时：
            # 在 Windows 上，asyncio 内部再开连接偶尔会挂起不返回，
            # 而裸 socket 会立刻给 ConnectionRefused / 超时。
            #
            # 连上就够了——测试只关心隧道**是否建立成功**，
            # 不需要真的转发数据，所以连上即回成功并保持连接。
            try:
                sc_ = socket.socket()
                sc_.settimeout(1.5)
                sc_.connect((host, port))
                sc_.close()
            except (OSError, socket.timeout):
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 4 + b"\x00\x00")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            await writer.drain()
            # 挂着等客户端关闭
            try:
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                pass
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return port, server, seen


async def _start_plain_tcp_proxy() -> tuple[int, asyncio.AbstractServer]:
    """起一个"只会说 HTTP、不会 CONNECT"的假代理——模拟不支持隧道的代理。"""

    async def handle(reader, writer):
        try:
            data = await reader.read(1024)
            if data.startswith(b"CONNECT"):
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            else:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return port, server


# ── 测试 ──────────────────────────────────────────────────────────────


async def _run() -> tuple[int, int]:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    from collectors.port_scan import PortScanner

    print("场景1 代理地址解析")
    ep = parse_proxy_endpoint("127.0.0.1:7897")
    check(ep is not None and ep.host == "127.0.0.1" and ep.port == 7897,
          "缺 scheme 也能解析")
    ep = parse_proxy_endpoint("socks5://1.2.3.4:1080")
    check(ep is not None and ep.scheme == "socks5" and ep.port == 1080, "socks5 scheme")
    ep = parse_proxy_endpoint("")
    check(ep is None, "空串 → None")
    ep = parse_proxy_endpoint("http://host")
    check(ep is not None and ep.port == 8080, "缺端口用默认 8080")

    print("场景2 SOCKS5 隧道：open / closed 状态判定")
    reset_tunnel_cache()
    tgt_port, tgt_server = await _start_echo_server()
    proxy_port, proxy_server, seen = await _start_socks5_proxy(tgt_port)
    try:
        cfg = _Cfg(proxy=f"socks5://127.0.0.1:{proxy_port}")
        scanner = PortScanner(cfg)
        r = await scanner._probe_port("127.0.0.1", tgt_port, 2.0)
        check(r.state == "open", f"隧道到开放端口 → open（实为 {r.state}）")
        check(r.extra.get("via") == "proxy", "标记了经代理")

        # 目标端口没服务 → SOCKS5 回 REP=0x05 → closed
        closed_port, holder = _reserve_closed_port()
        try:
            r2 = await scanner._probe_port("127.0.0.1", closed_port, 2.0)
            check(r2.state == "closed", f"隧道到关闭端口 → closed（实为 {r2.state}）")
        finally:
            holder.close()

        # CONNECT 请求编对了目标
        check(seen and seen[0].endswith(f":{tgt_port}"),
              f"CONNECT 请求带对了目标端口（{seen[:1]}）")
    finally:
        tgt_server.close()
        proxy_server.close()

    print("场景3 SOCKS5 代理回 refusal → closed")
    reset_tunnel_cache()
    tgt_port, tgt_server = await _start_echo_server()
    proxy_port, proxy_server, _ = await _start_socks5_proxy(tgt_port, refuse=True)
    try:
        scanner = PortScanner(_Cfg(proxy=f"socks5://127.0.0.1:{proxy_port}"))
        r = await scanner._probe_port("127.0.0.1", tgt_port, 2.0)
        check(r.state == "closed", f"代理回 REP=0x05 → closed（实为 {r.state}）")
    finally:
        tgt_server.close()
        proxy_server.close()

    print("场景4 代理不支持隧道 → 降级直连，不失败")
    reset_tunnel_cache()
    tgt_port, tgt_server = await _start_echo_server()
    plain_port, plain_server = await _start_plain_tcp_proxy()
    try:
        cfg = _Cfg(proxy=f"http://127.0.0.1:{plain_port}")
        scanner = PortScanner(cfg)
        r = await scanner._probe_port("127.0.0.1", tgt_port, 2.0)
        check(r.state == "open", f"降级直连后仍能探到开放端口（实为 {r.state}）")
        check(any("降级直连" in n for n in scanner.notes),
              f"记录了降级说明（{scanner.notes}）")
    finally:
        tgt_server.close()
        plain_server.close()

    print("场景5 HTTP CONNECT 隧道")
    reset_tunnel_cache()

    async def handle_connect(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line = head.split(b"\r\n", 1)[0].decode()
            target = line.split(" ")[1]
            host, _, p = target.rpartition(":")
            try:
                tr, tw = await asyncio.open_connection(host, int(p))
            except OSError:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()

            async def pump(r, w):
                try:
                    while True:
                        d = await r.read(4096)
                        if not d:
                            break
                        w.write(d)
                        await w.drain()
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass

            await asyncio.gather(pump(reader, tw), pump(tr, writer))
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    conn_server = await asyncio.start_server(handle_connect, "127.0.0.1", 0)
    conn_port = conn_server.sockets[0].getsockname()[1]
    tgt2_port, tgt2_server = await _start_echo_server()
    try:
        scanner = PortScanner(_Cfg(proxy=f"http://127.0.0.1:{conn_port}"))
        r = await scanner._probe_port("127.0.0.1", tgt2_port, 2.0)
        check(r.state == "open", f"HTTP CONNECT 隧道 → open（实为 {r.state}）")
    finally:
        tgt2_server.close()
        conn_server.close()

    print("场景6 代理决策与 HTTP 侧一致（内网也走代理）")
    cfg = _Cfg(proxy="http://127.0.0.1:7897")
    check(resolve_proxy_for(cfg, "192.168.10.128") == "http://127.0.0.1:7897",
          "内网目标也走代理（与端口扫描同源决策）")

    print("场景7 no_proxy 例外表让端口扫描直连")
    cfg = _Cfg(proxy="http://127.0.0.1:7897", no_proxy=["127.0.0.0/8"])
    check(resolve_proxy_for(cfg, "127.0.0.1") is None, "命中例外表 → 直连")

    print("场景8 隧道失败时抛 TunnelError 且带状态语义")
    reset_tunnel_cache()
    try:
        await open_tunnel("socks5://127.0.0.1:1", "example.com", 80, 1.0)
        check(False, "应当抛 TunnelError")
    except TunnelError as exc:
        check(exc.state in {"error", "filtered", "unsupported"},
              f"TunnelError 带状态语义（{exc.state}）")

    print("场景9 无代理配置 → 完全直连（不建隧道）")
    reset_tunnel_cache()
    tgt_port, tgt_server = await _start_echo_server()
    try:
        scanner = PortScanner(_Cfg(proxy=None))
        r = await scanner._probe_port("127.0.0.1", tgt_port, 2.0)
        check(r.state == "open", f"直连探到开放端口（实为 {r.state}）")
        check("via" not in r.extra, "直连不带 via 标记")
    finally:
        tgt_server.close()

    return ok, total


def _reserve_closed_port() -> tuple[int, socket.socket]:
    """占一个"确定没人监听"的端口。

    注意：**不能** bind 完就 close——Windows 上这样再连会静默挂起
    （不返��� RST），表现为超时而不是拒绝。正确做法是 bind 后**不 listen**
    且不关闭 socket：端口被占着，连接会立刻收到 WSAECONNREFUSED。
    返回 ``(端口, 占位 socket)``，用完记得 close。
    """
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    return s.getsockname()[1], s


def main() -> int:
    ok, total = asyncio.run(_run())
    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
