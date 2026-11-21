"""本地 Mock Server：安全验收唯一允许的"目标"。

为什么必须用它：验收要求"被拒绝的请求不得产生任何网络副作用"。
这句话只有在**能数清收到了几个请求**时才是可验证的——连真实目标
永远证明不了"没发出去"。这里起两个回环 HTTP 服务：

* **A** —— 被测目标（绑定为隔离测试环境）；
* **B** —— 另一台"外部主机"（同机不同端口，对范围校验而言就是越界）。

每条到达的请求都记进 ``records``：方法、路径、主机、关键头、请求体。
用例结束后 harness 取增量，得到"HTTP 是否真的发出 / 发到了哪"。

所有服务只绑 ``127.0.0.1``，不监听外部地址；不向任何生产目标发请求。
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class RequestRecord:
    server: str
    method: str
    path: str
    host: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def line(self) -> str:
        return f"{self.server}:{self.method} {self.path}"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "acceptance-mock/1.0"

    # 关掉默认 stderr 日志（否则每个请求刷一行，报告里全是噪音）
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    # ── 统一入口 ──────────────────────────────────────────────────
    def _handle(self) -> None:  # noqa: C901 —— 路由表就是这个函数的全部内容
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        srv: "_MockServer" = self.server  # type: ignore[assignment]
        rec = RequestRecord(
            server=srv.label,
            method=self.command,
            path=self.path,
            host=f"127.0.0.1:{srv.server_port}",
            headers={k.lower(): v for k, v in self.headers.items()},
            body=raw.decode("utf-8", "replace"),
        )
        with srv.lock:
            srv.records.append(rec)

        path = self.path.split("?", 1)[0]
        status, headers, body = self._route(path)
        data = body.encode("utf-8")
        self.send_response(status)
        headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        headers.setdefault("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _route(self, path: str) -> tuple[int, dict[str, str], str]:
        srv: "_MockServer" = self.server  # type: ignore[assignment]
        peer = srv.peer_port

        if path == "/ok":
            return 200, {}, "ok"
        if path == "/json":
            return 200, {"Content-Type": "application/json"}, '{"id":"obj-1234"}'
        if path == "/api/users" and self.command == "POST":
            return 201, {
                "Location": "/api/users/4321",
                "Content-Type": "application/json",
            }, '{"id":"4321"}'
        if path == "/api/users/4321":
            return 200, {"Content-Type": "application/json"}, '{"id":"4321"}'
        if path.startswith("/api/users/"):
            return 200, {"Content-Type": "application/json"}, '{"id":"other"}'
        if path == "/upload" and self.command == "POST":
            return 201, {"Content-Type": "application/json"}, '{"id":"file-7777"}'
        if path == "/api/fail" and self.command == "POST":
            # 创建失败（500）：对象根本没建立，台账不得登记
            return 500, {}, "boom"
        if path == "/export":
            return 200, {}, "exported-data-should-never-be-fetched"
        if path == "/login":
            return 200, {}, "login-page"
        # ── 认证初始化（AUTH_BOOTSTRAP）用例专用 ────────────────────
        # 只新增**具体路径**路由，不改动任何既有路径的行为：认证用例需要
        # 一个"真的能登录成功"的目标，才能验证"登录成功不放行后续请求"。
        if path == "/api/auth/captcha" and self.command == "GET":
            return 200, {"Content-Type": "application/json"}, '{"uuid":"mock-uuid-1"}'
        if path == "/api/auth/login" and self.command == "POST":
            return 200, {"Content-Type": "application/json"}, (
                # 三段式 JWT（alg=none，中段是 {"sub":"1001"}）：core.auth
                # 只认真 JWT 形态，假 token 会让登录被判定为失败。
                '{"access_token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMDAxIn0.x","uid":"1001"}'
            )
        if path == "/api/auth/refresh" and self.command == "POST":
            return 200, {"Content-Type": "application/json"}, (
                '{"access_token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMDAxIn0.y"}'
            )
        if path == "/api/auth/logout" and self.command == "POST":
            return 200, {"Content-Type": "application/json"}, '{"ok":true}'
        if path == "/redirect-same":
            return 302, {"Location": "/ok"}, ""
        if path == "/redirect-chain":
            return 302, {"Location": "/redirect-same"}, ""
        if path == "/redirect-cross":
            target = f"http://127.0.0.1:{peer}/steal"
            return 302, {"Location": target}, ""
        if path == "/steal":
            return 200, {}, "cross-host-secret"
        if path == "/search":
            return 200, {}, "search-result"
        return 404, {}, "not found"

    # 所有方法都走同一入口——未知方法也要被记录（UNKNOWN 命令测试要用）
    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle
    do_PROPFIND = _handle


class _MockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, label: str, peer_port: int = 0) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.label = label
        self.peer_port = peer_port
        self.records: list[RequestRecord] = []
        self.lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        try:
            self.shutdown()
            self.server_close()
        except Exception:  # noqa: BLE001 —— 关服务失败不该拖垮验收
            pass

    @property
    def port(self) -> int:
        return int(self.server_port)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def binding(self) -> str:
        """环境绑定模式：host:port（与 policy 的 ``[scheme://]host-glob[:port]`` 对齐）。"""
        return f"127.0.0.1:{self.port}"

    def count(self) -> int:
        with self.lock:
            return len(self.records)

    def since(self, n: int) -> list[RequestRecord]:
        with self.lock:
            return list(self.records[n:])


class MockNet:
    """两个 mock 服务的生命周期与观测入口。"""

    def __init__(self) -> None:
        self.b = _MockServer("B")
        self.b.start()
        self.a = _MockServer("A", peer_port=self.b.port)
        self.a.start()

    # ── 观测 ──────────────────────────────────────────────────────
    def snapshot(self) -> tuple[int, int]:
        return self.a.count(), self.b.count()

    def delta(self, snap: tuple[int, int]) -> list[RequestRecord]:
        return self.a.since(snap[0]) + self.b.since(snap[1])

    def reset(self) -> None:
        for s in (self.a, self.b):
            with s.lock:
                s.records.clear()

    @property
    def target(self) -> str:
        return self.a.base

    @property
    def outsider(self) -> str:
        return self.b.base

    def bindings(self) -> dict[str, str]:
        return {self.a.binding: "isolated_test", self.b.binding: "isolated_test"}

    def close(self) -> None:
        self.a.stop()
        self.b.stop()


def records_to_json(records: list[RequestRecord]) -> str:
    """报告/调试用：把请求记录压成一行 JSON 数组。"""
    return json.dumps(
        [{"server": r.server, "method": r.method, "path": r.path} for r in records],
        ensure_ascii=False,
    )


__all__ = ["MockNet", "RequestRecord", "records_to_json"]
