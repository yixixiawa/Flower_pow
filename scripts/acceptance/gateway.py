"""统一 HTTP 出口（Gateway）的运行时追踪。

要回答两个问题，不能靠读代码猜：

1. **这次请求走了哪个出口？** —— 只有经过 ``core.proxy.build_client_kwargs``
   构造的客户端才算"统一 Gateway"；裸 ``httpx.AsyncClient()`` 是绕过。
2. **请求真的发出去了吗？发了几跳？** —— 在 ``_send_single_request``
   这一层记录。httpx 内部跟随重定向时**每一跳都会经过它**，所以
   跨主机重定向会留下一条打给外部主机的发送记录——这正是"重定向后
   每一跳必须重新检查范围"的验证点。

实现方式：在验收进程内给 httpx 打补丁，采集事实后由 harness 取增量。
补丁只在验收进程生效，不改产品代码行为。
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any


def _norm(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False, default=str)
        return value
    except (TypeError, ValueError):
        return str(value)


def _fp(kwargs: dict[str, Any]) -> str:
    """客户端构造参数的指纹——用来判断"这份参数是不是 Gateway 发的"。"""
    items = sorted((str(k), _norm(v)) for k, v in (kwargs or {}).items())
    return json.dumps(items, ensure_ascii=False, default=str, sort_keys=True)


def _caller() -> str:
    """取"谁构造了这个客户端"（跳过本文件与 httpx 内部帧）。"""
    try:
        for fr in reversed(traceback.extract_stack()[:-2]):
            name = fr.filename.replace("\\", "/")
            if "/httpx/" in name or name.endswith("/acceptance/gateway.py"):
                continue
            return f"{name.rsplit('/', 1)[-1]}:{fr.lineno}"
    except Exception:  # noqa: BLE001
        pass
    return "?"


class GatewayTracer:
    """httpx 出口追踪器。``install()`` / ``uninstall()`` 成对使用。"""

    def __init__(self) -> None:
        self.issued: list[dict[str, Any]] = []
        self.clients: list[dict[str, Any]] = []
        self.sends: list[dict[str, Any]] = []
        self._pending: list[dict[str, Any]] = []
        self._installed = False
        self._orig: dict[str, Any] = {}

    # ── 安装 / 卸载 ───────────────────────────────────────────────
    def install(self) -> None:
        if self._installed:
            return
        import httpx

        import core.proxy as proxy_mod

        self._orig["bck"] = proxy_mod.build_client_kwargs
        self._orig["async_init"] = httpx.AsyncClient.__init__
        self._orig["async_send"] = httpx.AsyncClient._send_single_request
        self._orig["sync_init"] = httpx.Client.__init__
        self._orig["sync_send"] = httpx.Client._send_single_request

        tracer = self
        orig_bck = self._orig["bck"]

        def build_client_kwargs(cfg, url: str = "", *, force: bool = False):
            kw = orig_bck(cfg, url, force=force)
            entry = {"url": url, "fp": _fp(kw), "consumed": False}
            tracer.issued.append(entry)
            tracer._pending.append(entry)
            return kw

        proxy_mod.build_client_kwargs = build_client_kwargs
        # 顶层 ``from core.proxy import build_client_kwargs`` 的模块持有旧引用
        # （collectors/asset_search.py 就是），不重绑就会把合法出口误判成绕过。
        for mod in list(sys.modules.values()):
            try:
                if getattr(mod, "build_client_kwargs", None) is orig_bck:
                    setattr(mod, "build_client_kwargs", build_client_kwargs)
            except Exception:  # noqa: BLE001
                continue

        def _claim(kw: dict[str, Any]) -> dict[str, Any] | None:
            fp = _fp(kw)
            for entry in tracer._pending:
                if not entry["consumed"] and entry["fp"] == fp:
                    entry["consumed"] = True
                    return entry
            return None

        orig_async_init = self._orig["async_init"]

        def async_init(self_, *a, **kw):
            orig_async_init(self_, *a, **kw)
            hit = _claim(kw)
            governed = hit is not None
            self_._acc_governed = governed
            self_._acc_client_id = len(tracer.clients)
            tracer.clients.append({
                "kind": "async",
                "governed": governed,
                "caller": _caller(),
                "url": (hit or {}).get("url", ""),
                "fp": _fp(kw)[:120],
            })

        orig_async_send = self._orig["async_send"]

        async def async_send(self_, request):
            try:
                url = str(request.url)
                host = request.url.netloc.decode("ascii", "replace") if isinstance(
                    request.url.netloc, bytes
                ) else str(request.url.netloc)
            except Exception:  # noqa: BLE001
                url, host = "?", "?"
            tracer.sends.append({
                "method": getattr(request, "method", "?"),
                "url": url,
                "host": host,
                "governed": bool(getattr(self_, "_acc_governed", False)),
                "client_id": getattr(self_, "_acc_client_id", -1),
            })
            return await orig_async_send(self_, request)

        orig_sync_init = self._orig["sync_init"]

        def sync_init(self_, *a, **kw):
            orig_sync_init(self_, *a, **kw)
            hit = _claim(kw)
            governed = hit is not None
            self_._acc_governed = governed
            self_._acc_client_id = len(tracer.clients)
            tracer.clients.append({
                "kind": "sync",
                "governed": governed,
                "caller": _caller(),
                "url": (hit or {}).get("url", ""),
                "fp": _fp(kw)[:120],
            })

        orig_sync_send = self._orig["sync_send"]

        def sync_send(self_, request):
            try:
                url = str(request.url)
                host = str(request.url.netloc)
            except Exception:  # noqa: BLE001
                url, host = "?", "?"
            tracer.sends.append({
                "method": getattr(request, "method", "?"),
                "url": url,
                "host": host,
                "governed": bool(getattr(self_, "_acc_governed", False)),
                "client_id": getattr(self_, "_acc_client_id", -1),
            })
            return orig_sync_send(self_, request)

        httpx.AsyncClient.__init__ = async_init
        httpx.AsyncClient._send_single_request = async_send
        httpx.Client.__init__ = sync_init
        httpx.Client._send_single_request = sync_send
        self._installed = True

    def uninstall(self) -> None:
        if not self._installed:
            return
        import httpx

        import core.proxy as proxy_mod

        proxy_mod.build_client_kwargs = self._orig["bck"]
        httpx.AsyncClient.__init__ = self._orig["async_init"]
        httpx.AsyncClient._send_single_request = self._orig["async_send"]
        httpx.Client.__init__ = self._orig["sync_init"]
        httpx.Client._send_single_request = self._orig["sync_send"]
        self._installed = False

    # ── 观测 ──────────────────────────────────────────────────────
    def snapshot(self) -> tuple[int, int]:
        return len(self.sends), len(self.clients)

    def delta(self, snap: tuple[int, int]) -> tuple[list[dict], list[dict]]:
        return self.sends[snap[0]:], self.clients[snap[1]:]

    def ungoverned(self) -> list[dict[str, Any]]:
        """全程出现过的所有"绕过统一 Gateway"的构造与发送。"""
        bad_clients = [c for c in self.clients if not c["governed"]]
        bad_sends = [s for s in self.sends if not s["governed"]]
        return [*bad_clients, *bad_sends]

    def summary(self) -> dict[str, Any]:
        return {
            "issued": len(self.issued),
            "clients": len(self.clients),
            "sends": len(self.sends),
            "ungoverned_clients": [c["caller"] for c in self.clients if not c["governed"]],
            "ungoverned_sends": [
                f"{s['method']} {s['url']}" for s in self.sends if not s["governed"]
            ],
        }


__all__ = ["GatewayTracer"]
