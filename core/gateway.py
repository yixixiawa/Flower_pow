"""目标面 HTTP 流量的**唯一出口**（第七轮整改：统一 Gateway）。

为什么需要它
------------
此前"统一出口"只统一了**代理参数**（:func:`core.proxy.build_client_kwargs`），
没有统一**请求本身**。于是有两个真实缺口：

1. ``detectors/base.py`` 的 ``send_request`` 只在**首个 URL** 上做策略检查，
   随后把请求交给 ``follow_redirects=True`` 的 httpx——服务端一跳 302 到
   授权范围外的主机，httpx 自己就跟过去了，**第二跳从未过策略检查**。
   目标范围校验被一次 302 绕开，且审计里看不到任何痕迹。
2. 拒绝事件只写在 runner 层。探测器路径（批量 POC）被拦的请求
   **没有任何审计记录**——"拦住了"这件事不可追溯。

本模块把三件事收敛到一处：

* **逐跳策略复检**：客户端固定 ``follow_redirects=False``，重定向由
  Gateway 自己循环；每一跳在发出**之前**重新跑策略检查（范围 + 分类 +
  环境），任何一跳被拒即停止，后续跳不再触网；
* **拒绝审计**：每一跳的拒绝都写一条 ``deny`` 事件（目标/命令/原因/
  第几跳），探测器的拦截不再只活在内存计数里；
* **唯一构造点**：``httpx.AsyncClient`` 只允许在本模块出现（静态门禁
  ``scripts/security_acceptance.py`` 会扫描全工程）。其他模块要客户端
  只能调 :func:`gateway_client`，要发目标面请求只能调
  :class:`HttpGateway`。

设计边界（刻意保守）
--------------------
* 重定向跳数上限 ``hop_limit``（默认 5），超限按**拒绝**处理（fail-closed），
  不无限跟；
* 只跟 http/https 跳转，``file://`` / ``gopher://`` 等一律拒绝；
* 跨主机跳转**不特殊豁免**——范围校验在每一跳上重算，出界即拒；
* Gateway 自己不做决策：决策权仍在 :mod:`policy.request_guard`，Gateway
  只负责"每一跳都问一次、被拒就停、并留痕"。避免出现第二套判定逻辑。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

from core.proxy import build_client_kwargs

# 检查函数签名：(url, method, body, approved) -> 拒绝原因（"" = 放行）
Checker = Callable[[str, str, str, bool], Awaitable[str]]

DEFAULT_HOP_LIMIT = 5
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def gateway_client(
    cfg,
    url: str = "",
    *,
    follow_redirects: bool | None = None,
    force_proxy: bool = False,
    timeout: float | None = None,
) -> httpx.AsyncClient:
    """构造 HTTP 客户端——**全工程唯一的 httpx 客户端构造点**。

    ``follow_redirects=None`` 跟随配置；Gateway 自己传 ``False``
    以便逐跳复检。代理决策仍走 :func:`core.proxy.build_client_kwargs`，
    不存在第二套出口参数。``cfg=None`` 是"当库调用"的场景（无配置
    上下文），给一份最小参数，仍旧只在本模块构造。
    """
    if cfg is None:
        return httpx.AsyncClient(
            timeout=timeout or 15.0,
            trust_env=False,
            follow_redirects=True if follow_redirects is None else follow_redirects,
        )
    kw = build_client_kwargs(cfg, url, force=force_proxy)
    kw["follow_redirects"] = (
        getattr(cfg, "follow_redirects", True) if follow_redirects is None else follow_redirects
    )
    if timeout is not None:
        kw["timeout"] = timeout
    return httpx.AsyncClient(**kw)


def gateway_sync_client(
    cfg,
    url: str = "",
    *,
    follow_redirects: bool | None = None,
    timeout: float | None = None,
) -> httpx.Client:
    """同步版统一构造点（``core.auth`` / ``kb.intel`` 的同步流程用）。

    与 :func:`gateway_client` 吃同一份代理/超时/TLS 参数，不得各写一套。
    """
    if cfg is None:
        return httpx.Client(
            timeout=timeout or 15.0,
            follow_redirects=True if follow_redirects is None else follow_redirects,
        )
    kw = build_client_kwargs(cfg, url)
    kw["follow_redirects"] = (
        getattr(cfg, "follow_redirects", True) if follow_redirects is None else follow_redirects
    )
    if timeout is not None:
        kw["timeout"] = timeout
    return httpx.Client(**kw)


@dataclass(slots=True)
class Hop:
    """一次重定向链上的单跳记录（审计与测试的证据来源）。"""

    url: str
    method: str
    status: int | None = None
    blocked: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "blocked": self.blocked,
            "reason": self.reason,
        }


@dataclass(slots=True)
class GatewayResult:
    """一次 Gateway 调用的完整结果。"""

    response: httpx.Response | None = None
    hops: list[Hop] = field(default_factory=list)
    blocked: bool = False
    reason: str = ""

    @property
    def blocked_hop(self) -> Hop | None:
        return next((h for h in self.hops if h.blocked), None)


class HttpGateway:
    """目标面请求的唯一发送入口。

    ``checker`` 由调用方注入（探测器传自己的 ``_policy_check`` 包装），
    Gateway 保证**每一跳**都调它一次。``audit`` 可选（:class:`policy.
    audit_logger.PolicyAudit`），提供时拒绝事件落盘。
    """

    def __init__(
        self,
        cfg,
        checker: Checker,
        *,
        audit: Any | None = None,
        hop_limit: int = DEFAULT_HOP_LIMIT,
        target_id: str = "",
        run_id: str = "",
    ) -> None:
        self.cfg = cfg
        self.checker = checker
        self.audit = audit
        self.hop_limit = max(1, int(hop_limit))
        self.target_id = target_id
        self.run_id = run_id
        # 可观测计数（验收测试据此判断"请求是否真的发出"）
        self.sent = 0
        self.blocked_count = 0
        self.redirect_count = 0
        self.last_hops: list[Hop] = []
        self._clients: dict[str, httpx.AsyncClient] = {}

    # ── 客户端缓存（按代理决策）──────────────────────────────────
    def _client(self, url: str) -> httpx.AsyncClient:
        from core.proxy import resolve_proxy_for

        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            host = ""
        key = resolve_proxy_for(self.cfg, host) or ""
        c = self._clients.get(key)
        # 固定 follow_redirects=False：重定向必须回到 Gateway 逐跳复检，
        # 不能让 httpx 在库内部替我们把下一跳发出去。
        if c is None:
            c = gateway_client(self.cfg, url, follow_redirects=False)
            self._clients[key] = c
        return c

    async def aclose(self) -> None:
        for c in self._clients.values():
            try:
                await c.aclose()
            except Exception:  # noqa: BLE001 —— 关闭失败不影响结果
                pass
        self._clients.clear()

    # ── 拒绝留痕 ────────────────────────────────────────────────
    def _audit_deny(self, hop: Hop, index: int, method: str) -> None:
        if self.audit is None:
            return
        try:
            self.audit.log(
                "deny",
                command="",
                decision="DENY",
                url=hop.url,
                target_id=self.target_id,
                run_id=self.run_id,
                reason=f"Gateway 第 {index + 1} 跳拒绝：{hop.reason}",
                extra={
                    "gateway": "core.gateway.HttpGateway",
                    "hop": index + 1,
                    "method": method,
                    "blocked_url": hop.url,
                },
            )
        except Exception:  # noqa: BLE001 —— 审计是旁路，不得炸断执行链
            pass

    # ── 主入口 ──────────────────────────────────────────────────
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: str | bytes | None = None,
        approved: bool = False,
        checker: Checker | None = None,
    ) -> GatewayResult:
        """发送一个请求；重定向逐跳复检。

        ``approved`` 仅用于上传类 REVIEW 的逐请求审批标记，透传给 checker
        （checker 不得用它放行 L3/DENY/UNKNOWN）。``checker`` 覆盖构造时
        注入的默认检查器——探测器按每次请求的 POC 上下文传入闭包，
        避免实例级状态被并发协程覆盖。
        """
        check = checker or self.checker
        cur = url
        m = (method or "GET").upper()
        body = content if isinstance(content, str) else (content or b"")
        body_text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        hops: list[Hop] = []
        self.last_hops = hops

        for index in range(self.hop_limit + 1):
            # ── 每一跳发出之前重新问一次策略 ──────────────────────
            reason = await check(cur, m, body_text, approved)
            if reason:
                hop = Hop(url=cur, method=m, blocked=True, reason=reason)
                hops.append(hop)
                self.blocked_count += 1
                self._audit_deny(hop, index, m)
                return GatewayResult(
                    response=None, hops=hops, blocked=True,
                    reason=f"第 {index + 1} 跳被策略拒绝：{reason}",
                )

            try:
                resp = await self._client(cur).request(
                    m, cur, headers=headers, content=body if body else None
                )
            except Exception:
                # 网络异常：把已发生的跳记录留下，异常由调用方转 Evidence.error
                raise
            self.sent += 1
            hops.append(Hop(url=cur, method=m, status=resp.status_code))

            if not self._should_follow(resp):
                return GatewayResult(response=resp, hops=hops)

            location = resp.headers.get("location") or ""
            try:
                await resp.aclose()
            except Exception:  # noqa: BLE001
                pass
            if not location:
                return GatewayResult(response=resp, hops=hops)

            nxt = urljoin(cur, location)
            scheme = (urlparse(nxt).scheme or "").lower()
            if scheme not in ("http", "https"):
                hop = Hop(
                    url=nxt, method=m, blocked=True,
                    reason=f"重定向目标协议 {scheme or '空'} 不在允许范围（仅 http/https）",
                )
                hops.append(hop)
                self.blocked_count += 1
                self._audit_deny(hop, index + 1, m)
                return GatewayResult(
                    response=None, hops=hops, blocked=True,
                    reason=f"第 {index + 2} 跳被拒绝：{hop.reason}",
                )

            # 303 / 302+POST：按浏览器语义改为 GET 并丢弃请求体
            if resp.status_code == 303 or (
                resp.status_code in (301, 302) and m == "POST"
            ):
                m, body, body_text = "GET", b"", ""
            cur = nxt
            self.redirect_count += 1

        # 跳数超限：不无限跟，按拒绝处理（fail-closed）
        hop = Hop(
            url=cur, method=m, blocked=True,
            reason=f"重定向超过 {self.hop_limit} 跳上限，停止跟随（fail-closed）",
        )
        hops.append(hop)
        self.blocked_count += 1
        self._audit_deny(hop, self.hop_limit, m)
        return GatewayResult(
            response=None, hops=hops, blocked=True, reason=hop.reason,
        )

    @staticmethod
    def _should_follow(resp: httpx.Response) -> bool:
        return resp.status_code in _REDIRECT_CODES and bool(resp.headers.get("location"))


async def close_quietly(*clients: httpx.AsyncClient | None) -> None:
    """并发关闭多个客户端（测试/异常收尾用）。"""
    await asyncio.gather(
        *(c.aclose() for c in clients if c is not None),
        return_exceptions=True,
    )


__all__ = [
    "Checker",
    "GatewayResult",
    "Hop",
    "HttpGateway",
    "gateway_client",
    "gateway_sync_client",
    "close_quietly",
]
