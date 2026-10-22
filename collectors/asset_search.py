"""网络空间测绘平台检索：统一入口，内部按优先级路由到各平台。

为什么是**一个入口**而不是每个平台一个工具
----------------------------------------
FOFA / Quake / Hunter / ZoomEye 功能高度相似，各自暴露成
``fofa_search`` / ``quake_search`` … 会让 Agent 每轮在四五个几乎一样
的工具里挑一个——选错就换个平台再试，和"参数填充死循环"是同一个模式；
四份 schema 还会白白吃掉几千 token 上下文。所以这里对 Agent 只暴露
**一个** ``search_assets`` 工具（见 core/tools/builtins.py），平台选择、
凭据路由、结果归一化全部在内部完成。

平台优先级（按国内资产覆盖 + API 规整度排序）
--------------------------------------------
1. **Quake**（360）：``X-QuakeToken`` 头，返回字段规整，国内覆盖好
2. **FOFA**（华顺信安）：email + key，``qbase64`` 传检索式
3. **Hunter**（奇安信）：api-key query 参数
4. **ZoomEye**（知道创宇）：先换 JWT 再检索，两步所以放最后

凭据**只从环境变量读**（.env 会由 core.envfile 注入 os.environ）：
``QUAKE_KEY`` / ``FOFA_EMAIL``+``FOFA_KEY`` / ``HUNTER_KEY`` / ``ZOOMEYE_KEY``。
没配 key 的平台直接跳过——不是报错，是降级：配了几个用几个。

外部依赖失败自动降级（项目既有约定）：单个平台超时/改版/限流只记
``errors``，不影响其余平台，更不往上抛。
"""

from __future__ import annotations

import base64
import os
from typing import Any
from urllib.parse import urlparse

import httpx

from core.state import Asset
from core.proxy import build_client_kwargs

# 平台优先级：靠前的先用。key 从环境变量读，缺 key 的平台整体跳过。
_PLATFORMS = ("quake", "fofa", "hunter", "zoomeye")

_ENV_KEYS = {
    "quake": ("QUAKE_KEY",),
    "fofa": ("FOFA_EMAIL", "FOFA_KEY"),
    "hunter": ("HUNTER_KEY",),
    "zoomeye": ("ZOOMEYE_KEY",),
}


def _keys() -> dict[str, str]:
    """读齐各平台凭据。缺项的平台不进结果——调用方按 key 存在性跳过。"""
    out: dict[str, str] = {}
    for p, names in _ENV_KEYS.items():
        vals = [os.environ.get(n, "").strip() for n in names]
        if all(vals):
            out[p] = vals[0] if len(vals) == 1 else "|".join(vals)
    return out


def platforms_available() -> list[str]:
    """当前配置了凭据的平台（按优先级排序）。"""
    have = _keys()
    return [p for p in _PLATFORMS if p in have]


def platforms_missing() -> list[str]:
    have = _keys()
    return [p for p in _PLATFORMS if p not in have]


# ── 各平台检索：统一返回 (assets, err) ──────────────────────────


async def _quake(client: httpx.AsyncClient, query: str, limit: int) -> tuple[list[Asset], str]:
    headers = {"X-QuakeToken": _keys()["quake"], "Content-Type": "application/json"}
    r = await client.post(
        "https://quake.360.net/api/v3/search/quake_service",
        headers=headers,
        json={"query": query, "start": 0, "size": min(limit, 100)},
    )
    d = r.json()
    if d.get("code"):
        return [], f"quake code={d.get('code')} {d.get('message', '')}"
    out: list[Asset] = []
    for it in (d.get("data") or [])[:limit]:
        svc = it.get("service") or {}
        http = svc.get("http") or {}
        host = (http.get("host") or "").strip()
        ip = (it.get("ip") or "").strip()
        port = svc.get("port")
        title = (http.get("title") or "").strip()
        if not host:
            continue
        out.append(Asset(
            kind="endpoint",
            value=host if host.startswith("http") else f"http://{host}",
            meta={"platform": "quake", "ip": ip, "port": port, "title": title},
            source="asset_search",
        ))
    return out, ""


async def _fofa(client: httpx.AsyncClient, query: str, limit: int) -> tuple[list[Asset], str]:
    email, key = _keys()["fofa"].split("|", 1)
    qbase64 = base64.b64encode(query.encode("utf-8")).decode()
    r = await client.get(
        "https://fofa.info/api/v1/search/all",
        params={
            "email": email, "key": key, "qbase64": qbase64,
            "size": min(limit, 100), "fields": "host,ip,port,title,domain",
        },
    )
    d = r.json()
    if d.get("error"):
        return [], f"fofa {d.get('errmsg', 'error')}"
    out: list[Asset] = []
    for row in (d.get("results") or [])[:limit]:
        # fields 顺序固定：host, ip, port, title, domain
        host, ip, port, title, domain = (list(row) + [""] * 5)[:5]
        host = str(host or "").strip()
        if not host:
            continue
        out.append(Asset(
            kind="endpoint",
            value=host if host.startswith("http") else f"http://{host}",
            meta={
                "platform": "fofa", "ip": str(ip), "port": port,
                "title": str(title or ""), "domain": str(domain or ""),
            },
            source="asset_search",
        ))
    return out, ""


async def _hunter(client: httpx.AsyncClient, query: str, limit: int) -> tuple[list[Asset], str]:
    r = await client.get(
        "https://hunter.qianxin.com/api/search",
        params={
            "api-key": _keys()["hunter"], "query": query,
            "page": 1, "size": min(limit, 100),
        },
    )
    d = r.json()
    if d.get("code") != 200:
        return [], f"hunter code={d.get('code')} {d.get('message', '')}"
    out: list[Asset] = []
    for it in ((d.get("data") or {}).get("arr") or [])[:limit]:
        url = str(it.get("url") or "").strip()
        if not url:
            continue
        out.append(Asset(
            kind="endpoint",
            value=url,
            meta={
                "platform": "hunter", "ip": str(it.get("ip") or ""),
                "port": it.get("port"), "title": str(it.get("title") or ""),
                "status_code": it.get("status_code"),
            },
            source="asset_search",
        ))
    return out, ""


async def _zoomeye(client: httpx.AsyncClient, query: str, limit: int) -> tuple[list[Asset], str]:
    key = _keys()["zoomeye"]
    # ZoomEye host search 要先换 JWT（两步），所以排最后
    r = await client.post(
        "https://api.zoomeye.org/v2/user/info", json={"api_key": key}
    )
    if r.status_code != 200:
        return [], f"zoomeye token http={r.status_code}"
    token = (r.json() or {}).get("access_token") or ""
    if not token:
        return [], "zoomeye 无 access_token"
    r2 = await client.get(
        "https://api.zoomeye.org/host/search",
        headers={"Authorization": f"JWT {token}"},
        params={"query": query, "page": 1},
    )
    d = r2.json()
    out: list[Asset] = []
    for it in (d.get("matches") or [])[:limit]:
        ip = str(it.get("ip") or "").strip()
        portinfo = it.get("portinfo") or {}
        port = portinfo.get("port")
        if not ip:
            continue
        out.append(Asset(
            kind="port",
            value=f"{ip}:{port}" if port else ip,
            meta={
                "platform": "zoomeye", "port": port,
                "app": str(portinfo.get("app") or ""),
                "title": str((portinfo.get("title") or [""])[0]
                             if isinstance(portinfo.get("title"), list)
                             else portinfo.get("title") or ""),
            },
            source="asset_search",
        ))
    return out, ""


_DISPATCH = {"quake": _quake, "fofa": _fofa, "hunter": _hunter, "zoomeye": _zoomeye}


# ── 统一入口 ────────────────────────────────────────────────────


def _normalize_query(query: str, target: str = "") -> str:
    """检索式兜底：用户给了自然语言时，尽量拼成平台能吃的语法。

    各平台语法不同（FOFA ``domain="x.com"`` / Quake ``domain:"x.com"``），
    这里只做最低限度适配：纯关键词原样传（各平台都支持全文），
    带 ``=``/``:`` 的视为用户已按某平台语法写好，同样原样传——
    **不猜语法**，猜错比不猜更难排查。
    """
    q = (query or "").strip()
    if not q and target:
        host = urlparse(target if "://" in target else f"http://{target}").hostname or target
        q = host
    return q


async def search_assets(
    query: str,
    *,
    cfg: Any = None,
    target: str = "",
    limit: int = 50,
) -> tuple[list[Asset], list[str]]:
    """检索目标相关资产。返回 ``(assets, errors)``。

    - 只调用**配了 key** 的平台，按优先级全部跑完再合并去重；
    - 单平台失败只进 ``errors``（降级），不影响其他平台；
    - 去重按 ``(kind, value)``：同一资产多个平台都报只留一条，
      meta 里记录全部来源平台。
    """
    q = _normalize_query(query, target)
    if not q:
        return [], ["query 为空"]
    keys = _keys()
    avail = [p for p in _PLATFORMS if p in keys]
    if not avail:
        return [], [f"未配置任何平台凭据（需要 {' / '.join(_ENV_KEYS[p][0] for p in _PLATFORMS)}）"]

    limit = max(1, min(int(limit or 50), 200))
    assets: list[Asset] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    # 客户端参数统一走 core/proxy.build_client_kwargs（含 timeout/proxy/UA）——
    # **不要再单独传 timeout**：build_client_kwargs 里已经有一份，重复传
    # 会 TypeError（这个坑本测试的 MockTransport 第一次就跑出来了）。
    # cfg 为空（直接当库调用）时给一份最小配置，不碰代理决策。
    if cfg is not None:
        client_kw = build_client_kwargs(cfg, "https://quake.360.net")
    else:
        client_kw = {"timeout": 15.0, "trust_env": False}
    try:
        async with httpx.AsyncClient(**client_kw) as client:
            for p in avail:
                try:
                    got, err = await _DISPATCH[p](client, q, limit)
                except Exception as exc:  # noqa: BLE001 —— 单平台失败降级
                    errors.append(f"{p}: {type(exc).__name__}: {exc}")
                    continue
                if err:
                    errors.append(err)
                for a in got:
                    k = (a.kind, a.value)
                    if k in seen:
                        continue
                    seen.add(k)
                    assets.append(a)
    except Exception as exc:  # noqa: BLE001 —— 客户端都建不起来时整体降级
        return [], [f"HTTP 客户端初始化失败：{type(exc).__name__}: {exc}"]
    return assets, errors
