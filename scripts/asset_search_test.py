"""search_assets 统一入口回归测试：平台路由、响应解析、降级。

用 httpx MockTransport 模拟各平台的真实响应结构（不发真实请求），
锁死：① 只调已配 key 的平台；② 各平台 JSON 归一化为 Asset；
③ 单平台失败只降级不崩；④ 一个平台都不配时给出配 key 指引。
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from collectors import asset_search as AS

PASS = 0
_ALL_KEYS = ("QUAKE_KEY", "FOFA_EMAIL", "FOFA_KEY", "HUNTER_KEY", "ZOOMEYE_KEY")


def check(cond: bool, msg: str, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  OK   {msg}")
    else:
        print(f"  FAIL {msg}" + (f"（实={detail}）" if detail else ""))
        raise SystemExit(1)


class FakeCfg:
    class scan:
        # build_client_kwargs 需要的字段（真实 ScanConfig 都有）
        timeout = 5.0
        verify_tls = False
        follow_redirects = True
        user_agent = "flower_pow-test"
        proxy = None
        no_proxy: list[str] = []
        proxy_autodetect = False


def _set_keys(**kw):
    for k in _ALL_KEYS:
        os.environ.pop(k, None)
    for k, v in kw.items():
        os.environ[k] = v


def main() -> int:
    print("场景1 未配任何 key：降级并给出配 key 指引")
    _set_keys()
    check(AS.platforms_available() == [], "可用平台为空")
    assets, errs = asyncio.run(AS.search_assets('domain="x.com"', cfg=FakeCfg.scan))
    check(assets == [] and errs and "未配置" in errs[0], "返回错误指引而非抛异常", str(errs))

    print("\n场景2 Quake 解析（X-QuakeToken + 嵌套 service.http）")
    _set_keys(QUAKE_KEY="fake-token")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("X-QuakeToken")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={
            "code": 0,
            "data": [
                {"ip": "1.2.3.4", "service": {"port": 443,
                 "http": {"host": "a.example.com", "title": "后台登录"}}},
                {"ip": "5.6.7.8", "service": {"port": 80,
                 "http": {"host": "b.example.com", "title": ""}}},
            ],
        })

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient
    httpx.AsyncClient = lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"})
    try:
        assets, errs = asyncio.run(AS.search_assets('domain:"example.com"', cfg=FakeCfg.scan))
    finally:
        httpx.AsyncClient = orig
    check(seen.get("auth") == "fake-token", "带 X-QuakeToken 头")
    check("example.com" in seen.get("body", ""), "query 进请求体")
    check(len(assets) == 2 and assets[0].value == "http://a.example.com", "归一化为 Asset（补协议头）", str(assets))
    check(assets[0].meta.get("title") == "后台登录" and assets[0].meta.get("platform") == "quake",
          "meta 带平台与标题")
    check(not errs, "无错误")

    print("\n场景3 FOFA 解析（email+key、qbase64、results 行式）")
    _set_keys(FOFA_EMAIL="a@b.c", FOFA_KEY="k")
    got = {}

    def handler2(request: httpx.Request) -> httpx.Response:
        got["params"] = dict(request.url.params)
        return httpx.Response(200, json={
            "error": False,
            "results": [["c.example.com", "9.9.9.9", 8443, "Tomcat", "example.com"]],
        })

    transport = httpx.MockTransport(handler2)
    httpx.AsyncClient = lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"})
    try:
        assets, errs = asyncio.run(AS.search_assets('domain="example.com"', cfg=FakeCfg.scan))
    finally:
        httpx.AsyncClient = orig
    fparams = got.get("params", {})
    check(fparams.get("email") == "a@b.c" and fparams.get("key") == "k",
          "FOFA 双凭据齐全", str(got))
    check(fparams.get("fields") == "host,ip,port,title,domain", "fields 固定顺序")
    check(len(assets) == 1 and assets[0].value == "http://c.example.com", "results 行式解析", str(assets))
    check(assets[0].meta.get("port") == 8443, "port 进 meta")

    print("\n场景4 Hunter / ZoomEye 解析")
    _set_keys(HUNTER_KEY="hk")
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={
        "code": 200, "data": {"arr": [{"url": "https://d.example.com/x", "ip": "2.2.2.2",
                                       "port": 443, "title": "T", "status_code": 200}]}}))
    httpx.AsyncClient = lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"})
    try:
        assets, errs = asyncio.run(AS.search_assets("app=Tomcat", cfg=FakeCfg.scan))
    finally:
        httpx.AsyncClient = orig
    check(len(assets) == 1 and assets[0].value == "https://d.example.com/x", "Hunter URL 原样保留", str(assets))

    _set_keys(ZOOMEYE_KEY="zk")
    calls = {"n": 0}

    def zhandler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"access_token": "jwt-t"})
        return httpx.Response(200, json={"matches": [
            {"ip": "3.3.3.3", "portinfo": {"port": 22, "app": "ssh", "title": ["SSH"]}}]})

    transport = httpx.MockTransport(zhandler)
    httpx.AsyncClient = lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"})
    try:
        assets, errs = asyncio.run(AS.search_assets("ssh", cfg=FakeCfg.scan))
    finally:
        httpx.AsyncClient = orig
    check(calls["n"] == 2, "ZoomEye 两步：先换 JWT 再检索")
    check(len(assets) == 1 and assets[0].value == "3.3.3.3:22", "ZoomEye 归一为 host:port", str(assets))
    check(assets[0].kind == "port", "端口类资产 kind=port")

    print("\n场景5 单平台失败只降级，其余平台照常")
    _set_keys(QUAKE_KEY="q", HUNTER_KEY="h")

    def mixed(request: httpx.Request) -> httpx.Response:
        if "quake" in str(request.url):
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={"code": 200, "data": {"arr": [
            {"url": "https://ok.example.com", "ip": "1.1.1.1", "port": 443}]}})

    transport = httpx.MockTransport(mixed)
    httpx.AsyncClient = lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"})
    try:
        assets, errs = asyncio.run(AS.search_assets('domain:"example.com"', cfg=FakeCfg.scan))
    finally:
        httpx.AsyncClient = orig
    check(len(assets) == 1 and assets[0].value == "https://ok.example.com",
          "失败的平台不影响成功的平台", str(assets))
    check(errs and any("quake" in e for e in errs), "失败平台进 errors", str(errs))

    print(f"\n结果：{PASS} 项断言全过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
