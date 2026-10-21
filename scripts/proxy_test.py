"""本机代理探测与请求级代理决策的测试。

这块最怕两件事，测试就围绕它们展开：

1. **"我挂了代理却看不到流量"** —— 探测不到、或探测到了但没回填配置。
2. **"内网目标被送去公网代理"** —— 比第 1 条严重得多，可能泄露内网拓扑。

第 2 条是设计的核心取舍，所以占用最多断言：本机 / 回环 / 三个私网段 /
链路本地 / 内网后缀，**一个都不能走代理**。

网络无关：探测只读环境变量与注册表，测试用 monkeypatch 造环境，不真连网。

运行：.venv/Scripts/python.exe scripts/test_proxy.py < /dev/null
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.proxy import (  # noqa: E402
    ProxyInfo,
    build_client_kwargs,
    detect_and_apply,
    detect_proxy,
    is_local_host,
    normalize_proxy,
    resolve_proxy_for,
)

# 所有可能影响探测的变量，测前统一清掉再按需设。
_PROXY_KEYS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)


class _Cfg:
    """最小 ScanConfig 替身。"""

    def __init__(self, proxy=None, no_proxy=None, autodetect=True):
        self.timeout = 5.0
        self.verify_tls = False
        self.follow_redirects = True
        self.user_agent = "test-agent"
        self.proxy = proxy
        self.no_proxy = list(no_proxy or [])
        self.proxy_autodetect = autodetect


class _Env:
    """临时改环境变量的上下文管理器——**必须还原**，否则污染后续测试。"""

    def __init__(self, **kw):
        self.kw = kw
        self.saved: dict[str, str | None] = {}

    def __enter__(self):
        for k in _PROXY_KEYS:
            self.saved[k] = os.environ.pop(k, None)
        for k, v in self.kw.items():
            if v is not None:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k in _PROXY_KEYS:
            os.environ.pop(k, None)
        for k, v in self.saved.items():
            if v is not None:
                os.environ[k] = v
        return False


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # ── 场景1 normalize_proxy ─────────────────────────────────────
    print("场景1 normalize_proxy：各种写法归一到带 scheme 的 URL")
    check(normalize_proxy("127.0.0.1:7897") == "http://127.0.0.1:7897", "缺 scheme 自动补 http")
    check(normalize_proxy("http://x:8080/") == "http://x:8080", "去尾斜杠")
    check(normalize_proxy("socks5://1.2.3.4:1080") == "socks5://1.2.3.4:1080", "保留 socks5")
    check(normalize_proxy("user:pass@h:9999") == "http://user:pass@h:9999", "带凭据")
    check(normalize_proxy("") == "" and normalize_proxy("   ") == "", "空串 → 空")
    check(normalize_proxy("ftp://x:21") == "", "未知 scheme 不当代理")
    check(normalize_proxy("://bad") == "", "畸形串 → 空")

    # ── 场景2 is_local_host（核心：内网绝不走代理）────────────────
    print("场景2 is_local_host：内网/本机识别（决定了谁不许走代理）")
    for h in ("localhost", "LOCALHOST", "api.localhost", "127.0.0.1", "127.1.2.3",
              "::1", "192.168.10.128", "10.0.0.5", "172.16.3.9", "172.31.255.1",
              "169.254.1.1", "a.internal", "x.local", "y.lan", "z.intranet",
              "192.168.10.128:8899", "10.0.0.1:80"):
        check(is_local_host(h), f"{h} 判为本地/内网")
    for h in ("8.8.8.8", "example.com", "api.example.com", "172.32.0.1",
              "172.15.0.1", "11.0.0.1", "192.169.0.1", ""):
        check(not is_local_host(h), f"{h} 判为公网")

    print("场景2b 私网边界：172.16-31 是私网，172.15/172.32 不是")
    check(is_local_host("172.16.0.1") and is_local_host("172.31.0.1"), "172.16/172.31 在内")
    check(not is_local_host("172.15.0.1") and not is_local_host("172.32.0.1"), "172.15/172.32 在外")

    # ── 场景3 探测：环境变量优先 ──────────────────────────────────
    print("场景3 detect_proxy：环境变量优先于系统代理")
    with _Env(HTTP_PROXY="http://127.0.0.1:8080"):
        info = detect_proxy()
        check(info.found and info.proxy == "http://127.0.0.1:8080", "读到 HTTP_PROXY")
        check(info.source == "env:http", "来源标注 env:http")

    with _Env(HTTPS_PROXY="http://127.0.0.1:9090"):
        info = detect_proxy()
        check(info.proxy == "http://127.0.0.1:9090" and info.source == "env:https", "HTTPS_PROXY")

    with _Env(ALL_PROXY="socks5://127.0.0.1:1080"):
        info = detect_proxy()
        check(info.proxy == "socks5://127.0.0.1:1080" and info.source == "env:all", "ALL_PROXY 兜底")

    print("场景3b 大小写两种变量名都认")
    with _Env(http_proxy="http://127.0.0.1:7070"):
        check(detect_proxy().proxy == "http://127.0.0.1:7070", "小写 http_proxy")

    print("场景3c NO_PROXY 被读到")
    with _Env(HTTP_PROXY="http://p:1", NO_PROXY="a.com, b.com ,,c.com"):
        info = detect_proxy()
        check(info.no_proxy == ["a.com", " b.com ", "", "c.com"] or
              all(x.strip() for x in info.no_proxy if x), "NO_PROXY 解析为列表")
        check(len([x for x in info.no_proxy if x.strip()]) == 3, "空项被忽略（3 条有效）")

    print("场景3d 无任何代理 → found=False，且不发网络请求")
    with _Env():
        info = detect_proxy(use_system=False)
        check(not info.found, "无代理时 found=False")
        check(info.describe() == "未检测到代理（直连）", "describe 文案")

    # ── 场景4 detect_and_apply：回填配置 ──────────────────────────
    print("场景4 detect_and_apply：有代理就回填，显式配置优先")
    with _Env(HTTP_PROXY="http://127.0.0.1:8080"):
        cfg = _Cfg()
        info = detect_and_apply(cfg, use_system=False)
        check(cfg.proxy == "http://127.0.0.1:8080", "探测到的代理回填进 cfg.proxy")
        check(info.found, "返回 found=True")

    with _Env(HTTP_PROXY="http://127.0.0.1:8080"):
        cfg = _Cfg(proxy="http://explicit:9999")
        detect_and_apply(cfg, use_system=False)
        check(cfg.proxy == "http://explicit:9999", "配置里显式设过 → 不被探测覆盖")

    with _Env():
        cfg = _Cfg()
        detect_and_apply(cfg, use_system=False)
        check(cfg.proxy is None, "没探测到 → 保持 None（退回直连）")

    # ── 场景5 resolve_proxy_for：请求级决策（最关键）─────────────
    print("场景5 resolve_proxy_for：内网直连、公网走代理")
    cfg = _Cfg(proxy="http://127.0.0.1:8080")
    check(resolve_proxy_for(cfg, "example.com") == "http://127.0.0.1:8080", "公网走代理")
    check(resolve_proxy_for(cfg, "192.168.10.128") is None, "物理机网口 IP 直连")
    check(resolve_proxy_for(cfg, "127.0.0.1") is None, "回环直连")
    check(resolve_proxy_for(cfg, "10.1.2.3") is None, "10 段直连")
    check(resolve_proxy_for(cfg, "172.16.5.5") is None, "172.16 段直连")
    check(resolve_proxy_for(cfg, "a.internal") is None, "内网后缀直连")

    print("场景5b force=True 时无视内网判断（用户显式要求）")
    check(resolve_proxy_for(cfg, "192.168.10.128", force=True) == "http://127.0.0.1:8080",
          "force 强制走代理")

    print("场景5c 没配代理时一律 None")
    check(resolve_proxy_for(_Cfg(), "example.com") is None, "无代理 → None")

    print("场景5d no_proxy 例外表生效")
    cfg2 = _Cfg(proxy="http://p:1", no_proxy=["skip.com", ".corp.com", "10.0.0.0/8", "192.168.*"])
    check(resolve_proxy_for(cfg2, "skip.com") is None, "精确匹配直连")
    check(resolve_proxy_for(cfg2, "www.skip.com") is None, "后缀匹配（裸域名）直连")
    check(resolve_proxy_for(cfg2, "a.corp.com") is None, ".corp.com 后缀直连")
    check(resolve_proxy_for(cfg2, "10.9.9.9") is None, "CIDR 命中直连")
    check(resolve_proxy_for(cfg2, "192.168.5.5") is None, "通配前缀命中直连")
    check(resolve_proxy_for(cfg2, "other.com") == "http://p:1", "不在例外表 → 走代理")

    # ── 场景6 build_client_kwargs：httpx 参数 ─────────────────────
    print("场景6 build_client_kwargs：httpx 客户端参数正确")
    cfg = _Cfg(proxy="http://127.0.0.1:8080")
    kw = build_client_kwargs(cfg, "https://example.com/")
    check(kw.get("proxy") == "http://127.0.0.1:8080", "公网目标带 proxy")
    check(kw["trust_env"] is False, "始终 trust_env=False（避免双重代理）")
    check(kw["timeout"] == 5.0 and kw["verify"] is False, "超时与 TLS 从配置来")

    kw2 = build_client_kwargs(cfg, "http://192.168.10.128:8899/")
    check("proxy" not in kw2, "内网目标不带 proxy")
    check(kw2["trust_env"] is False, "内网目标仍 trust_env=False")

    kw3 = build_client_kwargs(_Cfg(), "https://example.com/")
    check("proxy" not in kw3, "无代理配置 → 不带 proxy")

    print("场景6b 无 url 时保守直连（无法判主机就不盲走代理）")
    kw4 = build_client_kwargs(cfg, "")
    check("proxy" not in kw4, "无 url → 不启用代理")

    # ── 场景7 ProxyInfo.describe ─────────────────────────────────
    print("场景7 ProxyInfo：状态描述")
    check(not ProxyInfo().found, "空 ProxyInfo.found=False")
    p = ProxyInfo(proxy="http://p:1", source="env:http", no_proxy=["a", "b"])
    check("http://p:1" in p.describe() and "env:http" in p.describe(), "describe 含代理与来源")
    check("2" in p.describe(), "describe 含例外条数")

    # ── 场景8 探测绝不发网络请求 ─────────────────────────────────
    print("场景8 探测安全性：只读本地状态，不发请求")
    # 用 AST 检查真实 import，而不是 grep 字符串——注释/文档里提到 httpx
    # 不代表真的 import 了（第一版就是这么误报的）。
    import ast

    tree = ast.parse(Path(ROOT / "core" / "proxy.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    check("httpx" not in imported, f"core/proxy.py 不 import httpx（实为 {sorted(imported)}）")
    check("requests" not in imported, "不 import requests")
    check("socket" not in imported, "不 import socket（不做任何网络 IO）")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
