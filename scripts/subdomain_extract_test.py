"""子域枚举采集器的测试。

覆盖五块，都是"看起来对、实际会错"的地方：

1. **主域抽取**——``urlparse`` 对裸域名不生效、``.co.uk``/``.edu.cn``
   这类**多段公共后缀**必须最长匹配、IP 必须拒绝、裸 ``host:port`` 要剥端口。
2. **记录清洗**——通配符、换行分隔的多域名、主域自身、脏标签
   （``a..b`` / ``-x``）都必须处理干净。
3. **单源查询**——请求参数、5xx/非 JSON/网络异常一律降级为空集 + note。
4. **多源聚合**——crt.sh 整站 502 时必须**自动换源**并且**照样出结果**；
   各源独立降级；同一主机名按可信度归属；失败必须留痕（不能伪装成"没资产"）。
5. **排列组合**——只允许"减前缀 / 换前缀"，且结果必须仍属该主域；
   绝不能把"给主域加前缀"的爆破逻辑混进来（那不符合"被动"语义）。

网络部分用假的 httpx 客户端替身，不真打任何被动源——
测试必须能离线、快速、稳定重复跑。

运行：.venv/Scripts/python.exe scripts/subdomain_extract_test.py < /dev/null
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _srcs import module_source  # noqa: E402

from collectors.subdomain_extract import (  # noqa: E402
    CRT_SH_URL,
    ENV_PREFIXES,
    HACKERTARGET_URL,
    PASSIVE_SOURCES,
    PUBLIC_SUFFIXES,
    SOURCE_PRIORITY,
    SubdomainCandidate,
    SubdomainCollector,
)


class _Cfg:
    timeout = 10.0
    verify_tls = True
    user_agent = "test-agent"
    proxy = None
    no_proxy: list = []
    follow_redirects = True


class _Resp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Client:
    """假 httpx 客户端——按 URL 片段路由响应，记录请求参数。"""

    def __init__(self, routes=None, raise_exc=None, default=None):
        self.routes = routes or {}
        self.raise_exc = raise_exc
        self.default = default if default is not None else _Resp(200, [])
        self.calls: list[dict] = []
        self.is_closed = False

    async def get(self, url, params=None, timeout=None, **_kw):
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if self.raise_exc is not None:
            raise self.raise_exc
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return self.default

    async def aclose(self):
        self.is_closed = True


def _wire(sc, **kw) -> _Client:
    """把假客户端接到采集器上（替换 ``client()``，避免真建连接）。"""
    c = _Client(**kw)
    sc.client = lambda url=CRT_SH_URL, _c=c: _c  # noqa: ARG005
    return c


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # ── 场景1 主域抽取 ────────────────────────────────────────────
    print("场景1 main_domain：从各形态输入里抽出注册域（不多截、不少截）")
    md = SubdomainCollector.main_domain
    check(md("example.com") == "example.com", "裸域名")
    check(md("https://example.com/") == "example.com", "带协议与路径")
    check(md("http://a.b.example.com:8080/x?y=1") == "example.com", "深层子域带端口查询串")
    check(md("a.b.example.com:8080/x?y=1") == "example.com", "无 scheme 的裸 host:port 也要剥端口")
    check(md("  EXAMPLE.COM.  ") == "example.com", "大小写 + 尾点 + 空白")
    check(md("127.0.0.1") == "", "IPv4 拒绝（无子域可言）")
    check(md("http://127.0.0.1:8899") == "", "IPv4 带端口拒绝")
    check(md("localhost") == "", "单标签拒绝")
    check(md("") == "", "空串拒绝")
    check(md("a b.com") == "", "含空格的畸形串拒绝")

    # 关键回归：多段公共后缀曾把主域截断成公共后缀本身。
    # gdust.edu.cn → edu.cn 会导致查询 %.edu.cn 拉回全国高校域名，
    # 并让排列组合产出 dev.edu.cn 这类垃圾。实网事故。
    print("  -- 多段公共后缀（截断 bug 回归）--")
    check(md("https://gdust.edu.cn") == "gdust.edu.cn", "gdust.edu.cn 不被截成 edu.cn")
    check(md("http://www.gdust.edu.cn") == "gdust.edu.cn", "www.gdust.edu.cn 收敛到注册域")
    check(md("https://cas.gdust.edu.cn") == "gdust.edu.cn", "cas.gdust.edu.cn 收敛到注册域")
    check(md("example.com.cn") == "example.com.cn", "example.com.cn 不被截成 com.cn")
    check(md("a.b.example.com.cn") == "example.com.cn", "深层 .com.cn 收敛正确")
    check(md("https://x.example.co.uk") == "example.co.uk", "co.uk 不被截成 co.uk")
    check(md("example.co.jp") == "example.co.jp", "co.jp 正确")
    check(md("lab-l4web5.rzsec.cn") == "rzsec.cn", "单段后缀仍取末两段")
    # 输入本身就是公共后缀 → 拒绝，比硬造一个"主域"更有用
    check(md("edu.cn") == "", "输入是公共后缀 → 拒绝")
    check(md("com.cn") == "", "输入是公共后缀 → 拒绝")
    check(md("co.uk") == "", "输入是公共后缀 → 拒绝")

    # ── 场景2 记录清洗 ────────────────────────────────────────────
    print("场景2 _accept：被动源记录里的子域清洗")
    acc = SubdomainCollector._accept
    check(acc("api.example.com", "example.com") == {"api.example.com"}, "普通子域通过")
    check(acc("*.example.com", "example.com") == set(), "通配符剥掉后等于主域 → 排除")
    check(acc("*.api.example.com", "example.com") == {"api.example.com"}, "通配符子域保留")
    check(acc("example.com", "example.com") == set(), "主域自身不算子域")
    check(acc("evil.com", "example.com") == set(), "非该主域的子域排除")
    check(acc("notexample.com", "example.com") == set(), "后缀相近但不属主域 → 排除")
    check(acc("a..b.example.com", "example.com") == set(), "连续点脏数据排除")
    check(acc("-bad.example.com", "example.com") == set(), "以连字符开头的标签排除")
    check(acc("API.Example.COM.", "example.com") == {"api.example.com"}, "大小写 + 尾点归一化")
    check(acc("", "example.com") == set(), "空串排除")
    check(acc("a@b.example.com", "example.com") == set(), "含 @ 排除")
    # urlscan 的 domain: 过滤很松，无关域名必须被这道闸门挡掉
    check(acc("www.huffpost.com", "example.com") == set(), "urlscan 混进来的无关域名被挡")

    # ── 场景3 单源查询（crt.sh）失败降级 ──────────────────────────
    print("场景3 query_crtsh：请求参数 / 多行拆分 / 失败降级")

    async def t_query():
        # 3a 正常：name_value 换行分隔多域名
        payload = [
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.dev.example.com"},
            {"name_value": "example.com"},
            {"name_value": "other.com"},
        ]
        sc = SubdomainCollector(_Cfg())
        c = _wire(sc, routes={"crt.sh": _Resp(200, payload)})
        got = await sc.query_crtsh("example.com")
        check(
            got == {"api.example.com", "www.example.com", "dev.example.com"},
            "多行 name_value 拆开、通配符剥星、主域与外人排除",
            f"got={sorted(got)}",
        )
        check(c.calls and c.calls[0]["url"] == CRT_SH_URL, "打到 crt.sh 入口")
        check(c.calls[0]["params"] == {"q": "%.example.com", "output": "json"}, "查询参数正确")

        # 3b 5xx 降级
        sc2 = SubdomainCollector(_Cfg())
        _wire(sc2, routes={"crt.sh": _Resp(502, None)})
        check(await sc2.query_crtsh("example.com") == set(), "HTTP 5xx 静默降级为空集")
        check(any("502" in n for n in sc2.notes), "5xx 记一条 note")

        # 3c 非 JSON 降级
        sc3 = SubdomainCollector(_Cfg())
        _wire(sc3, routes={"crt.sh": _Resp(200, None, text="<html>rate limited</html>")})
        check(await sc3.query_crtsh("example.com") == set(), "非 JSON 响应降级为空集")
        check(any("不是 JSON" in n for n in sc3.notes), "非 JSON 记一条 note")

        # 3d 网络异常降级
        sc4 = SubdomainCollector(_Cfg())
        _wire(sc4, raise_exc=RuntimeError("boom"))
        check(await sc4.query_crtsh("example.com") == set(), "网络异常降级为空集")
        check(any("不可达" in n for n in sc4.notes), "网络异常记一条 note")

    asyncio.run(t_query())

    # ── 场景4 多源聚合：一个源挂了不影响其他源 ─────────────────────
    print("场景4 query_passive / merge_sources：多源并发 + 独立降级")

    _RAPID_HTML = (
        "<html><body><table><tbody>"
        '<tr><th scope="row ">1</th><td>api.example.com</td><td>1.2.3.4</td></tr>'
        '<tr><th scope="row ">2</th><td>dev.example.com</td><td>1.2.3.5</td></tr>'
        "</tbody></table></body></html>"
    )
    _URLSCAN_JSON = {
        "results": [
            {"page": {"domain": "scan.example.com", "url": "https://scan.example.com/a"}},
            # urlscan 的 domain: 过滤很松，这条无关域名必须被 _accept 挡掉
            {"page": {"domain": "huffpost.com", "url": "https://www.huffpost.com/x"}},
        ]
    }

    async def t_multi():
        # 4a 全源可用：各源结果合并、按可信度归属
        sc = SubdomainCollector(_Cfg())
        _wire(
            sc,
            default=_Resp(200, []),
            routes={
                "crt.sh": _Resp(200, [{"name_value": "api.example.com"}]),
                "hackertarget": _Resp(
                    200, None, text="api.example.com,1.2.3.4\nweb.example.com,5.6.7.8\n"
                ),
                "rapiddns": _Resp(200, None, text=_RAPID_HTML),
                "urlscan": _Resp(200, _URLSCAN_JSON),
                "otx": _Resp(200, {"passive_dns": [{"hostname": "dns.example.com"}]}),
            },
        )
        per = await sc.query_passive("example.com")
        check(set(per) == set(PASSIVE_SOURCES), "所有声明的源都被查询", f"got={sorted(per)}")
        check(list(per) == list(SOURCE_PRIORITY), "返回字典按可信度保序")
        found, origin = SubdomainCollector.merge_sources(per)
        check(
            found == {
                "api.example.com",
                "web.example.com",
                "dev.example.com",
                "scan.example.com",
                "dns.example.com",
            },
            "各源结果合并去重",
            f"found={sorted(found)}",
        )
        check(origin["api.example.com"] == "crt.sh", "同现多源时归给最可信的源")
        check(origin["web.example.com"] == "hackertarget", "仅 hackertarget 有的归它")
        check("huffpost.com" not in found, "urlscan 的无关域名被严格过滤")

        # 4b **核心回归**：crt.sh 整站 502 时必须自动换源且照样出结果
        sc2 = SubdomainCollector(_Cfg())
        _wire(
            sc2,
            default=_Resp(200, []),
            routes={
                "crt.sh": _Resp(502, None),
                "hackertarget": _Resp(
                    200, None, text="webvpn.example.com,1.1.1.1\nm.example.com,2.2.2.2\n"
                ),
                "otx": _Resp(429, None),
            },
        )
        cands = await sc2.run("https://example.com", passive_only=True)
        hosts = [c.host for c in cands]
        check(hosts == ["m.example.com", "webvpn.example.com"], "crt.sh 502 时仍拿到结果（换源生效）")
        check(all(c.source == "hackertarget" for c in cands), "来源如实标注为 hackertarget")
        check(any("crt.sh" in n and "502" in n for n in sc2.notes), "crt.sh 失败留痕")
        check(any("otx" in n and "429" in n for n in sc2.notes), "otx 限流留痕")

        # 4c 全源皆挂 → 空结果 + **每个源的失败都留痕**
        sc3 = SubdomainCollector(_Cfg())
        _wire(sc3, routes={}, default=_Resp(500, None))
        check(await sc3.run("https://example.com") == [], "全源失败 → 空列表")
        check(len(sc3.notes) >= len(PASSIVE_SOURCES), "每个源的失败都有 note（不伪装成'没资产'）")

        # 4d 主域解析不出来 → 不发任何请求
        sc4 = SubdomainCollector(_Cfg())
        c4 = _wire(sc4)
        check(await sc4.run("http://127.0.0.1:8899/") == [], "IP 目标返回空列表")
        check(c4.calls == [], "IP 目标不发任何请求")

    # ── 场景4b 各源解析细节（正文格式差异）────────────────────────
    print("场景4b 各源解析：状态码看不出错的情况")
    asyncio.run(t_multi())

    async def t_parse():
        sc = SubdomainCollector(_Cfg())

        # hackertarget 额度用尽：**HTTP 200 + 正文报错**，只看状态码会静默失真
        sc1 = SubdomainCollector(_Cfg())
        _wire(sc1, routes={"hackertarget": _Resp(200, None, text="API count exceeded")})
        got = await sc1.query_passive("example.com")
        check(got["hackertarget"] == set(), "额度用尽 → 空集")
        check(any("额度" in n for n in sc1.notes), "额度用尽必须留痕（不能当成'没子域'）")

        # hackertarget "no records found" 是**有效结论**，不是失败
        sc2 = SubdomainCollector(_Cfg())
        _wire(sc2, routes={"hackertarget": _Resp(200, None, text="no records found")})
        got2 = await sc2.query_passive("example.com")
        check(got2["hackertarget"] == set(), "no records found → 空集")
        check(not any("hackertarget" in n for n in sc2.notes), "no records found 不记为失败")

        # rapiddns 结构变化：不能静默返回空，必须当失败上报
        sc3 = SubdomainCollector(_Cfg())
        _wire(sc3, routes={"rapiddns": _Resp(200, None, text="<html>改版了</html>")})
        await sc3.query_passive("example.com")
        check(any("rapiddns" in n and "结构" in n for n in sc3.notes), "rapiddns 结构变化必须留痕")

        # rapiddns 明确"找到 0 条"→ 有效结论
        sc4 = SubdomainCollector(_Cfg())
        _wire(
            sc4,
            routes={"rapiddns": _Resp(200, None, text="<html>Found 0 subdomain</html>")},
        )
        got4 = await sc4.query_passive("example.com")
        check(got4["rapiddns"] == set(), "rapiddns 0 条 → 空集")
        check(not any("rapiddns" in n for n in sc4.notes), "rapiddns 0 条不记为失败")

        # otx 404 是"该域没记录"，不是失败
        sc5 = SubdomainCollector(_Cfg())
        _wire(sc5, routes={"otx": _Resp(404, None)})
        got5 = await sc5.query_passive("example.com")
        check(got5["otx"] == set(), "otx 404 → 空集")
        check(not any("otx" in n for n in sc5.notes), "otx 404 不记为失败")

        # 每个源都必须带源级超时（crt.sh 挂的时候是"一直转"）
        sc6 = SubdomainCollector(_Cfg())
        c6 = _wire(sc6, routes={"crt.sh": _Resp(200, [{"name_value": "a.example.com"}])})
        await sc6.query_passive("example.com")
        check(all(call["timeout"] for call in c6.calls), "每个源请求都带超时")

        # _accept 对所有源统一生效（不能有源绕过严格收敛）
        src_methods = [n for n in dir(sc) if n.startswith("_src_")]
        check(len(src_methods) == len(PASSIVE_SOURCES), "每个声明的源都有实现方法")
        for name in PASSIVE_SOURCES:
            check(
                hasattr(sc, "_src_" + name.replace(".", "_")),
                f"源 {name} 的实现方法存在",
            )

    asyncio.run(t_parse())

    # ── 场景5 排列组合 ────────────────────────────────────────────
    print("场景5 permute：只做减前缀 / 换前缀，结果仍属主域")
    sc = SubdomainCollector(_Cfg())
    known = {
        "api.example.com",
        "dev.api.example.com",
        "staging.example.com",
        "www.example.com",
    }
    out = sc.permute("example.com", known)
    check("dev.api.example.com" not in out, "输入本身不在输出里")
    check("api.example.com" in out, "减前缀：dev.api → api")
    check("test.example.com" in out, "换前缀：staging → test")
    check(all(h.endswith(".example.com") for h in out), "全部仍属该主域")
    check("example.com" not in out, "主域自身不出现")
    check("shop.example.com" not in out, "不做服务前缀爆破（不是被动枚举该干的事）")
    check("dev.www.example.com" not in out, "www 不做叠加前缀（避免 dev.www 垃圾）")
    check("dev.portal.example.com" not in out, "不产 dev.portal 这类堆叠（rest 不是主域）")
    check("portal.portal.example.com" not in out, "不产 portal.portal 这类自我堆叠")
    check(len(out) > 0, "非空")
    # 多段后缀下也必须只产出该注册域的候选
    out2 = sc.permute("gdust.edu.cn", {"staging.gdust.edu.cn", "api.gdust.edu.cn"})
    check(all(h.endswith(".gdust.edu.cn") for h in out2), "多段后缀下仍收敛到注册域")
    check(not any(h.endswith(".edu.cn") and not h.endswith(".gdust.edu.cn") for h in out2),
          "不产出 dev.edu.cn 这类越界候选")

    # ── 场景6 Candidate → Asset ───────────────────────────────────
    print("场景6 SubdomainCandidate.to_asset：来源标注与 guessed 标志")
    cert = SubdomainCandidate("api.example.com", "crt.sh").to_asset("example.com")
    ht = SubdomainCandidate("web.example.com", "hackertarget").to_asset("example.com")
    guess = SubdomainCandidate("dev.example.com", "permutation").to_asset("example.com")
    check(cert.kind == "subdomain", "kind 为 subdomain")
    check(cert.value == "api.example.com", "value 是主机名")
    check(cert.meta["source"] == "crt.sh" and cert.meta["guessed"] is False, "crt.sh 不是猜测")
    check(ht.meta["source"] == "hackertarget" and ht.meta["guessed"] is False, "任何被动源都不是猜测")
    check(guess.meta["source"] == "permutation" and guess.meta["guessed"] is True, "permutation 标记为猜测")
    check(cert.meta["base"] == "example.com", "meta 带主域")

    # ── 场景7 run() 两种模式 + 排序 ───────────────────────────────
    print("场景7 run()：passive_only 开关与输出顺序")

    async def t_run():
        payload = [
            {"name_value": "staging.example.com"},
            {"name_value": "api.example.com"},
        ]
        # 7a passive_only=True：不调 permute
        sc = SubdomainCollector(_Cfg())
        _wire(sc, default=_Resp(200, []), routes={"crt.sh": _Resp(200, payload)})
        a = await sc.run("https://example.com/", passive_only=True)
        check([c.host for c in a] == ["api.example.com", "staging.example.com"], "被动模式排序稳定")
        check(all(c.source == "crt.sh" for c in a), "被动模式来源如实标注")

        # 7b passive_only=False：带猜测
        sc2 = SubdomainCollector(_Cfg())
        _wire(sc2, default=_Resp(200, []), routes={"crt.sh": _Resp(200, payload)})
        b = await sc2.run("https://example.com/", passive_only=False)
        hosts = [c.host for c in b]
        check(
            hosts.index("api.example.com") < hosts.index("dev.example.com")
            if "dev.example.com" in hosts
            else True,
            "被动源结果排在猜测之前",
        )
        check(any(c.source == "permutation" for c in b), "含猜测候选")
        check(len(set(hosts)) == len(hosts), "无重复主机名")
        check(b[-1].source == "permutation" or all(
            c.source == "permutation" for c in b[len(a):]
        ), "猜测候选统一排在末尾")

        # 7c assets() 便捷出口
        sc4 = SubdomainCollector(_Cfg())
        _wire(sc4, default=_Resp(200, []), routes={"crt.sh": _Resp(200, payload)})
        assets = await sc4.assets("example.com", passive_only=True)
        check(len(assets) == 2 and all(x.kind == "subdomain" for x in assets), "assets() 产出 subdomain 资产")

    asyncio.run(t_run())

    # ── 场景8 内置工具已注册 + 派发约定 ───────────────────────────
    print("场景8 工具注册：BUILTINS 与执行器派发")
    from core.tools import BUILTINS  # noqa: E402

    names = [t.name for t in BUILTINS]
    check("recon_subdomains" in names, "BUILTINS 里有 recon_subdomains")
    t = next((x for x in BUILTINS if x.name == "recon_subdomains"), None)
    check(t is not None and t.group == "侦察", "分组为侦察")
    props = (t.params.get("properties") or {}) if t else {}
    check("domain" in props and "passive_only" in props, "参数含 domain / passive_only")
    check((t.params.get("required") or []) == ["domain"], "domain 为必填")

    from core.tools import ToolRunner  # noqa: E402

    check(hasattr(ToolRunner, "_h_recon_subdomains"), "执行器有 _h_recon_subdomains 处理器")

    # 关键回归：处理器曾经**缺末尾 return**，导致"有结果时返回 None"。
    # 这是真的踩到过——工具明明枚举到子域，模型却收到 None。
    import ast  # noqa: E402

    rec_src = Path(ROOT / "core" / "tools" / "runner" / "recon.py").read_text(encoding="utf-8")
    fn = next(
        n
        for n in ast.walk(ast.parse(rec_src))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == "_h_recon_subdomains"
    )
    check(isinstance(fn.body[-1], ast.Return), "处理器末尾必须有 return（否则成功路径返回 None）")
    # 来源标签必须是**动态**的：旧的 `"crt.sh" if c.source == "crt.sh" else "猜测"`
    # 会把 hackertarget/rapiddns 等源拿到的子域误标成"猜测"。
    rec_fn_src = ast.get_source_segment(rec_src, fn) or ""
    check('c.source == "crt.sh"' not in rec_fn_src,
          "处理器不再硬编码 crt.sh 作为来源标签（否则其他源被误标成猜测）")
    check("[{c.source}]" in rec_fn_src.replace(" ", ""),
          "展示时直接输出真实来源名")

    # ── 场景9 planner / scheduler 已接入 ──────────────────────────
    print("场景9 自动接入：planner 与 scheduler 的侦察阶段")
    import core.planner as planner_mod  # noqa: E402
    import core.scheduler as sched_mod  # noqa: E402

    check(hasattr(planner_mod, "_is_ip"), "planner 有 _is_ip 辅助函数")
    check(planner_mod._is_ip("10.0.0.1") and not planner_mod._is_ip("a.example.com"), "_is_ip 判定正确")
    psrc = Path(ROOT / "core" / "planner.py").read_text(encoding="utf-8")
    check("SubdomainCollector" in psrc and "子域枚举" in psrc, "planner._recon 接入子域枚举")
    check("来源 crt.sh" not in psrc, "planner 不再硬编码 crt.sh 来源文案")
    ssrc = module_source("core.scheduler")
    check("SubdomainCollector" in ssrc and "子域枚举" in ssrc, "scheduler._phase2_recon 接入子域枚举")
    check("from collectors.subdomain_extract import SubdomainCollector" in ssrc, "scheduler 模块级 import")
    check("来源 crt.sh" not in ssrc, "scheduler 不再硬编码 crt.sh 来源文案")
    # 全部被动源失败时，note 必须落到 result.notes（否则失效被伪装成"没资产"）
    check("sc.notes" in ssrc, "scheduler 在空结果时回填失败 note")

    # ── 场景10 模块卫生 ───────────────────────────────────────────
    print("场景10 模块卫生：常量与依赖")
    import collectors.subdomain_extract as se_mod  # noqa: E402

    check(not hasattr(se_mod, "SERVICE_PREFIXES"), "不做前缀爆破 → 不保留 SERVICE_PREFIXES")
    check(isinstance(ENV_PREFIXES, tuple) and len(ENV_PREFIXES) >= 5, "ENV_PREFIXES 非空")
    check(not ({"git", "jenkins", "gitlab", "jira", "confluence"} & set(ENV_PREFIXES)),
          "ENV_PREFIXES 只含环境语义，不混服务名")
    check("edu.cn" in PUBLIC_SUFFIXES and "co.uk" in PUBLIC_SUFFIXES and "com.cn" in PUBLIC_SUFFIXES,
          "公共后缀表含关键多段后缀")
    check(not any(s.startswith(".") for s in PUBLIC_SUFFIXES), "后缀表项不带前导点")
    check(HACKERTARGET_URL.startswith("https://"), "hackertarget 走 https")
    check(len(SOURCE_PRIORITY) == len(PASSIVE_SOURCES), "优先级表覆盖所有源")

    # ── 场景11 RAG query 消费 subdomain 资产 ──────────────────────
    print("场景11 build_query：子域前缀拆词进检索语料")
    from core.state import Asset, Fingerprint, ScanResult  # noqa: E402
    from kb.retriever import build_query  # noqa: E402

    sr = ScanResult(
        target="https://example.com",
        fingerprints=[Fingerprint(target="https://example.com", http_status=200)],
        assets=[Asset(kind="subdomain", value="admin.portal.example.com")],
    )
    q = build_query(sr)
    check("admin" in q and "portal" in q, "子域前缀作为独立词进入 query", f"q={q!r}")
    check("admin.portal.example.com" not in q, "整串不进 query（只拆词）")

    sr2 = ScanResult(
        target="https://example.com",
        fingerprints=[Fingerprint(target="https://example.com", http_status=200)],
        assets=[Asset(kind="subdomain", value="www.example.com")],
    )
    q2 = build_query(sr2)
    check("www" not in q2, "www 这类无信息量前缀被过滤")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
