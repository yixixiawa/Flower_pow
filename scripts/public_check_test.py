"""公开性核验的回归测试。

复现的真实问题：命中一条"敏感信息/未授权访问"，但它其实是**公开演示站点**
有意放出来的内容。自动探针判不了"设计如此"，只能靠人一眼看出来——
而人看出来的其实还是证据：首页写着"演示站点"、站点自己挂了那个链接。

覆盖：
  1. 路径/主机归一化（大小写、尾斜杠、默认端口）
  2. 首页解析：title / 正文 / 同域链接 / sitemap / robots
  3. 打分与分档：强（站点自己公开）/ 中（自述演示站）/ 弱（只是像）/ 无
  4. **弱档不自动排除**（删错一条真实漏洞的代价不对称）
  5. robots 明确禁止抓取 → 反向证据，把判定压下来
  6. 抓取失败 → 绝不判成公开（不误删）
  7. 真实 HTTP：本地假"演示站"端到端跑通，且同一 host 只回源一次
  8. 接入：ToolRunner.check_public 自动排除 + 写排除清单 + 进报告复核附录
  9. apply=false 只报告不改动；配置开关存在且默认开

运行：.venv/Scripts/python.exe scripts/test_public_check.py
"""

from __future__ import annotations

import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _srcs import cli_source, module_source  # noqa: E402

from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session  # noqa: E402
from core.state import Category, Evidence, Finding, Severity  # noqa: E402
from core.tools import ToolRunner  # noqa: E402
from core.tools import BUILTINS  # noqa: E402
from detectors.public_check import (  # noqa: E402
    HostContext,
    PublicResourceChecker,
    host_of,
    normalize_path,
    page_links,
    page_text,
    page_title,
    path_of,
    robots_disallows,
    sitemap_paths,
)


def mk(poc_id: str, at: str) -> Finding:
    return Finding(
        poc_id=poc_id,
        name=poc_id,
        severity=Severity.MEDIUM,
        category=Category.HEADER_CHECK,
        matched_at=at,
        evidence=Evidence(url=at, poc_id=poc_id),
        verdict="true_positive",
        confidence=0.9,
    )


class FakeCfg:
    """``cfg.scan`` 用**真的** ScanConfig。

    一开始我手写了个只有 readonly/timeout/concurrency 的假对象，
    结果 ``build_client_kwargs`` 读 ``verify_tls`` / ``user_agent`` 直接
    AttributeError，被 ``_get_text`` 的兜底吞掉 → 根页面"抓取失败" →
    全部判为证据不足。假对象比真对象更容易骗过测试。
    """

    def __init__(self, **scan_kw) -> None:
        self.scan = ScanConfig(**scan_kw)

    class rag:
        poc_dir = "./poc"


def ctx(host: str, **kw) -> HostContext:
    """构造一份"已经拿到根页面"的假上下文（``root_ok=True``）。"""
    c = HostContext(base=f"https://{host}", host=host, fetched=True, root_ok=True)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


# 起一个本地假站。``demo=True`` 时首页自述"演示站点"，``False`` 时是完全
# 普通的首页——两种都要有，否则"分档"这件事根本测不出来（演示站首页那句话
# 会给**每一条**发现都加上 2 分）。
_SERVERS: list[HTTPServer] = []


def serve(demo: bool) -> tuple[int, list[str]]:
    """返回 ``(端口, 收到的请求路径列表)``。进程退出时自动关掉。"""
    hits: list[str] = []

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            if self.path == "/":
                title = "某某产品 · 在线演示" if demo else "某某产品"
                text = "本站为演示站点，数据每周重置。" if demo else "欢迎使用本产品。"
                self._o(f"<html><head><title>{title}</title></head><body>{text}"
                        '<a href="/download/setup.exe">下载</a></body></html>',
                        "text/html")
            elif self.path == "/sitemap.xml":
                self._o(f"<urlset><url><loc>http://127.0.0.1:{self.server.server_port}"
                        "/download/manual.pdf</loc></url></urlset>", "application/xml")
            elif self.path == "/robots.txt":
                self._o("User-agent: *\nDisallow: /admin\n", "text/plain")
            else:
                self.send_error(404)

        def _o(self, text, ctype):
            raw = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):   # 静音
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _SERVERS.append(srv)
    return srv.server_port, hits


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    print("场景1 路径与主机归一化")
    check(normalize_path("https://a.com/Docs/X/?q=1#f") == "/docs/x", "去 query/fragment + 小写")
    check(normalize_path("/") == "/", "根路径保持 /")
    check(normalize_path("docs/") == "/docs", "补前导斜杠 + 去尾斜杠")
    check(normalize_path("/a/b/") == "/a/b", "多层路径去尾斜杠")
    check(path_of("https://a.com/x") == "/x", "path_of 走同一套")
    check(host_of("https://A.com:8443/x") == "a.com", "host 小写、去端口")
    check(host_of("demo.ikuai8.com") == "demo.ikuai8.com", "裸域名也能解析")

    print("\n场景2 首页解析")
    html = """<html><head><title>爱快 iKuai · 在线演示</title>
    <script>var x = "/not-a-link.js";</script></head>
    <body><h1>演示站点</h1>
      <a href="/docs/manual.pdf">手册</a>
      <a href="https://cdn.other.com/x.js">外部</a>
      <img src="/assets/logo.png">
      <a href="javascript:void(0)">忽略</a>
    </body></html>"""
    check(page_title(html) == "爱快 iKuai · 在线演示", f"取 title，实={page_title(html)!r}")
    text = page_text(html)
    check("演示站点" in text and "手册" in text, "正文含关键词与链接文字")
    check("var x" not in text, "script 内容不计入正文（避免误命中 demo 变量名）")
    links = page_links(html, "demo.ikuai8.com")
    check("/docs/manual.pdf" in links and "/assets/logo.png" in links,
          f"收同域相对链接，实={sorted(links)}")
    check(not any("cdn.other.com" in x for x in links), "站外链接被排除")
    check(len(sitemap_paths(
        "<urlset><url><loc>https://d.com/a/b</loc></url><url><loc>https://d.com/c</loc></url></urlset>"
    )) == 2, "sitemap 解析 loc")
    rules = robots_disallows("User-agent: *\nDisallow: /admin\nDisallow: /private/\n# 注释\nAllow: /")
    check(rules == ["/admin", "/private/"], f"robots 取 Disallow 规则，实={rules}")

    print("\n场景3 分档：强（自动删）/ 中（只提示）/ 弱 / 无")
    ck = PublicResourceChecker(ScanConfig(), verbose=False)

    # 强：站点自己公开链接了这个资源（最硬的证据，资源级）
    v = ck.evaluate(
        ctx("demo.ikuai8.com", root_title="演示站点", links={"/db.sql"}),
        mk("path-backup", "https://demo.ikuai8.com/db.sql"),
    )
    check(v.confidence == "strong" and v.is_public, f"站点自己挂了链接 → 强，实={v.confidence}")
    check(v.auto_dismissible, "强档自动排除")
    check("公开列出了该资源" in v.reason_text(), f"原因写明证据，实={v.reason_text()!r}")

    # 强：自述演示站 + demo 主机名 叠加
    v = ck.evaluate(
        ctx("demo.example.com", root_title="某某系统", body_text="本站为演示环境，数据每日重置"),
        mk("api-missing-auth", "https://demo.example.com/api/v1/users"),
    )
    check(v.score == 3 and v.confidence == "strong",
          f"自述演示站 + demo 主机名 → 强，实={v.score}/{v.confidence}")
    check(v.auto_dismissible, "叠加证据够强，自动排除")

    # 中：只有"自述演示站"这一条 —— **不自动排除**
    # 因为这类措辞在真实产品营销页上随处可见（"请申请演示环境"就命中"演示环境"），
    # 拿它自动删掉整站所有发现是在用误删风险换省事。
    v = ck.evaluate(
        ctx("app.example.com", root_title="某某系统 · 演示环境", body_text="本站为演示环境"),
        mk("sqli", "https://app.example.com/api/order?id=1"),
    )
    check(v.confidence == "suspect" and not v.is_public,
          f"仅自述演示站 → 中档，实={v.confidence}/{v.score}")
    check(not v.auto_dismissible, "**中档不自动排除**（营销页也会命中这类措辞）")

    # 弱：只是路径落在公开目录，证据不足
    v = ck.evaluate(
        ctx("shop.example.com", root_title="某某商城", body_text="欢迎选购"),
        mk("path-firmware", "https://shop.example.com/download/setup.exe"),
    )
    check(v.confidence == "weak" and not v.is_public,
          f"仅公开目录 → 弱档，不判公开，实={v.confidence}/{v.score}")
    check(not v.auto_dismissible, "**弱档不自动排除**（避免删掉真实漏洞）")

    # 无：看不出任何公开特征
    v = ck.evaluate(
        ctx("shop.example.com", root_title="某某商城", body_text="欢迎选购"),
        mk("sqli", "https://shop.example.com/api/order?id=1"),
    )
    check(v.confidence == "none" and not v.is_public, f"无公开特征 → none，实={v.confidence}")
    check("无公开特征" in v.reason_text(), "如实说明未命中")

    # 公开目录 + demo 主机名 = 2 分 → 中（仍不自动排除）
    v = ck.evaluate(
        ctx("demo.example.com", root_title="控制台", body_text="登录"),
        mk("path-firmware", "https://demo.example.com/download/setup.exe"),
    )
    check(v.score == 2 and v.confidence == "suspect",
          f"公开目录 + demo 主机名 → 中档，实={v.score}/{v.confidence}")
    check(not v.auto_dismissible, "2 分档一律不自动排除")

    print("\n场景4 robots 反向证据")
    v_norm = ck.evaluate(
        ctx("demo.example.com", root_title="演示站点", body_text="演示环境"),
        mk("path-x", "https://demo.example.com/download/setup.exe"),
    )
    v_deny = ck.evaluate(
        ctx(
            "demo.example.com", root_title="演示站点", body_text="演示环境",
            robots_denied=["/download"],
        ),
        mk("path-x", "https://demo.example.com/download/setup.exe"),
    )
    check(v_deny.score == v_norm.score - 2,
          f"robots 禁止抓取扣分，实={v_norm.score} → {v_deny.score}")
    v_hard = ck.evaluate(
        ctx("plain.example.com", root_title="x", body_text="y", robots_denied=["/download"]),
        mk("path-x", "https://plain.example.com/download/setup.exe"),
    )
    check(not v_hard.is_public and v_hard.score <= 0,
          f"扣分后不足以判公开，实={v_hard.score}")
    check(v_hard.confidence == "none", "被反向证据压回 none")

    print("\n场景5 抓取失败绝不判成公开")
    v = ck.evaluate(
        ctx("x.example.com", error="根页面抓取失败", root_ok=False),
        mk("p", "https://x.example.com/a"),
    )
    check(not v.is_public and v.confidence == "none", "抓不到根页面 → 不判公开（不误删）")
    check("不判定" in " ".join(v.reasons) or "失败" in " ".join(v.reasons),
          f"如实说明失败原因，实={v.reasons}")
    v = PublicResourceChecker(ScanConfig()).evaluate(
        HostContext(base="", host="", fetched=False), mk("p", "/a")
    )
    check(not v.is_public, "完全没抓取时也不判公开")

    print("\n场景6 真实 HTTP 端到端（本地假演示站）")
    port6, hits6 = serve(demo=True)
    base = f"http://127.0.0.1:{port6}"

    import asyncio

    async def e2e():
        c = PublicResourceChecker(ScanConfig(timeout=5), verbose=True)
        try:
            fs = [mk("path-setup", f"{base}/download/setup.exe"),
                  mk("api-missing-auth", f"{base}/api/v1/users"),
                  mk("path-manual", f"{base}/download/manual.pdf")]
            return await c.check_many(base, fs)
        finally:
            await c.aclose()

    vs = asyncio.run(e2e())
    by = {v.poc_id: v for v in vs}
    check(by["path-setup"].confidence == "strong",
          f"首页链接 + 自述演示站 → 强，实={by['path-setup'].confidence}/{by['path-setup'].score}")
    check(by["path-manual"].confidence == "strong",
          f"sitemap 公开列出 → 强，实={by['path-manual'].confidence}")
    check(by["api-missing-auth"].confidence == "suspect",
          f"仅自述演示站 → 中档（不自动删），实={by['api-missing-auth'].confidence}")
    check(by["path-setup"].is_public and by["path-manual"].is_public
          and not by["api-missing-auth"].is_public,
          "只有资源级证据的两条判为公开")
    check(sorted(hits6) == ["/", "/robots.txt", "/sitemap.xml"],
          f"同一个 host 只回源一次（/ + sitemap + robots），实={sorted(hits6)}")

    print("\n场景7 接入 ToolRunner：三档各自处置正确")
    tmp = Path(tempfile.mkdtemp())
    from core import exclusions

    exclusions.set_store_path(tmp / "exclusions.json")

    # 用**普通站**（首页没有任何演示措辞）跑三档：
    #   linked     → 站点自己挂了链接 → 强 → 自动排除
    #   api        → 什么都没命中   → none → 保持有效
    #   public dir → 只是路径像公开目录 → 弱 → 只提示
    port7, _ = serve(demo=False)
    base2 = f"http://127.0.0.1:{port7}"
    sess2 = Session(target=base2)
    a = mk("path-setup", f"{base2}/download/setup.exe")     # 首页挂了链接 → 强
    b = mk("api-missing-auth", f"{base2}/api/v1/users")     # 无特征 → none
    c_weak = mk("path-old", f"{base2}/download/old.exe")    # 仅公开目录 → 弱
    sess2.result.add_findings([a, b, c_weak])
    out = asyncio.run(
        ToolRunner(FakeCfg(), [], str(tmp)).check_public(sess2, ref="all")
    )

    check("自动排除 1 条" in out, f"只自动排除强档那条，实={out!r}"[:220])
    check("疑似待确认 1 条" in out, f"弱档报为疑似，实={out.splitlines()[-1]!r}")
    check("保持有效 1 条" in out, f"无特征那条保持有效，实={out.splitlines()[-1]!r}")
    check(a.dismissed, "强档被标记为已排除")
    check(b.active and not b.dismissed, "无公开特征的保持有效")
    check(c_weak.active and not c_weak.dismissed, "弱档**没有**被自动排除")
    check(len(sess2.result.active_findings()) == 2, "有效发现剩 2 条")
    check(len(sess2.result.dismissed_findings()) == 1, "已排除 1 条")
    check("站点自己发布的链接" in a.dismiss_reason,
          f"排除原因带资源级证据，实={a.dismiss_reason!r}")
    check(exclusions.is_excluded(base2, a.poc_id, a.matched_at),
          "写进了持久化排除清单（重扫不再报出）")
    check(not exclusions.is_excluded(base2, c_weak.poc_id, c_weak.matched_at),
          "弱档没有写进排除清单")

    from output.report import write_markdown

    md = write_markdown(sess2.result, tmp).read_text(encoding="utf-8")
    check("已排除的发现（误报复核）" in md, "报告带复核附录")
    check("自动判定为公开资源" in md, "附录里写明是自动判定 + 证据")
    check("| 有效发现 | 2 条 |" in md, "有效发现数正确（弱档仍计入有效）")
    detail = md.split("## 渗透测试结果")[1].split("## 已排除")[0]
    check("path-old" in detail and "api-missing-auth" in detail,
          "弱档与无特征项仍在「发现详情」里")
    check("path-setup" not in detail, "已排除项不在「发现详情」里")
    appendix = md.split("## 已排除的发现")[1]
    check("path-setup" in appendix, "已排除项出现在复核附录里")

    print("\n场景8 apply=false 只报告不改动")
    port8, _ = serve(demo=False)
    base3 = f"http://127.0.0.1:{port8}"
    s3 = Session(target=base3)
    x = mk("path-setup", f"{base3}/download/setup.exe")
    s3.result.add_findings([x])
    out3 = asyncio.run(
        ToolRunner(FakeCfg(), [], str(tmp)).check_public(s3, ref="all", apply=False)
    )
    check("建议排除" in out3, f"只报告不改动，实={out3!r}"[:200])
    check(not x.dismissed and len(s3.result.active_findings()) == 1, "发现未被改动")

    print("\n场景9 工具注册与配置开关")
    names = [b.name for b in BUILTINS]
    check("check_public_finding" in names, "工具已注册")
    spec = [b for b in BUILTINS if b.name == "check_public_finding"][0]
    check("ref" in (spec.params.get("required") or []), "ref 必填")
    check("apply" in spec.params["properties"], "有 apply 开关")
    check(spec.group == "报告", f"归到报告组，实={spec.group}")
    sc = ScanConfig()
    check(getattr(sc, "auto_dismiss_public", None) is True, "配置项默认开")

    src = module_source("core.scheduler")
    check("_phase5b_public_check" in src and "await self._phase5b_public_check(" in src,
          "扫描流水线接上了公开性核验")
    check("auto_dismiss_public" in src, "核验受配置开关控制")
    rsrc = module_source("core.repl")
    check("/fp" not in rsrc, "REPL 不再有 /fp（误报排除统一走 Agent 工具）")
    trsrc = module_source("core.tools.runner.report")
    check("def check_public(" in trsrc, "公开性核验仍只有 ToolRunner.check_public 一处实现")
    check("apply" in trsrc, "check_public 保留 apply 开关（只报告不改动）")
    fsrc = cli_source()
    check("--auto" in fsrc, "CLI 有 --auto")

    print(f"\n{ok}/{total} 通过")
    for s in _SERVERS:
        try:
            s.shutdown()
            s.server_close()
        except Exception:  # noqa: BLE001
            pass
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
