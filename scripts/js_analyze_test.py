"""JS 静态分析提取测试（进程内起本地 HTTP 服务，不触外网）。

覆盖的是「为什么工具只挖出 5 个接口」那三个根因，以及放宽后的边界：

  1. 路径判别：业务前缀白名单已去掉，/role/getAll 这类能进；静态资源、MIME、
     日期目录、hash 路由、模块相对引用要挡住
  2. 压缩形态：o("monitor/online/query",t) 这种别名 + 无前导斜杠的调用
  3. baseURL 拼接：相对路径要还原成可直接访问的 /api/... 形态
  4. 模块图：import/from/import()/require 的相对边要跟进，裸模块名不收
  5. 端到端：懒加载 chunk（*-api-*.js）真的被下载并提取
  6. 抓取上限：JS 不再吃 4KB 的 max_body_capture

运行：.venv/Scripts/python.exe scripts/js_analyze_test.py
"""

from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.js_analyze import (  # noqa: E402
    JsAnalyzer,
    extract_base_url,
    extract_endpoints,
)
from core.config_loader import ScanConfig  # noqa: E402
from detectors.js_logic import JsLogicDetector, JsSource  # noqa: E402
from scripts._srcs import module_source  # noqa: E402


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # ── 场景 1：路径判别 ─────────────────────────────────────────
    print("场景1 路径判别（前缀白名单已去掉，结构判别兜底）")
    js = r"""
    var a = "/role/getAll";
    var b = "/oa/noticeType/getAll";
    var c = "/monitor/log/query";
    var d = "/e/aspx/get_info.aspx";
    var e = "/static/img/logo.png";
    var f = "/assets/app.js";
    var g = "/2024/10/13";
    var h = "/api";
    var i = "/a1b2c3d4e5f6a7b8";
    """
    eps = extract_endpoints(js)
    check("/role/getAll" in eps, "/role/getAll 被收录（白名单时代挖不到）")
    check("/oa/noticeType/getAll" in eps, "/oa/noticeType/getAll 被收录")
    check("/monitor/log/query" in eps, "/monitor/log/query 被收录")
    check("/e/aspx/get_info.aspx" in eps, ".aspx 不算静态资源，要收")
    check("/static/img/logo.png" not in eps, ".png 被挡")
    check("/assets/app.js" not in eps, ".js 被挡")
    check("/2024/10/13" not in eps, "纯日期目录被挡（无字母）")
    check("/api" in eps, "单段短路径 /api 允许（合法接口形态）")
    check("/a1b2c3d4e5f6a7b8" not in eps, "hash 路由被挡（全 16 进制段）")

    js2 = 'x("/static/font/icon")'
    check("/static/font/icon" in extract_endpoints(js2), "无后缀的静态目录仍收（宁可多收）")

    long_path = "/" + "a" * 130
    check(extract_endpoints(f'"{long_path}"') == [], "超长路径被挡（>120）")

    # ── 场景 2：压缩别名调用 ─────────────────────────────────────
    print("\n场景2 压缩形态（o(\"path\",t) 这类别名调用）")
    packed = 'o("monitor/online/query",t);o("role/list",e);'
    eps = extract_endpoints(packed, "/api")
    check("/api/monitor/online/query" in eps, "别名调用 + baseURL 拼成完整路径")
    check("/api/role/list" in eps, "第二个别名调用同样收")
    check(
        extract_endpoints('o("login",t)', "/api") == [],
        "相对单段不收（o(\"login\") 太容易撞变量名）",
    )
    check(
        'text/plain' not in "".join(extract_endpoints('t("text/plain")')),
        "MIME 类型不被当路径",
    )
    check(
        extract_endpoints('o("a/b",t)') == ["/a/b"],
        "无 baseURL 时退化为 /a/b（不猜前缀）",
    )

    # ── 场景 3：baseURL ─────────────────────────────────────────
    print("\n场景3 baseURL 提取")
    check(extract_base_url('{baseURL:"/api"}') == "/api", 'baseURL:"/api" 取出 /api')
    check(
        extract_base_url('baseURL = "https://api.x.com/v2"') == "/v2",
        "完整 URL 的 base 只取 path（不跨域拼 host）",
    )
    check(extract_base_url('const x = 1') == "", "没有 baseURL 返回空串")
    check(extract_base_url('baseURL:"${BASE}"') == "", "模板占位符不当 base")

    # ── 场景 4：import 上下文排除 ────────────────────────────────
    print("\n场景4 import 语句里的字符串不算接口")
    imp = 'import a from"./chunk/vendor.js";const r=require("../utils/index.js");'
    check(extract_endpoints(imp) == [], "import/require 的相对引用全部排除")
    check(
        extract_endpoints('import e from "./api/user"') == [],
        "无 .js 后缀的 import 也不当接口",
    )

    # ── 场景 5：模块图的边 ──────────────────────────────────────
    print("\n场景5 模块图：import 边解析")
    ja = JsAnalyzer(ScanConfig())
    base_url = "https://t.edu.cn/static/js/app.js"
    edges = ja.import_edges(
        'import x from "./chunk/role.js";'
        'import("./chunk/monitor-api.js");'
        'const y = require("./util.js");'
        'import "https://cdn.x.com/lib.js";'
        'import v from "vue";'
        'import "./style.css";',
        base_url,
    )
    check("https://t.edu.cn/static/js/chunk/role.js" in edges, "from 相对边解析成绝对 URL")
    check(
        "https://t.edu.cn/static/js/chunk/monitor-api.js" in edges,
        "动态 import() 也被跟进（懒加载 chunk 的关键）",
    )
    check("https://t.edu.cn/static/js/util.js" in edges, "require 边被跟进")
    check("https://cdn.x.com/lib.js" in edges, "跨域脚本边保留")
    check(not any("vue" in e for e in edges), "裸模块名 vue 不收")
    check(not any(".css" in e for e in edges), "非脚本文件不收")
    check(len(edges) == len(set(edges)), "边已去重")

    # 打包器 chunk 清单：不是 import 语句，而是一个纯字符串数组
    vite = 'x=["js/vue-router-a1.js","js/monitor-api-390a.js","css/index-b2.css"]'
    v_edges = ja.import_edges(vite, "https://t.edu.cn/cas-admin/js/index.js")
    check(
        "https://t.edu.cn/cas-admin/js/monitor-api-390a.js" in v_edges,
        "chunk 清单数组里的 monitor-api 被跟进（Vite 形态）",
    )
    check(
        "https://t.edu.cn/cas-admin/js/vue-router-a1.js" in v_edges,
        "清单里的其它 chunk 也收",
    )
    check(not any(".css" in e for e in v_edges), "清单里的 css 不跟")
    check(
        JsAnalyzer.resolve_ref("js/x.js", "https://h/cas-admin/js/index.js")
        == "https://h/cas-admin/js/x.js",
        "裸相对路径按入口父目录解析（否则会变成 /js/js/x.js）",
    )
    check(
        JsAnalyzer.resolve_ref("chunk/x.js", "https://h/static/js/app.js")
        == "https://h/static/js/chunk/x.js",
        "首段与当前目录名不匹配时退回 urljoin",
    )

    # ── 场景 6：抓取上限 ────────────────────────────────────────
    print("\n场景6 上限放宽（4KB 截断是只挖到 5 个接口的头号原因）")
    cfg = ScanConfig()
    check(cfg.js_max_bytes >= 1_000_000, f"js_max_bytes={cfg.js_max_bytes} ≥ 1MB")
    check(cfg.max_body_capture == 4096, "max_body_capture 保持 4KB（那是报告用的，不影响 JS）")
    check(cfg.js_max_files >= 50, f"js_max_files={cfg.js_max_files} ≥ 50（原 12）")
    check(cfg.js_logic_max_endpoints >= 50, f"js_logic_max_endpoints={cfg.js_logic_max_endpoints} ≥ 50（原 25）")
    check(cfg.js_max_depth >= 1, f"js_max_depth={cfg.js_max_depth} ≥ 1（要跟进一层 import）")

    src = module_source("collectors.js_analyze")
    check("capture_limit=cap" in src, "JS 抓取显式传 capture_limit")
    check(
        "capture_limit" in module_source("detectors.base"),
        "send_request 支持 capture_limit 覆盖",
    )
    ep_block = src.split("_ENDPOINT_RE", 1)[1][:260] if "_ENDPOINT_RE" in src else ""
    check(
        "api|" not in ep_block and "rest|service" not in ep_block,
        "_ENDPOINT_RE 里没有 api|/rest|/service 这类业务词白名单",
    )

    # ── 场景 7：端到端（本地服务，验证 chunk 真的被下） ──────────
    print("\n场景7 端到端：懒加载 chunk 必须被下载")

    HTML = (
        "<html><head>"
        '<script src="/static/js/app.js"></script>'
        "</head><body>hi</body></html>"
    )
    APP_JS = (
        'const http={baseURL:"/api"};'
        'import("./chunk/monitor-api-9f.js");'
        'o("monitor/online/query",t);'
        + "/*pad*/" + "A" * 8000 + ";"
        'var home="/home/index";'
    )
    CHUNK_JS = (
        'n("/role/getAll");n("/oa/noticeType/getAll");'
        'n("/monitor/log/query");'
    )

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # 静音
            pass

        def do_GET(self):
            body = {"/": HTML, "/static/js/app.js": APP_JS,
                    "/static/js/chunk/monitor-api-9f.js": CHUNK_JS}.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript" if self.path.endswith(".js") else "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    try:
        cfg2 = ScanConfig()
        ja2 = JsAnalyzer(cfg2)
        assets = asyncio.run(ja2.run(f"http://127.0.0.1:{port}", verbose=False))
        asyncio.run(ja2.aclose())
        vals = {a.value for a in assets if a.kind == "endpoint"}
        print(f"        提取到：{sorted(vals)}")
        check("/home/index" in vals, "首页 bundle 里的接口提取到")
        check("/api/monitor/online/query" in vals, "压缩别名 + baseURL 拼接正确（端到端）")
        check("/role/getAll" in vals, "import 进来的 chunk 里的接口提取到（核心回归）")
        check("/oa/noticeType/getAll" in vals, "chunk 内第二条接口也在")
        check("/monitor/log/query" in vals, "chunk 内第三条接口也在")
        check(len(vals) >= 5, f"总计 ≥5 个接口（实际 {len(vals)}）")

        # 4KB 截断回归：APP_JS 的接口在 8000 字符 padding 之后
        check(len(APP_JS) > 4096, f"测试样本 {len(APP_JS)} 字符 > 4KB（确保测的是截断修复）")
        check("/home/index" in vals, "4KB 之后的接口仍被提取（证明没用 max_body_capture）")

        # js_logic 的 endpoints 走同一套提取
        det = JsLogicDetector(cfg2)
        got = det.endpoints([JsSource("(inline)", CHUNK_JS)])
        check(("/role/getAll", "(inline)") in got, "js_logic.endpoints 复用同一提取器")
        check(
            any(p.startswith("/oa/") for p, _ in got),
            "js_logic 也能挖到 oa 模块接口",
        )
        asyncio.run(det.aclose())
    finally:
        srv.shutdown()

    # ── 场景 8：排序（放宽后噪声会盖住真接口） ──────────────────
    print("\n场景8 接口排序：噪声沉底，真接口在前")
    from detectors.js_logic import ep_rank

    ranked = sorted(
        ["/gi", "/tzgg", "/e/aspx/get_info.aspx", "/collection/StuInfoSupply/download"],
        key=ep_rank,
    )
    print(f"        排序后：{ranked}")
    check(
        ranked[-1] in ("/gi", "/tzgg"),
        f"单段导航目录排最后（实际 {ranked[-1]}）",
    )
    check(
        ranked[0].startswith("/collection/") or "aspx" in ranked[0],
        f"多段真接口排最前（实际 {ranked[0]}）",
    )
    check(
        ep_rank("/admin/user/list")[0] == 0 and ep_rank("/tzgg")[0] == 1,
        "后台类路径拿 0 权重（优先探测）",
    )

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
