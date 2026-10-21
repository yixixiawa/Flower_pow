"""会话命名与报告命名的测试。

三件用户抱怨过的事，都是"名字读不出来"的问题：
1. 会话目录是纯数字时间戳 → 看不出是哪次对话
2. 报告名是 report_<完整URL>_<unix时间戳> → 太长，认不出是谁
3. 报告名是 report_<完整主机>_<日期> → 子域没信息量、日期排在后面不好扫

现在的格式是 ``report_<日期>_<主域名>``，如 ``report_20261012_ftitle.studio.md``：
先按时间扫一眼就能定位，同一主域的 www/api/m 归到同一份报告。

运行：.venv/Scripts/python.exe scripts/test_naming.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.session import Session, list_sessions  # noqa: E402
from core.state import ScanResult  # noqa: E402
from output.report import (  # noqa: E402
    _report_stem,
    _unique_path,
    registrable_domain,
    target_domain,
    target_host,
    write_markdown,
)


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # ── 场景1 报告名 = report_日期_主域名 ────────────────────────
    print("场景1 报告文件名 report_<日期>_<主域名>")
    now = time.time()
    day = time.strftime("%Y%m%d", time.localtime(now))
    r = ScanResult(target="https://ftitle.studio", started_at=now)
    stem = _report_stem(r)
    check(stem == f"report_{day}_ftitle.studio",
          f"完整形如 report_日期_主域名，实={stem!r}")
    check(stem.startswith(f"report_{day}_"), "日期排在域名前面（先按时间定位）")
    check("http" not in stem, "不带协议前缀")

    # 同一站点不同路径 → 同一个文件名（不会散成好几份）
    r2 = ScanResult(target="https://ftitle.studio/api/v1/user/uploads", started_at=now)
    check(_report_stem(r2) == stem, "同域名不同路径 → 同一个报告名")

    # ── 场景2 主域名：去掉子域 ───────────────────────────────────
    print("\n场景2 主域名取可注册域名（去掉子域）")
    check(target_domain("https://www.ftitle.studio") == "ftitle.studio",
          f"www 前缀被去掉，实={target_domain('https://www.ftitle.studio')!r}")
    check(target_domain("https://api.ftitle.studio/x") == "ftitle.studio", "api 同上")
    check(target_domain("https://a.b.c.example.com") == "example.com", "多层子域也裁掉")
    check(target_domain("https://demo.ikuai8.com") == "ikuai8.com", "demo.ikuai8.com → ikuai8.com")
    check(registrable_domain("a.b.co.uk") == "b.co.uk",
          "两级公共后缀保留三段（co.uk 不能当主域名）")
    check(registrable_domain("example.co.uk") == "example.co.uk", "co.uk 下的正常域名不动")
    check(registrable_domain("192.168.1.10") == "192.168.1.10", "IPv4 原样")
    check(registrable_domain("localhost") == "localhost", "单段主机名原样")
    check(target_host("https://www.ftitle.studio") == "www.ftitle.studio",
          "target_host 仍返回完整主机（正文/区分端口用）")

    # 带端口的要区分（是两台不同服务）
    r3 = ScanResult(target="http://aigc-api.mzdc.net:8443", started_at=now)
    check("8443" in _report_stem(r3), f"端口保留用于区分，实={_report_stem(r3)!r}")

    # Windows 非法字符必须清掉，否则文件写不出来
    r4 = ScanResult(target="http://x.test:8080/a/b?c=1", started_at=now)
    bad = set('<>:"/\\|?*')
    check(not (bad & set(_report_stem(r4))),
          f"不包含 Windows 非法字符，实={_report_stem(r4)!r}")

    check(_report_stem(ScanResult(target="", started_at=now)).startswith("report_"),
          "空目标有兜底名，不会生成裸 'report_.md'")
    check("target" in _report_stem(ScanResult(target="", started_at=now)),
          f"空目标兜底用 target，实={_report_stem(ScanResult(target='', started_at=now))!r}")

    # ── 场景3 同名不同目标：加子域后缀，不静默合并 ────────────────
    print("\n场景3 主域名撞车时区分开（不能把两份报告合并成一份）")
    d0 = Path(tempfile.mkdtemp())
    ra = ScanResult(target="https://www.ftitle.studio", started_at=now)
    rb = ScanResult(target="https://api.ftitle.studio", started_at=now)
    pa = write_markdown(ra, d0)
    check(pa.name == f"report_{day}_ftitle.studio.md",
          f"先来的用主名，实={pa.name}")
    pb = write_markdown(rb, d0)
    check(pb != pa, f"另一个子站不写进同一个文件，实={pb.name}")
    check(pb.name == f"report_{day}_ftitle.studio_api.md",
          f"加子域后缀区分，实={pb.name}")
    check(pa.exists() and "www.ftitle.studio" in pa.read_text(encoding="utf-8"),
          "上一份报告没被覆盖")
    # 同一个目标重复导出仍写回自己那份
    pa2 = write_markdown(ra, d0)
    check(pa2 == pa, f"同一目标重复导出写回原文件，实={pa2.name}")
    check(_report_stem(ra, d0) == f"report_{day}_ftitle.studio",
          "归属一致时不做多余的后缀")
    check(_report_stem(rb, d0) == f"report_{day}_ftitle.studio_api",
          "归属冲突的判断是稳定的（第二次仍得到同一个后缀）")

    # ── 场景4 同名不覆盖（overwrite=False 的旧行为仍在）──────────
    print("\n场景4 overwrite=false 时仍不覆盖上一份")
    d = Path(tempfile.mkdtemp())
    p1 = _unique_path(d, stem, ".md")
    check(p1.name == f"{stem}.md", f"第一次直接用主名，实={p1.name}")
    p1.write_text("first")
    p2 = _unique_path(d, stem, ".md")
    check(p2.name == f"{stem}_2.md", f"第二次加序号，实={p2.name}")
    p2.write_text("second")
    check(p1.read_text() == "first", "上一份内容没被覆盖（改完再验一遍是常态）")
    p3 = _unique_path(d, stem, ".md")
    check(p3.name == f"{stem}_3.md", f"第三次继续递增，实={p3.name}")

    # 三种格式共用同一个 stem → 报告与 JSON 能对上号
    check(_unique_path(d, stem, ".json").name == f"{stem}.json",
          "json 与 md 共用 stem（便于对号入座）")

    # ── 场景5 会话目录名 = 日期_首轮标题 ─────────────────────────
    print("\n场景5 会话目录名用第一轮对话标题（不再是一串数字）")
    s = Session(target="http://aigc-api.mzdc.net")
    s.add_conversation("测 aigc 接口越权", ["http_probe"])
    s.add_conversation("出报告", ["record_finding"])
    check(s.display_title == "测 aigc 接口越权",
          f"标题取**第一轮**（第一句才是'要测什么'），实={s.display_title!r}")
    check(s.slug.startswith(time.strftime("%Y%m%d") + "_"),
          f"slug 以日期开头（字典序==时间序），实={s.slug!r}")
    check("测" in s.slug and "aigc" in s.slug, f"slug 含标题，实={s.slug!r}")
    check(not s.slug.split("_", 1)[1].isdigit(), "slug 不是纯数字")

    # 落盘后目录名就是 slug，session_id 同步为目录名
    base = Path(tempfile.mkdtemp())
    f = s.save(base)
    check(f.parent.name == s.slug, f"目录名 = slug，实={f.parent.name!r}")
    check(s.session_id == f.parent.name, "session_id 与目录名一致（/resume 才能对得上）")

    # ── 场景6 目录名稳定：追加对话后不改名 ───────────────────────
    print("\n场景6 已经存过的会话不再改名（否则旧路径失效）")
    s.add_conversation("深挖 OSS 写权限", ["record_finding"])
    f2 = s.save(base)
    check(f2.parent.name == f.parent.name,
          f"追加一轮后目录名不变，实={f2.parent.name!r}")
    check(s.display_title == "测 aigc 接口越权",
          "首轮标题仍作为会话名（不因后续发言而漂移）")

    # ── 场景7 无标题时给出可用兜底 ───────────────────────────────
    print("\n场景7 兜底与容错")
    s2 = Session(target="http://x.test")
    check(s2.display_title == "http://x.test",
          f"没有对话时退回目标，实={s2.display_title!r}")
    s3 = Session(target="")
    check(s3.display_title == s3.session_id, "连目标都没有时退回 id，不返回空串")

    # 标题里的非法字符不能进目录名
    s4 = Session(target="http://x.test")
    s4.add_conversation('测 a/b:c?d*e"f<g>h|i')
    check(not (set('<>:"/\\|?*') & set(s4.slug)),
          f"标题里的非法字符已清洗，实={s4.slug!r}")

    # 超长标题必须截断（Windows 路径长度限制）
    s5 = Session(target="http://x.test")
    s5.add_conversation("测" * 200)
    check(len(s5.slug) <= 60, f"超长标题被截断，实长={len(s5.slug)}")

    # ── 场景8 list_sessions 返回可读名 ───────────────────────────
    print("\n场景8 /sessions 与 /resume 拿到的是可读名")
    s6 = Session(target="http://aigc-api.mzdc.net")
    s6.add_conversation("OSS 写权限复现", [])
    base2 = Path(tempfile.mkdtemp())
    s6.save(base2)
    items = list_sessions(base2)
    check(len(items) == 1, f"列出 1 条，实={len(items)}")
    name, loaded = items[0]
    check("OSS" in name, f"返回的 name 含标题关键词，实={name!r}")
    check(loaded.display_title == "OSS 写权限复现", "载入后标题仍可读")

    # 旧格式（纯数字目录）仍能加载，不会被新命名规则排除
    legacy = base2 / "1789000000"
    legacy.mkdir()
    (legacy / "session.json").write_text(
        '{"version": 2, "target": "http://old.test", "session_id": "1789000000"}',
        encoding="utf-8",
    )
    names = [n for n, _s in list_sessions(base2)]
    check("1789000000" in names, f"旧数字目录仍可列出（兼容），实={names}")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
