"""全自动模式 / SQL 注入改版 / 上传人工审核 的测试。

覆盖三件本次改动的事，都是**逻辑**而非网络，所以全程用假请求：

1. SQL 注入：放行全部规则 + 两轮制 + 拿到版本号或库名就停
2. 文件上传：无审核通道 / 拒绝 / 放行 三种路径下请求到底发没发
3. Alt+Shift 与 ``/auto``：热键哨兵、命令注册、确认取消与确认执行的分支

运行：python scripts/test_autopilot.py
"""

from __future__ import annotations

import asyncio
import builtins
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import ScanConfig  # noqa: E402
from core.session import Session  # noqa: E402
from core.state import (  # noqa: E402
    Asset,
    Category,
    Evidence,
    Fingerprint,
    Finding,
    ScanResult,
    Severity,
)
from detectors.exploit import (  # noqa: E402
    _SQL_NAME_PAYLOADS,
    _SQL_UNION_COLS,
    _SQL_UNION_NAME,
    _SQL_UNION_VERSION,
    _SQL_VERSION_PAYLOADS,
    ExploitProbeDetector,
    Op,
)


class FakeDet(ExploitProbeDetector):
    """把 HTTP 换成「按序号吐预设响应」的假检测器。"""

    def __init__(self, cfg, bodies, **kw) -> None:
        super().__init__(cfg, **kw)
        self._bodies = bodies
        self.sent: list[str] = []

    async def send_request(self, url, poc=None, method="GET", headers=None, body=""):
        i = len(self.sent)
        self.sent.append(url)
        b = self._bodies(i) if callable(self._bodies) else (
            self._bodies[i] if i < len(self._bodies) else ""
        )
        ev = Evidence(url=url, method=method)
        ev.status_code = 200
        ev.body_excerpt = b
        return ev


def version_body(det: ExploitProbeDetector, ver: str = "8.0.32") -> str:
    """UNION 回显：值被本轮唯一标记夹住。"""
    return f"<html>id: {det.tag}{ver}{det.tag}</html>"


def name_body(det: ExploitProbeDetector, name: str = "shop_db") -> str:
    return f"<html>id: {det.tag}{name}{det.tag}</html>"


async def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    base = "http://t.test"
    ops3 = [
        Op(method="GET", path="/api/item", params=["id"]),
        Op(method="GET", path="/api/user", params=["uid"]),
        Op(method="GET", path="/api/order", params=["no"]),
    ]

    # ── 场景1 规则已全部放行 ─────────────────────────────────────
    print("场景1 SQL 注入：放行全部规则（不再只取 3 条）")
    cfg = ScanConfig()
    det = FakeDet(cfg, [])
    plan = det.sqli_plan()
    expect_n = (
        len(_SQL_VERSION_PAYLOADS)
        + len(_SQL_UNION_VERSION) * len(_SQL_UNION_COLS)
        + len(_SQL_NAME_PAYLOADS)
        + len(_SQL_UNION_NAME) * len(_SQL_UNION_COLS)
    )
    check(len(plan) == expect_n, f"计划条目数 = 全规则数 {expect_n}", f"实={len(plan)}")
    goals = [g for g, _d, _p in plan]
    check(goals[0] == "version", "第一个目标是版本号")
    check(goals.index("name") == goals.count("version"),
          "版本号条目全部排在库名（底线）之前", f"实={goals}")
    check(len(det.sql_payloads(0)) == len(_SQL_VERSION_PAYLOADS),
          "sql_payloads 返回全集而非按序号切片")
    check(any("UNION ALL SELECT" in p for _g, _d, p in plan), "UNION 回显规则已放行")
    check(any("DATABASE()" in p or "DB_NAME()" in p or "current_database()" in p
              for _g, _d, p in plan), "底线（库名）规则已放行")
    check(not any("information_schema" in p.lower() for _g, _d, p in plan),
          "不再拖库：计划里没有 information_schema 类 payload")

    # ── 场景2 第 1 轮就拿到版本号 → 立刻停 ───────────────────────
    print("\n场景2 拿到版本号即停（不再进行下一步）")
    det = FakeDet(cfg, lambda i: version_body(det))
    fs = await det._sweep_sqli(base, ops3)
    check(det.sqli_goal is not None and det.sqli_goal[0] == "version",
          "取到版本号", f"实={det.sqli_goal}")
    check(det.sqli_goal[2] == "8.0.32", "取值正确", f"实={det.sqli_goal}")
    check(len(fs) == 1, "只生成 1 条发现", f"实={len(fs)}")
    check(fs and fs[0].severity == Severity.CRITICAL, "版本号 → CRITICAL")
    check(fs and "sqli" in fs[0].tags and "version" in fs[0].tags, "带上 sqli/version 标签")
    n1 = len(det.sent)
    check(n1 <= len(ops3), f"第 1 轮命中后不再打第 2 轮（请求 {n1} ≤ 接口数 {len(ops3)}）",
          f"实={n1}")
    fs2 = await det._sweep_sqli(base, ops3)
    check(len(det.sent) == n1 and fs2 == [],
          "再次调用时一个请求都不发（拿到就停是持久状态）", f"实={len(det.sent) - n1} 次新增")

    # ── 场景3 取不到版本号 → 退到底线库名 ────────────────────────
    print("\n场景3 只有库名时退到底线（HIGH）")
    det = FakeDet(cfg, lambda i: name_body(det))
    fs = await det._sweep_sqli(base, ops3)
    check(det.sqli_goal is not None and det.sqli_goal[0] == "name",
          "退到库名", f"实={det.sqli_goal}")
    check(det.sqli_goal[2] == "shop_db", "库名取值正确", f"实={det.sqli_goal}")
    check(len(fs) == 1 and fs[0].severity == Severity.HIGH, "库名 → HIGH（不是 CRITICAL）")
    check(fs and fs[0].poc_id == "sqli-dbname", "poc_id 走库名档", f"实={fs[0].poc_id if fs else ''}")

    # ── 场景4 报错回显型（无 UNION 标记）────────────────────────
    print("\n场景4 报错回显也能取到版本号")
    det = FakeDet(
        cfg,
        lambda i: (
            "SQLSTATE[HY000]: You have an error in your SQL syntax; "
            "MySQL server version 5.7.42-log" if i == 0 else ""
        ),
    )
    fs = await det._sweep_sqli(base, ops3)
    check(det.sqli_goal is not None and det.sqli_goal[0] == "version",
          "从报错里读出版本号", f"实={det.sqli_goal}")

    # ── 场景5 什么都没取到 → 不留假阳性 ──────────────────────────
    print("\n场景5 全规则打完仍无值 → 不生成发现")
    det = FakeDet(cfg, lambda i: "<html>ok</html>")
    fs = await det._sweep_sqli(base, ops3)
    check(fs == [], "没有发现", f"实={len(fs)}")
    check(det.sqli_goal is None, "未取得任何目标值")
    check(len(det.sent) <= len(ops3), "无候选点时不会放大请求量（第 2 轮不启动）",
          f"实={len(det.sent)}")

    # ── 场景6 只报 SQL 报错特征 → 疑似但不登记 ──────────────────
    print("\n场景6 只有报错特征 → 疑似点，登记进 notes 而非 findings")
    det = FakeDet(
        cfg,
        lambda i: (
            "You have an error in your SQL syntax near ''" if i == 0
            else "<html>nothing</html>"
        ),
    )
    fs = await det._sweep_sqli(base, ops3)
    check(fs == [], "不生成发现（避免把报错当注入）", f"实={len(fs)}")
    check(any("疑似注入点" in n for n in det.notes),
          "notes 里说明是疑似", f"实={det.notes}")

    # ── 场景7 上传：没有审核通道 → 一个请求都不发 ────────────────
    print("\n场景7 文件上传 · 无人工审核通道")
    cfg_u = ScanConfig(file_upload_probe_enabled=True, upload_require_approval=True)
    up_ops = [Op(method="POST", path="/api/upload", body_fields=["file"])]
    det = FakeDet(cfg_u, lambda i: "ok", approver=None)
    fs = await det.probe_upload(base, up_ops)
    check(fs == [], "无通道时不出发现")
    check(len(det.sent) == 0, "一个上传请求都没发", f"实={len(det.sent)}")
    check(any("没有人工审核通道" in n for n in det.notes),
          "notes 说明跳过原因", f"实={det.notes}")
    check(det.stats["upload"]["skipped"] == len(up_ops), "统计记为 skipped")

    # ── 场景8 上传：人工拒绝 → 不发 ──────────────────────────────
    print("\n场景8 文件上传 · 人工拒绝")
    seen_desc: list[str] = []

    async def deny(desc: str) -> bool:
        seen_desc.append(desc)
        return False

    det = FakeDet(cfg_u, lambda i: "ok", approver=deny)
    fs = await det.probe_upload(base, up_ops)
    check(fs == [] and len(det.sent) == 0, "拒绝后不发请求", f"实={len(det.sent)}")
    check(len(seen_desc) == 1, "每个接口都问了一次", f"实={len(seen_desc)}")
    d0 = seen_desc[0] if seen_desc else ""
    check("上传" in d0 and "fp_" in d0, "审核文案写明了动作与文件名", d0[:80])
    check("手工清理" in d0, "审核文案提醒了会留下文件", d0[:80])
    check(any("拒绝" in n for n in det.notes), "notes 记录了拒绝")

    # ── 场景9 上传：人工放行 → 只发一次 ──────────────────────────
    print("\n场景9 文件上传 · 人工放行")
    async def allow(desc: str) -> bool:
        return True

    det = FakeDet(cfg_u, lambda i: "ok", approver=allow)
    fs = await det.probe_upload(base, up_ops)
    check(len(det.sent) == 1, "放行后发了 1 次上传", f"实={len(det.sent)}")
    check(det.stats["upload"]["attempted"] == 1, "统计记为 attempted")

    # ── 场景10 审核通道抛异常 → 按拒绝处理 ───────────────────────
    print("\n场景10 审核通道异常 → 按拒绝处理（fail closed）")
    async def boom(desc: str) -> bool:
        raise RuntimeError("input closed")

    det = FakeDet(cfg_u, lambda i: "ok", approver=boom)
    fs = await det.probe_upload(base, up_ops)
    check(len(det.sent) == 0, "异常时不发请求", f"实={len(det.sent)}")
    check(any("审核通道异常" in n for n in det.notes), "notes 记录了异常", f"实={det.notes}")

    # ── 场景11 开关关掉 → 上传仍被禁 ─────────────────────────────
    print("\n场景11 file_upload_probe_enabled=false 时仍不上传")
    cfg_off = ScanConfig(file_upload_probe_enabled=False, upload_require_approval=True)
    det = FakeDet(cfg_off, lambda i: "ok", approver=allow)
    fs = await det.probe_upload(base, up_ops)
    check(fs == [] and len(det.sent) == 0, "开关关闭时不发请求")

    # ── 场景12 Alt+Shift 哨兵 ────────────────────────────────────
    print("\n场景12 Alt+Shift 热键哨兵")
    from core.completer import HOTKEY_FULL_AUTO

    check(HOTKEY_FULL_AUTO == "\x00__full_auto__", "哨兵值固定")
    check("\x00" in HOTKEY_FULL_AUTO, "含 NUL：键盘不可能产生，不会和真实输入混淆")
    check(HOTKEY_FULL_AUTO.strip() != "", "strip 后仍非空（不会被空输入分支吃掉）")

    # ── 场景13 /auto 命令已注册 ──────────────────────────────────
    print("\n场景13 /auto 命令注册")
    from core.repl import AUTO_WARN, COMMANDS, HELP, Repl

    check("/auto" in COMMANDS, "/auto 在补全候选里")
    check("/auto" in HELP, "/auto 在 /help 文本里")
    check("Alt+Shift" in HELP, "/help 写明了热键")
    for kw in ("SQL 注入", "放行全部规则", "版本号", "数据库名", "手工清理"):
        check(kw in AUTO_WARN, f"警告内容写明了：{kw}")

    # ── 场景14 _autopilot 的分支 ─────────────────────────────────
    print("\n场景14 全自动执行分支")
    tmp = Path(tempfile.mkdtemp())

    class Cfg:
        output_dir = str(tmp)
        data_dir = str(tmp)

        class scan:
            readonly = False
            timeout = 5
            concurrency = 2

        class llm:
            enabled = False
            api_key = ""
            model = "x"
            base_url = "http://x"
            deep_model = ""
            model_warnings: list = []

        class rag:
            poc_dir = "./poc"

    sess = Session(target="http://t.test")
    repl = Repl(Cfg(), sess, agent=False, probes=[])

    # 14a 没有目标 → 直接返回
    repl.session.target = ""
    real_input = builtins.input
    builtins.input = lambda *a, **k: "y"
    try:
        calls = []
        await repl._autopilot()
        check(True, "无目标时安全返回（不询问、不发请求）")
    finally:
        builtins.input = real_input

    # 14b 回答 n → 取消，Scheduler 不构造
    repl.session.target = "http://t.test"
    built = []
    fake = types.ModuleType("core.scheduler")

    class FakeSched:
        def __init__(self, cfg, approver=None):
            built.append(approver)

        async def scan(self, target, verbose=True):
            r = ScanResult(target=target)
            r.assets = [Asset(kind="api", value="/api/item")]
            r.findings = [
                Finding(poc_id="p1", name="X", severity=Severity.LOW,
                        category=Category.INJECTION, matched_at=target)
            ]
            r.fingerprints = [Fingerprint(target=target, tech=["nginx"])]
            r.notes = ["note1"]
            return r

    fake.Scheduler = FakeSched
    had = sys.modules.get("core.scheduler")
    sys.modules["core.scheduler"] = fake
    try:
        builtins.input = lambda *a, **k: "n"
        await repl._autopilot()
        check(built == [], "回答 n → 不构造 Scheduler（真的什么都没跑）", f"实={built}")
        check(len(sess.result.assets) == 0, "取消时不写入任何资产")

        # 14c 回答 y → 跑完整条流水线，结果并回会话
        builtins.input = lambda *a, **k: "y"
        await repl._autopilot()
        check(len(built) == 1, "确认后构造了 Scheduler 并跑了一次", f"实={built}")
        check(built and built[0] is not None, "全自动把审核通道传给了 Scheduler")
        check(len(sess.result.assets) == 1, "资产并回会话", f"实={len(sess.result.assets)}")
        check(len(sess.result.findings) == 1, "发现并回会话")
        check(len(sess.result.fingerprints) == 1, "指纹并回会话")
        check("note1" in sess.result.notes, "notes 并回会话")
        check(len(sess.turns) == 1, "记了一轮 turn", f"实={len(sess.turns)}")
        check(bool(sess.conversations), "记了一条对话索引")
        check((tmp / "reports").exists() or any(tmp.rglob("*.md")),
              "报告已导出到输出目录")
    finally:
        builtins.input = real_input
        if had is not None:
            sys.modules["core.scheduler"] = had
        else:
            sys.modules.pop("core.scheduler", None)

    # ── 场景15 合并去重 ──────────────────────────────────────────
    print("\n场景15 结果合并去重（同一条不记两遍）")
    sess2 = Session(target="http://t.test")
    sess2.result.assets = [Asset(kind="api", value="/api/item")]
    sess2.result.findings = [
        Finding(poc_id="p1", name="X", severity=Severity.LOW, category=Category.INJECTION,
                matched_at="http://t.test/api/item")
    ]
    repl2 = Repl(Cfg(), sess2, agent=False, probes=[])
    res = ScanResult(target="http://t.test")
    res.assets = [Asset(kind="api", value="/api/item"), Asset(kind="path", value="/admin")]
    res.findings = [
        Finding(poc_id="p1", name="X", severity=Severity.LOW, category=Category.INJECTION,
                matched_at="http://t.test/api/item"),
        Finding(poc_id="p2", name="Y", severity=Severity.HIGH, category=Category.INJECTION,
                matched_at="http://t.test/admin"),
    ]
    n = repl2._merge_scan(res)
    check(n["assets"] == 1, "只并入 1 条新资产（重复的那条被去重）", f"实={n['assets']}")
    check(n["findings"] == 1, "只并入 1 条新发现", f"实={n['findings']}")
    check(len(sess2.result.assets) == 2, "资产总数正确", f"实={len(sess2.result.assets)}")

    print(f"\n{'=' * 46}")
    print(f"  {ok}/{total} 通过")
    print("=" * 46)
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
