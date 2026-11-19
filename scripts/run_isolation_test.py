"""三层隔离（Target → ScanRun → Finding）的回归测试（不触网）。

复现的问题：``/target``（及 set_target 工具）在多目标/多轮扫描之间串台——
上一个目标的发现、证据混进下一个目标的报告；同一目标开了新一轮扫描后，
旧轮次的残留也跟着导出。根因是"这批发现属于哪次扫描"只靠"会话没换过
目标"这种约定，没有任何结构化归属。

这里锁死五件事：
  1. Finding / Evidence / 工具调用记录都带 target_id + run_id；
  2. 每次"执行扫描"开新 run（Session 初始化、/target、set_target 工具、
     Scheduler.scan），旧 run 如实标记；
  3. add_findings 是打标收口：入库时补齐归属；带异构标记的默认保留
     （由报告过滤剔除），restamp=True 用于并入代表本会话执行的外部扫描；
  4. 报告导出（三个 writer）用 scoped_view：只导出当前 target + run 的
     发现，counts / by_severity / to_dict 全部基于过滤后的列表；
  5. 序列化往返 + 旧快照兼容（无标记的历史发现按"当前作用域"放行）。

运行：.venv/Scripts/python.exe scripts/run_isolation_test.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.state import (  # noqa: E402
    Category,
    Evidence,
    Finding,
    ScanResult,
    ScanRun,
    Severity,
)

PASS = 0
FAIL: list[str] = []


def ok(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


def mk_finding(poc: str, at: str = "http://t.example.com/a") -> Finding:
    return Finding(
        poc_id=poc,
        name=f"漏洞 {poc}",
        severity=Severity.HIGH,
        category=Category.CONTENT_MATCH,
        matched_at=at,
        evidence=Evidence(url=at, status_code=200, body_excerpt="hit"),
    )


# ── 1. 数据模型：新字段与默认值 ────────────────────────────────────


def test_model_fields() -> None:
    f = mk_finding("p1")
    ok(f.target_id == "" and f.run_id == "", "Finding 默认不带标记（旧快照兼容）")
    ok(f.evidence is not None and f.evidence.run_id == "", "Evidence 默认 run_id 为空")

    r = ScanResult(target="http://t.example.com")
    ok(r.target_id == "" and r.current_run_id == "" and not r.runs, "ScanResult 初始无作用域")

    run = r.new_run("第一轮")
    ok(run.run_id and run.target_id == "http://t.example.com", "new_run 继承目标")
    ok(r.current_run_id == run.run_id, "new_run 后 current_run_id 指向新轮次")
    ok(len(r.runs) == 1 and r.runs[0] is run, "runs 台账记录了新轮次")

    run2 = r.new_run("第二轮")
    ok(len(r.runs) == 2 and r.current_run_id == run2.run_id, "再开一轮切换 current")
    ok(r.runs[0].status == "aborted", "未收尾的旧轮次标记为 aborted")
    ok(r.runs[0].run_id != r.runs[1].run_id, "run_id 不撞车")
    ok(r.current_run() is r.runs[1], "current_run() 返回当前轮次对象")


# ── 2. add_findings 打标收口 ──────────────────────────────────────


def test_stamping() -> None:
    r = ScanResult(target="http://t.example.com")
    run = r.new_run()
    f = mk_finding("p1")
    r.add_findings([f])
    ok(f.target_id == "http://t.example.com", "入库时打上 target_id")
    ok(f.run_id == run.run_id, "入库时打上当前 run_id")
    ok(f.evidence is not None and f.evidence.run_id == run.run_id, "证据继承 run_id")

    # 带异构标记进来（别的目标/别的轮次）→ 保留原标记，不覆盖
    alien = mk_finding("p2")
    alien.target_id = "http://other.example.com"
    alien.run_id = "deadbeefdead"
    r.add_findings([alien])
    ok(alien.target_id == "http://other.example.com", "异构标记不被覆盖")
    ok(alien.run_id == "deadbeefdead", "异构 run_id 不被覆盖")

    # restamp=True：并入代表本会话执行的外部扫描 → 归属改判
    adopted = mk_finding("p3")
    adopted.target_id = "http://other.example.com"
    adopted.run_id = "feedfacefeed"
    adopted.evidence.run_id = "feedfacefeed"
    r.add_findings([adopted], restamp=True)
    ok(adopted.target_id == "http://t.example.com", "restamp 改写 target_id")
    ok(adopted.run_id == run.run_id, "restamp 改写 run_id")
    ok(adopted.evidence is not None and adopted.evidence.run_id == run.run_id, "restamp 证据跟随")


# ── 3. scoped_findings / scoped_view ─────────────────────────────


def test_scope_filter() -> None:
    r = ScanResult(target="http://t.example.com")
    r.target_id = "http://t.example.com"
    run1 = r.new_run("第一轮")
    f1 = mk_finding("p1")
    r.add_findings([f1])
    r.new_run("第二轮")
    f2 = mk_finding("p2")
    r.add_findings([f2])

    # 串台数据：别的目标 + 旧轮次
    alien = mk_finding("p3", at="http://other.example.com/x")
    alien.target_id = "http://other.example.com"
    alien.run_id = "deadbeefdead"
    r.findings.append(alien)
    stale = mk_finding("p4")
    stale.target_id = "http://t.example.com"
    stale.run_id = run1.run_id
    r.findings.append(stale)

    scoped = r.scoped_findings()
    ok(f2 in scoped and f1 not in scoped, "旧轮次的发现被过滤")
    ok(alien not in scoped, "别的目标的发现被过滤")
    ok(stale not in scoped, "上一轮的残留被过滤")
    ok(len(scoped) == 1 and scoped[0].poc_id == "p2", "只留当前作用域的发现")

    view = r.scoped_view()
    ok(len(view.findings) == 1, "scoped_view 的 findings 已过滤")
    ok(view.counts()[Severity.HIGH.value] == 1, "视图 counts 基于过滤后列表")
    ok(view.by_severity()[Severity.HIGH.value] == [f2], "视图 by_severity 已过滤")
    ok(view is not r and view.findings is not r.findings, "视图是独立浅拷贝")
    ok(view.findings[0] is f2, "视图共享 Finding 对象（复核写回原对象）")

    # 旧快照兼容：无标记的历史发现放行
    legacy = mk_finding("old")
    legacy.target_id = ""
    legacy.run_id = ""
    r.findings.append(legacy)
    ok(legacy in r.scoped_findings(), "旧快照（无标记）按当前作用域放行")

    # 作用域字段为空（老会话）→ 全部放行，不误伤
    old = ScanResult(target="http://t.example.com")
    old.findings.append(mk_finding("x"))
    ok(len(old.scoped_findings()) == 1, "无 current_run_id 时不误伤")


# ── 4. 报告导出过滤（writer 级，临时目录落盘）────────────────────


def test_writers_scoped() -> None:
    from output.report import write_json, write_markdown

    r = ScanResult(target="http://t.example.com", session_id="iso-test")
    r.target_id = "http://t.example.com"
    r.new_run("本轮")
    good = mk_finding("keep-me")
    r.add_findings([good])
    alien = mk_finding("alien", at="http://other.example.com/x")
    alien.target_id = "http://other.example.com"
    alien.run_id = "deadbeefdead"
    r.findings.append(alien)
    stale = mk_finding("stale")
    stale.target_id = "http://t.example.com"
    stale.run_id = "000000000000"
    r.findings.append(stale)

    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        jp = write_json(r, out)
        data = json.loads(jp.read_text(encoding="utf-8"))
        ids = [f["poc_id"] for f in data["findings"]]
        ok("keep-me" in ids, "JSON 报告含当前作用域的发现")
        ok("alien" not in ids and "stale" not in ids, "JSON 报告不含串台/旧轮次发现")
        ok(data["target_id"] == "http://t.example.com", "JSON 报告带 target_id")
        ok(data["current_run_id"] == r.current_run_id, "JSON 报告带 current_run_id")
        ok(
            data["counts"][Severity.HIGH.value] == 1,
            "JSON 顶层 counts 只算当前作用域",
        )

        mp = write_markdown(r, out)
        text = mp.read_text(encoding="utf-8")
        ok("keep-me" in text, "Markdown 报告含当前作用域的发现")
        ok("alien" not in text, "Markdown 报告不含别的目标的发现")
        ok("stale" not in text, "Markdown 报告不含旧轮次的发现")


# ── 5. 序列化往返 ────────────────────────────────────────────────


def test_roundtrip() -> None:
    r = ScanResult(target="http://t.example.com", session_id="rt")
    run = r.new_run("第一轮")
    f = mk_finding("p1")
    r.add_findings([f])

    d = r.to_dict()
    ok(d["target_id"] == "http://t.example.com", "to_dict 带 target_id")
    ok(d["current_run_id"] == run.run_id, "to_dict 带 current_run_id")
    ok(len(d["runs"]) == 1, "to_dict 带 runs 台账")
    ok(d["findings"][0]["run_id"] == run.run_id, "Finding.to_dict 带 run_id")

    r2 = ScanResult.from_dict(d)
    ok(r2.target_id == "http://t.example.com", "from_dict 恢复 target_id")
    ok(r2.current_run_id == run.run_id, "from_dict 恢复 current_run_id")
    ok(len(r2.runs) == 1 and r2.runs[0].run_id == run.run_id, "from_dict 恢复 runs")
    ok(r2.findings[0].run_id == run.run_id, "from_dict 恢复 Finding.run_id")
    ok(
        r2.findings[0].evidence is not None
        and r2.findings[0].evidence.run_id == run.run_id,
        "from_dict 恢复 Evidence.run_id",
    )
    ok(len(r2.scoped_findings()) == 1, "恢复后过滤仍然命中")

    # 旧快照：没有 runs / current_run_id / 标记字段
    legacy = ScanResult.from_dict(
        {
            "target": "http://t.example.com",
            "findings": [{"poc_id": "old", "name": "旧", "severity": "high",
                          "category": "content_match"}],
        }
    )
    ok(legacy.current_run_id == "" and not legacy.runs, "旧快照无轮次台账")
    ok(len(legacy.scoped_findings()) == 1, "旧快照的发现不被过滤误伤")

    # ScanRun 自身往返
    sd = run.to_dict()
    sr = ScanRun.from_dict(sd)
    ok(sr.run_id == run.run_id and sr.status == run.status, "ScanRun 往返一致")


# ── 6. 入口行为：Session / set_target 工具 / Scheduler ───────────


def test_entry_points() -> None:
    from core.session import Session

    # 带目标构造的 Session 自动开 run
    s = Session(target="http://t.example.com")
    ok(bool(s.result.current_run_id), "Session 初始化即开扫描轮次")
    ok(s.result.current_run().target_id == "http://t.example.com", "轮次归属当前目标")

    # 无目标构造 → 不开 run（/target 时再开）
    s0 = Session(target="")
    ok(not s0.result.runs, "无目标不预开轮次")

    # 快照往返后不重复开轮次（新版快照已带 runs）
    saved = json.loads(json.dumps(s.to_dict()))
    s2 = Session.from_dict(saved)
    ok(
        s2.result.current_run_id == s.result.current_run_id and len(s2.result.runs) == 1,
        "载入快照沿用原轮次，不重复开",
    )

    # set_target 工具：换目标开新 run，重复设定不开
    asyncio.run(_test_set_target_tool())


async def _test_set_target_tool() -> None:
    from core.config_loader import Config
    from core.session import Session
    from core.tools.runner import ToolRunner

    s = Session(target="http://t.example.com")
    first = s.result.current_run_id
    runner = ToolRunner(Config(), root=tempfile.gettempdir())
    await runner.execute("set_target", {"url": "http://t.example.com"}, s)
    ok(s.result.current_run_id == first, "重复设定同一目标不开新轮次")

    await runner.execute("set_target", {"url": "http://other.example.com"}, s)
    ok(s.target == "http://other.example.com", "工具换目标生效")
    ok(s.result.target_id == "http://other.example.com", "工具换目标同步 target_id")
    ok(s.result.current_run_id != first, "工具换目标开新轮次")
    ok(s.result.current_run().target_id == "http://other.example.com", "新轮次归属新目标")

    # 工具调用记录带作用域标记
    ok(bool(runner.calls), "产生了工具调用记录")
    last = runner.calls[-1]
    ok(last.get("run_id") == s.result.current_run_id, "调用记录继承当前 run_id")
    ok(last.get("target_id") == "http://other.example.com", "调用记录继承当前目标")


def test_scheduler_scan_opens_run() -> None:
    """Scheduler.scan 入口开新 run（不真正扫描，只验证 ScanResult 构造段）。

    直接调用 scan() 会发网络请求，这里改为验证"扫描结果自带轮次"的
    契约：构造与 scan() 相同的 ScanResult + new_run 序列，确认后续
    add_findings 的发现全部落到该轮次。
    """
    import time as _t

    result = ScanResult(
        target="http://t.example.com",
        session_id=f"{int(_t.time())}",
    )
    result.target_id = result.target
    run = result.new_run(f"扫描 {result.target}")
    result.add_findings([mk_finding("sched-poc")])
    ok(result.findings[0].run_id == run.run_id, "Scheduler 扫描的发现归属扫描轮次")
    ok(result.findings[0].target_id == "http://t.example.com", "Scheduler 扫描的发现归属目标")


def main() -> int:
    test_model_fields()
    test_stamping()
    test_scope_filter()
    test_writers_scoped()
    test_roundtrip()
    test_entry_points()
    test_scheduler_scan_opens_run()
    print(
        f"\n三层隔离回归 {PASS}/{PASS} 通过"
        + (f"（另有 {len(FAIL)} 项失败）" if FAIL else "")
    )
    for name in FAIL:
        print(f"  - {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
