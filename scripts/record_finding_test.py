"""手工发现登记 + 流式截断检测的回归测试。

复现的真实问题：模型用 curl 手工验证出 14 个漏洞（含 8 个 Critical），
但 findings库里只有探针自动登记的 2 条 → 导出报告只有 2 项。
原因��**没有任何工具能登记手工发现**。

覆盖：
  1. record_finding 能登记手工发现，且进findings 列表
  2. 重复登记同一发现不会重复累加
  3.缺证据/缺位置被拒绝（项目「证据优先」地基）
  4. 手工登记的发现会进导出报告
  5. severity/category 映射正确
  6. 流式默认 max_tokens 被放大到 STREAM_MIN_TOKENS
  7. 流式 finish_reason=length 被识别并 yield error
  8. 系统提示包含「必须登记」纪律
  9. 目标归属拦截：域名会话里登记 IP（及反向）被拦，同形态放行

运行：.venv/Scripts/python.exe scripts/test_record_finding.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.session import Session  # noqa: E402
from core.state import Category, Severity  # noqa: E402
from core.tools import ToolRunner  # noqa: E402
from core.tools import BUILTINS  # noqa: E402
from llm import prompt as P  # noqa: E402


class FakeCfg:
    output_dir = "."
    readonly = True
    class scan:
        readonly = True
        timeout = 10
        concurrency = 8
    class rag:
        poc_dir = "./poc"


async def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp())
    cfg = FakeCfg()
    cfg.output_dir = str(tmp)
    session = Session(target="http://juice.test")
    runner = ToolRunner(cfg, [], str(tmp))

    print("场景1 工具已注册且对模型可见")
    names = [b.name for b in BUILTINS]
    check("record_finding" in names, "record_finding 在工具清单里")
    spec = [b for b in BUILTINS if b.name == "record_finding"][0]
    check(set(spec.params.get("required") or []) >=
          {"name", "severity", "matched_at", "evidence", "payload"},
          "必填参数含证据与 payload")

    print("\n场景2 登记手工发现（原 bug 的核心）")
    r = await runner.execute("record_finding", {
        "name": "SQL 注入", "severity": "critical",
        "matched_at": "http://juice.test/rest/products/search?q=test')) UNION SELECT 1--",
        "evidence": "id 字段回显 3.44.2（SQLite 版本号），UNION 注入成立",
        "payload": "GET /rest/products/search?q=test')) UNION SELECT sqlite_version()--",
        "expected": "响应 data[0].id 等于数据库版本号",
        "remediation": "改用参数化查询",
        "category": "sqli",
    }, session)
    check("已登记" in r, f"登记成功：{r[:60]}")
    check(len(session.result.findings) == 1, f"findings 有 1 项，实={len(session.result.findings)}")
    f = session.result.findings[0]
    check(f.severity == Severity.CRITICAL, f"等级正确 = {f.severity.label}")
    check(f.category == Category.CONTENT_MATCH, "category 映射为 CONTENT_MATCH")
    check(f.poc_id.startswith("manual_"), f"poc_id 带 manual_ 前缀 = {f.poc_id}")
    check(f.detector == "manual", "detector=manual（与探针发现区分）")
    check(f.verdict == "true_positive" and f.confidence == 1.0, "手工验证默认已确认")

    print("\n场景3 重复登记不累加")
    again = await runner.execute("record_finding", {
        "name": "SQL 注入", "severity": "critical",
        "matched_at": "http://juice.test/rest/products/search?q=test')) UNION SELECT 1--",
        "evidence": "重复验证", "payload": "GET /x", "category": "sqli",
    }, session)
    check(len(session.result.findings) == 1, f"仍是 1 项，实={len(session.result.findings)}")
    check("已存在" in again, "明确告知已存在")

    print("\n场景4 缺证据/缺位置被拒绝")
    no_ev = await runner.execute("record_finding", {
        "name": "猜测的漏洞", "severity": "high",
        "matched_at": "http://juice.test/x", "evidence": "", "payload": "GET /x",
    }, session)
    check("evidence" in no_ev and "登记失败" in no_ev, f"缺证据被拒：{no_ev[:50]}")
    no_at = await runner.execute("record_finding", {
        "name": "无位置", "severity": "high", "matched_at": "",
        "evidence": "有证据", "payload": "GET /x",
    }, session)
    check("matched_at" in no_at and "登记失败" in no_at, "缺位置被拒")
    no_pay = await runner.execute("record_finding", {
        "name": "缺 payload", "severity": "high",
        "matched_at": "http://juice.test/p", "evidence": "有证据", "payload": "",
    }, session)
    check("payload" in no_pay and "登记失败" in no_pay, "缺 payload 被拒")
    check(len(session.result.findings) == 1, "被拒的没有入库")

    print("\n场景5 severity / category 映射")
    cases = [("sqli", Category.CONTENT_MATCH), ("idor", Category.API_AUTHZ),
             ("lfi", Category.FILE_OP), ("rce", Category.RCE),
             ("info_disclosure", Category.HEADER_CHECK)]
    for cat, want in cases:
        r2 = await runner.execute("record_finding", {
            "name": f"{cat} 测试", "severity": "medium",
            "matched_at": f"http://juice.test/{cat}", "evidence": "evidence",
            "payload": f"GET /{cat}", "category": cat,
        }, session)
        check("已登记" in r2, f"{cat} 登记成功")
    got = [x.category for x in session.result.findings[1:]]
    check(got == [w for _, w in cases], f"category 映射正确，实={got}")
    # 未知category 不应抛异常
    r3 = await runner.execute("record_finding", {
        "name": "未知分类", "severity": "low",
        "matched_at": "http://juice.test/u", "evidence": "e",
        "payload": "GET /u", "category": "zzz",
    }, session)
    check("已登记" in r3, "未知 category 回落而不报错")

    print("\n场景6 手工发现进入导出报告（原 bug 的验证点）")
    from output.report import write_markdown
    p = write_markdown(session.result, tmp, "")
    body = p.read_text(encoding="utf-8")
    check("SQL 注入" in body, "手工登记的漏洞出现在报告里")
    check("UNION SELECT 1--" in body, "命中位置保留")
    check("3.44.2" in body, "证据内容保留")
    check("参数化查询" in body, "修复建议保留")
    check("UNION SELECT sqlite_version()" in body, "payload 原样输出")
    check("预期返回" in body, "预期返回字段存在")
    # 「实际命中」对**手工登记**的发现已不再输出：判定依据就是 evidence，
    # 它在报告里是「漏洞说明」那一段。以前 matched_pattern 也存一份同样的
    # 文本，报告里就出现两遍一模一样的话（真实事故：22 条发现每条都重复）。
    check("实际命中" not in body, "手工发现不再重复输出「实际命中」（与说明同源）")
    check("**漏洞说明**" in body, "说明按段落渲染，而不是挤进一条列表项")
    check("触发 POC" in body, "触发 POC 字段存在")
    # 探针发现(0条) + 手工登记(7条) = 7
    check(f"共 {len(session.result.findings)}" in body or
          f"{len(session.result.findings)} 条" in body,
          f"报告反映全部 {len(session.result.findings)} 条发现")

    print("\n场景7 流式 max_tokens 放大 + 截断识别")
    import llm.client as LC
    check(LC.STREAM_MIN_TOKENS >= 4096,
          f"STREAM_MIN_TOKENS={LC.STREAM_MIN_TOKENS}（远大于默认 2048）")

    class FakeDelta:
        def __init__(self, text=None, tcs=None):
            self.content = text
            self.tool_calls = tcs
    class FakeChoice:
        def __init__(self, text=None, tcs=None, fr=None):
            self.delta = FakeDelta(text, tcs)
            self.finish_reason = fr
    class FakeChunk:
        def __init__(self, ch):
            self.choices = [ch] if ch else []
    class FakeStream:
        def __init__(self, chunks):
            self.chunks = chunks
        def __iter__(self):
            return iter(self.chunks)

    c = LC.LLMClient.__new__(LC.LLMClient)
    c.calls = 0; c.total_ms = 0; c.errors = []
    c.api_key = "k"
    c.cfg = type("C", (), {
        "temperature": 0.2, "max_tokens": 2048,
        "model": "m", "deep_model": "m",
    })()
    c.supports_tools = False; c.tool_note = ""; c.available = True

    # 未截断：正常走完
    c._open_stream = lambda *a, **k: FakeStream([
        FakeChunk(FakeChoice("你好")), FakeChunk(FakeChoice("世界", fr="stop")),
    ])
    evs = list(c.stream_chat([{"role": "user", "content": "x"}]))
    types = [e["type"] for e in evs]
    check("done" in types, f"正常结束，有 done 事件（{types}）")
    check(not any("截断" in e.get("message", "") for e in evs), "未误报截断")

    # 被截断
    c2 = LC.LLMClient.__new__(LC.LLMClient)
    c2.calls = 0; c2.total_ms = 0; c2.errors = []
    c2.api_key = "k"
    c2.cfg = type("C", (), {"temperature": 0.2, "max_tokens": 2048,
                          "model": "m", "deep_model": "m"})()
    c2.supports_tools = False; c2.tool_note = ""; c2.available = True
    c2._open_stream = lambda *a, **k: FakeStream([
        FakeChunk(FakeChoice("开头")), FakeChunk(FakeChoice("...", fr="length")),
    ])
    evs2 = list(c2.stream_chat([{"role": "user", "content": "x"}]))
    errs = [e for e in evs2 if e["type"] == "error"]
    check(bool(errs), "截断时yield error")
    check(any("截断" in e["message"] for e in errs), f"错误文案明确：{errs[0]['message'][:50] if errs else ''}")
    check(not any(e["type"] == "done" for e in evs2), "截断时不再发 done（避免上层当成完整）")
    check(any("截断" in e for e in c2.errors), "截断记入 errors")

    print("\n场景8 系统提示包含登记纪律")
    check("record_finding" in P.AGENT_SYSTEM, "提示词提到 record_finding")
    check("等于没测" in P.AGENT_SYSTEM, "点明不登记的后果")
    check("export_report" in P.AGENT_SYSTEM, "说明报告来自 findings 列表")
    check("不要把完整报告直接打在对话里" in P.AGENT_SYSTEM, "禁止把报告打在对话里")

    print("\n场景9 目标归属拦截（防「测了别的 IP 却用主域名登记」）")
    n_before = len(session.result.findings)
    # 会话目标是域名，却登记一个 IP —— 典型串线（SSRF 反射出的内网地址、
    # 顺手扫到的邻居站），必须拦下
    blocked = await runner.execute("record_finding", {
        "name": "内网某服务未授权", "severity": "high",
        "matched_at": "http://10.0.0.5:8080/admin",
        "evidence": "直接返回管理面板", "payload": "GET /admin",
        "category": "idor",
    }, session)
    check("已拦截" in blocked, f"域名会话里登记 IP 被拦：{blocked[:60]}")
    check("/target" in blocked, "拦截文案提示先切换目标")
    check(len(session.result.findings) == n_before, "被拦的没有入库")

    # 目标本身就是 IP 时，登记域名同样要拦（反过来的串线）
    ip_session = Session(target="http://10.0.0.5:8080")
    blocked2 = await runner.execute("record_finding", {
        "name": "某域名越权", "severity": "high",
        "matched_at": "http://other.example.com/admin",
        "evidence": "越权读取", "payload": "GET /admin",
        "category": "idor",
    }, ip_session)
    check("已拦截" in blocked2, f"IP 会话里登记域名被拦：{blocked2[:60]}")
    check(len(ip_session.result.findings) == 0, "被拦的没有入库")

    # 同形态不同主机（子域名 / 多主机业务）必须放行——那是正常业务形态
    sub = await runner.execute("record_finding", {
        "name": "子域越权", "severity": "high",
        "matched_at": "http://api.juice.test/admin",
        "evidence": "越权读取", "payload": "GET /admin",
        "category": "idor",
    }, session)
    check("已登记" in sub, f"同形态不同主机放行：{sub[:60]}")

    # 裸主机（没 scheme）也要能识别形态
    bare = await runner.execute("record_finding", {
        "name": "裸 IP 登记", "severity": "high",
        "matched_at": "10.0.0.5:8080/admin",
        "evidence": "直连内网", "payload": "GET /admin",
        "category": "idor",
    }, session)
    check("已拦截" in bare, f"裸 IP 形态也能识别：{bare[:60]}")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
