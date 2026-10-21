"""报告内容完整性 + 会话历史回填的回归测试。

复现的真实问题（用户报「报告输出的内容并没有达到预期，没能输出完整内容」）：
原始报告里每条发现的 PoC 只有一行请求、``<<< 响应:`` 下面是一段中文分析
——因为：

1. **登记那一刻就截断了**：``record_finding`` 把说明砍到 500 字符、
   matched_pattern 400、body_excerpt 800，模型写的研判与复现步骤直接丢；
2. **说明文字冒充响应体**：同一段文本被同时塞进 ``body_excerpt``，
   报告渲染时它就成了"服务端返回"；
3. **没有原始响应可贴**：模型验证完没把响应交给登记工具，
   报告里那条发现就只有请求。

覆盖：
  1. record_finding 完整保留长文本（不再 500 字符截断）
  2. 原始报文结构化：payload/response 被拆成请求行/头/状态码/正文
  3. 命中即落盘 Burp 式报文，artifact 回填
  4. 没传 response 时自动附上最近一次同 URL 的 http_request 响应
  5. 完全没响应时如实报缺，不编造
  6. 报告：说明按段落渲染、不再重复输出「实际命中」
  7. 报告：说明文字不会被当成响应体贴进 ``<<< 响应:``
  8. 回填：只按 URL 精确匹配（query 不同即算不同请求，杜绝错配）
  9. 回填：只填空字段，绝不覆盖已有记录；正文截断如实传递
 10. 老快照端到端：回填 → 报告 PoC 段出现真实请求/响应
 11. 截断判据：完整正文不得被误标成残缺版（多字节按字节数比对）
 12. 响应体是说明文字冒充的 → 换成历史里的真响应（别浪费到手的证据）

运行：.venv/Scripts/python.exe scripts/test_backfill.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.backfill import backfill_findings, collect_exchanges  # noqa: E402
from core.config_loader import ScanConfig  # noqa: E402
from core.rawmsg import parse_tool_result  # noqa: E402
from core.session import Session  # noqa: E402
from core.state import Category, Evidence, Finding, Severity  # noqa: E402
from core.tools import ToolRunner  # noqa: E402
from output.report import _burp_transcript, write_markdown  # noqa: E402


class FakeCfg:
    def __init__(self, root: Path, **scan_kw) -> None:
        self.output_dir = str(root)
        self.scan = ScanConfig(**scan_kw)

    class rag:
        poc_dir = "./poc"


def fake_history(entries: list[tuple[str, dict, str]]) -> list[dict]:
    """构造 (工具名, 入参, 工具结果) 形式的历史消息对。"""
    out: list[dict] = []
    for i, (name, args, result) in enumerate(entries):
        cid = f"call_{i}"
        out.append({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": cid,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)},
            }],
        })
        out.append({"role": "tool", "tool_call_id": cid, "content": result})
    return out


def http_result(method: str, url: str, code: int, body: str,
                headers: dict | None = None, size: int | None = None) -> str:
    """复刻 ``_h_http_request`` 的工具结果格式。

    ``size`` 是服务端声明的响应体字节数（缺省等于正文长度）；
    正文预览超过 1500 字符才会写「截断」——与真实实现一致，
    这里**不能**无条件写：否则回填端会把完整响应全判成残缺版。
    """
    hdrs = headers or {"server": "nginx/1.29.0", "content-type": "text/plain"}
    shown = body[:1500]
    mark = f"截断 {len(shown)} 字符" if len(shown) < len(body) else f"{len(shown)} 字符"
    lines = [
        f"{method} {url}",
        f"状态码：{code}  耗时：42ms  正文大小：{size if size is not None else len(body)}B",
        "关键响应头：",
        *[f"  {k}: {v}" for k, v in hdrs.items()],
        f"正文（{mark}）：",
        shown,
    ]
    return "\n".join(lines)


def old_http_result(method: str, url: str, code: int, body: str, shown: int = 1500) -> str:
    """复刻**早期版本**的工具结果格式：无论切没切都写「正文（截断 N 字符）」，
    且 N 是**切片前**的全长。真实会话里的历史就是这个形态。"""
    return "\n".join([
        f"{method} {url}",
        f"状态码：{code}  耗时：42ms  正文大小：{len(body.encode('utf-8'))}B",
        "关键响应头：",
        "  server: nginx/1.29.0",
        f"正文（截断 {len(body)} 字符）：",
        body[:shown],
    ])


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp())
    root = tmp / "output"
    root.mkdir()

    print("场景1 record_finding 不再截断长文本")
    sess = Session(target="https://lab.test")
    runner = ToolRunner(FakeCfg(root, evidence_dir=str(root / "evidence")), [], str(tmp))
    long_ev = "攻击链分步说明：" + "A" * 3000
    long_fix = "修复建议：" + "B" * 1200
    asyncio.run(runner.execute("record_finding", {
        "name": "长文本发现", "severity": "high", "matched_at": "https://lab.test/a?x=1",
        "evidence": long_ev, "payload": "GET /a?x=1 HTTP/1.1", "remediation": long_fix,
        "category": "lfi",
    }, sess))
    f = sess.result.findings[0]
    check(len(f.description) == len(long_ev),
          f"说明完整保留（{len(f.description)}/{len(long_ev)}，旧实现卡在 500）")
    check(len(f.remediation) == len(long_fix), f"修复建议完整保留（{len(f.remediation)}）")
    check(f.evidence.matched_pattern == "",
          "matched_pattern 不再重复存说明（否则报告出现两遍同样的话）")

    print("\n场景2 原始报文结构化（request/response 各归各位）")
    req = "\n".join(["POST /api/x HTTP/1.1", "Host: lab.test",
                     "Content-Type: application/json", "", '{"a":1}'])
    resp = "\n".join(["HTTP/1.1 201 Created", "server: nginx/1.29.0",
                      "content-type: application/json", "", '{"ok":true}'])
    asyncio.run(runner.execute("record_finding", {
        "name": "结构化", "severity": "medium", "matched_at": "https://lab.test/api/x",
        "evidence": "证据", "payload": req, "response": resp, "category": "authz",
    }, sess))
    ev = sess.result.findings[1].evidence
    check(ev.status_code == 201, f"状态行解析出状态码（实={ev.status_code}）")
    check(ev.response_headers.get("server") == "nginx/1.29.0", "响应头解析")
    check(ev.body_excerpt == '{"ok":true}', "响应体落到 body_excerpt")
    check(ev.request_line.startswith("POST /api/x HTTP/1.1"),
          "请求原文保留（含请求行）")
    check("Content-Type: application/json" in ev.request_line, "请求头保留原大小写")
    check(ev.artifact.startswith("evidence/") and (root / ev.artifact).is_file(),
          f"命中即落盘（artifact={ev.artifact}）")
    art = (root / ev.artifact).read_text(encoding="utf-8")
    check("[RESPONSE]" in art and "HTTP/1.1 201" in art and '{"ok":true}' in art,
          "落盘文件是 Burp 式请求/响应对")

    print("\n场景3 说明文字不得被当成响应体渲染")
    s2 = Session(target="https://lab.test")
    desc = "路径穿越可读取容器内任意文件，实测 94070 字节的 SQLite 库可完整下载。"
    fd = Finding(
        poc_id="manual_lfi_1", name="旧版登记", severity=Severity.HIGH,
        category=Category.FILE_OP, matched_at="https://lab.test/dl?file=../../etc/passwd",
        description=desc,
        evidence=Evidence(
            url="https://lab.test/dl?file=../../etc/passwd",
            # 旧版把说明同时塞进 body_excerpt（真实事故）
            body_excerpt=desc, matched_pattern=desc, payload_sent="GET /dl?file=../../etc/passwd",
        ),
    )
    s2.result.add_findings([fd])
    req2, resp2, note2 = _burp_transcript(fd.evidence, root, description=desc)
    check(desc[:20] not in resp2, "说明文字没有出现在响应位置")
    check("已剔除" in note2, f"如实说明响应缺失的原因（实={note2!r}）")
    md2 = write_markdown(s2.result, root / "s2").read_text(encoding="utf-8")
    check("没有原始响应报文" in md2, "报告里明确标注「只有请求、没有响应」")
    check(md2.count(desc[:20]) == 1, "说明只出现一次（不再说明/实际命中各来一遍）")

    print("\n场景4 自动附上最近一次同 URL 的 http_request 响应")
    s3 = Session(target="https://lab.test")
    r3 = ToolRunner(FakeCfg(root, evidence_dir=str(root / "evidence")), [], str(tmp))
    r3._recent_http.append({
        "url": "https://lab.test/api/cases/1049", "method": "GET",
        "request_line": "GET /api/cases/1049 HTTP/1.1\nHost: lab.test",
        "status_code": 200, "response_headers": {"content-type": "application/json"},
        "body": '{"internal_note":"flag{x}"}', "body_size": 27, "elapsed_ms": 18,
    })
    out = asyncio.run(r3.execute("record_finding", {
        "name": "IDOR", "severity": "high", "matched_at": "https://lab.test/api/cases/1049",
        "evidence": "未授权可读", "payload": "GET /api/cases/1049", "category": "idor",
    }, s3))
    ev3 = s3.result.findings[0].evidence
    check(ev3.status_code == 200, f"自动补上状态码（实={ev3.status_code}）")
    check("flag{x}" in ev3.body_excerpt, "自动补上响应正文")
    check("最近一次同 URL" in out, "返回值里说明响应来源")

    print("\n场景5 完全没响应时如实报缺，不编造")
    s4 = Session(target="https://lab.test")
    r4 = ToolRunner(FakeCfg(root, evidence_dir=str(root / "evidence")), [], str(tmp))
    out = asyncio.run(r4.execute("record_finding", {
        "name": "孤立发现", "severity": "low", "matched_at": "https://lab.test/none",
        "evidence": "只有一句话", "payload": "GET /none", "category": "other",
    }, s4))
    ev4 = s4.result.findings[0].evidence
    check(ev4.status_code is None, "不猜状态码")
    check("没有原始响应报文" in out, "登记结果里明确警告缺响应")

    print("\n场景6 回填：解析历史里的 http_request 结果")
    hist = fake_history([
        ("recon_openapi", {"url": "https://lab.test/openapi.json"},
         "不是请求结果，应被忽略"),
        ("http_request", {"url": "https://lab.test/a?x=1"},
         http_result("GET", "https://lab.test/a?x=1", 200, "AAA")),
        ("http_request", {"url": "https://lab.test/b?p=../etc/passwd"},
         http_result("GET", "https://lab.test/b?p=../etc/passwd", 200, "root:x:0:0")),
    ])
    ex = collect_exchanges(hist)
    check(len(ex) == 2, f"只认 http_request 的结果（实={len(ex)}）")
    check(ex[0]["status_code"] == 200 and ex[0]["body"] == "AAA", "请求结果字段解析正确")

    print("\n场景7 回填只按 URL 精确匹配（query 不同即不同请求）")
    s5 = Session(target="https://lab.test")
    s5.history = hist
    # 两条 URL 只差 query：绝不能互相串响应（真实事故：environ 被挂上 passwd）
    s5.result.add_findings([
        Finding(poc_id="p_env", name="environ", severity=Severity.HIGH,
                category=Category.FILE_OP, matched_at="https://lab.test/b?p=../proc/self/environ",
                description="d", evidence=Evidence(url="https://lab.test/b?p=../proc/self/environ")),
        Finding(poc_id="p_passwd", name="passwd", severity=Severity.HIGH,
                category=Category.FILE_OP, matched_at="https://lab.test/b?p=../etc/passwd",
                description="d",
                evidence=Evidence(url="https://lab.test/b?p=../etc/passwd")),
    ])
    stat = backfill_findings(s5, evidence_dir=str(root / "evidence"))
    check(stat["filled"] == 1, f"只补上 query 完全一致的那条（实={stat['filled']}）")
    env_ev = s5.result.findings[0].evidence
    pw_ev = s5.result.findings[1].evidence
    check(env_ev.status_code is None, "environ 那条**没有**被挂上 passwd 的响应")
    check(pw_ev.body_excerpt == "root:x:0:0", "passwd 那条补上了自己的响应")
    check(any("原始报文回填" in n for n in s5.result.notes), "回填在会话里留痕")

    print("\n场景8 回填只填空字段，绝不覆盖已有记录")
    s6 = Session(target="https://lab.test")
    s6.history = hist
    keep = Finding(
        poc_id="manual_keep", name="已有响应", severity=Severity.HIGH,
        category=Category.FILE_OP, matched_at="https://lab.test/a?x=1", description="d",
        evidence=Evidence(url="https://lab.test/a?x=1", status_code=403,
                          body_excerpt="原始记录", body_size=4,
                          payload_sent="GET /a?x=1"),
    )
    s6.result.add_findings([keep])
    stat = backfill_findings(s6, evidence_dir=str(root / "evidence"))
    check(stat["filled"] == 0, "已有响应的发现不参与回填")
    check(keep.evidence.status_code == 403, "已有状态码不被覆盖")
    check(keep.evidence.body_excerpt == "原始记录", "已有响应体不被覆盖")

    print("\n场景9 老快照端到端：回填 → 报告出现真实请求/响应")
    s7 = Session(target="https://lab.test")
    s7.history = fake_history([
        ("http_request", {"url": "https://lab.test/dl?file=../etc/passwd"},
         http_result("GET", "https://lab.test/dl?file=../etc/passwd", 200,
                     "root:x:0:0\nportal:x:999:999::/app:/usr/sbin/nologin")),
    ])
    s7.result.add_findings([Finding(
        poc_id="manual_lfi_9", name="路径穿越", severity=Severity.CRITICAL,
        category=Category.FILE_OP, matched_at="https://lab.test/dl?file=../etc/passwd",
        description="说明文字", evidence=Evidence(url="https://lab.test/dl?file=../etc/passwd"),
    )])
    stat = backfill_findings(s7, evidence_dir=str(root / "evidence"))
    check(stat["filled"] == 1 and stat["items"][0]["truncated"] is False,
          "回填 1 条且非截断")
    md7 = write_markdown(s7.result, root / "s7").read_text(encoding="utf-8")
    check("<<< 响应:" in md7, "报告 PoC 段出现响应段")
    check("HTTP/1.1 200" in md7 and "root:x:0:0" in md7, "响应内容来自真实报文")
    check("响应：HTTP 200" in md7, "响应元信息（状态/字节/耗时）落位")

    print("\n场景10 正文截断如实传递（工具结果只有预览版）")
    s8 = Session(target="https://lab.test")
    s8.history = fake_history([
        ("http_request", {"url": "https://lab.test/big"},
         http_result("GET", "https://lab.test/big", 200, "x" * 100, size=94070)),
    ])
    s8.result.add_findings([Finding(
        poc_id="manual_big", name="大文件", severity=Severity.HIGH,
        category=Category.FILE_OP, matched_at="https://lab.test/big",
        description="d", evidence=Evidence(url="https://lab.test/big"),
    )])
    stat = backfill_findings(s8, evidence_dir=str(root / "evidence"))
    check(stat["items"][0]["truncated"] is True, "标记出正文是预览截断版")
    check(s8.result.findings[0].evidence.body_size == 94070, "保留服务端声明的原始大小")

    print("\n场景11 截断判据：完整正文不得被误标成残缺版")
    # 真实事故：早期实现无论切没切都写「正文（截断 N 字符）」（N 是预览长度），
    # 回填端照字面判 → 34 条完整响应全被标成"预览截断版"，报告跟着一起错。
    short = parse_tool_result(http_result("GET", "https://lab.test/s", 200, "hello"))
    check(short["body_truncated"] is False, "短正文（未切）不算截断")
    check(short["body"] == "hello" and short["status_code"] == 200, "短正文解析正确")
    long_body = "y" * 2000
    long_r = parse_tool_result(http_result("GET", "https://lab.test/l", 200, long_body,
                                           size=len(long_body)))
    check(long_r["body_truncated"] is True, "预览超过 1500 字符 → 判为截断")
    check(len(long_r["body"]) == 1500, f"预览按上限切（实={len(long_r['body'])}）")
    # 中文按字符数不该触发：60 字节/20 字符的完整正文
    zh = parse_tool_result(http_result("GET", "https://lab.test/zh", 200, "中文正文" * 5))
    check(zh["body_truncated"] is False, "多字节正文按字节数比对，不误判")
    # 真实会话的历史是**旧格式**：完整响应也写着「截断 N 字符」，
    # 照字面判 → 15 条完整响应全被标成残缺版（实测踩到）。
    old_ok = parse_tool_result(old_http_result("GET", "https://lab.test/o", 200, "p" * 100))
    check(old_ok["body_truncated"] is False, "旧格式：完整正文不得被判截断")
    check(old_ok["body"] == "p" * 100, "旧格式完整正文照常解析")
    old_cut = parse_tool_result(
        old_http_result("GET", "https://lab.test/oc", 200, "q" * 3000))
    check(old_cut["body_truncated"] is True, "旧格式：真被切（N>1500）仍能识别")
    check(len(old_cut["body"]) == 1500, f"旧格式预览切在上限（实={len(old_cut['body'])}）")

    print("\n场景12 响应体是说明文字冒充的 → 换成历史里的真响应")
    # 渲染端只能把假响应体清空（清完这条就成了"有请求没响应"）；
    # 历史里明明有真响应，就该换上去，而不是浪费掉。
    desc_bogus = "路径穿越可读取容器内任意文件，实测 94070 字节的 SQLite 库可完整下载，无需任何鉴权。"
    s9 = Session(target="https://lab.test")
    s9.history = fake_history([
        ("http_request", {"url": "https://lab.test/f?file=../etc/passwd"},
         http_result("GET", "https://lab.test/f?file=../etc/passwd", 200, "root:x:0:0")),
    ])
    bed = Evidence(
        url="https://lab.test/f?file=../etc/passwd", status_code=200,
        response_headers={"server": "nginx"}, body_excerpt=desc_bogus,
        body_size=len(desc_bogus),
        request_line="GET /f?file=../etc/passwd HTTP/1.1",
    )
    s9.result.add_findings([Finding(
        poc_id="manual_fake", name="假响应", severity=Severity.CRITICAL,
        category=Category.FILE_OP, matched_at=bed.url,
        description=desc_bogus, evidence=bed)])
    stat = backfill_findings(s9, evidence_dir=str(root / "evidence"))
    check(stat["filled"] == 1, f"假响应体的发现参与回填（实={stat['filled']}）")
    check(bed.body_excerpt == "root:x:0:0", "假响应体被真响应替换（有状态码也要换）")
    md9 = write_markdown(s9.result, root / "s9").read_text(encoding="utf-8")
    check(desc_bogus[:20] not in md9.split("<<< 响应:", 1)[1],
          "报告 `<<< 响应:` 段不再是说明文字")
    check("root:x:0:0" in md9, "报告 `<<< 响应:` 段是真响应")
    check("已剔除" not in md9, "真响应到位后不再出现「已剔除」提示")

    print(f"\n结果：{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
