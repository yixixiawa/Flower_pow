"""Burp 式报文报告 + 证据落盘的回归测试。

需求来源：用户要求报告里的 PoC 像 Burp Suite 一样展示网络报文，
格式对齐正式交付的渗透报告（每条漏洞：漏洞描述 / PoC / 安全建议）。

**请求与响应的契约（改过一次，见场景 5b）**：
报告内展示时，**请求包完整保留**、**响应只给大概内容**。复现靠的是请求——
少一个 Cookie 或路径参数，粘到 Repeater 就是另一个请求；而完整响应可能
几百 KB，全贴进来报告没法看，完整响应永远在证据文件里。

两个支撑改动：
  * ``detectors/base.py`` 命中时把完整原始报文落盘到 evidence/ 并
    回填 ``ev.artifact``（此前 artifact 字段从未被赋值，报告里的
    "原始报文：evidence/xxx"是死链）；
  * ``output/report.py`` 的发现详情改为 4.X 结构，PoC 段渲染
    ``>>> 请求:`` / ``<<< 响应:`` 完整报文（artifact 优先，
    字段重建兜底，截断如实标注）。

覆盖：
  1. make_finding 触发落盘：文件生成、artifact 回填、内容完整
     （请求行/请求头/[RESPONSE]/状态行/响应头/超过 4KB 的 body）
  2. 撞名防护：不同 URL 相同响应不互相覆盖
  3. evidence_dir="off" 关闭落盘；网络错误（无状态码）不落盘
  4. full_body 不进入序列化（快照/JSON 报告不背几十 KB 全文）
  5. _burp_transcript：artifact 优先 / 字段重建兜底 / 截断标注 /
     ``..`` 穿行不读 / 响应展示上限
  5b. **请求不受展示上限约束**：10KB 的请求完整保留，同长度的响应才截——
     早期版本对两者用同一个 6000 字符上限，把复现所依赖的请求也砍了尾巴
  6. 报告端到端：4.X 结构、>>> 请求 / <<< 响应、保密声明、报告编号、
     payload 与请求重复时不单列
  7. 说明文字不得冒充响应体（旧版把中文研判塞进 body_excerpt）
  8. 多行 payload 用围栏块；Markdown 转义清理不动 Windows 路径

运行：.venv/Scripts/python.exe scripts/test_burp_report.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import ScanConfig  # noqa: E402
from core.state import (  # noqa: E402
    Category, Evidence, Finding, POC, RequestSpec, ScanResult, Severity,
)
from detectors.http_detector import HttpDetector  # noqa: E402
from output.report import _burp_transcript, write_markdown  # noqa: E402


def mk_ev(url: str, body: str = "x" * 9000, status: int = 200) -> Evidence:
    ev = Evidence(
        url=url, method="GET", status_code=status,
        request_line=f"GET {url.split('://', 1)[1][url.split('://', 1)[1].find('/'):] if '/' in url.split('://', 1)[1] else '/'} HTTP/1.1\nHost: demo.example.com\nUser-Agent: test-agent",
        request_headers={"User-Agent": "test-agent"},
        response_headers={"server": "nginx", "content-type": "application/json"},
        body_excerpt=body[:4096], body_size=len(body), elapsed_ms=12,
        payload_sent="", expected="", matched_pattern="",
    )
    ev.full_body = body
    return ev


def mk_poc() -> POC:
    return POC(
        id="path-env", name="环境配置文件泄露", category=Category.PATH_PROBE,
        severity=Severity.HIGH, request=RequestSpec(paths=["/.env"]),
        remediation="封锁该路径并轮换凭据",
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

    tmp = Path(tempfile.mkdtemp())
    outdir = tmp / "output"
    evdir = outdir / "evidence"

    print("场景1 make_finding 触发落盘，内容完整")
    det = HttpDetector(ScanConfig(evidence_dir=str(evdir)))
    ev = mk_ev("http://demo.example.com/.env")
    f = det.make_finding(mk_poc(), ev)
    files = list(evdir.glob("*.http"))
    check(len(files) == 1, f"落盘了一个 .http 文件，实={len(files)}")
    check(ev.artifact.startswith("evidence/") and ev.artifact.endswith(".http"),
          f"artifact 回填为相对 output_dir 的路径，实={ev.artifact!r}")
    content = files[0].read_text(encoding="utf-8")
    check("GET /.env HTTP/1.1" in content, "文件含完整请求行")
    check("Host: demo.example.com" in content, "文件含请求头")
    check("[RESPONSE]" in content, "文件含 [RESPONSE] 分隔")
    check("HTTP/1.1 200" in content, "文件含状态行")
    check("server: nginx" in content, "文件含响应头")
    check(len(content) > 9000, "body 超过 4096 也完整落盘（不是 excerpt 截断版）")
    check(f.evidence is ev, "finding 携带同一份证据")

    print("场景2 撞名防护：不同 URL 相同响应 → 两个文件")
    det2 = HttpDetector(ScanConfig(evidence_dir=str(evdir)))
    ev_a = mk_ev("http://demo.example.com/users/1")
    ev_b = mk_ev("http://demo.example.com/users/2")
    det2.make_finding(mk_poc(), ev_a)
    det2.make_finding(mk_poc(), ev_b)
    check(ev_a.artifact != ev_b.artifact,
          f"不同 URL 的 artifact 不同（{ev_a.artifact!r} vs {ev_b.artifact!r}）")

    print("场景3 关闭与异常路径")
    det_off = HttpDetector(ScanConfig(evidence_dir="off"))
    ev_off = mk_ev("http://demo.example.com/x")
    det_off.make_finding(mk_poc(), ev_off)
    check(not ev_off.artifact, "evidence_dir=off 不落盘")
    ev_err = Evidence(url="http://demo.example.com/y", error="ConnectError")
    det.make_finding(mk_poc(), ev_err)
    check(not ev_err.artifact, "网络错误（无状态码）不落盘")

    print("场景4 full_body 不进序列化")
    d = ev.to_dict()
    check("full_body" not in d, "to_dict 不含 full_body（快照不背全文）")
    ev2 = Evidence.from_dict(d)
    check(ev2 is not None and ev2.full_body == "", "from_dict 后 full_body 为空（靠 artifact 回读）")

    print("场景5 _burp_transcript：artifact 优先")
    req, resp, note = _burp_transcript(ev, outdir)
    check("GET /.env HTTP/1.1" in req, "请求来自落盘文件")
    check("HTTP/1.1 200" in resp and "server: nginx" in resp, "响应含状态行与响应头")
    check(len(resp) > 4096, "响应来自落盘完整版（超过 4KB excerpt 的上限）")
    check("完整内容见上方报文文件" in resp, "超过展示上限时报告内如实标注")
    check("完整原始报文" in note and "evidence/" in note, "备注指向报文文件")

    print("场景5b 请求完整、响应概要（展示上限只约束响应）")
    ev_big = mk_ev("http://demo.example.com/big", body="y" * 9000)
    ev_big.artifact = ""
    # 10KB 的请求包：远超响应那 6000 字符的展示上限，但远小于 64KB 防爆上限
    long_req = "POST /big HTTP/1.1\n" + "\n".join(
        f"x-header-{i}: {'v' * 200}" for i in range(20)
    ) + "\n\n" + "p" * 9000
    ev_big.request_line = long_req
    req_b, resp_b, _ = _burp_transcript(ev_big, outdir)
    check(len(req_b) > 6000, f"请求不被 6000 字符展示上限截断（实={len(req_b)}）")
    check("仅展示前段" not in req_b, "未触发 64KB 防爆截断")
    check(req_b.rstrip().endswith("p" * 9000), "请求体尾部完整保留")
    check("v" * 200 in req_b, "请求头完整保留")
    check(len(resp_b) <= 6200, f"响应仍受 6000 字符展示上限（实={len(resp_b)}）")

    print("场景6 _burp_transcript：无 artifact 字段重建 + 截断标注")
    ev_re = mk_ev("http://demo.example.com/no-art", body="short body")
    ev_re.artifact = ""
    req, resp, note = _burp_transcript(ev_re, outdir)
    check("HTTP/1.1 200" in resp and "short body" in resp, "字段重建出响应")
    check("server: nginx" in resp, "重建含响应头")
    check(not note, "body 未超 excerpt 时不加截断备注")
    ev_cut = mk_ev("http://demo.example.com/cut", body="z" * 9000)
    ev_cut.artifact = ""
    ev_cut.full_body = ""  # 快照恢复的形态：只有 excerpt
    _, resp_c, note_c = _burp_transcript(ev_cut, outdir)
    check(len(resp_c) < 5000, "快照恢复的只有 4KB excerpt")
    check("截断版" in note_c and "9000" in note_c, "如实标注截断与原始大小")

    print("场景7 artifact 安全：.. 穿行不读")
    ev_tra = mk_ev("http://demo.example.com/t")
    ev_tra.artifact = "../../../etc/passwd"
    req_t, resp_t, _ = _burp_transcript(ev_tra, outdir)
    check("root:" not in resp_t, "不读 evidence 目录之外的文件（退回字段重建）")

    print("场景8 报告端到端：4.X 结构 + Burp 报文")
    res = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res.add_findings([f])
    md = write_markdown(res, outdir).read_text(encoding="utf-8")
    check("## 渗透测试结果" in md, "章节名为「渗透测试结果」")
    check("### 4.1 [高危] 环境配置文件泄露" in md, "条目编号 4.1 + 等级 + 名称")
    for sub in ("4.1.1 漏洞描述", "4.1.2 PoC", "4.1.3 安全建议"):
        check(f"#### {sub}" in md, f"子节 {sub} 存在")
    check(">>> 请求:" in md and "<<< 响应:" in md, "PoC 段是 Burp 式请求/响应对")
    check("GET /.env HTTP/1.1" in md, "报告含完整请求行")
    check("server: nginx" in md, "报告含响应头")
    check("【保密声明】" in md, "头部有保密声明")
    check("报告编号 | `FP-20251009-" in md, "头部有报告编号")
    check("封锁该路径并轮换凭据" in md, "安全建议落位")

    print("场景9 payload 与请求重复时不单列；无证据的手工发现不崩")
    ev_p = mk_ev("http://demo.example.com/p", body="b")
    ev_p.artifact = ""
    ev_p.payload_sent = "GET /p HTTP/1.1\nHost: demo.example.com\nUser-Agent: test-agent"
    res2 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res2.add_findings([Finding(
        poc_id="p", name="n", severity=Severity.MEDIUM,
        category=Category.HEADER_CHECK, matched_at=ev_p.url, evidence=ev_p)])
    md2 = write_markdown(res2, outdir).read_text(encoding="utf-8")
    check("发送 payload" not in md2, "payload 已在报文里时不重复单列")
    res3 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res3.add_findings([Finding(
        poc_id="m", name="手工发现", severity=Severity.LOW,
        category=Category.CONTENT_MATCH, matched_at="http://demo.example.com/x")])
    md3 = write_markdown(res3, outdir).read_text(encoding="utf-8")
    check("未附原始报文" in md3, "无证据的手工发现如实说明")

    print("场景10 说明文字不得冒充响应体（旧报告最致命的一处伪造）")
    # 旧版 record_finding 把说明同时塞进 body_excerpt，报告里这段中文分析
    # 就摆在 `<<< 响应:` 下面，读起来像"服务端返回了这个"。
    desc_probe = "路径穿越可读取容器内任意文件，实测 94070 字节的 SQLite 库可完整下载。"
    ev_fake = Evidence(
        url="http://demo.example.com/dl?file=../../etc/passwd",
        method="GET", status_code=200, body_size=len(desc_probe),
        request_line="GET /dl?file=../../etc/passwd HTTP/1.1\nHost: demo.example.com",
        response_headers={"server": "nginx"}, body_excerpt=desc_probe,
        matched_pattern=desc_probe, payload_sent="GET /dl?file=../../etc/passwd",
    )
    res4 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res4.add_findings([Finding(
        poc_id="fake", name="旧版登记", severity=Severity.HIGH,
        category=Category.FILE_OP, matched_at=ev_fake.url,
        description=desc_probe, evidence=ev_fake)])
    md4 = write_markdown(res4, outdir).read_text(encoding="utf-8")
    tail = md4.split("<<< 响应:", 1)[1] if "<<< 响应:" in md4 else ""
    check(desc_probe[:20] not in tail, "说明文字没有出现在 `<<< 响应:` 之后")
    check("已剔除" in md4, "如实说明这段文字被当作响应体剔除及原因")
    check(md4.count(desc_probe[:20]) == 1, "说明只出现一次（不再说明/实际命中各来一遍）")
    check("**漏洞说明**" in md4, "说明按独立段落渲染（不再塞进列表项）")

    print("场景11 多行 payload 用围栏块，单行仍用行内代码")
    ev_ml = mk_ev("http://demo.example.com/login", body="ok")
    ev_ml.artifact = ""
    ev_ml.payload_sent = (
        "POST /login HTTP/1.1\nHost: demo.example.com\n"
        "Content-Type: application/json\n\n{\"u\":\"admin' OR 1=1--\"}"
    )
    _, _, _ = _burp_transcript(ev_ml, outdir)
    res5 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res5.add_findings([Finding(
        poc_id="ml", name="多行 payload", severity=Severity.HIGH,
        category=Category.API_AUTHZ, matched_at=ev_ml.url, evidence=ev_ml)])
    md5 = write_markdown(res5, outdir).read_text(encoding="utf-8")
    check("- 发送 payload：" in md5, "payload 与报文不重复时单列")
    check("admin' OR 1=1--" in md5, "多行 payload 内容完整保留")
    payload_sec = md5.split("- 发送 payload：", 1)[1]
    check(payload_sec.lstrip().startswith("```http"),
          "多行 payload 用 ```http 围栏块（行内反引号包不住多行）")
    ev_one = mk_ev("http://demo.example.com/one", body="ok")
    ev_one.artifact = ""
    ev_one.payload_sent = "GET /one?x=1 HTTP/1.1"
    res6 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res6.add_findings([Finding(
        poc_id="one", name="单行 payload", severity=Severity.LOW,
        category=Category.CONTENT_MATCH, matched_at=ev_one.url, evidence=ev_one)])
    md6 = write_markdown(res6, outdir).read_text(encoding="utf-8")
    check("- 发送 payload：`GET /one?x=1 HTTP/1.1`" in md6, "单行 payload 用行内代码")

    print("场景12 Markdown 转义清理（模型从 Markdown 复制粘贴带进来的反斜杠）")
    ev_esc = mk_ev("http://demo.example.com/esc", body="ok")
    ev_esc.artifact = ""
    ev_esc.payload_sent = "GET /esc HTTP/1.1"
    res7 = ScanResult(target="http://demo.example.com", started_at=1760000000.0)
    res7.add_findings([Finding(
        poc_id="esc", name="转义", severity=Severity.MEDIUM,
        category=Category.CONTENT_MATCH, matched_at=ev_esc.url,
        description="用 \\`id\\` 与 \\* 通配符查询 C:\\Windows\\System32",
        evidence=ev_esc)])
    md7 = write_markdown(res7, outdir).read_text(encoding="utf-8")
    check("`id`" in md7 and "\\`id\\`" not in md7, "反引号转义被清掉")
    check("与 * 通配符" in md7, "星号转义被清掉")
    check("C:\\Windows\\System32" in md7, "Windows 路径的反斜杠**不动**（不是 Markdown 转义）")

    print("场景13 落盘文件的截断标注：差几字节不标，真缺内容才标")
    # 实测：880 字节的 /etc/passwd 因为工具结果里 strip 掉一个行尾换行，
    # 落盘时被标成「仅保留前 879 字符」——报告读起来像残页，其实是完整的。
    ev_t1 = mk_ev("http://demo.example.com/t1", body="root:x:0:0\n" * 80)
    ev_t1.body_size = len(ev_t1.full_body.encode("utf-8")) + 1
    ev_t1.artifact = ""
    ev_t2 = mk_ev("http://demo.example.com/t2", body="y" * 9000)
    ev_t2.full_body = "y" * 200          # 真只剩预览（快照恢复的形态）
    ev_t2.body_size = 9000
    ev_t2.artifact = ""
    det_t = HttpDetector(ScanConfig(evidence_dir=str(evdir)))
    det_t.make_finding(mk_poc(), ev_t1)
    det_t.make_finding(mk_poc(), ev_t2)
    c1 = (outdir / ev_t1.artifact).read_text(encoding="utf-8")
    c2 = (outdir / ev_t2.artifact).read_text(encoding="utf-8")
    check("[TRUNCATED]" not in c1, "只差 1 字节不写截断标注（否则报告像残页）")
    check("[TRUNCATED]" in c2 and "9000" in c2, "真缺内容时如实标注原始字节数")

    print(f"\n结果：{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
