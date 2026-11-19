"""Finding Validator 回归测试：Agent → 正式报告之间的质量闸门。

覆盖的真实问题：模型很擅长把"看起来像漏洞"的东西写成一段结论。没有原始
响应、没有成立依据、影响一栏写「存在安全风险」——内容看着完整，交付方
拿着却无法复核。这个闸门要求七项信息齐全、具体、可核实，否则拦成
**待验证线索**（不进报告、不计漏洞数），并说清缺什么。

覆盖：
  1. 七字段齐全 → 通过
  2. 逐字段缺失 → 各自被点名（缺什么说得出来）
  3. 占位内容（待补充）→ 等于没填
  4. 套话/空话影响（存在安全风险 / 可能导致数据泄露）→ 拦截
  5. 空泛漏洞类型、非法 URL、无请求行、只有状态码、依据无锚点 → 拦截
  6. 触发条件与实际影响写成同一句 → 拦截
  7. record_finding 合格 → Finding 带 trigger/impact/validated
  8. record_finding 不合格 → 0 条发现 + 1 条线索 + 明确缺失字段
  9. 补齐后重提 → 自动销案（线索 promoted）
 10. 同一条线索反复提交不重复堆积（覆盖而非追加）
 11. 导出前复核：绕过提交路径的手工发现被降级 + 转线索，报告正文不含它
 12. 报告正文渲染「触发条件 / 实际影响」
 13. 线索进会话快照、但不进报告 JSON（正式报告必须干净）
 14. list_clues 工具区分"待补填"与"已升级"

运行：.venv/Scripts/python.exe scripts/finding_validator_test.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.session import Session  # noqa: E402
from core.state import (  # noqa: E402
    Category,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from core.tools import ToolRunner  # noqa: E402
from core.validation import FindingValidator, Submission  # noqa: E402

GOOD_RESP = (
    "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 26\n\n"
    '{"data":[{"id":"3.44.2"}]}'
)
GOOD_REQ = (
    "GET /rest/products/search?q=test')) UNION SELECT sqlite_version()-- HTTP/1.1\n"
    "Host: juice.test"
)


def good(**over) -> Submission:
    base = dict(
        vuln_type="SQL 注入",
        url="http://juice.test/rest/products/search?q=test",
        trigger="未认证用户在 q 参数注入 UNION 语句即可触发，无需任何凭证",
        raw_request=GOOD_REQ,
        raw_response=GOOD_RESP,
        basis=(
            "响应 data[0].id 回显 3.44.2（SQLite 版本号），"
            "与正常查询返回的 id=1 不同，证明 UNION 注入成立"
        ),
        impact="读取数据库版本号与 users 表内容，实测拿到 3 个用户的口令哈希",
        name="SQL 注入",
        severity="高危",
        base_url="http://juice.test",
    )
    base.update(over)
    return Submission(**base)


class FakeCfg:
    output_dir = "."
    readonly = True

    class scan:
        readonly = True
        timeout = 10
        concurrency = 8
        evidence_dir = ""

    class rag:
        poc_dir = "./poc"


def fields(res) -> set[str]:
    return {i.key for i in res.issues}


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    v = FindingValidator()

    print("场景1 七字段齐全 → 通过")
    r = v.validate(good())
    check(r.ok, f"全齐通过，实={[(i.key, i.kind) for i in r.issues]}")
    check(r.score == 1.0, f"通过率 1.0，实={r.score}")

    print("\n场景2 逐字段缺失 → 点名")
    cases = {
        "vuln_type": "漏洞类型",
        "url": "受影响 URL",
        "trigger": "触发条件",
        "raw_request": "原始请求",
        "raw_response": "原始响应",
        "basis": "漏洞成立依据",
        "impact": "实际影响",
    }
    for key, label in cases.items():
        res = v.validate(good(**{key: ""}))
        check(
            not res.ok and key in fields(res) and label in res.missing,
            f"缺 {label} 被拦并点名",
            f"issues={[(i.key, i.kind) for i in res.issues]}",
        )
    empty_blank = v.validate(good(impact="   "))
    check("impact" in fields(empty_blank), "纯空白等同未填")

    print("\n场景3 占位内容 → 等于没填")
    for text in ("待补充", "暂无", "TODO", "N/A", "见上文"):
        res = v.validate(good(trigger=text))
        kinds = {i.kind for i in res.issues if i.key == "trigger"}
        check(
            not res.ok and "placeholder" in kinds,
            f"触发条件「{text}」被判占位",
            f"{kinds}",
        )

    print("\n场景4 套话/空话影响 → 拦截")
    for text in ("存在安全风险", "可能导致数据泄露", "影响未知", "会造成严重后果"):
        res = v.validate(good(impact=text))
        check(not res.ok and "impact" in fields(res), f"影响「{text}」被拦")
    # 具体到"泄露什么"就放行——闸门拦的是空话，不是短句
    res = v.validate(good(impact="泄露数据库口令，可直连内网数据库"))
    check(res.ok, "写出具体后果就放行")

    print("\n场景5 格式/可核实性")
    check(
        "vuln_type" in fields(v.validate(good(vuln_type="漏洞"))),
        "「漏洞」不是漏洞类型",
    )
    check(
        "url" in fields(v.validate(good(url="某接口"))),
        "「某接口」不是可重放 URL",
    )
    check(
        "url" in fields(v.validate(good(url="ftp://a.test/x"))),
        "非 http(s) 拒绝",
    )
    rel = v.validate(good(url="/api/x"))
    check(rel.ok, "相对路径能按 base_url 补齐", f"{[(i.key, i.kind) for i in rel.issues]}")
    check(
        "raw_request" in fields(v.validate(good(raw_request="有个请求"))),
        "没有请求行 → 拦截",
    )
    check(
        "raw_response" in fields(v.validate(good(raw_response="HTTP/1.1 200 OK"))),
        "只有状态码 → 拦截",
    )
    check(
        "basis" in fields(v.validate(good(basis="疑似存在注入，建议排查"))),
        "成立依据没有可核对锚点 → 拦截",
    )
    dup = good(basis=GOOD_RESP)
    check(
        "basis" in fields(v.validate(dup)),
        "成立依据 = 响应原文 → 拦截（没说明为什么能证明）",
    )
    check(
        "trigger" in fields(
            v.validate(good(trigger=good().url))
        ),
        "触发条件只重复 URL → 拦截",
    )
    same = v.validate(good(trigger="未授权即可读取该接口的全部订单数据字段啊", impact="未授权即可读取该接口的全部订单数据字段啊"))
    check("impact" in fields(same), "触发条件与实际影响写成同一句 → 拦截")

    print("\n场景6 拦截文案说清缺什么")
    res = v.validate(good(impact="", raw_response=""))
    msg = res.block_message("clue_test01", headline="[高危] SQL 注入 @ http://x")
    check("已拦截" in msg, "明确标记已拦截")
    check("clue_test01" in msg, "给出线索 ID")
    check("实际影响" in msg and "原始响应" in msg, "列出缺失字段")
    check("不会出现在报告" in msg, "说明不进报告")
    check("record_finding" in msg, "给出补齐后的升级路径")

    print("\n场景7 record_finding：合格 → 正式发现")
    tmp = Path(tempfile.mkdtemp())
    cfg = FakeCfg()
    cfg.output_dir = str(tmp)
    session = Session(target="http://juice.test")
    runner = ToolRunner(cfg, [], str(tmp))

    base_call = dict(
        name="SQL 注入",
        severity="high",
        matched_at="http://juice.test/rest/products/search?q=test",
        evidence=good().basis,
        payload=GOOD_REQ,
        response=GOOD_RESP,
        trigger=good().trigger,
        impact=good().impact,
        category="sqli",
    )
    out = asyncio.run(runner.execute("record_finding", base_call, session))
    check("已登记（通过质量闸门）" in out, f"登记成功：{out[:60]}")
    check(len(session.result.findings) == 1, "进 findings 1 条")
    f = session.result.findings[0]
    check(f.validated, "Finding.validated = True")
    check(f.trigger and f.impact, "trigger/impact 落到 Finding 上")
    check(f.status is FindingStatus.CONFIRMED, "定级仍为已确认")

    print("\n场景8 record_finding：不合格 → 0 条发现 + 1 条线索")
    bad_call = dict(base_call)
    bad_call.pop("impact")
    bad_call["matched_at"] = "http://juice.test/other"
    out = asyncio.run(runner.execute("record_finding", bad_call, session))
    check("已拦截" in out, f"被拦：{out[:50]}")
    check("实际影响" in out, "返回里点名缺失字段")
    check(len(session.result.findings) == 1, "没有新增发现")
    clues = session.result.pending_clues
    check(len(clues) == 1, f"登记为线索 1 条，实={len(clues)}")
    check(clues[0].status == "pending", "线索状态 pending")
    check("实际影响" in clues[0].missing, "线索记下缺失字段")

    print("\n场景9 补齐后重提 → 自动销案")
    fixed = dict(bad_call)
    fixed["impact"] = "读取该接口全部订单数据，实测拿到 42 条含手机号与地址"
    out = asyncio.run(runner.execute("record_finding", fixed, session))
    check("已登记" in out and "销案" in out, f"补齐后通过并销案：{out[:60]}")
    check(len(session.result.findings) == 2, "正式发现 +1")
    check(
        all(c.status == "promoted" for c in session.result.pending_clues),
        "原线索标记 promoted",
    )

    print("\n场景10 反复提交同一条线索不堆积")
    n0 = len(session.result.pending_clues)
    for _ in range(3):
        asyncio.run(
            runner.execute(
                "record_finding",
                {**base_call, "matched_at": "http://juice.test/dup", "impact": "存在安全风险"},
                session,
            )
        )
    check(
        len(session.result.pending_clues) == n0 + 1,
        f"三条同类拦截只留 1 条线索，实={len(session.result.pending_clues) - n0}",
    )

    print("\n场景11 导出前复核：绕过提交路径的手工发现被降级")
    rogue = Finding(
        poc_id="manual_rogue",
        name="可疑的任意文件读取",
        severity=Severity.HIGH,
        category=Category.FILE_OP,
        matched_at="http://juice.test/download?file=../../etc/passwd",
        description="请求后返回了 root:x:0:0 的内容，疑似文件读取",
        evidence=Evidence(
            url="http://juice.test/download?file=../../etc/passwd",
            method="GET",
            request_line="GET /download?file=../../etc/passwd HTTP/1.1\nHost: juice.test",
            status_code=200,
            response_headers={"Content-Type": "text/plain"},
            body_excerpt="root:x:0:0:root:/root:/bin/bash",
        ),
        detector="manual",
        status=FindingStatus.CONFIRMED,
    )
    session.result.findings.append(rogue)
    from output.report import write_markdown

    md = write_markdown(session.result, tmp, "").read_text(encoding="utf-8")
    check(rogue.status is FindingStatus.NEEDS_REVIEW, "缺 trigger/impact 被降级为待复核")
    check("报告闸门拦截" in rogue.status_reason, f"状态原因写明：{rogue.status_reason[:40]}")
    check(
        any(c.source == "report-audit" for c in session.result.pending_clues),
        "导出复核也登记线索",
    )
    # 被拦的**不进正式发现正文**：它只会出现在「待人工复核」附录里
    # （附录明确标注"不计入已确认漏洞"，与线索清单是两种视图）。
    body_part = md.split("## 待人工复核")[0]
    check("可疑的任意文件读取" not in body_part, "被拦的不在正式发现正文里")
    check(
        "可疑的任意文件读取" in md.split("## 待人工复核")[-1],
        "只在待复核附录里出现（可复核、但不算漏洞）",
    )

    print("\n场景12 报告正文渲染触发条件 / 实际影响")
    check("触发条件" in md and good().trigger in md, "触发条件进正文")
    check("实际影响" in md and "42 条含手机号" in md, "实际影响进正文")

    print("\n场景13 线索进快照、不进报告 JSON")
    snap = session.to_dict()["result"]
    check("pending_clues" in snap and snap["pending_clues"], "会话快照含线索")
    from output.report import write_json

    data = json.loads(write_json(session.result, tmp).read_text(encoding="utf-8"))
    check("pending_clues" not in data, "报告 JSON 不含线索")
    check(data["status_counts"]["needs_review"] >= 1, "降级项计入待复核计数")

    print("\n场景14 list_clues 区分待补填与已升级")
    out = asyncio.run(runner.execute("list_clues", {}, session))
    check("待验证线索" in out and "不计入漏洞数量" in out, "抬头说清不算漏洞")
    check("待补填" in out, "列出待补填项")
    check("缺失字段" in out, "列出缺什么")
    out_all = asyncio.run(runner.execute("list_clues", {"include_promoted": True}, session))
    check("已升级" in out_all, "include_promoted 能看到历史")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
