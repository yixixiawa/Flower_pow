"""三档定级 + 证据质量评分 + 第二次独立验证的回归测试（不触网）。

复现的问题：只有"确认 / 误报"两档时，POC 一次命中 + 模型一句"置信度 0.95"
就能把一条发现写进正式报告。而 0.95 是模型**对自己判断的信心**，不是
"该漏洞为真的概率 95%"——把两者当成一回事，就是误报的主要来源。

这里锁死三件事：
  1. 三档语义（Confirmed / Needs Review / Rejected）互斥且口径明确；
  2. EvidenceQuality 六维打分与强度分档，LLM 置信度不参与这个分数；
  3. 第二次独立验证四步（完整性 → 反向验证 → 独立复测 → 定级）的行为，
     用**假 fetch** 模拟各种响应，全程不发真实请求。

覆盖：
  1. FindingStatus：标签/说明/官方口径/宽松解析（含旧词 true_positive）
  2. EvidenceQuality：强度分档逐档对表（很弱/弱/中等/强/很强）
  3. decide_status：无响应 / 基线一致 / 复测失败 / 证据缺项 / 模型误报降级 / 强证据确认
  4. 二次验证：软 404 被驳回、真命中确认、复测不一致转复核、POST 跳过复测、
     基线取不到时不误判、header 类不走路径基线
  5. 序列化：status 往返 + 旧快照（confirmed=False）映射到 REJECTED
  6. ScanResult：counts 只算已确认，status_counts 三档
  7. apply_triage：模型只写置信度，不改证据分；判误报只降级
  8. 报告/JSON：三档计数、证据质量行、待复核附录
  9. 人工排除与三档联动（dismiss → REJECTED，undo 恢复原档）

运行：.venv/Scripts/python.exe scripts/finding_status_test.py
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
    EvidenceQuality,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    decide_status,
    dismiss_finding,
    restore_finding,
)
from detectors.second_pass import SecondPassVerifier  # noqa: E402

BASE = "http://t.example.com"


# ── 假 HTTP：只按 URL 返回预置响应，绝不发真实请求 ────────────────


class FakeDet:
    """最小 ``send_request`` 契约实现。

    ``routes`` 的 key 是 URL；值为 ``(status, body)`` 或 callable。未命中路由
    时返回 404 空页（相当于"随机不存在路径"）。
    """

    def __init__(self, routes: dict[str, object], *, fail_hosts: bool = False) -> None:
        self.routes = routes
        self.fail_hosts = fail_hosts
        self.calls: list[str] = []

    async def send_request(self, url, poc=None, method="GET", headers=None, body=""):
        self.calls.append(url)
        item = self.routes.get(url)
        if callable(item):
            item = item(url)
        if item is None:
            if self.fail_hosts:
                return Evidence(url=url, error="ConnectError: boom")
            return Evidence(
                url=url, status_code=404, body_excerpt="<html>not found</html>",
                body_size=24, response_headers={"server": "nginx"},
            )
        status, text = item  # type: ignore[misc]
        return Evidence(
            url=url,
            status_code=status,
            body_excerpt=text,
            body_size=len(text.encode("utf-8")),
            response_headers={"server": "nginx", "content-type": "text/html"},
        )


def mk(
    poc_id: str = "path-env",
    *,
    url: str = f"{BASE}/.env",
    status: int = 200,
    body: str = "DB_PASSWORD=sup3rsecret\nAPI_KEY=abcd1234",
    method: str = "GET",
    category: Category = Category.PATH_PROBE,
    detector: str = "http",
) -> Finding:
    return Finding(
        poc_id=poc_id,
        name=f"发现 {poc_id}",
        severity=Severity.HIGH,
        category=category,
        matched_at=url,
        evidence=Evidence(
            url=url,
            method=method,
            status_code=status,
            body_excerpt=body,
            body_size=len(body.encode("utf-8")),
            response_headers={"server": "nginx"},
            matched_pattern="响应内容 包含 DB_PASSWORD",
        ),
        detector=detector,
    )


def run(coro):
    return asyncio.run(coro)


def main() -> int:  # noqa: C901 - 测试脚本，线性铺开更易读
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # ── 1. 三档枚举 ───────────────────────────────────────────────
    print("场景1 三档状态语义")
    check(FindingStatus.CONFIRMED.label == "已确认漏洞", "CONFIRMED 中文标签")
    check(FindingStatus.NEEDS_REVIEW.label == "待人工复核", "NEEDS_REVIEW 中文标签")
    check(FindingStatus.REJECTED.label == "误报或无效命中", "REJECTED 中文标签")
    check(FindingStatus.CONFIRMED.official is True, "只有 CONFIRMED 算正式漏洞")
    check(
        not FindingStatus.NEEDS_REVIEW.official and not FindingStatus.REJECTED.official,
        "待复核与误报都不计入正式漏洞",
    )
    for raw, want in (
        ("confirmed", FindingStatus.CONFIRMED),
        ("true_positive", FindingStatus.CONFIRMED),
        ("needs_manual", FindingStatus.NEEDS_REVIEW),
        ("待复核", FindingStatus.NEEDS_REVIEW),
        ("false_positive", FindingStatus.REJECTED),
        ("REJECTED", FindingStatus.REJECTED),
    ):
        check(FindingStatus.parse(raw) is want, f"parse({raw!r}) → {want.value}")
    check(
        FindingStatus.parse("") is FindingStatus.CONFIRMED,
        "空值缺省为 CONFIRMED（老代码语义：未被否定的命中）",
    )
    check(
        FindingStatus.NEEDS_REVIEW.description.startswith("有可疑现象"),
        "待复核的说明写清了「不计入已确认数量」",
    )

    # ── 2. EvidenceQuality 分档 ───────────────────────────────────
    print("\n场景2 证据评分分档（对照需求里的强度表）")
    only_200 = EvidenceQuality(response_valid=True)
    check(only_200.points == 5, f"只有 HTTP 200 → 5 分，实={only_200.points}")
    check(only_200.strength_label == "很弱", "只有 200 判「很弱」")

    weak = EvidenceQuality(response_valid=True, evidence_complete=True,
                           baseline_different=True)
    check(weak.points == 35, f"关键词级命中（基线可区分）→ 35 分，实={weak.points}")
    check(weak.strength_label == "弱", "无专属特征判「弱」")

    medium = EvidenceQuality(
        response_valid=True, evidence_complete=True,
        baseline_different=True, signature_specific=True,
    )
    check(medium.points == 60 and medium.strength_label == "中等",
          f"命中专属特征 → 中等（实={medium.points}/{medium.strength_label}）")

    strong = EvidenceQuality(
        response_valid=True, evidence_complete=True, baseline_different=True,
        signature_specific=True, reproducible=True, retest_attempted=True,
    )
    check(strong.points == 80 and strong.strength_label == "强",
          f"以上 + 复测一致 → 强（实={strong.points}/{strong.strength_label}）")

    very_strong = EvidenceQuality(
        response_valid=True, evidence_complete=True, baseline_different=True,
        signature_specific=True, reproducible=True, retest_attempted=True,
        impact_proven=True,
    )
    check(very_strong.points == 100 and very_strong.strength_label == "很强",
          "能证明实际影响 → 很强")
    check(abs(very_strong.score - 1.0) < 1e-6, "score 归一到 0~1")
    check("独立复测" in very_strong.line(), "六维明细可读化")

    skipped = EvidenceQuality(response_valid=True, evidence_complete=True,
                              baseline_different=True)
    check(
        any("非破坏性" in g for g in skipped.gaps()),
        "没复测时 gaps 说明是按非破坏性原则跳过",
    )
    rt = EvidenceQuality.from_dict(very_strong.to_dict())
    check(rt is not None and rt.points == 100, "六维往返不丢分")

    # ── 3. decide_status 规则表 ───────────────────────────────────
    print("\n场景3 定级规则（模型不能单独定性）")
    st, why = decide_status(EvidenceQuality(), verdict="true_positive", llm_confidence=0.99)
    check(st is FindingStatus.REJECTED and "无效证据" in why,
          "无有效响应：模型再自信也驳回", why)

    same_as_baseline = EvidenceQuality(
        response_valid=True, evidence_complete=True,
        baseline_different=False, baseline_similarity=0.97,
    )
    st, why = decide_status(same_as_baseline, verdict="true_positive", llm_confidence=0.95)
    check(st is FindingStatus.REJECTED and "反向验证" in why,
          "与基线一致 → 驳回（软 404 一类）", why)

    retest_failed = EvidenceQuality(
        response_valid=True, evidence_complete=True, baseline_different=True,
        signature_specific=True, retest_attempted=True, reproducible=False,
    )
    st, why = decide_status(retest_failed)
    check(st is FindingStatus.NEEDS_REVIEW and "复测未复现" in why,
          "复测未复现 → 待复核（不是误报）", why)

    incomplete = EvidenceQuality(response_valid=True, baseline_different=True,
                                 signature_specific=True, evidence_complete=False)
    st, why = decide_status(incomplete)
    check(st is FindingStatus.NEEDS_REVIEW and "证据不完整" in why,
          "证据缺项 → 待复核", why)

    st, why = decide_status(strong, verdict="false_positive", llm_confidence=0.95)
    check(st is FindingStatus.NEEDS_REVIEW,
          "模型判误报 + 强证据 → 只压到待复核，不驳回", why)
    check("自评信心" in why and "不是漏洞为真的概率" in why,
          "理由里点明了模型置信度不是概率量级", why)

    st, why = decide_status(strong, verdict="true_positive", llm_confidence=0.3)
    check(st is FindingStatus.CONFIRMED, f"证据分 0.80 + 复测一致 → 确认（{why}）")
    check(strong.points / 100 >= 0.70, "确认门槛与实现一致")

    st, _ = decide_status(None, verdict="true_positive", evidence_score=0.0)
    check(st is FindingStatus.NEEDS_REVIEW, "没有证据评估时不因模型一句话就确认")

    # ── 4. 第二次独立验证 ─────────────────────────────────────────
    print("\n场景4 第二次独立验证（假 fetch，不触网）")
    soft404_body = "<html><head><title>404</title></head><body>页面不存在</body></html>"
    det = FakeDet({f"{BASE}/.env": (200, soft404_body)})
    f_soft = mk(url=f"{BASE}/.env", body=soft404_body)
    v = SecondPassVerifier(det, base_url=BASE)
    q = run(v.evaluate(f_soft))
    check(q.baseline_different is False, "命中内容与基线一致 → 基线不可区分")
    check(f_soft.status is FindingStatus.REJECTED, "软 404 被判为误报/无效命中")
    check(any("反向验证" in n for n in f_soft.verify_notes), "过程记录里写明了反向验证结论")

    det = FakeDet({f"{BASE}/.env": (200, "DB_PASSWORD=sup3rsecret\nAPI_KEY=abcd1234")})
    f_real = mk()
    q = run(SecondPassVerifier(det, base_url=BASE).evaluate(f_real))
    check(q.response_valid and q.evidence_complete, "证据完整性检查通过")
    check(q.baseline_different is True, "与随机路径基线可区分")
    check(q.reproducible is True, "复测一致")
    check(q.impact_proven is True, "响应里的 DB_PASSWORD 被认作可证影响")
    check(f_real.status is FindingStatus.CONFIRMED,
          f"真命中 → 已确认（实={f_real.status.value}）")
    check(f_real.evidence_score >= 0.85, f"证据分 {f_real.evidence_score}")

    # 证据是预置的，所以复测就是该 URL 的第一次真实请求：
    # 让它返回一个和首次命中不同的页面，模拟"一次性异常"
    def flaky(_url):
        return (200, "<html>maintenance</html>")

    f_flaky = mk(url=f"{BASE}/env2")
    q = run(SecondPassVerifier(FakeDet({f"{BASE}/env2": flaky}), base_url=BASE).evaluate(f_flaky))
    check(q.retest_attempted and not q.reproducible, "复测拿到了不一致的响应")
    check(f_flaky.status is FindingStatus.NEEDS_REVIEW,
          "复测不一致 → 待复核（一次性异常不等于漏洞）")

    f_post = mk(url=f"{BASE}/upload", method="POST")
    det_post = FakeDet({f"{BASE}/upload": (200, "DB_PASSWORD=x")})
    q = run(SecondPassVerifier(det_post, base_url=BASE).evaluate(f_post))
    check(q.retest_attempted is False, "POST 不做复测")
    check(any("非破坏性" in n for n in f_post.verify_notes), "记录了跳过复测的原因")
    check(
        not any(BASE + "/upload" == c for c in det_post.calls[1:]),
        "确实没有重放 POST 请求",
    )

    f_blind = mk(url=f"{BASE}/blind")
    q = run(
        SecondPassVerifier(
            FakeDet({f"{BASE}/blind": (200, "DB_PASSWORD=x")}, fail_hosts=True),
            base_url=BASE,
        ).evaluate(f_blind)
    )
    check(q.baseline_different is True,
          "基线抓不到时不判成通用响应（判错方向的代价不对称）")
    check(f_blind.status is not FindingStatus.REJECTED, "取不到基线不驳回")

    f_hdr = mk(
        poc_id="hdr-missing-hsts", url=f"{BASE}/", status=200, body="<html>home</html>",
        category=Category.HEADER_CHECK,
    )
    q = run(SecondPassVerifier(FakeDet({}), base_url=BASE).evaluate(f_hdr))
    check(q.baseline_different is True, "响应头类发现不走路径基线")
    check(any("不适用路径基线" in n for n in f_hdr.verify_notes), "写明了原因")

    mixed = [
        mk("m-conf"), mk("m-review", url=f"{BASE}/r"), mk("m-rej", url=f"{BASE}/x"),
    ]
    stats = run(SecondPassVerifier(FakeDet({}), base_url=BASE).run(mixed))
    check(stats["checked"] == 3, "run() 汇总覆盖全部条目")
    check(
        stats["confirmed"] + stats["needs_review"] + stats["rejected"] == 3,
        f"三档计数自洽，实={stats}",
    )

    f_done = mk("p-already-dismissed", url=f"{BASE}/done")
    dismiss_finding(f_done, "公开演示站点")
    stats2 = run(SecondPassVerifier(FakeDet({}), base_url=BASE).run([f_done]))
    check(stats2["skipped_dismissed"] == 1, "已排除项跳过二次验证")
    check(f_done.status is FindingStatus.REJECTED,
          "已排除项不会被二次验证「复活」成已确认")

    # ── 5. 序列化与旧快照兼容 ─────────────────────────────────────
    print("\n场景5 序列化与旧快照兼容")
    d = f_real.to_dict()
    check(d["status"] == "confirmed" and d["confirmed"] is True, "to_dict 带三档与兼容字段")
    check(d["quality"]["score"] == f_real.evidence_score, "六维明细落盘")
    back = Finding.from_dict(d)
    check(back.status is FindingStatus.CONFIRMED and back.evidence_score > 0,
          "新快照往返一致")

    legacy = dict(d)
    legacy.pop("status")
    legacy.pop("quality")
    legacy.pop("evidence_score")
    legacy["confirmed"] = False
    check(
        Finding.from_dict(legacy).status is FindingStatus.REJECTED,
        "旧快照 confirmed=False → REJECTED（口径不变）",
    )
    legacy2 = dict(legacy)
    legacy2["confirmed"] = True
    check(Finding.from_dict(legacy2).status is FindingStatus.CONFIRMED,
          "旧快照 confirmed=True → CONFIRMED")
    bare = dict(d)
    bare.pop("status")
    bare.pop("confirmed")
    check(Finding.from_dict(bare).status is FindingStatus.CONFIRMED,
          "连字段都没有时按「未被否定」处理")

    # ── 6. ScanResult 统计口径 ────────────────────────────────────
    print("\n场景6 统计口径：只有已确认计入漏洞数")
    r = ScanResult(target=BASE)
    a = mk("p-conf")
    a.status = FindingStatus.CONFIRMED
    b = mk("p-review")
    b.status = FindingStatus.NEEDS_REVIEW
    b.status_reason = "反向验证通过但独立复测未复现，需人工确认"
    c = mk("p-rej")
    c.status = FindingStatus.REJECTED
    c.status_reason = "响应与随机路径基线一致（软 404）"
    r.add_findings([a, b, c])
    check(len(r.confirmed_findings()) == 1, "confirmed_findings 只含已确认")
    check(len(r.needs_review_findings()) == 1, "needs_review_findings 单独一档")
    check(len(r.rejected_findings()) == 1, "rejected_findings 单独一档")
    check(r.counts()[Severity.HIGH.value] == 1, "counts() 只算已确认")
    sc = r.status_counts()
    check(sc == {"confirmed": 1, "needs_review": 1, "rejected": 1}, f"三档计数，实={sc}")
    check(len(r.by_severity()[Severity.HIGH.value]) == 1, "by_severity 只含已确认")

    # ── 7. 模型研判不再定性 ───────────────────────────────────────
    print("\n场景7 模型研判只写置信度，不改证据分/定级口径")
    from llm.client import LLMClient

    x = mk("p-llm")
    x.status = FindingStatus.NEEDS_REVIEW
    x.evidence_score = 0.60
    x.quality = EvidenceQuality(
        response_valid=True, evidence_complete=True,
        baseline_different=True, signature_specific=True,
    )
    LLMClient.apply_triage([x], {"p-llm#0": {
        "verdict": "true_positive", "confidence": 0.95, "rationale": "看着像",
    }})
    check(x.confidence == 0.95, "置信度照实写入")
    check(x.evidence_score == 0.60, "证据分不被模型改高")
    check(x.status is FindingStatus.NEEDS_REVIEW,
          "0.95 的置信度不能把 0.60 的证据分抬成已确认")
    check("llm-reject" not in x.tags, "判真阳性不加误报标签")

    LLMClient.apply_triage([x], {"p-llm#0": {
        "verdict": "false_positive", "confidence": 0.99, "rationale": "通用页面",
    }})
    check(x.status is FindingStatus.NEEDS_REVIEW, "模型判误报：只降级，不越过证据")
    check("llm-reject" in x.tags, "误报标签留痕")

    # ── 8. 人工排除与三档联动 ─────────────────────────────────────
    print("\n场景8 人工排除与三档联动")
    y = mk("p-dismiss")
    y.status = FindingStatus.CONFIRMED
    dismiss_finding(y, "公开演示站点")
    check(y.status is FindingStatus.REJECTED, "人工排除 → 误报档")
    check("人工判定误报" in y.status_reason, "理由写明是人工判定")
    restore_finding(y)
    check(y.status is FindingStatus.CONFIRMED, "撤销 → 恢复排除前的档位")

    # ── 9. 报告与 JSON ────────────────────────────────────────────
    print("\n场景9 报告呈现三档")
    from output.report import write_json, write_markdown

    tmp = Path(tempfile.mkdtemp())
    r.notes.append("二次验证：确认 1 / 待复核 1 / 误报 1")
    md = write_markdown(r, tmp).read_text(encoding="utf-8")
    check("| 已确认漏洞 | 1 条 |" in md, "概览给出已确认条数")
    check("| 待人工复核 | 1 条" in md, "概览给出待复核条数")
    check("## 待人工复核（不计入已确认漏洞）" in md, "有待复核附录")
    check("## 已排除的发现（误报复核）" in md, "误报附录仍在")
    body = md.split("## 渗透测试结果")[1].split("## 待人工复核")[0]
    check("p-review" not in body, "待复核项不进发现详情")
    check("p-rej" not in body, "误报不进发现详情")
    check("定级：**已确认漏洞**" in md, "详情段写明定级")
    check("证据质量" in md, "详情段给出证据质量")

    data = json.loads(write_json(r, tmp).read_text(encoding="utf-8"))
    check(data["status_counts"] == {"confirmed": 1, "needs_review": 1, "rejected": 1},
          f"JSON 三档汇总，实={data['status_counts']}")
    check(len(data["needs_review"]) == 1 and len(data["rejected"]) == 1,
          "JSON 单列待复核与误报")
    check(data["needs_review"][0]["reason"], "待复核项带原因")
    check(data["active_findings"] == 1, "active_findings 只算已确认")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
