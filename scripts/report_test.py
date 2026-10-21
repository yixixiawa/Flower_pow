"""报告生成链路的回归测试（不触网、不调真实模型）。

复现并锁死原bug：报告只输出「证据已充分…」这类评述、缺少完整章节。

覆盖：
  1. 校验器拒绝占位语（「证据已充分」这类）
  2. 校验器接受完整报告
  3. max_tokens 截断会被识别（模拟 finish_reason=length）
  4. **发现详情段永远存在**，即使 AI 正文不可用
  5. 重复 notes 被折叠 + 哨兵前缀被剥掉
  6. render_report 不再输出「请补写」这类把任务变成审稿的措辞
  7. 无发现时仍要求输出完整五章

运行：.venv/Scripts/python.exe scripts/test_report.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.state import (  # noqa: E402
    Category, Evidence, Finding, ScanResult, Severity,
)
from llm import prompt as P  # noqa: E402
from llm.client import LLMClient  # noqa: E402
from output.report import _dedupe_notes, write_markdown  # noqa: E402


def make_finding(i: int = 0) -> Finding:
    return Finding(
        poc_id=f"p_{i}", name=f"测试发现{i}", severity=Severity.HIGH,
        category=Category.PATH_PROBE,
        matched_at=f"http://t/path/{i}",
        description="这是一个测试发现", remediation="加上白名单校验",
        verdict="true_positive", confidence=0.9,
        rationale="响应内容匹配特征",
        evidence=Evidence(url=f"http://t/path/{i}", status_code=200,
                          body_size=1234, elapsed_ms=88,
                          body_excerpt="admin: root"),
    )


def make_result(n: int = 4) -> ScanResult:
    r = ScanResult(target="http://demo.test")
    r.findings = [make_finding(i) for i in range(n)]
    return r


GOOD_REPORT = """## 一、测试目标与范围
本次对 http://demo.test 进行了授权测试。

## 二、风险概览
共发现 4 条安全问题，其中高危 4 条。

## 三、发现详情
### 1. 测试发现0
- 命中：http://t/path/0
- 修复建议：加上白名单校验
### 2. 测试发现1
- 命中：http://t/path/1
- 修复建议：加上白名单校验
### 3. 测试发现2
- 命中：http://t/path/2
- 修复建议：加上白名单校验
### 4. 测试发现3
- 命中：http://t/path/3
- 修复建议：加上白名单校验

## 四、整体评价与修复优先级
整体风险偏高，建议优先处理上述问题。
""" + "补充说明：本报告基于实际响应证据生成。" * 5

META_REPORT = """证据已充分，无需补充更多内容。
以上内容已覆盖全部测试要点，详见上文。
"""


class FakeLLMClient(LLMClient):
    """绕过真实调用，只测校验逻辑。"""

    def __init__(self):
        self.errors = []
        self.calls = 0

    def _report_ok(self, text, result):
        return LLMClient._report_ok(self, text, result)


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    llm = FakeLLMClient()

    print("场景1 校验器拒绝占位语（原 bug 的症状）")
    check(not llm._report_ok(META_REPORT, make_result()),
          "「证据已充分/详见上文」被判为不可用")
    check(not llm._report_ok("", make_result()), "空正文被判为不可用")
    check(not llm._report_ok("太短", make_result()), "过短正文被判为不可用")
    check(not llm._report_ok(
        "## 随便写点东西\n" + "填充内容。" * 60, make_result(4)),
        "缺章节的正文被判为不可用")
    check(not llm._report_ok(
        "## 测试目标\n## 风险概览\n希望这份报告对你有帮助。" + "填充。" * 60,
        make_result(4)),
        "含客套话元叙述被判为不可用")

    print("\n场景2 校验器接受完整报告")
    check(llm._report_ok(GOOD_REPORT, make_result(4)), "完整报告通过校验")
    r1 = make_result(1)
    check(llm._report_ok(GOOD_REPORT, r1), "1 条发现也通过")

    print("\n场景3 max_tokens 截断被识别")
    class FakeChoice:
        finish_reason = "length"
        class message:
            content = "## 一、测试目标与范围\n被截断了"
    class FakeResp:
        choices = [FakeChoice()]
    class FakeCompletions:
        def create(self, **kw):
            FakeCompletions.last_kw = kw
            return FakeResp()
    class FakeChat:
        completions = FakeCompletions()
    class FakeSdk:
        chat = FakeChat()
    # client 是只读 property（backing 为 _client），只能用 __new__ 绕过 __init__
    c = LLMClient.__new__(LLMClient)
    d = c.__dict__
    d.update(calls=0, total_ms=0, errors=[], _client=FakeSdk(), api_key="k")
    d["cfg"] = type("C", (), {
        "temperature": 0.2, "max_tokens": 2048,
        "model": "test-model", "deep_model": "test-deep",
    })()
    try:
        c.ask("sys", "user", max_tokens=4000)
        check(False, "截断时抛出异常（未抛出）")
    except RuntimeError as e:
        check("截断" in str(e), f"截断时抛出明确异常：{e}")
    check(any("截断" in e for e in c.errors), "错误被记录到 errors")
    check(FakeCompletions.last_kw.get("max_tokens") == 4000, "max_tokens 已传递")

    print("\n场景4 发现详情段永远存在（核心修复）")
    tmp = Path(tempfile.mkdtemp())
    res = make_result(3)
    p = write_markdown(res, tmp, ai_body="")          # 无AI 正文
    body = p.read_text(encoding="utf-8")
    check("## 渗透测试结果" in body, "无 AI 正文时详情段仍在")
    check("http://t/path/0" in body, "命中 URL 保留")
    check("加上白名单校验" in body, "修复建议保留")
    check("admin: root" in body, "响应证据保留")
    p2 = write_markdown(res, tmp, ai_body=META_REPORT)  # AI 给的是占位语
    body2 = p2.read_text(encoding="utf-8")
    check("## 渗透测试结果" in body2, "AI 正文是占位语时详情段仍在（关键）")
    check("http://t/path/1" in body2, "AI 失败也不丢证据")
    p3 = write_markdown(res, tmp, ai_body=GOOD_REPORT)
    body3 = p3.read_text(encoding="utf-8")
    check("## 渗透测试结果" in body3, "有正常 AI 正文时详情段仍在")
    check(body3.count("http://t/path/") >= 3, "详情段包含全部 3 条发现")

    print("\n场景5 notes 去重 + 哨兵前缀剥离")
    notes = ["会话头"] * 10+ ["业务模型"] * 3 + ["唯一一条"]
    out = _dedupe_notes(notes)
    check(len(out) == 3, f"3 种内容折叠成3 行，实={len(out)}")
    check(any("重复 10 次" in o for o in out), "重复 10 次被标注")
    check("会话头" in out[0], "哨兵/内容保留在第一行")
    sent = ["\x00report:会话头", "\x00report:会话头", "别的"]
    out2 = _dedupe_notes(sent)
    check(not any("\x00" in o for o in out2), "哨兵前缀已剥除")
    check(len(out2) == 2, f"折叠后 2 行，实={len(out2)}")

    print("\n场景6 render_report 不再诱导「审稿」")
    rp = P.render_report(make_result(4))
    check("请补写" not in rp, "不再出现「请补写」")
    check("# 渗透测试报告" not in rp, "不再伪造完整报告骨架给模型")
    check("以下是需要写成报告的结构化素材" in rp, "明确告知这是素材")
    check("## 一、测试目标与范围" in P.REPORT_SYSTEM, "系统提示要求五章齐全")
    for kw in ("证据已充分", "无需补充", "从略"):
        check(kw in P.REPORT_SYSTEM, f"系统提示显式禁止「{kw}」")
    check("完整、可直接交付" in P.REPORT_SYSTEM, "强调写交付物本身")

    print("\n场景7 无发现时仍要求完整报告")
    empty = ScanResult(target="http://empty.test")
    rp2 = P.render_report(empty)
    check("未发现有效漏洞" in rp2, "明确告知无发现")
    check("五章" in rp2, "仍要求输出五章")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
