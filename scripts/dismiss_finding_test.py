"""误报排除（删除/复核）的回归测试。

复现的真实问题：测试时发现报告里混进了误报，但**没有任何办法删掉它**——
findings 一旦入库就只能看着。典型误报是「公开演示站点」：站点本就建给人看，
暴露的配置、默认账号、接口文档属于设计而非漏洞，自动探针判断不了。

覆盖：
  1. Finding 三个新字段的往返 + 旧快照（无字段）兼容
  2. counts()/by_severity() 只算有效发现（报告概览随之自动正确）
  3. 报告：误报不出现在风险概览与发现详情，出现在「误报复核」附录
  4. JSON 导出：dismissed 标记 + active_findings/excluded 汇总
  5. 排除清单持久化：add/matches/remove/原子写/坏文件容错/host 归一
  6. 发现入库时自动套用排除清单（add_findings 是唯一收口）
  7. 工具注册与 handler 行为（无原因被拒、编号越界、undo、purge）
  8. 撤销必须连持久化清单一起删（否则重扫又标回来）
  9. 知识库不摄取已排除项
 10. REPL 命令注册（/fp）与编号稳定性（排除后编号不平移）

运行：.venv/Scripts/python.exe scripts/test_dismiss_finding.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _srcs import module_source  # noqa: E402

from core import exclusions  # noqa: E402
from core.session import Session  # noqa: E402
from core.state import (  # noqa: E402
    Category,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    dismiss_finding,
    restore_finding,
)
from core.tools import ToolRunner  # noqa: E402
from core.tools import BUILTINS  # noqa: E402


class FakeCfg:
    class scan:
        readonly = True
        timeout = 10
        concurrency = 8
    class rag:
        poc_dir = "./poc"


def mk(poc_id: str, sev: Severity = Severity.HIGH, at: str = "") -> Finding:
    return Finding(
        poc_id=poc_id,
        name=f"发现 {poc_id}",
        severity=sev,
        category=Category.CONTENT_MATCH,
        matched_at=at or f"https://demo.example.com/{poc_id}",
        evidence=Evidence(url=at or f"https://demo.example.com/{poc_id}", poc_id=poc_id),
        verdict="true_positive",
        confidence=0.9,
        rationale="探针命中",
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
    exclusions.set_store_path(tmp / "exclusions.json")

    print("场景1 Finding 字段往返与旧快照兼容")
    f = mk("path-backup-file")
    check(f.active is True, "默认是有效发现")
    dismiss_finding(f, "公开演示站点")
    check(f.dismissed and f.active is False, "标记后 dismissed=True、active=False")
    check(f.dismiss_reason == "公开演示站点", "原因被记录")
    check(f.dismissed_at > 0, "记录了排除时间")
    check(f.verdict == "true_positive",
          "**没有**改动 verdict（那是研判的客观结论，改了撤销就有损）")
    check("dismissed" in f.tags, "打上 dismissed 标签")
    back = Finding.from_dict(f.to_dict())
    check(back.dismissed and back.dismiss_reason == "公开演示站点",
          "to_dict/from_dict 往返保住排除状态")
    old = mk("legacy").to_dict()
    for k in ("dismissed", "dismiss_reason", "dismissed_at"):
        old.pop(k, None)
    lb = Finding.from_dict(old)
    check(lb.dismissed is False and lb.dismiss_reason == "",
          "旧快照（无这三个字段）加载后视为未排除")
    restore_finding(f)
    check(f.active and f.dismiss_reason == "" and "dismissed" not in f.tags,
          "撤销后字段与标签都干净")
    check(f.verdict == "true_positive", "撤销后 verdict 仍是原值（无损）")

    print("\n场景2 统计只看有效发现")
    r = ScanResult(target="https://demo.example.com")
    a, b, c = mk("p1"), mk("p2"), mk("p3", Severity.CRITICAL)
    r.add_findings([a, b, c])
    check(r.counts()[Severity.HIGH.value] == 2, "3 条都有效时 high=2")
    check(r.counts()[Severity.CRITICAL.value] == 1, "critical=1")
    dismiss_finding(a, "误报")
    check(r.counts()[Severity.HIGH.value] == 1, "排除一条后 high 降为 1")
    check(r.counts()[Severity.CRITICAL.value] == 1, "其他等级不受影响")
    check(len(r.active_findings()) == 2 and len(r.dismissed_findings()) == 1,
          "active/dismissed 视图各归各位")
    check(a not in r.by_severity().get(Severity.HIGH.value, []),
          "by_severity 不含已排除项（报告详情随之干净）")

    print("\n场景3 add_findings 去重与排序")
    n = r.add_findings([mk("p1")])          # 同 (poc_id, matched_at) 重复
    check(n == 0, f"重复发现不再累加，实={n}")
    check([x.poc_id for x in r.active_findings()][0] == "p3",
          "重排后 critical 在最前")

    print("\n场景4 报告：误报不进详情、进复核附录")
    from output.report import write_json, write_markdown

    md_path = write_markdown(r, tmp)
    md = md_path.read_text(encoding="utf-8")
    check("已排除的发现（误报复核）" in md, "有复核附录这一节")
    check("| 有效发现 | 2 条 |" in md, "有效发现数正确")
    check("已排除（误报） | 1 条" in md, "概览标出已排除条数")
    check("误报" in md.split("## 已排除的发现")[1][:400], "附录里能看到排除原因")
    detail = md.split("## 渗透测试结果")[1].split("## 已排除")[0]
    check("发现 p1" not in detail, "被排除项不出现在发现详情里")
    check("发现 p2" in detail and "发现 p3" in detail, "其余发现照常输出")

    j_path = write_json(r, tmp)
    data = json.loads(j_path.read_text(encoding="utf-8"))
    check(data["active_findings"] == 2, "JSON 顶层给了 active_findings")
    check(len(data["excluded"]) == 1 and data["excluded"][0]["reason"] == "误报",
          "JSON 顶层给了 excluded 汇总")
    check(data["counts"][Severity.HIGH.value] == 1, "JSON 里的 counts 也只算有效")
    check(any(x.get("dismissed") for x in data["findings"]),
          "findings 里保留 dismissed 标记（可追溯）")

    print("\n场景5 排除清单持久化")
    exclusions.set_store_path(tmp / "exclusions.json")
    good, msg = exclusions.add(
        "https://demo.example.com/x", "poc-x", "https://demo.example.com/a", "公开演示站点"
    )
    check(good, f"写入成功（{msg}）")
    check((tmp / "exclusions.json").exists(), "落盘文件存在")
    check(exclusions.is_excluded("demo.example.com", "poc-x", "https://demo.example.com/a"),
          "按 (poc_id, matched_at) 命中")
    check(exclusions.is_excluded("https://DEMO.example.com:443/y", "poc-x",
                                 "https://demo.example.com/a/"),
          "host 大小写/默认端口/尾斜杠都归一（换个写法排除不失效）")
    check(not exclusions.is_excluded("other.example.com", "poc-x",
                                     "https://demo.example.com/a"),
          "不同目标互不影响")
    check(exclusions.match_reason("demo.example.com", "poc-x",
                                  "https://demo.example.com/a") == "公开演示站点",
          "能取回记录的原因")
    exclusions.add("demo.example.com", "poc-noisy", "", "该 POC 在本站全误报",
                   scope="poc")
    check(exclusions.is_excluded("demo.example.com", "poc-noisy", "https://any/path"),
          "scope=poc 的条目对任意位置都命中")
    check(len(exclusions.entries("demo.example.com")) == 2, "该目标下有 2 条")
    n = exclusions.remove("demo.example.com", "poc-x", "https://demo.example.com/a")
    check(n == 1, f"删除返回条数，实={n}")
    check(not exclusions.is_excluded("demo.example.com", "poc-x",
                                     "https://demo.example.com/a"), "删除后不再命中")
    bad = tmp / "exclusions.json"
    bad.write_text("{ 这不是合法 JSON", encoding="utf-8")
    check(exclusions.load() == {} and exclusions.entries("demo.example.com") == [],
          "坏文件当空表，不抛异常")
    check(exclusions.summary() == [], "summary 也不炸")

    print("\n场景6 发现入库时自动套用排除清单")
    exclusions.set_store_path(tmp / "exclusions.json")
    exclusions.remove("demo.example.com")   # 清空重建
    exclusions.add("demo.example.com", "poc-known-fp",
                   "https://demo.example.com/old", "历史误报")
    sess = Session(target="https://demo.example.com")
    hit = mk("poc-known-fp", at="https://demo.example.com/old")
    fresh = mk("poc-new")
    sess.result.add_findings([hit, fresh])
    check(hit.dismissed, "命中排除清单的发现入库时就被标记")
    check("历史误报" in hit.dismiss_reason, f"带上历史原因，实={hit.dismiss_reason!r}")
    check(fresh.active, "未命中的发现不受影响")
    check(len(sess.result.active_findings()) == 1,
          "有效发现只剩 1 条（重扫不再把误报报出来）")
    n = sess.result.add_findings([mk("poc-known-fp", at="https://demo.example.com/old")])
    check(n == 0, "被排除的发现不会重复入库")

    print("\n场景7 工具注册与 handler 行为")
    names = [b.name for b in BUILTINS]
    check("dismiss_finding" in names, "dismiss_finding 在工具清单里")
    spec = [b for b in BUILTINS if b.name == "dismiss_finding"][0]
    check("ref" in (spec.params.get("required") or []), "ref 必填")
    check("reason" in spec.params["properties"], "reason 有参数定义")
    check(spec.group == "报告", f"归到报告组，实={spec.group}")
    f_spec = [b for b in BUILTINS if b.name == "findings"][0]
    check("include_dismissed" in f_spec.params["properties"],
          "findings 工具可以要求列出已排除项")

    runner = ToolRunner(FakeCfg(), [], str(tmp))
    s2 = Session(target="https://demo.example.com")
    exclusions.remove("demo.example.com")
    s2.result.add_findings([mk("p-a"), mk("p-b", Severity.MEDIUM)])
    out = runner.dismiss(s2, ref="1", reason="")
    check("reason 不能为空" in out, "缺原因被拒（报告要能解释为什么排除）")
    check(s2.result.active_findings()[0].active, "被拒时没有改动任何发现")

    out = runner.dismiss(s2, ref="99", reason="x")
    check("超出范围" in out, f"编号越界被拒，实={out[:40]!r}")
    out = runner.dismiss(s2, ref="", reason="x")
    check("ref 不能为空" in out, "空 ref 被拒")

    out = runner.dismiss(s2, ref="1", reason="公开演示站点，内容本就公开")
    check("已排除为误报" in out, f"成功排除，实={out[:40]!r}")
    check(s2.result.active_findings()[0].poc_id == "p-b", "被排除的是编号 1")
    check(exclusions.is_excluded(s2.target, "p-a", "https://demo.example.com/p-a"),
          "同时写进了持久化清单")

    out = runner.dismiss(s2, ref="1", undo=True)
    check("已撤销" in out, f"撤销成功，实={out[:40]!r}")
    check(len(s2.result.active_findings()) == 2, "撤销后两条都有效")
    check(not exclusions.is_excluded(s2.target, "p-a", "https://demo.example.com/p-a"),
          "撤销连持久化清单一起删（否则重扫又标回来）")

    out = runner.dismiss(s2, ref="1", purge=True)
    check("已彻底删除" in out, f"彻底删除成功，实={out[:40]!r}")
    check(len(s2.result.findings) == 1, "会话内真的删掉了")
    check(exclusions.is_excluded(s2.target, "p-a", "https://demo.example.com/p-a"),
          "彻底删除也落排除清单（否则下一轮又回来了）")

    print("\n场景8 引用解析：编号 / poc_id / 唯一子串")
    s3 = Session(target="https://demo.example.com")
    exclusions.remove("demo.example.com")
    s3.result.add_findings([mk("alpha-one"), mk("beta-two")])
    hit, err = ToolRunner.resolve_finding(s3, "1")
    check(hit is not None and hit.poc_id == "alpha-one", "编号 1 指向第一条")
    hit, err = ToolRunner.resolve_finding(s3, "2")
    check(hit is not None and hit.poc_id == "beta-two",
          "编号 2 指向第二条（同等级时保持入库序，编号稳定）")
    hit, err = ToolRunner.resolve_finding(s3, "beta-two")
    check(hit is not None and hit.poc_id == "beta-two", "完整 poc_id 命中")
    hit, err = ToolRunner.resolve_finding(s3, "beta")
    check(hit is not None and hit.poc_id == "beta-two", "唯一子串命中")
    hit, err = ToolRunner.resolve_finding(s3, "o")
    check(hit is None and "匹配到" in err, f"子串命中多条时拒绝而不是猜，实={err[:40]!r}")
    s4 = Session(target="https://demo.example.com")
    s4.result.add_findings([mk("dup-poc", at="https://demo.example.com/1"),
                            mk("dup-poc", at="https://demo.example.com/2")])
    hit, err = ToolRunner.resolve_finding(s4, "dup-poc")
    check(hit is None and "无法确定" in err, "同 poc_id 多位置时要求用编号")

    print("\n场景9 编号在排除后不平移")
    s5 = Session(target="https://demo.example.com")
    exclusions.remove("demo.example.com")
    s5.result.add_findings([mk("n1"), mk("n2", Severity.MEDIUM), mk("n3", Severity.LOW)])
    before = [f.poc_id for f in ToolRunner._finding_list(s5, include_dismissed=True)]
    ToolRunner.dismiss(s5, ref="2", reason="误报")
    after = [f.poc_id for f in ToolRunner._finding_list(s5, include_dismissed=True)]
    check(before == after, "全表编号顺序不因排除而改变（记下的编号仍指向同一条）")
    visible = [f.poc_id for f in ToolRunner._finding_list(s5)]
    check("n2" not in visible and visible == ["n1", "n3"], "默认视图隐藏已排除项")

    print("\n场景10 知识库不摄取已排除项")
    exclusions.remove("demo.example.com")
    s6 = Session(target="https://demo.example.com")
    ok_f, bad_f = mk("k-ok"), mk("k-bad")
    dismiss_finding(bad_f, "公开演示站点")
    s6.result.add_findings([ok_f, bad_f])
    from kb.knowledge import (
        DEFAULT_MIN_CONFIDENCE,
        KnowledgeStore,
        finding_to_record,
    )

    check(finding_to_record(bad_f, s6.target) is None,
          "已排除项被知识库门控拦下")
    check(finding_to_record(ok_f, s6.target) is not None,
          "有效发现仍可通过门控")

    store = KnowledgeStore(tmp / "kb_index.json")
    rep = store.ingest_findings(
        [bad_f], target=s6.target, min_severity=Severity.MEDIUM,
        min_confidence=DEFAULT_MIN_CONFIDENCE,
    )
    check(rep.accepted == 0, f"已排除项没被沉淀，实 accepted={rep.accepted}")
    check(rep.rejected_dismissed == 1,
          f"单独统计为「人工排除」而不是混进「未确认」或「误报」，实={rep.rejected_dismissed}")
    check("人工排除" in rep.line(), f"说明文案里能看到，实={rep.line()!r}")
    rep2 = store.ingest_findings(
        [ok_f], target=s6.target, min_severity=Severity.MEDIUM,
        min_confidence=DEFAULT_MIN_CONFIDENCE,
    )
    check(rep2.accepted == 1, f"有效发现照常沉淀，实 accepted={rep2.accepted}")

    print("\n场景11 REPL 命令注册")
    from core.repl import COMMANDS

    check("/fp" in COMMANDS, "/fp 在命令表里（补全与 /help 共用同一份）")
    import core.repl as _repl

    src = module_source("core.repl")
    check("ToolRunner.dismiss(" in src,
          "/fp 复用 ToolRunner.dismiss（人与模型同一套语义，不各写一遍）")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
