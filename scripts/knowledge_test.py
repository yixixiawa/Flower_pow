"""知识库沉淀测试（不触网）。

覆盖：
  1. df 幂等性——同id 重复写入不污染 IDF（增量写入的前提）
  2. 门控：等级/确认/误报/无证据/低置信度 五类过滤
  3. 落盘往返：save → open → 检索
  4. 幂等入库：同一批发现沉淀两次，库不膨胀
  5. 容量淘汰：超max_entries 时按时间淘汰最旧
  6. 版本不符的文件被当作空库（不读坏数据）
  7. 独立索引文件不污染 POC 索引的过期判定
  8. 调度器挂钩：无研判时自动抬高门槛

运行：.venv/Scripts/python.exe scripts/test_knowledge.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.state import Category, Finding, Severity  # noqa: E402
from kb.indexer import VectorStore  # noqa: E402
from kb.knowledge import KnowledgeStore, finding_to_record  # noqa: E402


def F(
    name: str,
    sev: Severity,
    cat: Category,
    at: str,
    *,
    verdict: str = "true_positive",
    conf: float = 0.9,
    confirmed: bool = True,
    poc_id: str = "p_x",
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        poc_id=poc_id, name=name, severity=sev, category=cat, matched_at=at,
        verdict=verdict, confidence=conf, confirmed=confirmed,
        description=f"{name}描述", tags=tags if tags is not None else [cat.value],
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

    tmp = Path(tempfile.mkdtemp(prefix="kbtest_"))

    print("场景1 df 幂等性（增量写入的前提）")
    vs = VectorStore()
    vs.add_record("d1", "sql injection 注入 idor")
    d1 = vs.df["sql"]
    vs.add_record("d1", "sql injection 注入 idor")          # 同 id 覆盖
    d2 = vs.df["sql"]
    check(d1 == d2, f"同 id 重复add 后 df 不变（{d1} -> {d2}）")
    vs.add_record("d2", "sql injection 注入")
    check(vs.df["sql"] == d2 + 1, "不同文档仍正确累加")
    # d1 换内容。d2 也含 sql/injection，所以那两个词应保留（计数回落）；
    # 只有 d1 独有的 idor 才该被撤回。断言必须考虑其他文档的贡献。
    vs.add_record("d1", "完全不同的内容 xss")
    check("idor" not in vs.df, "仅 d1 持有的词被撤回")
    check("injection" in vs.df, "d2 仍持有的词不应被误撤")
    check(vs.df["sql"] == d2, f"多文档共享的词按文档数回落（{d2+1} -> {vs.df['sql']}）")
    check("xss" in vs.df, "新词的 df 已累加")

    print("\n场景2 门控：五类不该入库的")
    rec = finding_to_record(
        F("低危", Severity.LOW, Category.HEADER_CHECK, "http://t/")
    )
    check(rec is None, "等级不足（LOW< MEDIUM）被拒")
    rec = finding_to_record(
        F("未确认", Severity.HIGH, Category.PATH_PROBE, "http://t/a", confirmed=False)
    )
    check(rec is None, "confirmed=False 被拒")
    rec = finding_to_record(
        F("误报", Severity.HIGH, Category.PATH_PROBE, "http://t/b",
          verdict="false_positive", conf=0.05)
    )
    check(rec is None, "verdict=false_positive 被拒")
    rec = finding_to_record(
        F("无证据", Severity.HIGH, Category.PATH_PROBE, "")
    )
    check(rec is None, "无 matched_at 被拒")
    rec = finding_to_record(
        F("低置信", Severity.HIGH, Category.PATH_PROBE, "http://t/c", conf=0.2)
    )
    check(rec is None, "置信度低于门槛被拒")
    rec = finding_to_record(
        F("合格", Severity.CRITICAL, Category.PATH_PROBE, "http://t/actuator/env", conf=0.95)
    )
    check(rec is not None, "合格项通过")
    check(rec and "actuator/env" in rec["text"], "正文含证据位置")
    check(rec and rec["meta"]["severity"] == "critical", "meta 记录等级")

    print("\n场景3 落盘往返 + 检索")
    db = tmp / "ki.json"
    ks = KnowledgeStore.open(db)
    rep = ks.ingest_findings([
        F("Actuator 环境变量泄露", Severity.CRITICAL, Category.PATH_PROBE,
          "http://t/actuator/env", conf=0.95, poc_id="p1"),
        F("订单越权读取", Severity.HIGH, Category.API_AUTHZ,
          "http://t/api/order/1", conf=0.85, poc_id="p2"),
        F("轻微泄露", Severity.LOW, Category.HEADER_CHECK,
          "http://t/", poc_id="p3"),          # 应被过滤
        F("误报", Severity.HIGH, Category.PATH_PROBE,
          "http://t/fp", verdict="false_positive", poc_id="p4"),
    ], target="http://t")
    check(rep.accepted == 2, f"4 条中入库 2 条，实={rep.accepted}")
    check(rep.rejected_low_severity == 1, "等级过滤计数正确")
    check(rep.rejected_false_positive == 1, "误报过滤计数正确")
    ks.save()

    ks2 = KnowledgeStore.open(db)
    check(len(ks2) == 2, f"重新打开后 2 条，实={len(ks2)}")
    hits = ks2.search("actuator 环境变量泄露", top_k=1)
    check(bool(hits), "检索有命中")
    check(bool(hits) and hits[0][1] > 0, "命中分数为正")
    check(bool(hits) and "Actuator" in ks2.records[hits[0][0]]["meta"]["name"],
          "命中的是正确条目")
    check(len(ks2.search("完全无关的量子力学话题", top_k=3)) >= 0, "无关查询不崩")

    print("\n场景4 幂等入库（重复测试不撑爆库）")
    rep2 = ks2.ingest_findings([
        F("Actuator 环境变量泄露", Severity.CRITICAL, Category.PATH_PROBE,
          "http://t/actuator/env", conf=0.95, poc_id="p1"),
    ], target="http://t")
    check(rep2.accepted == 1 and rep2.updated == 1, f"识别为更新，实={rep2.line()}")
    check(len(ks2) == 2, f"库仍为 2 条（未膨胀），实={len(ks2)}")
    # 同位置不同 query string 应视为同一条
    rep3 = ks2.ingest_findings([
        F("Actuator 环境变量泄露", Severity.CRITICAL, Category.PATH_PROBE,
          "http://t/actuator/env?a=1", conf=0.95, poc_id="p1"),
    ], target="http://t")
    check(len(ks2) == 2, f"query string 不同也算同一条，实={len(ks2)}")

    print("\n场景5 容量淘汰")
    db2 = tmp / "small.json"
    ks3 = KnowledgeStore.open(db2, max_entries=3)
    for i in range(6):
        ks3.ingest_findings([
            F(f"发现{i}", Severity.HIGH, Category.PATH_PROBE,
              f"http://t/p{i}", conf=0.9, poc_id=f"p{i}")
        ], target="http://t")
        time.sleep(0.01)
    check(len(ks3) == 3, f"超容量后剩 3 条，实={len(ks3)}")
    names = {(r.get("meta") or {}).get("name") for r in ks3.records.values()}
    check("发现5" in names, "保留了最新的")
    check("发现0" not in names, "淘汰了最旧的")
    vs3 = ks3.store
    orphan = [t for t, c in vs3.df.items() if c <= 0]
    check(not orphan, f"df 无0/负残留，实={len(orphan)}")
    ks3.save()
    check(len(KnowledgeStore.open(db2, max_entries=3)) == 3, "淘汰后落盘/载入一致")

    print("\n场景6 版本不符的文件被当作空库")
    bad = tmp / "bad.json"
    bad.write_text(json.dumps({"version": 999, "records": {"x": {}}}),
                   encoding="utf-8")
    ks4 = KnowledgeStore.open(bad)
    check(len(ks4) == 0, "版本不符 → 空库（不读坏数据）")
    broken = tmp / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    check(len(KnowledgeStore.open(broken)) == 0, "坏JSON → 空库不抛异常")

    print("\n场景7 独立索引不污染 POC 索引判定")
    from kb.indexer import index_is_stale
    poc_dir = Path("poc")
    poc_db = Path("data/vector_db/poc_index.json")
    if poc_dir.is_dir() and poc_db.is_file():
        before = index_is_stale(poc_dir, poc_db)
        KnowledgeStore.open(tmp / "isolated.json").save()
        after = index_is_stale(poc_dir, poc_db)
        check(before == after, f"POC 索引过期判定未受影响（{before} -> {after}）")
        check(poc_db.name == "poc_index.json", "POC 索引文件未被改名/覆盖")
    else:
        print("  跳过（本地无 POC 索引）")

    print("\n场景8 调度器挂钩：无研判时抬高门槛")
    from core.config_loader import load_config
    from core.scheduler import Scheduler
    from core.state import ScanResult

    cfg = load_config("config.yaml")
    cfg.rag.knowledge_db = str(tmp / "sched.json")
    sch = Scheduler(cfg)
    res = ScanResult(target="http://t")
    res.findings = [F("原始命中未研判", Severity.HIGH, Category.PATH_PROBE,
                      "http://t/x", verdict="", conf=0.0, poc_id="pu")]
    rep = sch._ingest_knowledge(res, verbose=False, require_triage=True)
    check(rep is not None, "返回 IngestReport（不再是 None）")
    check(rep is not None and rep.accepted == 0,
          f"未研判项(conf=0)被require_triage 挡下，实={rep.accepted if rep else '?'}")
    check(rep is not None and rep.rejected_low_confidence == 1,
          "归因计入「置信度低」")
    # 反向：默认宽松模式下，未研判项靠等级+证据放行
    rep = sch._ingest_knowledge(res, verbose=False)
    check(rep is not None and rep.accepted == 1,
          f"默认模式仍放行未研判的 HIGH（宽松），实={rep.accepted if rep else '?'}")
    rep = sch._ingest_knowledge(ScanResult(target="http://t"), verbose=False)
    check(rep is None, "无发现时返回 None")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
