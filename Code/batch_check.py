# -*- coding: utf-8 -*-
"""batch_check —— 一条/一批 POC 对多台服务器的批量检测驱动。

场景：同一软件部署在 N 台服务器上，验证某个漏洞是否普遍存在。
不走完整扫描流水线（侦察 → RAG → 研判），只做「加载 POC → 逐台验证」，
快、不出网、零 token。

用法::

    python Code/batch_check.py targets.txt                    # Code/ 下全部 POC
    python Code/batch_check.py targets.txt -p Code --out r.md # 指定 POC 目录与报告

``targets.txt`` 每行一个 URL（``#`` 开头是注释）::

    http://192.168.118.10:8080
    http://192.168.118.11:8080

也可用 ``--poc`` 只跑某几条::

    python Code/batch_check.py targets.txt --poc path-druid-unauth

为什么不用 ``flower_pow scan`` 循环跑：scan 是五阶段全流水线，每台都要
侦察 / RAG 召回 / LLM 研判，批量验证同一漏洞时 95% 的工作是重复的；
本脚本直接驱动 ``HttpDetector.verify``，每台只发 POC 声明的请求。
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from pathlib import Path

# 脚本在 Code/ 下，项目根是上一级——不切目录就没法 import 项目包
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config_loader import load_config  # noqa: E402
from core.state import Severity, safe_name  # noqa: E402
from detectors.http_detector import HttpDetector  # noqa: E402
from detectors.poc_loader import filter_executable, load_poc_dir  # noqa: E402


def load_targets(path: str) -> list[str]:
    """读目标清单：每行一个 URL，# 注释，空行跳过。"""
    out: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.rstrip("/"))
    return out


def pick_pocs(poc_dir: Path, only: list[str]) -> tuple[list, list[str]]:
    """加载并过滤 POC。返回 (pocs, errors)。"""
    pocs, errors = load_poc_dir(poc_dir)
    if only:
        wanted = set(only)
        pocs = [p for p in pocs if p.id in wanted]
        missing = wanted - {p.id for p in pocs}
        if missing:
            errors.append(f"--poc 指定的 id 不存在: {', '.join(sorted(missing))}")
    cfg = load_config()
    pocs, skips = filter_executable(pocs, readonly=cfg.scan.readonly)
    return pocs, errors + skips


async def run(pocs: list, targets: list[str], concurrency: int) -> list[dict]:
    """每个目标跑一遍全部 POC（run_many 自带并发与单条异常兜底）。"""
    cfg = load_config()
    det = HttpDetector(cfg.scan)
    sem = asyncio.Semaphore(concurrency)

    async def one(base: str) -> dict:
        async with sem:
            findings, errors = await det.run_many(pocs, base, concurrency=concurrency)
            hit_ids = {f.poc_id for f in findings}
            return {
                "target": base,
                "findings": findings,
                "errors": errors,
                "clean": [p.id for p in pocs if p.id not in hit_ids],
            }

    return await asyncio.gather(*(one(t) for t in targets))


def render(results: list[dict]) -> str:
    """汇总成「目标 × POC」矩阵文本。"""
    hit_rows: list[str] = []
    clean_rows: list[str] = []
    err_rows: list[str] = []
    for r in results:
        if r["errors"]:
            err_rows.append(f"  {r['target']}  {'; '.join(r['errors'][:3])}")
        by_poc = defaultdict(list)
        for f in r["findings"]:
            by_poc[f.poc_id].append(f)
        for poc_id, fs in sorted(by_poc.items()):
            best = max(fs, key=lambda f: Severity.order(f.severity) if hasattr(Severity, "order") else 0)
            hit_rows.append(f"  ✅命中  {r['target']}  [{poc_id}] {best.name}（{len(fs)} 处）")
        for p in r.get("clean", []):
            clean_rows.append(f"  ○未命中  {r['target']}  [{p}]")
    lines = ["", "════ 批量检测结果 ════"]
    lines += hit_rows or ["  （无命中）"]
    if err_rows:
        lines.append("── 错误 ──")
        lines += err_rows
    lines.append(f"共 {len(results)} 台目标，命中 {len(hit_rows)} 项")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="POC 批量检测：多台服务器 × Code/ 下的 POC")
    ap.add_argument("targets", help="目标清单文件（每行一个 URL）")
    ap.add_argument("-p", "--poc-dir", default=str(Path(__file__).resolve().parent),
                    help="POC 目录（默认：本脚本所在 Code/ 目录）")
    ap.add_argument("--poc", action="append", default=[],
                    help="只跑指定 id 的 POC（可重复）")
    ap.add_argument("-c", "--concurrency", type=int, default=4,
                    help="同时探测的目标数（默认 4）")
    ap.add_argument("--out", help="结果追加写入的 Markdown 报告路径")
    args = ap.parse_args()

    targets = load_targets(args.targets)
    if not targets:
        print("目标清单为空"); return 1
    pocs, errors = pick_pocs(Path(args.poc_dir), args.poc)
    if errors:
        print("加载告警：", *errors, sep="\n  ")
    if not pocs:
        print("没有可执行的 POC"); return 1

    print(f"POC {len(pocs)} 条 × 目标 {len(targets)} 台（并发 {args.concurrency}）")
    for p in pocs:
        print(f"  - [{p.id}] {p.name} ({p.severity.value})")

    results = asyncio.run(run(pocs, targets, args.concurrency))
    print(render(results))

    if args.out:
        with open(args.out, "a", encoding="utf-8") as fh:
            fh.write(render(results) + "\n")
        print(f"\n已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
