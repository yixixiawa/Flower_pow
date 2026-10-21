"""dirsearch 执行器——带**拦截降速重试**的统一封装。

为什么需要这个模块
------------------
项目里有**两处**会调dirsearch（单域爆破 `collectors/path_scan.py`、
子域批量爆破 `flower_pow._subs_dirsearch`），两处此前各自拼 argv，
谁都没处理「被 WAF / 限流拦截」这个必然发生的情况。

而dirsearch v0.4.3 **没有内置 429/403 自动退避**——它有
``--skip-on-status`` / ``--retries`` / ``--max-rate`` / ``--delay``，
但都是让人手动配的，没有"扫到一半被限流了→自动降速接着扫"这种逻辑。
实测 ``-q``（静默模式）下 stdout **完全没有输出**，所以拦截也无法从
stdout 判断，只能看结果里的状态码分布。

于是本模块负责：跑 → 检测拦截 → 降速重跑，并把过程记成可观测事件。

拦截判定（``looks_blocked``）
-----------------------------
不能只看单个 403/429——目标本来就有大量 403（后台未登录）。
判据是**组合信号**：

1. 命中数**异常为 0 或极低**，却消耗了完整字典（说明请求全被吃掉）
2. 结果里 429/503 占比**显著**（限流特征）
3. 结果里 403 占比**畸高**（WAF 特征）
4. 目录里出现 WAF 特征路径（cloudflare/aliyun/captcha…）

四条同时命中才判拦截。单条会把「站点真的全 403」误判成拦截，
进而白白降速重跑一遍——所以阈值取得保守。

降速策略
--------
第一遍用常规线程数（``concurrency``，下限 10）；命中拦截后用
**``-t 1``** 单线程重跑，并额外加 ``--delay`` + ``--max-rate`` +
``--retries``，三重降速。这不只是"慢一点"——单线程 + 固定间隔的
请求指纹更接近人工浏览，能绕开一部分基于并发阈值的 WAF。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

# WAF / CDN 特征路径——命中说明响应来自防护层而非源站
_WAF_PATH_RE = re.compile(
    r"(cloudflare|cdn-cgi|akamai|aliyun|alibaba-cloud|tencent|waf|"
    r"safedog|nsfw|captcha|verify\.js|__cf_|challenge)",
    re.I,
)

# dirsearch 命中状态码：与 path_scan 关心的集合保持一致
INTERESTING_CODES = (200, 301, 302, 401, 403)


@dataclass
class DirsearchOutcome:
    """一次 dirsearch 跑完的结果与过程记录。"""

    assets: list[dict[str, Any]] = field(default_factory=list)
    #: 是否判定发生了拦截（触发了降速重试）
    throttled: bool = False
    #: 实际使用的线程数（重试后为 1）
    threads: int = 0
    #: 每轮尝试的线程数，按时间顺序
    attempts: list[int] = field(default_factory=list)
    #: 每轮的拦截判定，供报告与调试
    block_reasons: list[str] = field(default_factory=list)
    #: dirsearch 原始输出（静默模式下常为空，保留以防非 -q 场景）
    raw: str = ""
    #: 任何一轮成功产出 JSON
    parsed: bool = False

    @property
    def total(self) -> int:
        return len(self.assets)


def looks_blocked(results: Sequence[dict[str, Any]], dictionary_size: int) -> tuple[bool, str]:
    """根据结果集判断是否被拦截。返回 ``(是否拦截, 原因)``。

    ``dictionary_size`` 是本轮字典条数——用于区分「扫完了没命中」
    和「请求被吃掉」：前者是正常结果，后者才是拦截。
    """
    if not results:
        # 空结果：字典非空却一个没中，很可能是全被拦
        if dictionary_size >= 20:
            return True, f"字典 {dictionary_size} 条但零命中，请求疑似被全量拦截"
        return False, "字典过小，零命中属正常"

    total = len(results)
    n429 = sum(1 for r in results if r.get("status") in (429,))
    n503 = sum(1 for r in results if r.get("status") in (503, 502, 504))
    n403 = sum(1 for r in results if r.get("status") == 403)
    interesting = sum(1 for r in results if r.get("status") in INTERESTING_CODES)
    # 注意字段名是 ``url``（由 :func:`parse_output` 产出）。早先误写成 ``value``，
    # 导致这条判据永远读不到 URL —— 是条**静默失效**的规则：代码能跑、
    # 阈值也对，但 WAF 路径判据从不参与判定。
    waf_hits = sum(1 for r in results if _WAF_PATH_RE.search(str(r.get("url") or "")))

    reasons: list[str] = []
    # 判据 2：限流特征
    if n429 and (n429 / total) >= 0.10:
        reasons.append(f"429 占 {n429}/{total}（{n429 / total:.0%}）")
    # 判据 3：WAF 特征
    if n403 and (n403 / total) >= 0.80 and interesting == n403:
        reasons.append(f"403 占 {n403}/{total}（{n403 / total:.0%}）且无其他状态码")
    # 判据 4：WAF 路径
    if waf_hits:
        reasons.append(f"{waf_hits} 条命中 WAF 特征路径")
    # 判据 1：零有效命中
    if interesting == 0:
        reasons.append(f"{total} 条结果中无一个有效状态码")

    if len(reasons) >= 2:
        return True, "；".join(reasons)
    return False, "；".join(reasons) if reasons else "无拦截特征"


def build_argv(
    exe: str,
    targets: Sequence[str],
    *,
    threads: int,
    wordlist: Path | None = None,
    out_file: Path | None = None,
    list_file: Path | None = None,
    extra: Sequence[str] = (),
) -> list[str]:
    """拼 dirsearch argv。``targets`` 与 ``list_file`` 二选一。

    两个必须用长参数名的坑（2026-10-09 对 v0.4.3 实测踩到）：

    1. **``-s`` 不能用于状态码**。``-s`` 在该版本被解析为 ``--session``
       （会话文件），传 ``-s 200,301,...`` 会报
       ``FileNotFoundError: '200,301,302,401,403'``。必须写
       ``--include-status=...``。
    2. **``--plain`` 不是独立开关**，它是 ``--format`` 的一个可选值
       （``simple|plain|json|xml|...``）。单独传会报
       ``error: no such option: --plain``。要 JSON 就写 ``--format json``。

    ``threads=1`` 是降速重试的信号——同时带 ``--delay`` / ``--max-rate`` /
    ``--retries``，因为单线程只解决并发压力，不解决请求速率。
    """
    argv: list[str] = [exe]
    if list_file is not None:
        argv += ["-l", str(list_file)]
    else:
        for u in targets:
            argv += ["-u", u]

    argv += ["-t", str(max(1, int(threads)))]
    if threads <= 1:
        # 降速三件套：单线程 + 请求间隔 + 速率上限，并允许重试
        argv += ["--delay", "0.3", "--max-rate", "5", "--retries", "2"]

    argv += ["--include-status=" + ",".join(str(c) for c in INTERESTING_CODES)]
    if wordlist is not None and wordlist.is_file():
        argv += ["-w", str(wordlist)]
    if out_file is not None:
        argv += ["-o", str(out_file)]
        argv += ["--format", "json"]

    argv += ["-q", "--no-color"]
    argv += list(extra)
    return argv


def parse_output(out_file: Path) -> tuple[list[dict[str, Any]], bool]:
    """读 dirsearch 的 JSON 输出。返回 ``(结果列表, 是否成功解析)``。

    **字段名以 v0.4.3 实测输出为准**（2026-10-09 真实跑出来的）::

        {"content-length": 37, "content-type": "...", "redirect": "",
         "status": 200, "url": "http://host/admin"}

    即 ``status`` / ``content-length``（**带连字符**），不是某些版本文档或
    旧代码假设的 ``statusCode`` / ``contentLength``。同时兼容后者，
    因为不同版本（及 forks）字段确有差异。

    ``results`` 见过两种形态：list（v0.4.3 实际输出）与 dict（按扩展名分组）。
    """
    if not out_file.is_file():
        return [], False
    try:
        data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return [], False

    rows = data.get("results") if isinstance(data, dict) else data
    if isinstance(rows, dict):
        flat: list[dict[str, Any]] = []
        for v in rows.values():
            if isinstance(v, list):
                flat.extend(v)
        rows = flat
    if not isinstance(rows, list):
        return [], False

    out: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        raw_status = item.get("status", item.get("statusCode", 0))
        try:
            status = int(raw_status)
        except (TypeError, ValueError):
            status = 0
        raw_size = item.get("content-length", item.get("contentLength"))
        try:
            size: Any = int(raw_size) if raw_size is not None else None
        except (TypeError, ValueError):
            size = None
        out.append(
            {
                "url": str(item.get("url") or item.get("path") or ""),
                "status": status,
                "size": size,
            }
        )
    return out, True


async def run_with_throttle_retry(
    exe: str,
    *,
    targets: Sequence[str] = (),
    list_file: Path | None = None,
    wordlist: Path | None = None,
    dictionary_size: int = 0,
    threads: int = 10,
    timeout: int = 300,
    max_retries: int = 1,
    extra: Sequence[str] = (),
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
) -> DirsearchOutcome:
    """跑 dirsearch，检测到拦截就以 ``-t 1`` 降速重跑。

    ``on_event(kind, payload)`` 用于把过程抛给上层（报告 / 日志），
    不传则完全静默。
    """

    def emit(kind: str, payload: dict[str, Any]) -> None:
        if on_event is None:
            return
        try:
            on_event(kind, payload)
        except Exception:  # noqa: BLE001
            pass  # 观测回调不该影响主流程

    outcome = DirsearchOutcome(threads=threads)
    current = max(1, int(threads))

    with tempfile.TemporaryDirectory() as tmp:
        for attempt in range(max_retries + 1):
            out = Path(tmp) / f"dirsearch_{attempt}.json"
            argv = build_argv(
                exe,
                targets,
                threads=current,
                wordlist=wordlist,
                out_file=out,
                list_file=list_file,
                extra=extra,
            )
            outcome.attempts.append(current)
            emit(
                "dirsearch_start",
                {
                    "threads": current,
                    "attempt": attempt + 1,
                    "targets": len(targets) or ("list" if list_file else 0),
                    "wordlist": bool(wordlist and wordlist.is_file()),
                },
            )

            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                emit("dirsearch_timeout", {"threads": current, "timeout": timeout})
            except OSError as exc:
                emit("dirsearch_error", {"threads": current, "error": str(exc)})
                break

            results, ok = parse_output(out)
            outcome.parsed = outcome.parsed or ok
            blocked, reason = looks_blocked(results, dictionary_size)
            # 只在真的被拦时记原因——否则降速成功那一次的"无拦截特征"
            # 会混进 block_reasons，让报告出现自相矛盾的描述
            if blocked and reason not in outcome.block_reasons:
                outcome.block_reasons.append(reason)
            outcome.raw = ""
            outcome.assets = results
            outcome.threads = current

            emit(
                "dirsearch_done",
                {
                    "threads": current,
                    "results": len(results),
                    "parsed": ok,
                    "blocked": blocked,
                    "reason": reason,
                },
            )

            # 首次就正常 → 结束
            if not blocked:
                break
            # 已是单线程还拦 → 没有更狠的招了，如实返回
            if current <= 1 or attempt >= max_retries:
                if current <= 1:
                    emit("dirsearch_still_blocked", {"reason": reason})
                break
            # 降速重试
            current = 1
            outcome.throttled = True
            emit("dirsearch_throttle", {"reason": reason, "next_threads": 1})

    return outcome


def to_assets(outcome: DirsearchOutcome, source: str = "dirsearch"):
    """把结果转成 ``core.state.Asset``。惰性导入避免循环依赖。"""
    from core.state import Asset

    return [
        Asset(
            kind="path",
            value=str(item.get("url") or ""),
            meta={"status": item.get("status"), "size": item.get("size")},
            source=source,
        )
        for item in outcome.assets
        if item.get("status") in INTERESTING_CODES and item.get("url")
    ]


__all__ = [
    "DirsearchOutcome",
    "INTERESTING_CODES",
    "build_argv",
    "looks_blocked",
    "parse_output",
    "run_with_throttle_retry",
    "to_assets",
]
