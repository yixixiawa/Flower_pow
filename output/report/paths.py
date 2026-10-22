"""路径规划：产物落哪、叫什么、撞名怎么办。

原 ``report.py`` 的路径段。三份产物共用同一套 stem 推导与撞名消歧，
所以单独成块——``overwrite`` 语义只在���里决定一次。"""

from __future__ import annotations

import json
import time
import hashlib
import re as _re
from pathlib import Path
from core.state import ScanResult
from core.state import safe_name
from output.report.naming import _split_host
from output.report.naming import _stamp
from output.report.naming import registrable_domain
from output.report.naming import target_domain


def _unique_path(outdir: Path, stem: str, suffix: str) -> Path:
    """避免覆盖：同名时追加 ``_2`` ``_3``。

    只在 ``overwrite=False`` 时用到（见 :func:`_target`）。
    """
    p = outdir / f"{stem}{suffix}"
    if not p.exists():
        return p
    for i in range(2, 100):
        p = outdir / f"{stem}_{i}{suffix}"
        if not p.exists():
            return p
    return outdir / f"{stem}_{int(time.time())}{suffix}"


def report_dir(outdir: Path, stem: str) -> Path:
    """一次导出的**专属文件夹**：``<outdir>/<stem>/``。

    三种格式（json/md/html）全部落在里面，目录名就是报告主干。
    以前三份产物平铺在 output/ 根下，扫几轮之后根目录堆满
    report_*/scan_*/subs_* 文件，想找"这次那份"得靠猜；
    收入文件夹后一次导出 = 一个目录，时间+域名一目了然。
    返回前保证目录已存在（writer 直接往里写）。
    """
    d = outdir / stem
    d.mkdir(parents=True, exist_ok=True)
    return d


def _target(outdir: Path, stem: str, suffix: str, overwrite: bool) -> Path:
    """算出这次要写到哪个文件（位于该次报告的文件夹内）。

    **默认就地覆盖同一个文件**（``overwrite=True``）。以前一律加 ``_2``/``_3``，
    结果是"改一轮导一次"堆出一串近似重复的报告，用户还得猜哪份是最新的；
    智能体也没法接着上一份改，只能整篇重写。

    报告是**可重新生成的产物**（证据文件在 ``evidence/`` 里另存，不受影响），
    覆盖它丢掉的只是上一次渲染结果，重跑一次就有。所以默认覆盖是安全的；
    确实想留档时传 ``overwrite=False``。
    """
    if overwrite:
        d = report_dir(outdir, stem)
        return d / f"{stem}{suffix}"
    # 非覆盖：候选**文件夹**递增——``_2`` 体现在文件夹名上
    # （``<outdir>/<stem_2>/<stem_2>.md``），不能把 _2 文件塞进第一份
    # 报告的文件夹里。writer 会自建 path.parent，这里不 mkdir。
    for i in range(1, 100):
        cand = stem if i == 1 else f"{stem}_{i}"
        p = outdir / cand / f"{cand}{suffix}"
        if not p.exists():
            return p
    stamp = f"{stem}_{int(time.time())}"
    return outdir / stamp / f"{stamp}{suffix}"


def report_paths(result: ScanResult, outdir: Path) -> dict[str, Path]:
    """三种格式**将要写入**的路径（覆盖模式下的确定性路径）。

    给调用方用：写之前先比对一下哪些是已存在的，好在返回值里说清
    "新建了哪些、覆盖了哪些"——覆盖必须是可见的，不能静默。
    """
    # 必须传 outdir：撞名判定要靠它读旧文件里记录的目标
    stem = _report_stem(result, outdir)
    d = report_dir(outdir, stem)
    return {ext: d / f"{stem}{_SUFFIX[ext]}" for ext in _FORMATS}


_SUFFIX = {"json": ".json", "md": ".md", "html": ".html"}
_FORMATS = ("json", "md", "html")


def plan_reports(
    result: ScanResult,
    outdir: Path,
    *,
    overwrite: bool = True,
    formats: tuple[str, ...] = _FORMATS,
) -> dict[str, Path]:
    """**一次性**决定这几种格式各自要写到哪个文件。

    为什么必须"一次决定"而不是让每个 ``write_*`` 自己算：``overwrite=False`` 时
    如果各自去 :func:`_unique_path`，先写的 json 占掉 ``_2`` 之后，后写的 md
    就会跳到 ``_3`` —— 三种格式主干对不上，报告与 JSON 快照就没法对号入座了
    （而它们本来是设计成共用同一个主干的）。

    ``overwrite=True`` 时就是**就地覆盖**的确定路径（同文件夹内）。
    """
    stem = _report_stem(result, outdir)
    if overwrite:
        d = report_dir(outdir, stem)
        return {ext: d / f"{stem}{_SUFFIX[ext]}" for ext in formats}
    # 找一个**这几种格式全都空闲**的文件夹，保证它们共用同一主干
    # （``_2`` 体现在文件夹名上：``<outdir>/<stem_2>/<stem_2>.md``）
    for i in range(1, 100):
        cand = stem if i == 1 else f"{stem}_{i}"
        d = outdir / cand
        paths = {ext: d / f"{cand}{_SUFFIX[ext]}" for ext in formats}
        if not any(p.exists() for p in paths.values()):
            return paths
    cand = f"{stem}_{int(time.time())}"
    d = outdir / cand
    return {ext: d / f"{cand}{_SUFFIX[ext]}" for ext in formats}


def _report_stem(result: ScanResult, outdir: Path | None = None) -> str:
    """报告文件名主干：``report_<日期>_<主域名>``，如 ``report_20261012_ftitle.studio``。

    日期在前、域名在后：先按时间扫一眼就能定位（"10 月 12 号那份"），
    多份报告按文件名排序时也天然就是时间序。

    给了 ``outdir`` 时会做**同名目标校验**：主域名相同但实际目标不同的两份报告
    不能悄悄合并成一份。发现撞了就给当前目标加一个子域后缀
    （``report_20261012_ftitle.studio_api.md``）；读不出旧文件的归属时不动
    （无法证明它属于别人，且用户本来就要求覆盖）。
    """
    base = f"report_{_stamp(result.started_at)}_{target_domain(result.target)}"
    if outdir is None:
        return base
    found = _existing_owner(outdir, base)
    if found is None:
        return base
    owner, _path = found
    if _same_target(owner, result.target):
        return base
    return f"{base}_{_disambiguator(result.target)}"


def _same_target(a: str, b: str) -> bool:
    """目标比较：忽略尾部斜杠与大小写（``https://A.com/`` == ``https://a.com``）。"""
    return (a or "").strip().rstrip("/").lower() == (b or "").strip().rstrip("/").lower()


def _recorded_target(path: Path) -> str:
    """从**已存在的报告**里读出它记录的目标；读不出返回空串。

    三种格式都写过目标：JSON 有 ``target`` 字段，Markdown 有 ``| 目标 | ``x`` |``
    表行，HTML 有标题。任一种能读出来就够用——不必要求它们都在。
    """
    try:
        if path.suffix == ".json":
            d = json.loads(path.read_text(encoding="utf-8"))
            return str(d.get("target") or "") if isinstance(d, dict) else ""
        head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return ""
    if path.suffix == ".md":
        m = _re.search(r"^\|\s*目标\s*\|\s*`([^`]+)`", head, _re.M)
        return m.group(1).strip() if m else ""
    if path.suffix in (".html", ".htm"):
        m = _re.search(r"<title>渗透测试报告\s*[—\-]\s*([^<]*)</title>", head)
        return m.group(1).strip() if m else ""
    return ""


def _existing_owner(outdir: Path, stem: str) -> tuple[str, Path] | None:
    """同名报告是否已存在、且归属哪个目标。都读不出来时返回 ``None``。

    报告现在住在自己的文件夹里（``<outdir>/<stem>/<stem>.md``），
    查存在性与读归属都要进文件夹看——只看根目录会永远找不到上一份。
    """
    for ext in (".md", ".json", ".html"):
        p = outdir / stem / f"{stem}{ext}"
        if not p.exists():
            continue
        owner = _recorded_target(p)
        if owner:
            return owner, p
    return None


def _disambiguator(target: str) -> str:
    """撞名时用的短后缀：优先取子域（``api``），没有子域就用主机名短哈希。"""
    host, _port = _split_host(target)
    d = registrable_domain(host)
    low = host.lower()
    if d and low.endswith("." + d):
        prefix = low[: -len(d) - 1].strip(".")
        if prefix:
            return safe_name(prefix.replace(".", "-"), 24)
    return "h" + hashlib.sha1(low.encode("utf-8")).hexdigest()[:6]
