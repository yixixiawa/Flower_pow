"""产物文件（artifact）的保存与**定点查询**——让大输出只在磁盘上存在一份。

为什么需要它
------------
工具输出一大（JS bundle、JSON、全端口扫描、dirsearch 结果），现在有两条路：
截断进上下文（模型看不到剩下的，于是换着法儿重试，烧额度）或者落盘后
让模型 ``read_file`` 一页页翻（一页 400 行，翻十页就吃掉几万 token）。

两条路都不好。真正需要的是"我要 ``postData`` 这个关键字附近的内容"、
"我要 ``$.data.list`` 里前 20 条"——**查询**，而不是**通读**。
本模块提供三个维度的查询与一个结果缓存：

* ``keyword``    —— 命中行 + 前后各几行；
* ``start_line`` / ``end_line`` —— 精确行范围；
* ``jsonpath``   —— ``$.a.b`` / ``$.a[0].b`` / ``$.a[*].b`` / ``$..key`` 子集。

缓存键 = ``(相对路径, mtime_ns, size, 查询参数)``：同一个 artifact 同一个查询
第二次直接命中缓存，不重复读盘、不重复计算（任务书 五.4）。文件一变
（mtime/size 变）缓存自然失效——不会返回上一次的内容。

安全边界
--------
只允许查**产物目录内**的文件（默认 ``<output_dir>/``）。``..``、绝对路径、
盘符、UNC 一律拒绝；最后用 ``resolve()`` 再确认一次落在根内，挡住符号链接/
junction 逃逸（与 :mod:`core.fsops` 同一套判据）。读产物不需要 ``readonly``，
它不碰目标。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: 单次查询返回的字符上限（超出截断并提示缩小范围）
MAX_QUERY_CHARS = 6000

#: 关键字命中上下文行数（默认前后各 3 行）
DEFAULT_CONTEXT = 3

#: 缓存条目上限
CACHE_SIZE = 64

_WRAP = 2000  # 落盘时单行折到这个长度：read_file/查询都按行算，单行 10 万字符没法读

_JSONPATH_TOKEN = re.compile(
    r"""
    \.\.(?P<deep>[A-Za-z_$][\w$-]*)      # ..key
    | \.(?P<key>[A-Za-z_$][\w$-]*)        # .key
    | \[(?P<idx>-?\d+)\]                 # [0]
    | \[\s*(?P<q>["'])(?P<qkey>.*?)(?P=q)\s*\]   # ["key"]
    | \[\s*(?P<star>\*)\s*\]             # [*]
    """,
    re.X,
)


class ArtifactError(Exception):
    """artifact 路径/查询不合法——调用方按"拒绝"处理，不回退成通读。"""


@dataclass
class QueryResult:
    path: str
    text: str
    matches: int = 0
    cached: bool = False
    total_lines: int = 0

    def render(self) -> str:
        head = f"artifact {self.path}（共 {self.total_lines} 行"
        head += f"，命中 {self.matches} 处" if self.matches else ""
        head += "，命中缓存）" if self.cached else "）"
        if not self.text:
            return head + "\n（查询没有命中。换关键字，或用 start_line/end_line 指定范围。）"
        return f"{head}\n{self.text}"


class ArtifactStore:
    """产物文件的保存与查询。"""

    def __init__(self, root: str | Path = ".", subdir: str = "tool-output") -> None:
        self.root = Path(root).resolve()
        self.base = self.root / subdir
        self._cache: dict[tuple, str] = {}
        self._seq = 0

    # ── 保存 ──────────────────────────────────────────────────────
    def save(self, text: str, name: str, *, wrap: int = _WRAP) -> str:
        """保存文本，返回**相对项目根**的路径（``tool-output/xxx.txt``）。

        超长单行折行：拉回来的 JSON 常常一整行几万字符，不折的话"按行查询"
        等于没有分页。
        """
        safe = re.sub(r"[^\w.\-]+", "_", str(name or "artifact"))[:60] or "artifact"
        self.base.mkdir(parents=True, exist_ok=True)
        self._seq += 1
        path = self.base / f"{safe}_{self._seq}.txt"
        lines: list[str] = []
        for ln in (text or "").splitlines() or [text or ""]:
            if len(ln) <= wrap:
                lines.append(ln)
            else:
                lines.extend(ln[i : i + wrap] for i in range(0, len(ln), wrap))
        path.write_text("\n".join(lines), encoding="utf-8")
        try:
            return str(path.relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(path)

    # ── 路径校验 ──────────────────────────────────────────────────
    def resolve(self, rel: str) -> Path:
        """把模型给相对路径解析成真实文件，越界就抛 :class:`ArtifactError`。"""
        raw = (rel or "").strip().replace("\\", "/")
        if not raw:
            raise ArtifactError("artifact 路径为空")
        if raw.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", raw):
            raise ArtifactError("只接受产物目录内的相对路径（绝对路径/盘符被拒绝）")
        if ".." in raw.split("/"):
            raise ArtifactError("路径包含 '..'，拒绝访问产物目录之外的文件")
        target = (self.root / raw).resolve()
        try:
            target.relative_to(self.base.resolve())
        except ValueError as exc:
            raise ArtifactError(f"路径不在产物目录（{self._rel_base()}）内") from exc
        if not target.is_file():
            raise ArtifactError(f"产物不存在：{raw}")
        return target

    def _rel_base(self) -> str:
        try:
            return str(self.base.resolve().relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(self.base)

    # ── 查询 ──────────────────────────────────────────────────────
    def query(
        self,
        rel: str,
        *,
        keyword: str = "",
        start_line: int = 0,
        end_line: int = 0,
        jsonpath: str = "",
        context: int = DEFAULT_CONTEXT,
        max_chars: int = MAX_QUERY_CHARS,
    ) -> QueryResult:
        path = self.resolve(rel)
        key = (
            str(path),
            path.stat().st_mtime_ns,
            path.stat().st_size,
            keyword,
            int(start_line or 0),
            int(end_line or 0),
            jsonpath,
            int(context or 0),
            int(max_chars or 0),
        )
        if key in self._cache:
            return QueryResult(path=rel, text=self._cache[key], matches=-1,
                               cached=True, total_lines=self._count_lines(path))

        raw = path.read_text(encoding="utf-8", errors="replace")
        lines = raw.splitlines()
        if jsonpath:
            text, n = _query_json(raw, jsonpath, max_chars=max_chars)
        elif keyword:
            text, n = _query_keyword(lines, keyword, context=context, max_chars=max_chars)
        elif start_line or end_line:
            text, n = _query_range(lines, start_line, end_line, max_chars=max_chars)
        else:
            # 无查询条件 = 预览开头（不是通读：明确截断并给出下一步建议）
            text = "\n".join(lines[:40])
            if len(lines) > 40:
                text += f"\n…（还有 {len(lines) - 40} 行。用 keyword 定位，或 start_line/end_line 指定范围）"
            n = 0
        if len(text) > max_chars:
            text = text[:max_chars] + f"\n…（已截断到 {max_chars} 字符，缩小范围再查）"
        self._remember(key, text)
        return QueryResult(path=rel, text=text, matches=max(0, n),
                           cached=False, total_lines=len(lines))

    def _remember(self, key: tuple, text: str) -> None:
        if len(self._cache) >= CACHE_SIZE:
            # 简单 FIFO：产物查询是一次性的，不需要更聪明的淘汰
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[key] = text

    @staticmethod
    def _count_lines(path: Path) -> int:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0


# ── 三种查询的实现 ────────────────────────────────────────────────
def _query_keyword(
    lines: list[str], keyword: str, *, context: int, max_chars: int
) -> tuple[str, int]:
    kw = keyword.strip()
    if not kw:
        return "", 0
    needle = kw.lower()
    hits = [i for i, ln in enumerate(lines) if needle in ln.lower()]
    if not hits:
        return "", 0
    ctx = max(0, int(context))
    out: list[str] = []
    used = 0
    shown: set[int] = set()
    for i in hits:
        lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
        chunk: list[str] = []
        for j in range(lo, hi):
            if j in shown:
                continue
            shown.add(j)
            chunk.append(f"{j + 1:>6}| {lines[j][:400]}")
        block = "\n".join(chunk)
        if used + len(block) > max_chars:
            out.append(f"…（命中 {len(hits)} 处，已达字符上限，缩小 keyword 或加行范围）")
            break
        out.append(block)
        used += len(block)
    return "\n--\n".join(out), len(hits)


def _query_range(
    lines: list[str], start_line: int, end_line: int, *, max_chars: int
) -> tuple[str, int]:
    lo = max(1, int(start_line or 1))
    hi = int(end_line or 0) or min(len(lines), lo + 199)
    hi = max(lo, min(hi, len(lines)))
    chunk = lines[lo - 1 : hi]
    text = "\n".join(f"{lo + i:>6}| {ln[:400]}" for i, ln in enumerate(chunk))
    return text[:max_chars], len(chunk)


def _query_json(raw: str, expr: str, *, max_chars: int) -> tuple[str, int]:
    """JSONPath 子集查询。解析失败按"拒绝"处理，不静默返回空。"""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"artifact 不是合法 JSON，无法用 jsonpath 查询：{exc.msg}") from exc
    matches = jsonpath_find(data, expr)
    if not matches:
        return "", 0
    chunks: list[str] = []
    used = 0
    for i, m in enumerate(matches):
        body = json.dumps(m, ensure_ascii=False, indent=2, default=str)
        if used + len(body) > max_chars:
            chunks.append(f"…（共 {len(matches)} 个匹配，已达字符上限，用更具体的路径缩小）")
            break
        chunks.append(f"[{i}] {body}")
        used += len(body)
    return "\n".join(chunks), len(matches)


def jsonpath_find(data: Any, expr: str) -> list[Any]:
    """极简 JSONPath 求值器：``$`` / ``.key`` / ``[0]`` / ``["k"]`` / ``[*]`` / ``..key``。"""
    path = (expr or "").strip()
    if not path.startswith("$"):
        raise ArtifactError("jsonpath 必须以 $ 开头，例如 $.data.list 或 $..id")
    nodes: list[Any] = [data]
    pos = 1
    while pos < len(path):
        m = _JSONPATH_TOKEN.match(path, pos)
        if not m:
            raise ArtifactError(f"jsonpath 语法不支持：{path[pos:]}（支持 .key / [n] / [*] / ..key）")
        pos = m.end()
        nxt: list[Any] = []
        if m.group("deep") is not None:
            nxt = _deep_find(nodes, m.group("deep"))
        elif m.group("key") is not None:
            key = m.group("key")
            nxt = [n[key] for n in nodes if isinstance(n, dict) and key in n]
        elif m.group("qkey") is not None:
            key = m.group("qkey")
            nxt = [n[key] for n in nodes if isinstance(n, dict) and key in n]
        elif m.group("idx") is not None:
            idx = int(m.group("idx"))
            for n in nodes:
                if isinstance(n, list) and -len(n) <= idx < len(n):
                    nxt.append(n[idx])
        else:  # [*]
            for n in nodes:
                if isinstance(n, list):
                    nxt.extend(n)
                elif isinstance(n, dict):
                    nxt.extend(n.values())
        nodes = nxt
        if not nodes:
            return []
    return nodes


def _deep_find(nodes: list[Any], key: str) -> list[Any]:
    out: list[Any] = []
    stack = list(nodes)
    guard = 0
    while stack and guard < 100_000:
        guard += 1
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k == key:
                    out.append(v)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


__all__ = [
    "ArtifactStore",
    "ArtifactError",
    "QueryResult",
    "jsonpath_find",
    "MAX_QUERY_CHARS",
]
