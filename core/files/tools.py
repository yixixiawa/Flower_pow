"""本地文件工具——给模型/计划用的**只读**入口。

三个工具，全部只读、全部只碰"用户已经授权给本会话"的文件：

* ``list_session_files`` —— 列清单（不含正文）
* ``read_local_file`` —— 按 file_id 读，带行号；可指定行区间
* ``grep_local_file`` —— 在已授权文件里搜关键字（按行返回命中与行号）

为什么不做成 Runner 的内置工具：Runner 的工具都会过**面向目标**的权限
矩阵（那套矩阵的输入是 URL/方法/POC）。本地文件与目标无关，混进去会让
矩阵凭空多出"没有 URL 的请求"这种语义空洞。所以单独一层，判据只有一条：
**file_id 是否在本会话的授权台账里**（其余一律拒绝）。
"""

from __future__ import annotations

import re

LOCAL_TOOLS: frozenset[str] = frozenset(
    {"list_session_files", "read_local_file", "grep_local_file"}
)

# 单次返回给模型的正文上限（按行截断，避免一次把 20 万字塞进上下文）
MAX_TOOL_LINES = 400
MAX_GREP_HITS = 60


def run_local_tool(name: str, args: dict, session) -> str:
    """执行一个本地文件工具。**永远返回文本**（不向上抛）。

    拒绝/失败也返回文本：调用方（模型或 Work）需要看到原因，而不是
    一个空字符串——静默失败会让模型以为"读到了但是空的"。
    """
    files = getattr(session, "files", None)
    if files is None:
        return "【不可用】当前会话没有文件上下文"
    args = args or {}

    if name == "list_session_files":
        if not files.records():
            return "（本会话还没有授权任何本地文件：用 /read <路径> 添加）"
        rows = ["ID        文件                     类型        行数  状态"]
        for r in files.records():
            try:
                p = files.read(r.file_id)
                state = "ok" if p.ok else f"解析失败：{p.error[:40]}"
                rows.append(f"{r.file_id:<9} {r.name[:24]:<24} {p.kind:<10} {p.lines:>5}  {state}")
            except Exception as exc:  # noqa: BLE001
                rows.append(f"{r.file_id:<9} {r.name[:24]:<24} {'-':<10} {'-':>5}  不可读：{exc}")
        return "\n".join(rows)

    file_id = str(args.get("file_id") or args.get("id") or "").strip()
    if not file_id:
        return "【参数不合法】需要 file_id（先用 list_session_files 查）"

    if name == "read_local_file":
        try:
            parsed = files.read(file_id)
        except Exception as exc:  # noqa: BLE001
            return f"【已拦截】{exc}"
        if not parsed.ok:
            body = parsed.numbered(limit=MAX_TOOL_LINES)
            return f"【解析失败】{parsed.error}\n（以下为原文，仅供参考）\n{body}"
        start = _int(args.get("start"), 1)
        lines = _int(args.get("lines"), MAX_TOOL_LINES)
        body = _numbered_range(parsed.text, start, lines)
        note = "（已截断）" if parsed.truncated else ""
        return f"{parsed.text and '' or ''}{body}{note}"

    if name == "grep_local_file":
        pattern = str(args.get("pattern") or args.get("keyword") or "").strip()
        if not pattern:
            return "【参数不合法】需要一个搜索关键字 pattern"
        try:
            parsed = files.read(file_id)
        except Exception as exc:  # noqa: BLE001
            return f"【已拦截】{exc}"
        if not parsed.ok and not parsed.text:
            return f"【解析失败】{parsed.error}"
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            rx = re.compile(re.escape(pattern), re.I)
        hits: list[str] = []
        for i, line in enumerate(parsed.text.splitlines(), 1):
            if rx.search(line):
                hits.append(f"{i:>5}| {line[:300]}")
                if len(hits) >= MAX_GREP_HITS:
                    hits.append(f"    …（命中超过 {MAX_GREP_HITS} 条，已截断）")
                    break
        if not hits:
            return f"（{parsed.kind} 内没有匹配「{pattern}」的行）"
        return "\n".join(hits)

    return f"【未知本地工具】{name}"


def _int(value, default: int) -> int:
    try:
        n = int(value)
        return n if n > 0 else default
    except (TypeError, ValueError):
        return default


def _numbered_range(text: str, start: int, count: int) -> str:
    lines = text.splitlines()
    begin = max(1, start)
    end = min(len(lines), begin - 1 + max(1, count))
    out = [f"{i:>5}| {lines[i - 1]}" for i in range(begin, end + 1)]
    if end < len(lines):
        out.append(f"    …（共 {len(lines)} 行，可用 start/lines 继续读）")
    return "\n".join(out)
