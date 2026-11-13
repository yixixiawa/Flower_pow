"""会话在磁盘上的存取：列出 / 取最近 / 清扫空壳。

``purge_empty_sessions`` 会**删目录**——所以判定从严（判空要看凭证、
阶段、系统开场白，光有 id 不算非空），宁可漏删不可误删。

**列表路径必须逐条容错**：磁盘上的快照是外部输入（旧版本写的、手改过的、
写到一半被截断的）。一条读不出来只跳过它自己，绝不能把整份历史列表带崩——
``/sessions`` 报错等于用户"看不到任何历史会话"。
"""

from __future__ import annotations

import sys
from pathlib import Path
from core.session.session import Session


def _warn_skipped(names: list[str]) -> None:
    """坏快照只在 stderr 报一行汇总，不污染 ``/sessions`` 的正表。"""
    if not names:
        return
    head = "、".join(names[:3]) + ("…" if len(names) > 3 else "")
    print(
        f"[session] 跳过 {len(names)} 个读不出来的快照：{head}"
        "（文件损坏或版本过旧；不影响其余会话）",
        file=sys.stderr,
    )


def list_sessions(
    base_dir: str | Path, limit: int | None = 10
) -> list[tuple[str, Session]]:
    """列出可恢复的会话，按最后更新时间倒序。

    返回 ``[(session_id, Session), ...]``，已排除读不出来的快照。
    ``limit=None`` 表示**不截断**（``/sessions`` 要看全量，否则会话一多
    就只能看见最近十条，老会话永远选不到）。

    排序用快照文件的 mtime 而不是 ``created_at``——用户可能连续恢复同一个
    会话很多次，最近碰过的才是想继续的那个。
    """
    root = Path(base_dir)
    if not root.is_dir():
        return []
    items: list[tuple[float, str, Session]] = []
    skipped: list[str] = []
    for d in root.iterdir():
        if not d.is_dir():
            continue
        f = d / "session.json"
        if not f.is_file():
            continue
        try:
            s = Session.load(f)
        except Exception:  # noqa: BLE001 - 兜底：load 已容错，这里防未来回归
            s = None
        if s is None:
            skipped.append(d.name)
            continue
        try:
            mt = f.stat().st_mtime
        except OSError:
            continue
        items.append((mt, d.name, s))
    items.sort(key=lambda x: x[0], reverse=True)
    _warn_skipped(skipped)
    out = [(name, s) for _mt, name, s in items]
    return out if limit is None else out[: max(0, int(limit))]


def latest_session(base_dir: str | Path) -> Session | None:
    """取最近一次会话，用于断点续跑。

    最近那份读不出来时**继续往前找**，而不是直接返回"没有会话"——
    否则一个坏文件就能让 ``--resume`` 彻底失效。
    """
    root = Path(base_dir)
    if not root.is_dir():
        return None
    dirs = [d for d in root.iterdir() if d.is_dir() and (d / "session.json").is_file()]

    def _mtime(d: Path) -> float:
        try:
            return (d / "session.json").stat().st_mtime
        except OSError:
            return 0.0

    for d in sorted(dirs, key=_mtime, reverse=True):
        s = Session.load(d)
        if s is not None:
            return s
    return None


def purge_empty_sessions(base_dir: str | Path) -> list[str]:
    """清掉历史遗留的空会话目录，返回被删掉的目录名列表。

    为什么要有这个"清扫"而不只是"退出不保存"：早期的版本**每次退出都无条件
    落盘**，于是磁盘上已经躺着一批空壳（用户点进来又直接 ``/quit`` 就产生一个）。
    改掉落盘逻辑只能让新的不再产生，旧的那些还得有人来收。

    这也是为什么它做成**单独可调用**的函数而不是塞进 ``list_sessions``：
    列目录是只读操作（``/sessions`` 不该悄悄删东西），删除要显式触发。

    只删通过 :meth:`Session.is_empty` 判定、且确实含 ``session.json`` 的目录；
    读不出来的快照一律不动（可能是手改坏了，交给用户自己看更安全）。
    """
    root = Path(base_dir)
    if not root.is_dir():
        return []
    removed: list[str] = []
    for d in sorted(root.iterdir()):
        f = d / "session.json"
        if not d.is_dir() or not f.is_file():
            continue
        try:
            s = Session.load(f)
        except Exception:  # noqa: BLE001 - 坏快照一律不动
            continue
        if s is None or not s.is_empty():
            continue
        # load 已把目录名认作权威 id，但这里显式传 name 更直白：
        # 我们遍历的就是磁盘上的目录，删它天经地义。
        if s.delete(root, name=d.name):
            removed.append(d.name)
    return removed


__all__ = [
    "Session",
    "Turn",
    "ConversationTurn",
    "Phase",
    "BusinessModel",
    "latest_session",
    "list_sessions",
    "purge_empty_sessions",
    "redact",
    "redact_messages",
]
