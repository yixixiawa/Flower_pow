"""公共小件：时间戳格式化与 notes 去重。

原 ``report.py`` 里被三份产物共用的小函数。单独成块是为了让 json / markdown /
html 都能依赖它，而不必互相依赖（否则三者会成环）。"""

from __future__ import annotations

from datetime import datetime


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


# core/repl.py 的 /report 会给执行说明加这个哨兵前缀，以便重复调用时
# 先清掉旧的再重写。输出前必须剥掉，不能出现在交付物里。
_NOTE_SENTINEL = "\x00report:"


def _dedupe_notes(notes: list[str]) -> list[str]:
    """把重复的执行说明折叠成「原句 × N」，并剥掉内部哨兵前缀。

    两件事：
    1. ``Session.result.notes`` 是**追加**的，同一条会话头会在每次
       ``/report`` 或每轮保存时被再写一遍。实测一份报告里出现过 10 遍
       完全相同的会话头——这种噪音会让读报告的人以为流程出了问题。
    2. ``core/repl.py`` 给 /report 产生的条目加了 ``\\x00report:`` 哨兵前缀
       以便重复调用时先清旧的；这个前缀不能出现在交付物里。

    保序：按首次出现的顺序输出，不打乱原有顺序。
    """
    counts: dict[str, int] = {}
    for raw in notes:
        # 剥掉内部哨兵前缀（\\x00 开头，正常文本不会有）
        n = raw[len(_NOTE_SENTINEL):] if raw.startswith(_NOTE_SENTINEL) else raw
        counts[n] = counts.get(n, 0) + 1
    return [
        n if c == 1 else f"{n}（重复 {c} 次）"
        for n, c in counts.items()
    ]

