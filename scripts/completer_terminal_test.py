"""输入区行为级回归：不漂移 / 上方不被擦 / 不用绝对定位。

用 `_terminal_sim` 的假屏幕检查**屏幕结果**，而不是匹配转义字符串——
后者是自证的：代码拿"相对输入区"的行号去做绝对定位照样能通过断言。

覆盖：逐键推进（含折行、中文双宽、贴底上滚）、退格收缩、Tab 候选列表、
真实按键循环（假 msvcrt，含 Tab 两段式）、无 ANSI 兜底、VT 探测缓存、
提交收尾 `_finish_line` / `_erase_input`。

运行：.venv/Scripts/python.exe scripts/completer_terminal_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _terminal_sim import (  # noqa: E402
    ARGS,
    CMDS,
    _INLINE,
    _StrSink,
    _Term,
    _TermSink,
    _blank_term,
    _drive_input,
    _input_span,
    _residue_below,
    drive_keys,
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
    # ── 场景14 输入区不漂移（真实 bug 行为级回归）──────────────────
    print("\n场景14 输入区不漂移、上方内容不被抹（真实 bug 行为级回归）")
    # 真实症状：敲字时整个输入区往下掉、屏幕上方的输出被擦掉。
    # 根因：_repaint 拿"相对输入区"的行列去做**绝对**定位（\x1b[行;列H），
    #       光标被扔到屏幕左上角，下一次重绘就从那里开始 \x1b[J 擦屏。
    # 这里用终端模拟器检查**屏幕结果**，而不是去匹配转义串。
    import core.completer as _M2
    import core.completer.reader as _R
    import core.completer.keys as _K
    import core.completer.width as _W

    orig_cols = _W._cols
    orig_vt = _K._VT_ENABLED
    _W._cols = lambda: 21
    _K._VT_ENABLED = True

    def drift_case(cols, rows, marker_row, keys, title):
        _W._cols = lambda: cols
        term, trace = _drive_input(_M2, cols, rows, marker_row, keys)
        offs = {s - m for _, s, m, _ in trace if s >= 0 and m >= 0}
        check(offs == {1},
              f"{title}：输入区始终紧贴 marker 下一行（偏移恒为 1）",
              f"实={sorted(offs)}")
        residue = _residue_below(term)
        check(not residue, f"{title}：输入区下方没有残留旧字符",
              f"残留在行 {residue}")
        check(not term.uses_absolute_positioning(),
              f"{title}：全程没有绝对定位（\\x1b[行;列H）", "")
        return term

    try:
        # 短输入（不折行）
        drift_case(40, 12, 5, "hello", "短输入")
        # 长输入折行，跨多行
        drift_case(21, 12, 5, "a" * 30, "折行")
        # 折行后回删：光标行号会变小，按"新 prefix 行号"上移必然移不够
        drift_case(21, 12, 5, "a" * 30 + "\b" * 18, "折行后回删")
        # 中文双宽折行
        drift_case(21, 12, 5, "中" * 20, "中文折行")
        # 中英混排
        drift_case(31, 12, 5, "a" * 12 + "中" * 6 + "b" * 9, "中英混排")
        # 输入区贴屏幕底部：会触发整体上滚，相对偏移仍须恒定
        term, _ = _drive_input(_M2, 21, 8, 6, "a" * 40)
        check(term.scrolls > 0, "输入区贴底时确实发生了上滚（用例有效）")
        check(not term.uses_absolute_positioning(),
              "上滚场景也没有绝对定位")

        # 光标停在**中间**时重绘也要准（左右方向键/行内编辑）
        term = _Term(21, 12)
        sink = _TermSink(term)
        term.r, term.c = 5, 0
        term.grid[5] = list("L5".ljust(21))
        long_buf = "a" * 30
        crow = _M2._repaint(sink, "> ", long_buf, 5, cur_row=0)
        # prefix="> "+5个a=7列 → 光标该在 (0, 7)
        check(crow == 0, f"光标在行内时返回所在行 0，实={crow}")
        check(term.row(5).startswith("> aaaaa"), f"输入区画在第 5 行，实={term.row(5)!r}")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ══ 以下三节是"手动确认手感"的三个动作，固化成自动化用例 ══════
    # 都是**行为级**的：断言屏幕结果，而不是匹配转义字符串。

    # ── 场景14b 超宽长输入：跨多行，输入区首行一动不动 ────────────
    print("\n场景14b 超宽长输入：跨多行但输入区首行不动、不滚动、无残留")
    _W._cols = lambda: 21
    _K._VT_ENABLED = True
    try:
        term, sink = _blank_term(21, 20, 5)
        sink.write(_INLINE)
        crow = _M2._layout(_INLINE, 21)[0]
        buf = ""
        starts = []
        for i in range(60):
            buf += "a"
            crow = _M2._repaint(sink, _INLINE, buf, len(buf), cur_row=crow)
            starts.append(term.row_starting(_INLINE))
        # 10 列提示符 + 60 字符 = 70 列，终端 21 列 → 21+21+21+7 → 4 行
        start, end = _input_span(term)
        check(set(starts) == {6},
              f"逐键推进中首行恒为 6，实={sorted(set(starts))}")
        check(start == 6, f"输入区从 marker 下一行开始，实={start}")
        check(end - start + 1 == 4,
              f"70 列在 21 列终端上占 4 行，实={end - start + 1}")
        check(term.scrolls == 0, f"屏幕还放得下，不该滚动，实={term.scrolls}")
        check(not _residue_below(term), f"下方无残留，实={_residue_below(term)}")
        check(term.row(5) == "###MARK###", f"上方未被擦，实={term.row(5)!r}")
        check(not term.uses_absolute_positioning(), "没有用到绝对定位")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景14c 折行后退格回短输入：一路退回原位、不留残影 ─────────
    print("\n场景14c 折行后退格回短输入：行数收缩回 1 行、首行不变、无残影")
    _W._cols = lambda: 21
    _K._VT_ENABLED = True
    try:
        term, sink = _blank_term(21, 20, 5)
        sink.write(_INLINE)
        crow = _M2._layout(_INLINE, 21)[0]

        buf = "a" * 40
        for i in range(len(buf)):
            crow = _M2._repaint(sink, _INLINE, buf[: i + 1], i + 1, cur_row=crow)
        # 10 + 40 = 50 列 → 21+21+8 → 3 行
        s1, e1 = _input_span(term)
        check(e1 - s1 + 1 == 3, f"40 字符时占 3 行，实={e1 - s1 + 1}")

        starts = []
        for _ in range(38):          # 退格到只剩 2 个字符
            buf = buf[:-1]
            crow = _M2._repaint(sink, _INLINE, buf, len(buf), cur_row=crow)
            starts.append(term.row_starting(_INLINE))
        s2, e2 = _input_span(term)
        check(len(buf) == 2, f"退格到位（剩 {len(buf)} 字符）")
        check(set(starts) == {6},
              f"退格过程中首行恒为 6（不移得不够），实={sorted(set(starts))}")
        check(e2 - s2 + 1 == 1,
              f"缩回 1 行（10+2=12 列 < 21），实={e2 - s2 + 1}")
        check(_residue_below(term) == [],
              f"旧折行残留已擦净，残留在 {_residue_below(term)}")
        check(term.row(6).startswith(_INLINE + "aa"),
              f"输入区内容正确，实={term.row(6)!r}")
        check(term.row(5) == "###MARK###", f"上方未被擦，实={term.row(5)!r}")
        check(not term.uses_absolute_positioning(), "没有用到绝对定位")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景14d Tab 弹候选后继续打字：输入区稳定在候选列表下方 ─────
    print("\n场景14d Tab 弹候选后继续打字：输入区稳定在候选列表下方")
    _W._cols = lambda: 21
    _K._VT_ENABLED = True
    try:
        term, sink = _blank_term(21, 20, 2)
        sink.write(_INLINE)
        crow = _M2._layout(_INLINE, 21)[0]

        buf = "x" * 30
        for i in range(len(buf)):
            crow = _M2._repaint(sink, _INLINE, buf[: i + 1], i + 1, cur_row=crow)

        rd = _M2.PromptReader(_M2.Completer(CMDS, ARGS), stream=sink)
        crow = rd._show_candidates(_INLINE, buf, len(buf),
                                   ["/help", "/status"], cur_row=crow)
        cand_row = term.row_starting("/help")
        start_tab, _ = _input_span(term)
        check(cand_row >= 0 and term.row_starting("/status") == cand_row + 1,
              "两条候选各占一行、连续排列")
        check(start_tab == cand_row + 2,
              f"输入区紧贴候选列表下方（候选 {cand_row}，输入 {start_tab}）")
        check(not _residue_below(term), f"候选下方无残留，实={_residue_below(term)}")
        check(term.row(2) == "###MARK###", f"上方未被擦，实={term.row(2)!r}")

        # 继续在折行输入区上打字：不能再漂移，也不能把候选擦掉
        starts = []
        for i in range(10):
            b2 = buf + "y" * (i + 1)
            crow = _M2._repaint(sink, _INLINE, b2, len(b2), cur_row=crow)
            starts.append(term.row_starting(_INLINE))
        check(set(starts) == {start_tab},
              f"继续打字时输入区不漂移，实={sorted(set(starts))}")
        check(term.row_starting("/help") == cand_row
              and term.row_starting("/status") == cand_row + 1,
              "候选列表仍在原处、没被擦掉")
        check(not _residue_below(term), f"继续打字后仍无残留，实={_residue_below(term)}")
        check(term.scrolls == 0, f"全程不该滚动，实={term.scrolls}")
        check(not term.uses_absolute_positioning(), "整个 Tab 流程没有绝对定位")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景14e 同样是这三件事，但走**真实按键循环** ────────────────
    print("\n场景14e 三条动作走真实按键循环（假 msvcrt 喂键，Windows 分支）")
    # 14b/14c/14d 直接调 _repaint/_show_candidates，只证明"重绘函数对"。
    # 这里从 read() 进去，按键序列由假的 msvcrt 提供——**键盘分发**（含 Tab
    # 的"第一次只记候选、第二次才展示"）一并覆盖。
    _K._VT_ENABLED = True
    try:
        # (1) 超宽长输入：逐键推进中首行不动、无残留
        _W._cols = lambda: 21
        out, term, trace = drive_keys(_R, 21, 20, 5, ["a"] * 60 + ["\r"])
        starts = {s for s, _m, _sc in trace}
        check(starts == {6}, f"[按键] 超宽长输入首行恒为 6，实={sorted(starts)}")
        check(out == "a" * 60, f"[按键] 读回完整输入，实长度={len(out)}")
        check(_residue_below(term) == [], f"[按键] 下方无残留，实={_residue_below(term)}")
        check(term.row(5) == "###MARK###", "[按键] 上方未被擦")
        check(not term.uses_absolute_positioning(), "[按键] 全程无绝对定位")

        # (2) 折行后退格到短输入：一路退回 1 行，不留残影
        _W._cols = lambda: 21
        out, term, trace = drive_keys(
            _R, 21, 20, 5, ["a"] * 40 + ["\b"] * 38 + ["\r"]
        )
        starts = {s for s, _m, _sc in trace}
        check(starts == {6}, f"[按键] 退格过程中首行恒为 6，实={sorted(starts)}")
        check(out == "aa", f"[按键] 退格到剩 2 字符，实={out!r}")
        _s, e = _input_span(term)
        check(e - _s + 1 == 1, f"[按键] 缩回 1 行，实={e - _s + 1}")
        check(_residue_below(term) == [], f"[按键] 旧折行残留已擦净，实={_residue_below(term)}")
        check(term.row(5) == "###MARK###", "[按键] 上方未被擦")
        check(not term.uses_absolute_positioning(), "[按键] 全程无绝对定位")

        # (3) Tab 唯一候选直接补齐（证明补全真的接在键盘上）
        _W._cols = lambda: 40
        out, term, _tr = drive_keys(_R, 40, 12, 3, list("/repor") + ["\t", "\r"])
        check(out == "/report", f"[按键] Tab 把 /repor 补成 /report，实={out!r}")

        # (4) Tab 弹候选列表 → 继续打字：输入区稳定在候选列表下方
        # 终端 12 列、提示符 10 列，所以 "/re" 就已经折行了——正好覆盖
        # "折行输入 + 候选列表 + 继续打字"三者叠加。
        # 候选条数由 CMDS 现算，不硬编码（第一版我按 REPL 的完整命令表猜了 3 条，
        # 而这里的 CMDS 只有两条匹配，断言就假失败了）。
        exp_cands = sorted(c for c in CMDS if c.startswith("/re"))
        _W._cols = lambda: 12
        keys = list("/re") + ["\t", "\t"] + list("port") + ["\r"]
        out, term, trace = drive_keys(_R, 12, 18, 3, keys)
        check(out == "/report", f"[按键] 候选后继续打字得到 /report，实={out!r}")
        # 前 5 次取键（/ r e 两次 Tab）时输入区还在原来的首行 4；
        # 第 2 次 Tab 弹出候选后输入区被顶到候选列表下方（4 + 候选行数）。
        n_cand = len(exp_cands)
        before = {s for s, _m, _sc in trace[:5]}
        after = {s for s, _m, _sc in trace[5:]}
        check(before == {4}, f"[按键] 弹候选前输入区首行恒为 4，实={sorted(before)}")
        check(after == {4 + n_cand},
              f"[按键] 继续打字时稳定在候选下方（首行 {4 + n_cand}），实={sorted(after)}")
        cand_rows = [term.row_starting(c) for c in exp_cands]
        check(cand_rows == [4 + i for i in range(n_cand)],
              f"[按键] {n_cand} 条候选连续排列在 4..，实={cand_rows} / {exp_cands}")
        check(_residue_below(term) == [], f"[按键] 候选与输入区下方无残留，实={_residue_below(term)}")
        check(term.row(3) == "###MARK###", "[按键] 候选列表没吃掉上方内容")
        check(not term.uses_absolute_positioning(), "[按键] 整个 Tab 流程无绝对定位")
        check(term.scrolls == 0, f"[按键] 不该滚动，实={term.scrolls}")

        # (5) 顺带覆盖键盘分发本身：方向键（\x00 + 扫描码）、Ctrl+U、空回车
        _W._cols = lambda: 40
        out, _t, _tr = drive_keys(
            _R, 40, 12, 3, list("abcd") + ["\x00", "K", "\x00", "K", "X", "\r"]
        )
        check(out == "abXcd", f"[按键] 左移两格后插入，实={out!r}")
        out, _t, _tr = drive_keys(_R, 40, 12, 3, list("abcd") + ["\x15", "\r"])
        check(out == "", f"[按键] Ctrl+U 清空，实={out!r}")
        out, _t, _tr = drive_keys(_R, 40, 12, 3, ["\r"])
        check(out == "", f"[按键] 空回车返回空串，实={out!r}")
        # Delete 删的是**光标处**字符，所以要先左移一位（光标在末尾时按 Delete
        # 什么也不该发生——这也是一条语义，顺手一起断言）
        out, _t, _tr = drive_keys(_R, 40, 12, 3, list("abc") + ["\x00", "S", "\r"])
        check(out == "abc", f"[按键] 光标在末尾时 Delete 无效果，实={out!r}")
        out, _t, _tr = drive_keys(
            _R, 40, 12, 3, list("abc") + ["\x00", "K", "\x00", "S", "\r"]
        )
        check(out == "ab", f"[按键] 左移后 Delete 删掉光标处字符，实={out!r}")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景15 没有 ANSI 时退回单行重绘（不写坏终端）────────────
    print("\n场景15 无 ANSI 兜底：退回 \r 重画，不写越界")
    _K._VT_ENABLED = False
    try:
        s = _StrSink()
        ret = _M2._repaint(s, "> ", "a" * 100, 50)
        o = s.get()
        check("\x1b[" not in o, f"兜底路径不写任何 ANSI 序列，实={o!r}")
        check(o.startswith("\r") and o.count("\r") >= 2,
              "仍用 \\r 回行首 + 重画")
        check(ret == 0, f"兜底路径按单行处理，返回行号 0，实={ret!r}")

        # 单行内容必须被裁进 cols-1 列，否则会折行
        from core.completer import _plain_row_text
        check(_plain_row_text("short", 20) == "short", "短内容原样返回")
        cropped = _plain_row_text("a" * 50, 20)
        check(len(cropped) == 19 and cropped == "a" * 19,
              f"超宽裁到 19 列（cols-1），实={len(cropped)}")
        # 混合宽度：按显示列裁，不是按字符数
        cn = _plain_row_text("中" * 30, 21)
        check(sum(2 for _ in cn) <= 20, f"中文按显示列裁，实宽={sum(2 for _ in cn)}")
        # 超宽时保留末尾（看得见刚敲的字），而不是保留开头
        check(_plain_row_text("PREFIX" + "z" * 40, 10) == "z" * 9,
              "左截断保留末尾")

        # ── 行为级：兜底路径也不许让输入区往下掉 ──
        # 早先这里按整行宽度清屏并原样重写整行，超过一行就折行，于是每敲一个
        # 字符输入区往下掉一行（实测 25 个字符掉了 6 行、糊出 7 行残留）。
        _W._cols = lambda: 21          # 模拟器宽 21，_cols 必须一致
        term = _Term(21, 14)
        sink2 = _TermSink(term)
        term.grid[5] = list("###MARK###".ljust(21))
        term.r, term.c = 6, 0
        base_row = term.r
        buf2 = ""
        for k in "a" * 25:
            buf2 += k
            _M2._repaint(sink2, "> ", buf2, len(buf2))
        check(term.r == base_row,
              f"兜底路径光标行不漂移，实={term.r}（应为 {base_row}）")
        check(term.scrolls == 0, f"兜底路径不触发滚动，实={term.scrolls}")
        check(term.row(5) == "###MARK###", f"上方内容未被动，实={term.row(5)!r}")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景16 VT（ANSI）能力探测是进程级一次性的 ─────────────────
    print("\n场景16 VT（ANSI）能力探测")
    from core.completer import _enable_vt
    first = _enable_vt()
    check(isinstance(first, bool), f"返回布尔，实={first!r}")
    check(_enable_vt() is first, "重复调用结果稳定（缓存，不反复改控制台模式）")

    # ── 场景17 提交收尾：先把光标移到输入区末尾再换行 ─────────────
    print("\n场景17 提交收尾 _finish_line（折行也不残留）")
    from core.completer import _finish_line, _erase_input

    _K._VT_ENABLED = True
    _W._cols = lambda: 21
    try:
        # full = "> " + 30 个 x = 32 列 → 第1行第11列（0 基）
        # 光标在中间（cur_row=0）→ 相对下移 1 行、右移到第 11 列。
        s = _StrSink()
        _finish_line(s, "> ", "x" * 30, 3, cur_row=0)
        o = s.get()
        check("\x1b[1B" in o, f"从第0行下移到输入区末行，实={o!r}")
        check("\x1b[11C" in o, f"右移到整行末尾第11列，实={o!r}")
        check("H" not in o.replace("\x1b[J", ""), f"不用绝对定位，实={o!r}")
        check(o.endswith("\n"), "最后补一个真换行")

        # 光标已在末行（cur_row=1）→ 不该再上下移动，只回列首再右移
        s = _StrSink()
        _finish_line(s, "> ", "x" * 30, 30, cur_row=1)
        o = s.get()
        check("\x1b[1B" not in o and "\x1b[1A" not in o,
              f"已在末行就不再上下移动，实={o!r}")
        check("\x1b[11C" in o, f"仍右移到末尾，实={o!r}")
        check(o.endswith("\n"), "换行在定位之后")

        # 无 ANSI 时不写定位，仍给个换行（不会卡住终端）
        _K._VT_ENABLED = False
        s = _StrSink()
        _finish_line(s, "> ", "abc", 3)
        o = s.get()
        check("\x1b[" not in o and o == "\n", f"兜底只写换行，实={o!r}")
        _K._VT_ENABLED = True

        # _erase_input：rows=0 时不上移，rows>0 时上移
        s = _StrSink()
        _erase_input(s, 0)
        check("\x1b[A" not in s.get(), "起点行不需要上移")
        s = _StrSink()
        _erase_input(s, 2)
        o = s.get()
        check("\x1b[2A" in o and "\x1b[J" in o, f"上移 2 行并清屏，实={o!r}")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景17b 提交后屏幕干净（行为级）───────────────────────────
    print("\n场景17b 回车提交后：输入行落在上方、输出从下方开始")
    _K._VT_ENABLED = True
    _W._cols = lambda: 21
    try:
        term = _Term(21, 14)
        sink = _TermSink(term)
        term.grid[3] = list("###MARK###".ljust(21))
        term.r, term.c = 6, 0
        inline = "[agent] > "
        buf = "x" * 30
        crow = 0
        for i in range(len(buf)):
            crow = _M2._repaint(sink, inline, buf[: i + 1], i + 1, cur_row=crow)
        _finish_line(sink, inline, buf, len(buf), cur_row=crow)
        check(not term.uses_absolute_positioning(), "提交收尾也不用绝对定位")
        check(term.row(3) == "###MARK###", f"上方 marker 未被动，实={term.row(3)!r}")
        # 提交后光标应停在输入区之下的新行
        start = term.row_starting(inline)
        check(start >= 0 and term.r > start,
              f"光标落到输入区下方（start={start}, cursor={term.r}）")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    # ── 场景18 候选列表在折行下不残留 ─────────────────────────────
    print("\n场景18 Tab 候选列表（折行下擦掉旧输入区）")
    _K._VT_ENABLED = True
    _W._cols = lambda: 21
    try:
        import io as _io2
        sink = _io2.StringIO()
        rd = _M2.PromptReader(_M2.Completer(CMDS, ARGS), stream=sink)
        # 长输入折成 2 行、光标在末行（cur_row=1）→ 下 1 行再上移 2 行回起点
        ret = rd._show_candidates("> ", "x" * 30, 30, ["/help", "/status"],
                                  cur_row=1)
        o = sink.getvalue()
        check("\x1b[2A" in o, f"上移 2 行回输入区起点，实={o!r}")
        check("\x1b[J" in o, "清屏序列存在")
        check("\x1b[J" in o and "H" not in o.replace("\x1b[J", ""),
              f"候选列表也不用绝对定位，实={o!r}")
        check(ret == 1, f"返回重画后光标所在行（=满行数 1），实={ret!r}")
        check("/help" in o and "/status" in o, "候选都列出")
        check(o.rstrip("\n").endswith("x" * 30), "输入区最后被重画回来")
    finally:
        _W._cols = orig_cols
        _K._VT_ENABLED = orig_vt

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
