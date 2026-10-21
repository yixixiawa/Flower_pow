"""终端模拟器——给补全/输入区的**行为级**回归提供一块忠实的假屏幕。

为什么不只断言转义序列：真正要保证的是**屏幕上的结果**——输入区始终停在
原处、上方已打印的内容不被动。只对着 ANSI 字符串做断言是自证的：代码把
"相对输入区"的行号拿去做绝对定位，照样能"通过"。

所以这里放一个忠实的控制台模型：按 cols 列折行、右边缘"待定折行"、
写到底行整体上滚，ANSI 上移(A)/下移(B)/右移(C)/擦除(J)/绝对定位(H)
全部按真实语义生效。

**本模块是测试公共设施，不是回归脚本**：文件名不带 `_test` 后缀，
`run_tests.py` 的 `*_test.py` 收集规则不会把它当成一个测试来跑。
"""

from __future__ import annotations

import re
import unicodedata

CMDS = ["/help", "/status", "/report", "/resume", "/quit", "/login",
        "/agent", "/assets", "/title", "/chats"]
ARGS = {
    "report": ["md", "html", "json", "all"],
    "assets": ["port", "path", "api", "endpoint"],
    "phase": ["recon", "model", "exploit", "iterate"],
    "agent": ["on", "off"],
    "login": ["admin@juice-sh.op", "user@example.com"],
    "title": ["1", "2", "3"],
}


# ── 终端模拟器：给「输入区不漂移」做**行为级**回归 ──────────────────
#
# 为什么不只断言转义序列：真正要保证的是**屏幕上的结果**——输入区始终停在
# 原处、上方已打印的内容不被动。只对着 ANSI 字符串做断言是自证的：代码把
# "相对输入区"的行号拿去做绝对定位（`\x1b[行;列H`），照样能"通过"。
#
# 所以这里放一个忠实的控制台模型：按 cols 列折行、右边缘"待定折行"、
# 写到底行整体上滚，ANSI 上移(A)/下移(B)/右移(C)/擦除(J)/绝对定位(H)
# 全部按真实语义生效。
_CSI = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])")


class _Term:
    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.pending = False        # 右边缘待定折行
        self.scrolls = 0
        self.raw = []               # 收到的原始字节流

    def _scroll(self):
        self.grid.pop(0)
        self.grid.append([" "] * self.cols)
        self.scrolls += 1

    def _newline(self):
        self.pending = False
        if self.r + 1 >= self.rows:
            self._scroll()
        else:
            self.r += 1
        self.c = 0

    def _put(self, ch):
        if self.pending:
            self._newline()
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if self.c + w > self.cols:
            self._newline()
        self.grid[self.r][self.c] = ch
        if w == 2 and self.c + 1 < self.cols:
            self.grid[self.r][self.c + 1] = ""
        self.c += w
        if self.c >= self.cols:
            self.c = self.cols       # 停在右边缘，等下一个字符才折行
            self.pending = True

    def feed(self, s):
        self.raw.append(s)
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == "\x1b":
                m = _CSI.match(s, i)
                if not m:
                    i += 1
                    continue
                nums = [int(x) for x in m.group(1).split(";") if x]
                op, n = m.group(2), (nums[0] if nums else 1)
                if op == "A":
                    self.r = max(0, self.r - n)
                elif op == "B":
                    self.r = min(self.rows - 1, self.r + n)
                elif op == "C":
                    self.c = min(self.cols, self.c + n)
                elif op == "D":
                    self.c = max(0, self.c - n)
                elif op == "J" and (nums[0] if nums else 0) == 0:
                    for cc in range(self.c, self.cols):
                        self.grid[self.r][cc] = " "
                    for rr in range(self.r + 1, self.rows):
                        self.grid[rr] = [" "] * self.cols
                elif op == "H":
                    self.r = max(0, min(self.rows - 1, n - 1))
                    self.c = max(0, min(self.cols,
                                        (nums[1] if len(nums) > 1 else 1) - 1))
                self.pending = False
                i = m.end()
                continue
            if ch == "\r":
                self.c = 0
                self.pending = False
            elif ch == "\n":
                self._newline()
            else:
                self._put(ch)
            i += 1

    def row(self, r):
        return "".join(self.grid[r]).rstrip()

    def raw_row(self, r):
        """不裁尾部空格的整行——匹配**以空格结尾**的提示符时必须用它。

        ``row()`` 会 rstrip，于是 ``"[agent] > "`` 变成 ``"[agent] >"``，
        而 ``"[agent] >".startswith("[agent] > ")`` 是 False：
        刚进输入循环、还没敲任何字符时提示符正好在行尾，会被判成"找不到输入区"。
        """
        return "".join(self.grid[r])

    def all_rows(self):
        return [self.row(r) for r in range(self.rows)]

    def row_starting(self, prefix):
        for r in range(self.rows):
            if self.raw_row(r).startswith(prefix):
                return r
        return -1

    def uses_absolute_positioning(self):
        """原始字节里有没有绝对光标定位（`\\x1b[行;列H` / `\\x1b[H`）。"""
        return bool(re.search(r"\x1b\[[0-9;]*H", "".join(self.raw)))


class _TermSink:
    """把 write 直接喂给终端模拟器。"""

    def __init__(self, term):
        self.term = term

    def write(self, s):
        self.term.feed(s)

    def flush(self):
        pass


class _StrSink:
    """只把写出的内容拼成字符串（用于断言转义序列本身）。"""

    def __init__(self):
        self.parts = []

    def write(self, s):
        self.parts.append(s)

    def flush(self):
        pass

    def get(self):
        return "".join(self.parts)


def _drive_input(mc, cols, rows, marker_row, keys, inline="[agent] > ",
                 pre="\n"):
    """模拟 PromptReader 的按键循环，返回 ``(term, trace)``。

    ``trace`` 每步记 ``(buffer 长度, 输入区首行, marker 行, 滚动次数)``。
    输入区首行与 marker 行的**相对偏移恒为 1** 才说明没有漂移——
    用相对值是因为输入区贴屏幕底部时上滚是正常的（一起往上走）。
    """
    term = _Term(cols, rows)
    sink = _TermSink(term)
    for r in range(rows):
        term.grid[r] = list(f"L{r}".ljust(cols))
    term.grid[marker_row] = list("###MARK###".ljust(cols))
    term.r, term.c = marker_row, 0

    prefix, _inline = mc._split_prompt(pre + inline)
    sink.write(prefix)
    sink.write(inline)
    crow = mc._layout(inline, cols)[0]

    buf, pos = "", 0
    trace = []
    for k in keys:
        if k == "\b":
            if pos <= 0:
                continue
            buf, pos = buf[: pos - 1] + buf[pos:], pos - 1
        else:
            buf, pos = buf[:pos] + k + buf[pos:], pos + 1
        crow = mc._repaint(sink, inline, buf, pos, cur_row=crow)
        trace.append((len(buf), term.row_starting(inline), marker_row_live(term),
                      term.scrolls))
    return term, trace


def marker_row_live(term):
    for r in range(term.rows):
        if term.row(r) == "###MARK###":
            return r
    return -1


# 交互层用的行内提示符。长 10 列（全半角），折行断言都按它算。
_INLINE = "[agent] > "


class _FakeMsvcrt:
    """假的 ``msvcrt``：按键序列喂键，并在**每次取键之前**回调。

    回调时机是关键：``getwch()`` 被调用的那一刻，上一次按键触发的重绘已经
    完成、这一键还没处理——正是"上一次重绘后屏幕长什么样"的快照点。
    于是逐键轨迹就拿到了。
    """

    def __init__(self, keys, on_key=None):
        self.q = list(keys)
        self.on_key = on_key
        self.used: list[str] = []

    def kbhit(self):
        return bool(self.q)

    def getwch(self):
        if self.on_key:
            self.on_key()
        ch = self.q.pop(0)
        self.used.append(ch)
        return ch


def drive_keys(mc, cols, rows, marker_row, keys, *, completer=None,
               inline=_INLINE):
    """用**真实按键循环**驱动 ``PromptReader.read()``，返回 ``(结果, 屏幕, 轨迹)``。

    为什么要这么测：直接调 ``_repaint`` / ``_show_candidates`` 只能证明"重绘函数
    本身对"，证明不了**键盘分发**对——Tab 那一段（第一次 Tab 只记候选、第二次才
    展示）就写在 ``_read_win`` 里，绕过它等于没测。
    轨迹每项是 ``(输入区首行, marker 行, 滚动次数)``。
    """
    term = _Term(cols, rows)
    sink = _TermSink(term)
    for r in range(rows):
        term.grid[r] = list(f"L{r}".ljust(cols))
    term.grid[marker_row] = list("###MARK###".ljust(cols))
    # 起点是 marker_row 本身：read() 会先写一个 "\n" 前缀把光标送到下一行，
    # 输入区才从 marker_row+1 开始。
    term.r, term.c = marker_row, 0

    trace = []

    def snap():
        trace.append((term.row_starting(inline), marker_row_live(term), term.scrolls))

    fake = _FakeMsvcrt(keys, on_key=snap)
    rd = mc.PromptReader(completer or mc.Completer(CMDS, ARGS), stream=sink)
    rd.enabled = True                      # 绕过 TTY 检查，直接进按键循环
    om, ow, od = mc.msvcrt, mc._WIN, mc._mods_held
    mc.msvcrt = fake
    mc._WIN = True                         # 强制走 Windows 按键分支（跨平台可测）
    mc._mods_held = lambda: False          # Alt+Shift 热键必须确定性地不触发
    try:
        out = rd.read("\n" + inline)
    finally:
        mc.msvcrt, mc._WIN, mc._mods_held = om, ow, od
    return out, term, trace


def _input_span(term, inline=_INLINE):
    """输入区占用的行区间 ``(首行, 末行)``；找不到返回 ``(-1, -1)``。"""
    start = term.row_starting(inline)
    if start < 0:
        return -1, -1
    end = start
    for r in range(start, term.rows):
        if term.row(r).strip():
            end = r
    return start, end


def _residue_below(term, inline=_INLINE):
    """输入区**下方**还残留内容的行号。

    重绘会 `\\x1b[J` 一直擦到屏幕末尾，所以输入区之下必须是空的。
    这里能抓到"旧折行没擦干净"——那正是输入区看起来往下跳时糊在下面的东西。
    """
    _start, end = _input_span(term, inline)
    if end < 0:
        return []
    return [r for r in range(end + 1, term.rows) if term.row(r).strip()]


def _blank_term(cols, rows, marker_row):
    """造一块预填 ``L0``/``L1``… 的屏幕，光标停在 marker 的下一行。"""
    term = _Term(cols, rows)
    for r in range(rows):
        term.grid[r] = list(f"L{r}".ljust(cols))
    term.grid[marker_row] = list("###MARK###".ljust(cols))
    term.r, term.c = marker_row + 1, 0
    return term, _TermSink(term)


