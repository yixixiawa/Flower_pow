"""重绘：把当前缓冲区画到流上。

两套实现——支持 VT 时用 ANSI 光标移动，不支持就退回**单行重绘 + 裁剪**，
不裁剪的话每敲一个字都会折行、输入区往下掉一行。"""

from __future__ import annotations

from core.completer.width import _cell_width
from core.completer.width import _display_width
from core.completer import width
from core.completer import keys
from core.completer.layout import _layout
from core.completer.layout import _move_to


# ── 重绘 ────────────────────────────────────────────────────────


def _repaint(stream, prompt: str, buf: str, pos: int, *, cur_row: int | None = None) -> int:
    """重画输入区（**支持折行**），并把光标放回逻辑位置 ``pos``。

    分三步：
    1. **回到输入区首行**：从光标当前所在行**相对**上移 ``cur_row`` 行；
    2. **清屏**：从那里一直擦到屏幕末尾（``\\x1b[J``），一次清干净所有折行；
    3. **重写并定位**：写 ``prompt + buf`` 后光标落在末尾（可能在若干行之下），
       再**相对**移回 ``prompt + buf[:pos]`` 的末尾。

    关键是全程只用**相对移动**，不用绝对定位——理由见 :func:`_move_to`。

    ``cur_row`` 必须是**上一次重绘返回的行号**（即光标此刻真实所在行）。
    不能拿"新 prefix 的行号"替代：删字符时新 prefix 比旧的短，行号更小，
    按它上移就会**移得不够**，输入区每次回删都往下掉一行。
    传 ``None``（首次调用）时退而用目标行号估算。

    返回值是本次重绘后光标所在行号，调用方**必须存下来**供下次传入。
    """
    cols = width._cols()
    full = prompt + buf
    prefix = prompt + buf[:pos]

    if not keys._enable_vt():
        _repaint_plain(stream, prompt, buf, pos, cols)
        # 兜底路径按单行处理，行号恒为 0
        return 0

    row, col = _layout(prefix, cols)        # 光标**该在**的位置
    end_row, _ = _layout(full, cols)        # 写完 full 后光标**会到**的位置
    if cur_row is None:
        cur_row = row

    out: list[str] = []
    if cur_row:
        out.append(f"\x1b[{cur_row}A")      # 相对上移回输入区首行
    out.append("\r\x1b[J")                  # 擦到屏幕末尾：清掉全部旧折行
    out.append(full)                        # 重写输入区
    _move_to(out, end_row, row, col)        # 相对移回光标该在的位置
    stream.write("".join(out))
    stream.flush()
    return row


def _plain_row_text(text: str, cols: int) -> str:
    """把一行内容裁进 ``cols - 1`` 显示列（无 ANSI 时的降级渲染）。

    超过宽度就**从左侧截断、保留末尾**：光标总在末尾附近，这样至少看得见
    自己刚敲进去的字。

    **为什么必须裁**：没有 ANSI 就没有任何"上移"手段，而 ``\\r`` 只回到当前
    物理行行首。一旦让这次输出折行，重画就落在折下来那一行，下一次又折到
    再下一行——每敲一个字符输入区就往下掉一行，旧内容糊在上面擦不掉。
    """
    limit = max(1, cols - 1)
    if _display_width(text) <= limit:
        return text
    keep: list[str] = []
    w = 0
    for ch in reversed(text):
        cw = _cell_width(ch)
        if w + cw > limit:
            break
        keep.append(ch)
        w += cw
    return "".join(reversed(keep))


def _repaint_plain(stream, prompt: str, buf: str, pos: int, cols: int) -> None:
    """无 ANSI 时的兜底重绘：**只操作当前物理行，保证永不折行**。

    早先这里按 ``wide`` 清屏还照原样重写整行，超过一行就折行，于是每敲一个
    字符输入区往下掉一行（实测 25 个字符掉 6 行）。现在先裁进一行，
    清屏宽度也固定为 ``cols - 1``，多写的部分立刻被随后的 ``\\r`` + 重写覆盖。
    """
    limit = max(1, cols - 1)
    shown = _plain_row_text(prompt + buf, cols)
    stream.write("\r" + " " * limit + "\r" + shown)
    if pos < len(buf):
        head = _plain_row_text(prompt + buf[:pos], cols)
        # 只有没发生左截断时 head 才是 shown 的前缀，这时才能靠重画把光标
        # 挪回插入点；截断了就退化为把光标留在行尾。
        if shown.startswith(head):
            stream.write("\r" + head)
    stream.flush()


def _split_prompt(prompt: str) -> tuple[str, str]:
    """把提示拆成「只打一次的前缀」与「参与重绘的行内部分」。

    **这是修「输入框自动换行」的关键。** 调用方传进来的 prompt 常常以 ``\\n``
    开头（例如 ``"\\n[agent] > "``，用来和上一轮输出隔开一行）。重绘时如果把
    整个 prompt 原样再写一遍，那个 ``\\n`` 就会**每敲一个字符吐一次**——
    看起来就是输入框自己在往下换行。
    """
    # 注意 rpartition 找不到分隔符时把整个串放在**第三段**，
    # 此时 head 是空串——取错变量会让不带换行的 prompt 整个消失。
    head, sep, inline = (prompt or "").rpartition("\n")
    if sep:
        return head + "\n", inline
    return "", inline


