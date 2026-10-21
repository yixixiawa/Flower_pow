"""折行布局：把输入缓冲区摊成「物理行」。

右边缘留一个**待定折行**位——最后一个字符紧贴右边缘时先不折，
再输一个字符才折，否则擦除时行数会来回跳。"""

from __future__ import annotations

from core.completer.width import _ANSI_RE
from core.completer.width import _cell_width
from core.completer import width
from core.completer import keys


# ── 折行布局：把 buffer 摊成「物理行」────────────────────────────
#
# 单行重绘（\r + 空格 + 重写）在一行装得下时没问题；一旦输入超过一行，
# 控制台会**自动折行**，此时：
#   * \r 只回到**当前物理行**行首，回不到逻辑行首；
#   * 清屏宽度被钉在 cols-1，只能清掉一行，上面的旧内容永远擦不掉。
# 结果就是每敲一个字整个输入框往上跳、残留一堆旧字符。
#
# 解法是自己算出「这段内容占几行、光标在第几行第几列」，然后用 ANSI
# 逐行清除 + 精确定位。下面这组函数就是这个布局计算。
# 字符占几列统一走 `_cell_width`（全项目唯一定义）。


def _layout(text: str, cols: int) -> tuple[int, int]:
    """把 ``text`` 按终端宽度 ``cols`` 折行，返回 ``(行号, 列号)``。

    ``cols`` 传**终端实际列数**（``width._cols()`` 的返回值），**不要再减一**：
    控制台就是按 ``cols`` 列折行的。人为少算一列，我们算出的折行位置就和
    终端对不上、行号偏大——那也是"输入区乱跳"的一半原因。

    返回的列号**可能正好等于 ``cols``**：表示这一行的最后一列刚写满，光标
    停在右边缘、处于"待定折行"状态（再敲一个字符才会真正换行）。保留这个
    取值，后面的相对定位才能精确回位。

    ANSI 转义（颜色）在这里就要去掉：它不占显示列，算进去会让折行位置整体
    偏移。去掉了之后返回的列号就是**真实显示列**，正好是 ``\\x1b[<n>C`` 要的。
    """
    text = _ANSI_RE.sub("", text or "")
    if cols < 1:
        cols = 1
    row = 0
    col = 0
    for ch in text:
        w = _cell_width(ch)
        if col + w > cols:      # 放不下 → 换行（双宽字符不会被劈成两半）
            row += 1
            col = 0
        col += w
    return row, col


def _move_to(out: list[str], from_row: int, row: int, col: int) -> None:
    """把光标从 ``from_row`` **相对**移到同一输入区内的 ``(row, col)``。

    **必须用相对移动**（``\\x1b[<n>A`` / ``\\x1b[<n>B`` / ``\\x1b[<n>C``），
    **不能用绝对定位**（``\\x1b[<行>;<列>H``）：绝对定位的坐标是整个屏幕的，
    而我们算出来的行列是"相对输入区首行"的。拿相对坐标去做绝对定位，光标
    会被扔到屏幕左上角，下一次重绘就从那里开始擦屏——表现就是整个输入区
    乱跳、上方已打印的内容被抹掉。

    相对移动还有第二个好处：不受屏幕滚动影响。输入区贴着屏幕底部时内容会
    上滚，绝对坐标全部失效，相对位移却依然成立。
    """
    delta = row - from_row
    if delta > 0:
        out.append(f"\x1b[{delta}B")      # 下移
    elif delta < 0:
        out.append(f"\x1b[{-delta}A")     # 上移
    out.append("\r")
    if col > 0:
        out.append(f"\x1b[{col}C")        # 右移到目标列


def _finish_line(
    stream, prompt: str, buf: str, pos: int, *, keep: str = "", cur_row: int = 0
) -> None:
    """提交/中断时收尾：把光标移到输入区末尾再换行。

    为什么不能直接写 ``\\n``：折行后光标可能停在**中间某一行的行首**，
    此时那个 ``\\n`` 只下移一行，输入区**剩下的折行**还挂在下面，
    紧接着 shell/下一轮的输出就会和残留字符混在一起。

    所以先按 ``full``（``prompt + buf``）折行后的末尾坐标，**相对**地把光标
    挪到输入区**最后一行末尾**（所有内容都已"落"在上方），再补一个真正的
    换行，光标就干净地落到输入区之后的空行上。

    ``cur_row`` 是**光标此刻所在的行**（相对输入区首行）。调用方必须把上一
    次重绘返回的行号原样传进来——提交时光标可能停在中间某行，只有知道它
    现在在哪，才能算出需要上下移动几行。
    """
    cols = width._cols()
    full = prompt + buf
    if keys._enable_vt():
        end_row, end_col = _layout(full, cols)
        out: list[str] = []
        _move_to(out, cur_row, end_row, end_col)
        stream.write("".join(out))
    stream.write("\n" + keep)
    stream.flush()


def _erase_input(stream, rows: int) -> None:
    """把光标所在行**及以上 rows 行**的输入区擦掉（用于 Tab 候选列表）。

    列表打印完要重新画输入区，但如果直接重画，上面那份（可能折行的）旧
    输入区会留下残影。这里先上移 ``rows`` 行回到输入区起点，清到屏幕末尾，
    随后调用方重写 ``prompt + buf``。
    """
    if not keys._enable_vt():
        return
    out = []
    if rows:
        out.append(f"\x1b[{rows}A")
    out.append("\r\x1b[J")
    stream.write("".join(out))


