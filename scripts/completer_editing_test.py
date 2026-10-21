"""提示符拆分 / 列宽计算 / 行内光标 / 按词跳转 / 折行布局的回归。

这些都是 `core.completer` 的**纯函数**与 `PromptReader` 的按键分发，
不碰终端模拟器（那套在 `_terminal_sim.py` + `completer_terminal_test.py`）。

运行：.venv/Scripts/python.exe scripts/completer_editing_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")
    print("\n场景10 输入框不得自动换行（真实 bug 回归）")
    # 症状：在 agent 提示栏打字时每敲一个字符就往下走一行。
    # 根因：prompt 是 "\n[agent] > "，重绘时把整个 prompt（含那个 \n）重写一遍。
    from core.completer import _split_prompt, _display_width

    pre, inline = _split_prompt("\n[agent] > ")
    check(pre == "\n" and inline == "[agent] > ",
          f"前导换行只留在前缀里（prefix={pre!r} inline={inline!r}）")
    pre2, inline2 = _split_prompt("[agent] > ")
    check(inline2 == "[agent] > ",
          f"不带换行时整串留在行内部分（inline={inline2!r}）")
    check(_split_prompt("> ")[1] == "> ", "简单 prompt 不被吞掉")

    check(_display_width("中文abc") == 7, "中文按双宽计列（2+2+3=7）")
    check(_display_width("\x1b[36mabc\x1b[0m") == 3, "ANSI 转义不计列宽")

    class FakeKey:
        """假的 msvcrt。``kbhit`` 必须有——读取循环先 kbhit 再 getwch，
        缺了它 read() 会抛 AttributeError 并退回 input()，测试就卡在等 stdin。"""

        def __init__(self, keys): self.k = list(keys)
        def kbhit(self): return bool(self.k)
        def getwch(self): return self.k.pop(0)

    def run_keys(keys, prompt="\n[agent] > "):
        """用一串假按键驱动一次真实的行读取，返回 (读到的文本, 输出流)。"""
        import core.completer.reader as _M
        import io as _io
        real = _M.msvcrt
        try:
            _M.msvcrt = FakeKey(list(keys))
            buf = _io.StringIO()
            rd = _M.PromptReader(_M.Completer(["/help", "/status"]), stream=buf)
            rd.enabled = True
            text = rd.read(prompt)
            return text, buf.getvalue()
        finally:
            _M.msvcrt = real

    text, out = run_keys(["生", "成", "渗", "\r"])
    check(text == "生成渗", f"中文输入完整读回（{text!r}）")
    # 提交时那一次 \n 是必要的（要换到下一行），前导 1 次 + 提交 1 次 = 2
    check(out.count("\n") == 2,
          f"重绘期间不再吐换行（实际 {out.count('\n')} 个，应为 2）")

    # ── 场景11 左右方向键能在已输入内容里移动光标（真实 bug 回归）──
    print("\n场景11 光标可以在行内移动（不是只能改末尾）")
    # 功能键是**两次** getwch：先前缀 \x00，再扫描码。
    # 写成一个字符串 "\x00K" 的话，假 msvcrt 会一次返回两个字符，
    # ch in ("\x00","\xe0") 判断就落空了——这是测试自身的坑，不是实现的。
    L = ["\x00", "K"]      # ←（扫描码 0x4B）
    R = ["\x00", "M"]      # →（扫描码 0x4D）
    HOME = ["\x00", "G"]   # Home（0x47）
    END = ["\x00", "O"]    # End（0x4F）
    DEL = ["\x00", "S"]    # Delete（0x53）

    t, _ = run_keys(["a", "b", "c"] + L + ["X", "\r"])
    check(t == "abXc", f"← 一次后在中间插入：abc→abXc，实={t!r}")

    t, _ = run_keys(["a", "b", "c"] + L + L + ["X", "\r"])
    check(t == "aXbc", f"连按两次 ← 到 b 前插入：实={t!r}")

    t, _ = run_keys(["a", "b", "c"] + L * 4 + ["X", "\r"])
    check(t == "Xabc", f"← 到头也不越界（多按无副作用）：实={t!r}")

    t, _ = run_keys(["a", "b", "c"] + L + R + ["X", "\r"])
    check(t == "abcX", f"← 再 → 抵消，插在末尾：实={t!r}")

    t, _ = run_keys(["a", "b", "c"] + HOME + ["X", "\r"])
    check(t == "Xabc", f"Home 后插入行首：实={t!r}")

    t, _ = run_keys(["a", "b", "x", "c"] + HOME + R + R + DEL + ["\r"])
    check(t == "abc", f"Home→→ 后 Delete 删掉 x：实={t!r}")

    t, _ = run_keys(["a", "b", "c"] + L + ["\b", "\r"])
    check(t == "ac", f"← 后退格删的是光标前一个（不是末尾）：实={t!r}")

    t, _ = run_keys(["a", "b", "c", "\b", "\r"])
    check(t == "ab", "不移动时退格仍是删末尾")

    t, _ = run_keys(["a", "b", "c"] + END + ["X", "\r"])
    check(t == "abcX", f"End 后插入末尾：实={t!r}")

    # 光标回到行中间时，重绘必须把光标也送回去——
    # 否则看起来光标在末尾、实际插入点在中间，下一次输入会"跳"。
    _, out = run_keys(["a", "b", "c"] + L + ["X", "\r"])
    check(out.rstrip("\n").endswith("X"),
          "重绘后光标停在插入点（行尾残留的是刚插入的字符）",
          repr(out[-24:]))

    print("\n场景12 按词跳转（Ctrl+← / Ctrl+→）")
    from core.completer import _next_word, _prev_word

    s = "/report md"
    check(_prev_word(s, len(s)) == 8, "Ctrl+← 从行尾跳到 md 前", f"实={_prev_word(s, len(s))}")
    check(_prev_word(s, 8) == 0, "再跳一次到行首（整条命令算一个词）",
          f"实={_prev_word(s, 8)}")
    check(_next_word(s, 0) == 8, "Ctrl+→ 从行首跳到 md", f"实={_next_word(s, 0)}")
    check(_next_word(s, 8) == len(s), "再跳一次到行尾")
    check(_prev_word("", 0) == 0 and _next_word("", 0) == 0, "空行不越界")

    t, _ = run_keys(list("/report m") + ["\x00", "s", "X", "\r"])
    check(t == "/report Xm", f"Ctrl+← 后插入：实={t!r}")

    # ── 场景13 折行布局计算 ───────────────────────────────────────
    print("\n场景13 折行布局：算出行号与列号")
    from core.completer import _cell_width, _layout

    check(_cell_width("中") == 2 and _cell_width("a") == 1, "单字宽度区分全角/半角")

    # cols 传**终端实际列数**，不是 cols-1
    check(_layout("abc", 10) == (0, 3), f"短串→第0行第3列，实={_layout('abc', 10)}")
    # 正好写满一行时**仍在这一行**，列号 == cols，表示处在"待定折行"。
    # 早先这里返回 (1, 0)（人为少算一列），行号被算大 → 相对定位整体错位。
    check(_layout("a" * 10, 10) == (0, 10),
          f"正好写满→仍在第0行右边缘（待定折行），实={_layout('a' * 10, 10)}")
    check(_layout("a" * 11, 10) == (1, 1),
          f"再敲一个才真正换行，实={_layout('a' * 11, 10)}")
    check(_layout("a" * 25, 10) == (2, 5), f"两行半→第2行第5列，实={_layout('a' * 25, 10)}")

    # 双宽字符不能被劈成两半：列满了应该整体换行
    check(_layout("中" * 5, 10) == (0, 10),
          f"5 个中文恰好占满 10 列→仍在第0行右边缘，实={_layout('中' * 5, 10)}")
    check(_layout("中" * 5 + "a", 10) == (1, 1),
          f"多出的半角字符换行到第1行第1列，实={_layout('中' * 5 + 'a', 10)}")
    # 9 个半角占 0..8 列（col=9），再来双宽：9+2>10 放不下 → 整体挪到下一行
    check(_layout("a" * 9 + "中", 10) == (1, 2),
          f"9 列 + 双宽整体换行到第1行第2列，实={_layout('a' * 9 + '中', 10)}")
    check(_layout("中a", 4) == (0, 3), f"双宽+半角共 3 列，实={_layout('中a', 4)}")

    # ANSI 颜色不占显示列，必须先剥掉再折行，否则整行位置偏移
    esc = chr(27)
    check(_layout(f"{esc}[31mabc{esc}[0m", 10) == (0, 3),
          f"颜色转义不算宽度，实={_layout(esc + '[31mabc' + esc + '[0m', 10)}")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
