"""候选与补全逻辑（纯逻辑，不碰终端）。

``Completer.complete`` 只做「给一段输入，返回 (前缀, 候选, 公共前缀长度)」，
所以可以脱离终端单测。"""

from __future__ import annotations

from collections.abc import Sequence


# ── 候选与补全逻辑 ──────────────────────────────────────────────


class Completer:
    """命令 + 参数两级补全。

    ``commands`` 是命令清单（含 ``/`` 前缀），``args`` 是
    ``命令 -> 参数候选`` 的映射（键可带或不带前缀，内部会归一）。
    """

    def __init__(
        self,
        commands: Sequence[str],
        args: dict[str, Sequence[str]] | None = None,
    ) -> None:
        self.commands = sorted({c for c in commands if c})
        # 归一化成不带前斜杠的键，避免调用方到处写 '/'
        self.args = {
            k.lstrip("/"): list(v) for k, v in (args or {}).items() if v
        }

    def complete(self, buf: str) -> tuple[str, list[str], int]:
        """算出一个 ``(新缓冲区, 候选列表, 公共前缀长度)``。

        语义定义（``head`` = 已确定的前缀含空格，``tail`` = 正在输入的**最后一个词**）：
        候选总是**替换 ``tail``**而不是追加——这是让 ``/re<Tab> → /report``
        与 ``/report m<Tab> → /report md`` 都能工作的唯一一致做法。
        早先按「追加」写，结果 ``/report`` 会被补成 ``/report/report``。
        """
        if " " not in buf:
            head, tail = "", buf
            cands = [c for c in self.commands if c.startswith(tail)]
            if not cands:
                return buf, [], 0
            return _common_prefix(cands), cands, 0
        head, _, tail = buf.rpartition(" ")
        cmd = head.strip().lstrip("/")
        cands = [a for a in self.args.get(cmd, []) if a.startswith(tail)]
        if not cands:
            return buf, [], 0
        # rpartition 丢掉的那个分隔空格要显式补回来
        return f"{head} {_common_prefix(cands)}", cands, 0


def _common_prefix(cands: Sequence[str]) -> str:
    if not cands:
        return ""
    s = cands[0]
    for other in cands[1:]:
        i = 0
        m = min(len(s), len(other))
        while i < m and s[i] == other[i]:
            i += 1
        s = s[:i]
        if not s:
            break
    return s


