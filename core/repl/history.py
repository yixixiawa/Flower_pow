"""``_HistoryMixin``：对话历史与轮次标题。

每轮对话的标题是**从模型回复里提炼的**，并单独存一份——
会话快照只存原始对话，标题另存 ``history.jsonl``。"""

from __future__ import annotations

import asyncio
import time as _t
from core.repl.consts import _call_name


class _HistoryMixin:
    def _push_history(self, text: str) -> None:
        """记录输入历史，供上下键翻取。"""
        h = self.reader.history
        if h and h[-1] == text:
            return
        h.append(text)
        if len(h) > 200:
            del h[: len(h) - 200]

    def _make_title(self, user_text: str, reply: str, tools: list[str]) -> str:
        """给这一轮对话起个≤20 字的中文标题。

        优先用小模型总结（更准），失败退回「取用户输入前N 字」。
        标题是索引不是交付物，所以**不额外占用深度模型**。
        """
        text = (user_text or "").strip()
        if self.llm and getattr(self.llm, "available", False):
            try:
                t = self.llm.ask(
                    "你给对话轮次起标题。只输出标题本身，不要引号、句号、解释。\n"
                    "要求：中文，不超过 20 字，概括这轮在做什么。",
                    f"用户：{text[:300]}\n"
                    + (f"助手要点：{reply[:300]}" if reply else ""),
                    max_tokens=64,
                )
                t = (t or "").strip().strip("「」\"'").splitlines()[0][:40].strip()
                if t and "：" not in t[:3]:
                    return t
            except Exception:  # noqa: BLE001
                pass
        # 退化：取用户输入的合适长度片段
        s = " ".join(text.split())
        if not s:
            return "空轮次"
        return (s[:20] + "…") if len(s) > 20 else s

    def _record_conversation(self, user_text: str, reply: str) -> None:
        """记录一轮对话的标题 + 工具清单。"""
        # 用 .get 双键兜底：ToolRunner 的记录历史上出现过 "tool"/"name" 不一致，
        # 直接下标取会在旧记录上再次 KeyError。
        tools = (
            sorted({_call_name(c) for c in self.runner.calls} - {""})
            if self.runner
            else []
        )
        if tools and len(self.runner.calls) > 3:
            # 本轮工具很多时取最后几个，前面的是前几轮的
            tools = tools[-3:]
        title = self._make_title(user_text, reply, tools)
        self.session.add_conversation(title, tools)
        self._refresh_completer()

    def _chats(self) -> None:
        """列出本会话的对话标题索引。"""
        cs = self.session.conversations
        if not cs:
            print("（还没有对话记录）")
            return
        print(f"\n对话索引（{len(cs)} 轮）：")
        for c in cs:
            try:
                when = _t.strftime("%H:%M", _t.localtime(c.at))
            except (ValueError, OSError):
                when = "?"
            tools = ("  用到 " + "、".join(c.tools[:4])) if c.tools else ""
            print(f"  #{c.no:<3} {when}{tools}\n      {c.title}")

    def _set_title(self, no: int, text: str) -> None:
        """手工改某个标题。"""
        cs = self.session.conversations
        if not cs:
            print("（还没有对话记录）")
            return
        if not 1 <= no <= len(cs):
            print(f"编号需在 1-{len(cs)} 之间（用 /chats 看有哪些）")
            return
        if not text.strip():
            print("用法：/title <编号> <新标题>")
            return
        cs[no - 1].title = text.strip()[:40]
        self._refresh_completer()
        print(f"#{no} 标题已改为：{cs[no-1].title}")

    # ── 写操作人工审核 ────────────────────────────────────────────
    async def _approve(self, desc: str) -> bool:
        """每**一次**写操作前的人工审核（现在只有文件上传会走到这里）。

        为什么必须一次一问：上传确实会在目标上留下文件。批量放行等于把
        "只写一次"变成"想写几次写几次"，出事了无法收场。
        """
        print("\n" + "─" * 62)
        print("  ⚠ 写操作待审核")
        print("─" * 62)
        for ln in (desc or "").splitlines():
            print("  " + ln)
        print("─" * 62)
        try:
            ans = await asyncio.to_thread(input, "  允许这一次？[y/N] ")
        except (EOFError, KeyboardInterrupt):
            return False
        ok = (ans or "").strip().lower() in ("y", "yes")
        print("  → " + ("已放行" if ok else "已拒绝"))
        return ok

    # ── 全自动（Alt+Shift / /auto）────────────────────────────────

