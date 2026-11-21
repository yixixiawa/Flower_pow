"""``_HistoryMixin``：对话历史与轮次标题。

每轮对话的标题是**从模型回复里提炼的**，并单独存一份——
会话快照只存原始对话，标题另存 ``history.jsonl``。"""

from __future__ import annotations

from typing import TYPE_CHECKING

import asyncio
import time as _t
from core.repl.consts import _call_name


if TYPE_CHECKING:  # 类型检查期继承成员契约；运行期 _Base 是 object，MRO 与行为不变
    from core.repl._contract import _ReplContract as _Base
else:
    _Base = object


class _HistoryMixin(_Base):
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

    # ── 历史归档（/history …）─────────────────────────────────────
    #
    # 与 /sessions、/resume 的分工：
    #   * /sessions、/resume 走的是**快照**（session.json）——恢复的是状态；
    #   * /history 走的是**事件流**（events.jsonl）——查看/导出/检索的是过程，
    #     resume 只把历史当"知识"注入，**不恢复目标、环境、审批与授权**。
    # 两套数据各存一份，互不覆盖；归档缺了不影响会话，会话快照坏了也不影响归档。

    _HISTORY_HELP = (
        "用法：/history [子命令]\n"
        "  /history                  查看当前会话归档状态\n"
        "  /history save             立即保存并重渲染 Markdown\n"
        "  /history list [N]         列出全部历史会话\n"
        "  /history show <id>        查看会话摘要\n"
        "  /history export <id> [路径] 导出完整 Markdown\n"
        "  /history search <关键词>   跨会话搜索事件\n"
        "  /history summary <id>     生成复盘摘要（写 summary.md）\n"
        "  /history resume <id>      把历史当知识注入（不恢复授权）\n"
        "  /history prune [天数] [保留条数] 按保留策略清理归档\n"
        "  <id> 可写序号（/history list 里的 #N）、目录名或唯一子串"
    )

    def _history(self, arg: str = "") -> None:
        parts = (arg or "").strip().split(maxsplit=1)
        sub = (parts[0].lower() if parts and parts[0] else "")
        rest = (parts[1].strip() if len(parts) > 1 else "")
        if sub in ("", "status", "st"):
            self._history_status()
        elif sub in ("save", "flush"):
            self._history_save()
        elif sub in ("list", "ls"):
            self._history_list(rest)
        elif sub in ("show", "info"):
            self._history_show(rest)
        elif sub in ("export", "md", "markdown"):
            self._history_export(rest)
        elif sub in ("search", "find", "grep"):
            self._history_search(rest)
        elif sub in ("summary", "sum", "retro"):
            self._history_summary(rest)
        elif sub in ("resume", "restore", "load"):
            self._history_resume(rest)
        elif sub in ("prune", "clean", "purge"):
            self._history_prune(rest)
        elif sub in ("help", "?"):
            print(self._HISTORY_HELP)
        else:
            # 只给了一个参数且不是子命令 → 当成 show 的 id
            self._history_show(sub)

    def _history_status(self) -> None:
        j = getattr(self.session, "journal", None)
        print(f"\n当前会话：{self.session.session_id}")
        print(f"  目标：{self.session.target or '（未设定）'}")
        if j is None:
            print("  归档：未绑定（本次会话不产生事件流）")
            return
        if not len(j):
            print(f"  归档目录：{j.dir}（还没有事件）")
            return
        info = j.verify()
        size = j.events_path.stat().st_size if j.events_path.is_file() else 0
        print(f"  归档目录：{j.dir}")
        print(f"  事件数：{info['events']}（events.jsonl {size} 字节）")
        print(f"  Markdown：{j.conversation_path}"
              f"{'' if j.conversation_path.is_file() else '（尚未渲染，/history save）'}")
        if info["corrupt"]:
            print(f"  ⚠ 损坏行 {len(info['corrupt'])} 条（已跳过，不影响其余记录）："
                  + "、".join(str(c["line"]) for c in info["corrupt"][:5]))
        if info["duplicates"]:
            print(f"  ℹ 重复事件 {len(info['duplicates'])} 条（写入幂等已拦）")
        if j.last_error:
            print(f"  ⚠ 最近一次写入错误：{j.last_error}")

    def _history_save(self) -> None:
        j = getattr(self.session, "journal", None)
        p = self._save()
        if j is None:
            print(f"已保存会话快照：{p}" if p else "本次会话没有内容，未保存。")
            return
        if not len(j):
            print(f"已保存会话快照：{p}" if p else "本次会话没有内容，未保存。")
            print("  归档还没有事件（说一句话或调一次工具后才有），"
                  "所以没有生成 conversation.md。")
            return
        try:
            md = j.write_all()
        except Exception as exc:  # noqa: BLE001 - 渲染失败要如实报
            print(f"[!] Markdown 渲染失败：{type(exc).__name__}: {exc}")
            return
        print(f"已保存：{p if p else '（会话为空，未写快照）'}")
        print(f"  事件流：{j.events_path}（{len(j)} 条）")
        print(f"  对话稿：{md}")
        print(f"  复盘摘要：{j.summary_path}")

    def _history_list(self, arg: str = "") -> None:
        from core.session import list_journals

        items = list_journals(self._journal_root())
        if not items:
            print("（还没有历史会话归档）")
            return
        show = items
        if arg.strip().isdigit():
            show = items[: max(1, int(arg.strip()))]
        print(f"\n历史会话归档（共 {len(items)} 个，用 /history show <编号> 查看）：")
        for i, it in enumerate(show, 1):
            meta = it["meta"] or {}
            try:
                when = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(it["mtime"]))
            except (ValueError, OSError, OverflowError):
                when = "?"
            target = str(meta.get("target") or "") or "（无目标）"
            env = str(meta.get("environment") or "-")
            n = int(meta.get("event_count") or 0)
            print(f"  #{i:<2} {it['name']}  {when}  事件 {n:<4} {env:12} {target}")

    def _open_history(self, ref: str):
        """解析 ``#N / 目录名 / 唯一子串`` → EventJournal；找不到返回 None。"""
        from core.session import list_journals, open_journal

        root = self._journal_root()
        r = (ref or "").strip()
        if not r:
            j = getattr(self.session, "journal", None)
            if j is None or not len(j):
                print("没有指定会话，且当前会话还没有归档（用 /history list 看有哪些）")
                return None
            return j
        items = list_journals(root)
        if not items:
            print("还没有历史会话归档（说一句话或调一次工具后才会产生）。")
            return None
        if r.isdigit():
            n = int(r)
            if not 1 <= n <= len(items):
                print(f"编号需在 1-{len(items)} 之间（用 /history list 查看）")
                return None
            r = items[n - 1]["name"]
        j = open_journal(root, r)
        if j is None:
            print(f"没有找到归档会话「{ref}」（用 /history list 查看）")
        return j

    def _history_show(self, ref: str = "") -> None:
        j = self._open_history(ref)
        if j is None:
            return
        events = j.events()
        meta = j.meta()
        counts: dict[str, int] = {}
        for e in events:
            counts[e.event_type] = counts.get(e.event_type, 0) + 1
        print(f"\n会话 {j.session_id}")
        print(f"  目录：{j.dir}")
        print(f"  时间：{_t.strftime('%Y-%m-%d %H:%M', _t.localtime(j.created_at))} 起"
              f"（事件 {len(events)} 条）")
        print(f"  目标：{meta.get('target') or '（未记录）'}"
              f"  环境：{meta.get('environment') or '（未记录）'}")
        if counts:
            print("  事件构成：" + "、".join(f"{k} {v}" for k, v in sorted(counts.items())))
        dialog = [e for e in events if e.event_type in ("USER_MESSAGE", "ASSISTANT_MESSAGE")]
        if dialog:
            print("  最近对话：")
            for e in dialog[-4:]:
                who = "用户" if e.event_type == "USER_MESSAGE" else "Agent"
                first = " ".join((e.content or "").split())[:80]
                print(f"    [{_t.strftime('%H:%M', _t.localtime(e.ts))}] {who}：{first}")
        findings = [e for e in events if e.event_type == "FINDING_CREATED"]
        if findings:
            print(f"  发现 {len(findings)} 条：")
            for e in findings[:5]:
                print(f"    - [{e.extra.get('severity', '-')}] {e.extra.get('name', '')}")
        print("  下一步：/history export %s | /history summary %s" % (j.session_id, j.session_id))

    def _history_export(self, arg: str = "") -> None:
        parts = (arg or "").strip().split(maxsplit=1)
        ref = parts[0] if parts else ""
        dest = parts[1].strip() if len(parts) > 1 else ""
        j = self._open_history(ref)
        if j is None:
            return
        try:
            p = j.write_all(dest=dest or None)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] 导出失败：{type(exc).__name__}: {exc}")
            return
        print(f"已导出：{p}")
        print(f"  复盘摘要：{j.summary_path}")
        print(f"  事件流：{j.events_path}")

    def _history_search(self, keyword: str = "") -> None:
        from core.session import search_all

        kw = (keyword or "").strip()
        if not kw:
            print("用法：/history search <关键词>")
            return
        hits = search_all(self._journal_root(), kw, limit=30)
        if not hits:
            print(f"（没有匹配「{kw}」的历史事件）")
            return
        print(f"\n匹配「{kw}」的事件 {len(hits)} 条：")
        for h in hits:
            ev = h["event"]
            when = _t.strftime("%m-%d %H:%M", _t.localtime(ev.ts))
            tag = ev.tool_name or ev.extra.get("command") or ev.event_type
            print(f"  [{when}] {h['session_id']}  {ev.event_type} · {tag}")
            print(f"      {h['snippet'][:140]}")
        print("\n用 /history show <会话名> 看上下文，/history export <会话名> 导出全文。")

    def _history_summary(self, ref: str = "") -> None:
        j = self._open_history(ref)
        if j is None:
            return
        conclusion, steps = _derive_conclusion(j)
        try:
            j.sync(conclusion=conclusion, next_steps=steps)
            j.write_all()
        except Exception as exc:  # noqa: BLE001
            print(f"[!] 摘要生成失败：{type(exc).__name__}: {exc}")
            return
        print(f"\n已生成复盘摘要：{j.summary_path}")
        print(f"  结论：{conclusion}")
        if steps:
            print("  后续工作：")
            for i, s in enumerate(steps, 1):
                print(f"    {i}. {s}")
        print(f"  完整对话稿：{j.conversation_path}"
              "（/history export 可重新渲染）")

    def _history_resume(self, ref: str = "") -> None:
        """把历史会话当**知识**注入当前对话。

        与 ``/resume`` 的区别（这是本条命令存在的理由）：
        ``/resume`` 恢复快照 = 恢复状态；``/history resume`` 只注入
        "当时说过什么、确认过什么、哪里失败过"——**不设目标、不恢复环境、
        不恢复任何审批/票据/Token**。历史记录只能作为知识和证据来源，
        不能成为新的执行授权。
        """
        j = self._open_history(ref)
        if j is None:
            return
        ctx = j.resume_context()
        if self.agent is None:
            print("当前不是 Agent 模式，无法注入模型。先 /agent on 后重试；")
            print("以下是这份历史的知识摘要（只读）：\n")
            print(ctx)
            return
        # 注入成一条 system 记录：模型看得到上下文，但这条不是用户授权指令
        self.agent.history.append({"role": "system", "content": ctx})
        self.session.sync_history(self.agent.history)
        print(f"已把会话 {j.session_id} 的历史作为**只读知识**注入对话"
              f"（{len(j)} 条事件）。")
        print("  注意：未恢复目标、环境、审批票据与任何凭证；")
        print("  要动手测试，请重新确认目标（/target <url>）与授权条件。")
        print("  目标当前仍为：" + (self.session.target or "（未设定）"))

    def _history_prune(self, arg: str = "") -> None:
        from core.session import prune

        parts = (arg or "").split()
        days = 0.0
        keep = 0
        try:
            if parts:
                days = float(parts[0])
            if len(parts) > 1:
                keep = int(parts[1])
        except ValueError:
            print("用法：/history prune [天数] [保留条数]（例：/history prune 90 200）")
            return
        if days <= 0 and keep <= 0:
            print("必须给出保留策略：天数或保留条数至少一个 > 0——不明确就不删。")
            print("  例：/history prune 90 200（删 90 天前的，且只保留最近 200 个会话）")
            return
        removed = prune(self._journal_root(), keep_days=days, keep_sessions=keep)
        if not removed:
            print("没有符合清理条件的归档。")
            return
        print(f"已清理 {len(removed)} 个归档目录：")
        for name in removed:
            print(f"  {name}")

    # ── 写操作人工审核 ────────────────────────────────────────────
    async def _approve(self, desc: str) -> str | bool:
        """每**一次**写操作前的人工审核（现在只有文件上传会走到这里）。

        为什么必须一次一问：上传确实会在目标上留下文件。批量放行等于把
        "只写一次"变成"想写几次写几次"，出事了无法收场。

        P1-4（第六轮整改）：返回**真实审批人身份**（str）而非裸布尔——
        审批审计必须能追责到"谁批的"；拒绝返回 False。
        """
        import getpass

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
        if not ok:
            return False
        user = getpass.getuser()
        return f"interactive:{user}"

    # ── 全自动（Alt+Shift / /auto）────────────────────────────────


# ── 复盘摘要的推导（确定性，不依赖模型）─────────────────────────────
def _derive_conclusion(journal) -> tuple[str, list[str]]:
    """从事件流统计出结论与后续工作。

    为什么不直接让模型写：复盘摘要要能**重放**——同一份 events.jsonl
    每次生成的结论应当一致，否则"归档"就变成了另一种不可复现的推断。
    统计能算的部分（条数、拦截、失败、发现）全部算出来；判断性的措辞
    保持克制，不臆造"漏洞成立"这类结论。
    """
    events = journal.events()
    meta = journal.meta()
    users = [e for e in events if e.event_type == "USER_MESSAGE"]
    calls = [e for e in events if e.event_type == "TOOL_CALL"]
    results = [e for e in events if e.event_type == "TOOL_RESULT"]
    denied = [
        e for e in events
        if e.event_type == "POLICY_DECISION"
        and (e.policy_decision or "").upper() in ("DENY", "UNKNOWN", "REVIEW")
    ]
    findings = [e for e in events if e.event_type == "FINDING_CREATED"]
    confirmed = [e for e in findings if e.extra.get("status") != "线索"]
    clues = [e for e in findings if e.extra.get("status") == "线索"]
    failed = [e for e in results if e.execution_status in
              ("blocked", "error", "badargs", "unknown", "timeout", "failed")]
    tasks_failed = [e for e in events if e.event_type == "TASK_FAILED"]
    reports = [e for e in events if e.event_type == "REPORT_CREATED"]

    parts = [
        f"会话 `{journal.session_id}` 共 {len(events)} 条事件："
        f"用户输入 {len(users)} 条、工具调用 {len(calls)} 次、"
        f"策略拦截 {len(denied)} 次、登记发现 {len(confirmed)} 条"
        + (f"（另有待验证线索 {len(clues)} 条）" if clues else "")
        + f"、失败路径 {len(failed) + len(tasks_failed)} 条。"
    ]
    if meta.get("target"):
        parts.append(f"测试目标：{meta['target']}；环境：{meta.get('environment') or '未知'}。")
    if confirmed:
        top = "；".join(
            f"[{e.extra.get('severity', '-')}] {e.extra.get('name', '')}"
            for e in confirmed[:5]
        )
        parts.append(f"已登记发现：{top}。")
    if denied:
        kinds = sorted({str(e.extra.get("command") or "未知操作") for e in denied})
        parts.append(
            "被策略拦截/待审批的操作：" + "、".join(kinds[:6])
            + "。拦截是**过程的终点**，不代表目标不存在该风险——"
            "需要重新确认授权后另行验证。"
        )
    if reports:
        parts.append(f"已导出报告 {len(reports)} 次（见 artifacts/报告事件）。")
    if not confirmed:
        parts.append("本次会话没有登记任何通过质量闸门的发现。")
    parts.append("（本结论由事件统计生成，不含推理判断；漏洞真实性以报告正文为准。）")

    steps: list[str] = []
    if denied:
        steps.append("对被拦截的操作重新确认目标授权（target/环境/身份）后，按登记入口重试。")
    if clues:
        steps.append(f"补齐 {len(clues)} 条待验证线索的缺失字段（原始请求/响应/成立依据/影响）后重新提交。")
    if tasks_failed:
        steps.append("检查失败的后台任务原因，必要时用 retry=true 显式重跑。")
    if not reports and confirmed:
        steps.append("用 /report 导出报告，把已确认发现交付出去。")
    if not steps:
        steps.append("按当前阶段继续迭代：换参数、换角色、换顺序重新验证权限边界。")
    return " ".join(parts), steps
