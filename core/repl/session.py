"""``_SessionMixin``：误报排除 / 对话轮 / 模型 / 报告 / 会话存取。

``_resume`` 载入后会顺带跑一次 ``_backfill``，从对话历史把当时的真实报文
回填到发现上——否则老会话导出的报告里只有请求、没有响应。"""

from __future__ import annotations

from pathlib import Path
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl.consts import _REPORT_NOTE_PREFIX


class _SessionMixin:
    async def _fp(self, raw: str) -> None:
        """``/fp`` —— 误报排除（人用的入口）。

        逻辑直接复用 ``ToolRunner.dismiss``——那是模型、/fp、CLI 三条入口的
        共同实现。各写一遍的话，"模型能排除、命令行不能"或"排除范围不一致"
        这类问题迟早出现，而且极难发现（每条入口单看都自洽）。
        """
        parts = raw.split(maxsplit=2)
        args = parts[1:]
        if not args or args[0].lower() in ("list", "ls", ""):
            self._findings(show_dismissed=True)
            self._fp_show_exclusions()
            return

        sub = args[0].lower()
        if sub in ("auto", "public"):
            # 回源站根目录核验公开性，够强就自动排除。
            # 本方法必须是 async 的：命令分发本身在事件循环里，
            # 用 run_until_complete 会直接抛 "This event loop is already running"。
            from core.tools import ToolRunner

            print("正在回源站根目录核验公开性……")
            out = await ToolRunner(
                self.cfg, self.probes or {}, "."
            ).check_public(self.session, ref="all")
            print(out)
            self._save()
            self._refresh_completer()
            return

        undo = sub == "undo"
        purge = sub == "del"
        scope = "poc" if sub == "poc" else "finding"

        if undo or purge:
            ref = args[1] if len(args) > 1 else ""
            reason = ""
        elif sub == "poc":
            ref = args[1] if len(args) > 1 else ""          # /fp poc <编号> <原因>
            reason = args[2] if len(args) > 2 else ""
        else:
            ref = args[0]                                     # /fp <编号|poc_id> <原因…>
            reason = args[1] if len(args) > 1 else ""

        if not ref:
            print(
                "用法：/fp <编号> <原因>　｜　/fp undo <编号>　｜　"
                "/fp del <编号>　｜　/fp poc <编号> <原因>"
            )
            return
        if not (undo or purge) and not reason.strip():
            print(
                "缺少排除原因。报告里会列出「误报排除的复核记录」，"
                "没有依据的排除等于不可复核。\n"
                "用法：/fp <编号> <原因>　例如：/fp 3 公开演示站点，内容本就公开"
            )
            return

        from core.tools import ToolRunner

        out = ToolRunner.dismiss(
            self.session, ref=ref, reason=reason,
            undo=undo, purge=purge, scope=scope,
        )
        print(out)
        if not out.startswith("排除失败"):
            self._save()
            self._refresh_completer()

    def _fp_show_exclusions(self) -> None:
        from core import exclusions

        items = exclusions.entries(self.session.target)
        if not items:
            return
        print(f"\n本目标的排除清单（{len(items)} 条，重扫自动套用）：")
        for e in items[:20]:
            where = "该 POC 全部命中" if not e.get("matched_at") else str(e["matched_at"])[:80]
            print(f"  · {e.get('poc_id')}　{where}")
            if e.get("reason"):
                print(f"    原因：{str(e['reason'])[:70]}")

    def _turns(self) -> None:
        if not self.session.turns:
            print("（还没有完成的轮次）")
            return
        print(f"\n共 {len(self.session.turns)} 轮：")
        for t in self.session.turns:
            print(
                f"  第{t.no}轮 [{t.phase.label}] {t.elapsed:.1f}s "
                f"+{t.new_assets}资产 +{t.new_findings}发现  "
                + "、".join(t.actions[:3])
            )

    def _model(self) -> None:
        m = self.session.model
        if not m.resources:
            print("（尚未建模，跑一轮业务建模）")
            return
        print(f"\n业务模型：{m.summary()}")
        print("\n资源（前 20）：")
        for r in m.resources[:20]:
            print(f"  {r}")
        if m.high_value:
            print(f"\n高价值操作（{len(m.high_value)}）：")
            for h in m.high_value[:12]:
                print(f"  {h}")
        if m.state_flows:
            print(f"\n业务流：{' → '.join(m.state_flows)}")
        if m.admin_ops:
            print(f"\n后台操作（{len(m.admin_ops)}）：")
            for a in m.admin_ops[:10]:
                print(f"  {a}")

    async def _report(self) -> None:
        from output.report import write_html, write_json, write_markdown

        s = self.session
        # notes 是**追加**的，而 /report 可能被反复调用。这里只重写本函数
        # 自己产生的条目（用哨兵前缀标记），否则每按一次 /report 就会
        # 多一份一模一样的会话头——实测出现过10 遍重复。
        # 前缀在输出前由 _report_note 剥掉，不会出现在报告里。
        s.result.notes[:] = [
            n for n in s.result.notes
            if not n.startswith(_REPORT_NOTE_PREFIX)
        ]
        s.result.notes.insert(0, f"{_REPORT_NOTE_PREFIX}交互式会话 {s.session_id}，共 {len(s.turns)} 轮")
        if s.model.resources:
            s.result.notes.insert(1, f"{_REPORT_NOTE_PREFIX}业务模型：{s.model.summary()}")
        for t in s.turns:
            s.result.notes.append(
                f"{_REPORT_NOTE_PREFIX}第{t.no}轮[{t.phase.label}] {'、'.join(t.actions)} "
                f"→ +{t.new_assets}资产 +{t.new_findings}发现"
            )
        if self.runner and self.runner.calls:
            ok = sum(1 for c in self.runner.calls if c["status"] == "ok")
            blk = sum(1 for c in self.runner.calls if c["status"] == "blocked")
            s.result.notes.append(
                f"{_REPORT_NOTE_PREFIX}Agent 工具调用 {len(self.runner.calls)} 次"
                f"（成功 {ok}、安全拦截 {blk}）"
            )

        # chat 路径以前硬传""，导致这里**永远拿不到 AI 报告**——
        # 也就是会话里按 /report 导出的一直是模板版，与 scan 命令行为不一致。
        ai_body = ""
        if self.llm and self.llm.available and s.result.findings:
            print("  正在生成 AI 分析正文…")
            ai_body = self.llm.write_report(s.result)
            if not ai_body:
                print("  [dim]AI 正文不可用（截断或校验未通过），已导出模板报告[/dim]")

        outdir = Path(self.cfg.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        paths = [write_json(s.result, outdir, ai_body)]
        paths.append(write_markdown(s.result, outdir, ai_body))
        paths.append(write_html(s.result, outdir, ai_body))
        print("\n报告已导出：")
        for p in paths:
            print(f"  {p}")

    def _resume(self, session_id: str = "") -> None:
        """恢复会话。``session_id`` 为空时取最近一次。

        恢复前先顺手清掉历史遗留的空壳（见 :func:`purge_empty_sessions`）：
        用户此刻正在挑要恢复哪一个，正是把噪音清掉的时机。清理结果只报一句
        汇总，不逐条刷屏。
        """
        base = Path(self.cfg.data_dir) / "sessions"
        gone = purge_empty_sessions(base)
        if gone:
            print(f"（已清理 {len(gone)} 个空会话：{'、'.join(gone[:3])}…）"
                  if len(gone) > 3 else f"（已清理 {len(gone)} 个空会话：{'、'.join(gone)}）")
        if session_id:
            prev = Session.load(base / session_id)
            if prev is None:
                print(f"没有找到会话 {session_id}（用 /sessions 看可恢复列表）")
                return
        else:
            prev = latest_session(base)
            if prev is None:
                print("（没有可恢复的会话）")
                return
        # 用户点名恢复的会话若本身是空的（旧版遗留），删掉并说清楚——
        # 否则"载入了一个什么都没记的会话"会让人以为快照坏了。
        if prev.is_empty() and prev.delete(base):
            print(f"会话 {prev.session_id} 是空会话（没目标、没对话、没结果），已删除。")
            print("   用 /sessions 看可恢复列表，或直接开始新的一次测试。")
            return
        self.session = prev
        self._planner = None
        print(f"已载入会话 {prev.session_id}：{prev.status_line()}")
        # Agent 持有 session 引用，恢复后必须换掉，否则模型看到的还是旧状态
        if self.agent is not None:
            self.agent.session = prev
            n = self.agent.restore(prev.history) if prev.history else 0
            if n:
                print(f"   已恢复对话历史 {n} 条（{prev.history_turns} 轮提问），模型记得上次聊过什么")
            else:
                print("   该会话没有对话历史（旧版本快照或当时未使用 Agent），模型将从零开始")
        elif prev.history:
            print(f"   已恢复对话历史 {len(prev.history)} 条（切到 Agent 模式后生效）")
        # 凭证与 token 刻意不落盘（快照可能被分享出去），所以恢复后要重新登录
        if prev.result.assets and not prev.credentials.get("token"):
            print("   提示：凭证不写入快照，需要重新 /login 才能做带凭证的测试")
        # 恢复后顺手回填：老快照里手工登记的发现常常只有请求没有响应
        # （旧版 record_finding 的锅），而当时的真实响应还在 history 里。
        # 补上之后 /report 导出的 PoC 段才完整。
        n = self._backfill(quiet=True)
        if n:
            print(f"   已从会话历史回填 {n} 条发现的原始报文（/report 重导即可看到）")

    def _backfill(self, quiet: bool = False) -> int:
        """从会话历史把真实报文回填到发现上，返回补上的条数。

        为什么需要它：``record_finding`` 早期版本把说明文字截断后又当成
        响应体存了——那些发现的报告就只剩请求、没有响应。数据源头已丢，
        但**当时的 http_request 结果还在对话历史里**（会话快照带了 history），
        所以恢复会话后能把响应补回去，重新导出就是一份完整报告。
        只补空字段，绝不动已有记录。
        """
        from core.backfill import backfill_findings

        stat = backfill_findings(
            self.session,
            evidence_dir=str(getattr(self.cfg.scan, "evidence_dir", "") or ""),
        )
        if quiet:
            return stat["filled"]
        print(
            f"历史里识别到 {stat['exchanges']} 次真实请求，"
            f"缺响应的发现 {stat['candidates']} 条，"
            f"已回填 {stat['filled']} 条。"
        )
        if stat["filled"]:
            print("   回填的正文是当时的**预览截断版**（工具结果里就这么多），"
                  "报告会如实标注；想要完整响应需要重新请求一次。")
            print("   现在可以 /report 重新导出，PoC 段就带上真实请求/响应了。")
        elif stat["candidates"]:
            print("   没匹配上：历史里没有同 URL 的请求记录"
                  "（会话历史只保留最近若干轮，早期轮次可能已被裁掉）。")
        return stat["filled"]

    def _clean_sessions(self) -> None:
        """``/clean``：删掉所有空会话目录（含历史遗留的）。"""
        base = Path(self.cfg.data_dir) / "sessions"
        gone = purge_empty_sessions(base)
        if not gone:
            print("没有空会话需要清理。")
            return
        print(f"已删除 {len(gone)} 个空会话：")
        for name in gone:
            print(f"  {name}")
        left = len(list_sessions(base, limit=10**6))
        print(f"   剩余 {left} 个会话用 /sessions 查看")

    def _sessions(self) -> None:
        """列出可恢复的会话。"""
        items = list_sessions(Path(self.cfg.data_dir) / "sessions", limit=10)
        if not items:
            print("（没有可恢复的会话）")
            return
        import time as _t

        print(f"\n可恢复会话（最近 {len(items)} 个，用 /resume <id> 载入）：")
        for name, s in items:
            try:
                when = _t.strftime("%m-%d %H:%M", _t.localtime(s.updated_at))
            except (ValueError, OSError):
                when = "?"
            c = s.counts()
            nfind = sum(c.values())
            hist = f"对话 {len(s.history)} 条" if s.history else "无对话"
            print(
                f"  {name}  {when}  {s.phase.label:4} "
                f"资产 {len(s.result.assets):3} 发现 {nfind:2} {hist}  {s.target or '（无目标）'}"
            )

    # ── 持久化 ────────────────────────────────────────────────────
    def _save(self) -> Path | None:
        """落盘会话；**空会话不落盘**，返回 None。

        以前这里是无条件 ``self.session.save(...)``，于是"进来看看就 /quit"
        每次都留一个空目录：``/sessions`` 列表被纯噪音填满，真正有用的那次
        被挤出"最近 N 条"，``/resume <Tab>`` 也补全出一串无差别空壳。

        现在先判空（:meth:`Session.is_empty`）：没目标、没说话、没资产/发现，
        就干脆不写盘。判定从严——拿不准一律保留，误删不可逆。

        注意：**已经有目录的老会话不会被这里删**。如果它本来就是空的，
        这里只是不再更新它；磁盘上残留的旧空壳由 :func:`purge_empty_sessions`
        在恢复/清理时收掉。
        """
        # 保存前把 Agent 对话历史同步进 Session，快照才是完整的
        if self.agent_on and self.agent is not None:
            self.session.sync_history(self.agent.history)
        if self.session.is_empty():
            return None
        return self.session.save(Path(self.cfg.data_dir) / "sessions")


