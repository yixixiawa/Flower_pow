"""``_SessionMixin``：误报排除 / 对话轮 / 模型 / 报告 / 会话存取。

``_resume`` 载入后会顺带跑一次 ``_backfill``，从对话历史把当时的真实报文
回填到发现上——否则老会话导出的报告里只有请求、没有响应。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pathlib import Path
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl.consts import _REPORT_NOTE_PREFIX


if TYPE_CHECKING:  # 类型检查期继承成员契约；运行期 _Base 是 object，MRO 与行为不变
    from core.repl._contract import _ReplContract as _Base
else:
    _Base = object


class _SessionMixin(_Base):
    def _sessions_dir(self) -> Path:
        """会话快照根目录（``data/sessions``）。

        单点定义：``/reset`` 要删快照、``/resume`` 要读快照、``_save`` 要写
        快照，四处都用同一个路径，散着写迟早有一处写歪。
        """
        return Path(self.cfg.data_dir) / "sessions"

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

    def _pick_session(self, base: Path, ref: str) -> "Session | None":
        """把用户给的引用解析成一个会话：``#3`` / 目录名 / id / 唯一子串。

        支持编号是为了"看得见就能选"——``/sessions`` 里每条都有 ``#N``，
        照着敲 ``/resume #N`` 即可，不用复制那一长串中文目录名。
        注意纯数字目录名（``1791789725``）优先按**名字**匹配，不会被
        误当成序号。
        """
        items = list_sessions(base, limit=None)
        if not items:
            return None
        ref = (ref or "").strip()

        if ref.startswith("#"):
            try:
                n = int(ref[1:])
            except ValueError:
                return None
            return items[n - 1][1] if 1 <= n <= len(items) else None

        for name, s in items:
            if ref in (name, s.session_id):
                return s

        if ref.isdigit():
            n = int(ref)
            if 1 <= n <= len(items):
                return items[n - 1][1]

        low = ref.lower()
        hits = [(name, s) for name, s in items if low in name.lower()]
        if len(hits) == 1:
            return hits[0][1]
        if len(hits) > 1:
            print(f"「{ref}」匹配到 {len(hits)} 个会话，请用编号或完整名字：")
            for name, _s in hits[:8]:
                print(f"  {name}")
        return None

    def _resume(self, session_id: str = "") -> None:
        """恢复会话。``session_id`` 为空时取最近一次。

        恢复前先顺手清掉历史遗留的空壳（见 :func:`purge_empty_sessions`）：
        用户此刻正在挑要恢复哪一个，正是把噪音清掉的时机。清理结果只报一句
        汇总，不逐条刷屏。
        """
        base = self._sessions_dir()
        gone = purge_empty_sessions(base)
        if gone:
            print(f"（已清理 {len(gone)} 个空会话：{'、'.join(gone[:3])}…）"
                  if len(gone) > 3 else f"（已清理 {len(gone)} 个空会话：{'、'.join(gone)}）")
        if session_id:
            prev = self._pick_session(base, session_id)
            if prev is None:
                print(f"没有找到会话 {session_id}（用 /sessions 看可恢复列表，"
                      f"支持 /resume #编号）")
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
            print("   提示：凭证不写入快照，需要重新取得凭证（Agent 模式下用 login 工具）才能做带凭证的测试")
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
        base = self._sessions_dir()
        gone = purge_empty_sessions(base)
        if not gone:
            print("没有空会话需要清理。")
            return
        print(f"已删除 {len(gone)} 个空会话：")
        for name in gone:
            print(f"  {name}")
        left = len(list_sessions(base, limit=10**6))
        print(f"   剩余 {left} 个会话用 /sessions 查看")

    def _sessions(self, arg: str = "") -> None:
        """``/sessions [N|all]``：列出可恢复的会话（默认全量，带序号）。

        以前这里硬编码 ``limit=10`` 且只印名字：会话一多，老会话就永远
        看不见，也无法"按编号挑"。现在：

        * 默认**列出全部**，超过 20 条时提示可用 ``/sessions N`` 只看最近 N 条
        * 每条带序号 ``#1``，``/resume #1`` 直接选
        * 显示标题（第一轮对话）、更新时间、阶段、资产/发现/对话条数、目标
        """
        items = list_sessions(self._sessions_dir(), limit=None)
        if not items:
            print("（没有可恢复的会话）")
            return
        import time as _t

        show = items
        want = (arg or "").strip().lower()
        if want and want not in ("all", "a"):
            try:
                n = int(want)
                show = items[: max(1, n)]
            except ValueError:
                print("用法：/sessions [N|all]（N=只看最近 N 条，默认全部）")
                return

        total = len(items)
        print(f"\n可恢复会话（共 {total} 个，用 /resume <编号|会话名> 载入）：")
        for i, (name, s) in enumerate(show, 1):
            try:
                when = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(s.updated_at))
            except (ValueError, OSError, OverflowError):
                when = "?"
            c = s.counts()
            nfind = sum(c.values())
            hist = f"对话 {len(s.history)} 条" if s.history else "无对话"
            title = (s.display_title or "").strip()
            # 目录名已经是 日期_标题、或标题就等于目标时不必重复印
            extra = (
                f"  {title}"
                if title and title not in name and title != (s.target or "")
                else ""
            )
            print(
                f"  #{i:<2} {name}{extra}\n"
                f"      {when}  {s.phase.label:4}  "
                f"资产 {len(s.result.assets):3} 发现 {nfind:2} {hist}  "
                f"{s.target or '（无目标）'}"
            )
        if len(show) < total:
            print(f"  （还有 {total - len(show)} 个更早的会话，用 /sessions all 看全量）")

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
        return self.session.save(self._sessions_dir())


