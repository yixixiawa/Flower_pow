"""``_CommandMixin``：目标 / 工具 / 凭证 / 轮询 / 状态 / 资产 / 发现。"""

from __future__ import annotations

import time as _t
from core.repl.consts import _console


class _CommandMixin:
    def _toggle_agent(self, on: bool) -> None:
        if on and self.agent is None:
            if not (self.cfg.llm.enabled and self.cfg.llm.api_key):
                print("没有可用的 API Key，无法启用 Agent。先用 /key 配置。")
                return
            self._build_agent()
            # 恢复出来的会话：把历史回填，模型才接得上之前聊的
            if self.session.history:
                n = self.agent.restore(self.session.history)
                print(f"   已回填对话历史 {n} 条")
        if not on and self.agent is not None:
            self.agent = None
            print("已切到剧本模式（第 1 轮信息收集 → 第 2 轮建模 → 第 3 轮测试 → 迭代）")
            return
        if on:
            print(f"已切到 Agent 模式（模型 {self.cfg.llm.model}，工具 {len(self.tools)} 个）")
        else:
            print("当前已是剧本模式")

    # ── 目标作用域：/reset 与 /target 切换共用 ────────────────────
    #
    # 「目标作用域」= 只对当前被测对象成立的数据。换目标或彻底重置时，
    # 这些东西必须一起清掉——留着就会串线：上一个目标的资产进下一个目标
    # 的报告、上一段对话里的目标被模型当成本轮的前提。
    def _purge_target_scope(self) -> None:
        """清空**与目标绑定**的全部数据（换目标 / 彻底重置时调用）。

        逐项说明为什么必须清：

        * ``assets`` / ``findings`` / ``fingerprints``：目标独有的产物，
          留着就是报告串线的直接来源。
        * ``notes`` / ``errors``：对目标写的备注与错误日志，换目标后
          描述的是另一个对象，属于误导。
        * ``credentials``：上一个目标的账号口令，对新目标无意义且
          不该跨目标留存。
        * ``turns`` / ``model``：轮次记录与**业务模型**（接口图、鉴权流），
          是上一个目标推导出来的，拿来指导新目标 = 拿错地图打仗。
        * ``agent.reset()``：对话历史与防死循环状态一并清掉，模型彻底失忆。
        * ``runner.reset_target_scope()``：运行期缓存（最近一次 HTTP 响应
          快照、端点/主机连击计数）也是目标专属的——留着的话登记发现时
          可能把**上一个目标**的响应当成新目标的贴进报告。
        """
        r = self.session.result
        r.assets.clear()
        r.findings.clear()
        r.fingerprints.clear()
        r.notes.clear()
        r.errors.clear()
        self.session.credentials.clear()
        self.session.turns.clear()
        from core.session import BusinessModel

        self.session.model = BusinessModel()
        if self.agent is not None:
            self.agent.reset()
        if self.runner is not None:
            self.runner.reset_target_scope()

    def _reset(self, args: str = "") -> None:
        """彻底重置：销毁当前所有数据，开启全新会话。

        与旧的"只清 Agent 对话历史、资产与发现保留"是两回事：
        现在是**把这把椅子砸了换把新的**——目标、资产、发现、指纹、备注、
        凭证、对话历史、盘上的会话快照，全部销毁。

        盘上那份快照也删：留着的话 ``/sessions`` 还能把它列出来、
        ``/resume`` 又能把旧目标的上下文请回来，那就叫"没留痕迹"了。
        （``output/`` 下的历史报告不动——那是交付物，不是会话状态。）
        """
        from core.session import Phase, Session

        old = self.session
        base = self._sessions_dir()
        if base:
            try:
                if old.delete(base):
                    print(f"已删除盘上会话快照：{old.dir_path}")
            except OSError as exc:
                print(f"（会话快照删除失败：{exc} —— 内存数据仍已清空）")

        self.session = Session(target="", phase=Phase.RECON)
        # 规划器持有旧 session 引用，必须一起换掉
        self._planner = None
        if self.agent is not None:
            self.agent.session = self.session
            self.agent.reset()
        if self.runner is not None:
            self.runner.reset_target_scope()
        print("✓ 已彻底重置。所有目标、资产、发现与上下文均已销毁。")
        self._refresh_completer()

    def _set_target(self, url: str) -> None:
        """设定/切换目标。

        **切换 = 换了一个被测对象**：旧目标的资产、发现、指纹、凭证、
        对话历史必须一起清空，否则新目标的报告里会混进旧目标的产物
        （真事故：域名会话里登记了另一个 IP 的漏洞，报告直接串线）。
        目标没变则什么都不做——重复设定同一目标不该毁掉已有进度。
        """
        url = (url or "").strip()
        if not url:
            print(f"当前目标：{self.session.target or '（未设定）'}")
            return
        norm = (url if "://" in url else f"http://{url}").rstrip("/")
        if self.session.target == norm:
            print("目标未改变。")
            return
        if self.session.target:
            print("⚠ 检测到目标切换，已清空上一目标的所有资产与发现。")
            self._purge_target_scope()
        self.session.target = norm
        self.session.result.target = norm
        print(f"✓ 目标已设定为：{norm}，上下文已完全重置。")
        self._refresh_completer()

    def _tools(self) -> None:
        from core.tools import BUILTINS, EXTERNAL_TOOLS

        print(f"\n内置工具 {len([b for b in BUILTINS if b.name != 'external_tool'])} 个：")
        groups: dict[str, list[str]] = {}
        for b in BUILTINS:
            groups.setdefault(b.group, []).append(b.name)
        for g, names in groups.items():
            print(f"  [{g}] {', '.join(names)}")

        if not self.probes:
            print("\n外部工具：未探测")
            return
        found = [p for p in self.probes if p.found]
        missing = [p for p in self.probes if not p.found]
        print(f"\n外部工具 {len(found)}/{len(self.probes)} 可用：")
        for p in found:
            tag = "  [攻击性·只读模式拦截]" if (p.spec.intrusive and self.cfg.scan.readonly) else ""
            print(f"  ✓ {p.spec.key:10} {p.status:12} {p.path}{tag}")
        if missing:
            print("  未安装：" + ", ".join(p.spec.key for p in missing))
        print(f"\n注册表共 {len(EXTERNAL_TOOLS)} 个，未探测到的不会暴露给模型（避免它去调不存在的命令）")

    def _set_key(self) -> None:
        from core.bootstrap import ensure_api_key
        from core.envfile import DEFAULT_ENV_PATH
        from core.tools import EnvReport

        rep = EnvReport(api_key_set=False)
        key, source, ok = ensure_api_key(self.cfg, rep, _console(), interactive=True, verify=True)
        if not key:
            print("未设置 API Key")
            return
        self.cfg.llm.api_key = key
        if self.agent is None and self.cfg.llm.enabled:
            self._build_agent()
        print(f"✓ Key 已生效（{source}，{DEFAULT_ENV_PATH}）")
        if self.agent_on:
            print(f"Agent 已就绪：模型 {self.cfg.llm.model}，工具 {len(self.tools)} 个")

    # ── 剧本模式动作 ──────────────────────────────────────────────

    async def _advance_and_run(self):
        if self.session.turn_no > 1:
            self.session.advance()
        t = await self.planner.run_turn(self.session)
        self._save()
        return t

    # ── 自动轮询到穷尽 ────────────────────────────────────────────

    async def _poll(self, raw: str = "") -> None:
        """``/poll [轮数]`` —— 自动连续跑轮，穷尽了才停。

        为什么要它：跑一个站点往往十几轮，每轮之间都要人守着敲一次回车；
        而"什么时候算测完"也只能靠人自己看。这里把两件事一起解决——
        循环由 :func:`core.progress.poll_until_done` 驱动，停止由
        :class:`core.progress.Exhaustion` 判定（连续 2 轮无产出且无建议）。

        轮数上限是**安全阀不是穷尽判据**：Agent 可以每轮都调一次工具、每轮都不
        产出结论，那样永远判不出穷尽，token 会一直烧。到上限时的措辞与"已穷尽"
        严格分开——否则用户会以为覆盖面完整了。
        """
        from core.progress import Exhaustion, RoundOutcome, poll_until_done

        if not self.session.target:
            print("还没有目标。先用 /target <url> 或直接说要测哪个站。")
            return

        parts = raw.split()
        want = 0
        if len(parts) > 1:
            try:
                want = int(parts[1])
            except ValueError:
                print(f"轮数要是个整数，收到 {parts[1]!r}。用法：/poll [轮数]")
                return

        cap = want or int(getattr(self.cfg.scan, "auto_max_rounds", 12) or 0)
        ex = Exhaustion(max_rounds=cap)
        mode = "Agent" if self.agent_on else "剧本"
        limit = f"{cap} 轮" if cap else "不限轮数"
        print(
            f"\n自动轮询（{mode}模式）：最多 {limit}，"
            f"连续 {ex.idle_limit} 轮没有任何新增（资产/发现/建模项）"
            f"即判定穷尽。Ctrl-C 可随时中断。"
        )

        async def one_round(no: int) -> RoundOutcome:
            a0 = len(self.session.result.assets)
            f0 = len(self.session.result.findings)
            m0 = len(self.session.model.resources)
            t0 = _t.perf_counter()
            suggestions: list[str] = []
            if self.agent_on:
                await self._run_agent(
                    "继续。基于当前状态判断下一步该做什么，然后执行。"
                )
            else:
                t = await self._advance_and_run()
                suggestions = list(getattr(t, "suggestions", []) or [])
            return RoundOutcome(
                no=no,
                new_assets=len(self.session.result.assets) - a0,
                new_findings=len(self.session.result.findings) - f0,
                # 建模阶段的主要产出不是资产也不是发现，不数它就会把
                # "这一轮建好了业务模型"误判成空转
                new_model=len(self.session.model.resources) - m0,
                suggestions=suggestions,
                elapsed=_t.perf_counter() - t0,
            )

        try:
            kind, history = await poll_until_done(
                one_round,
                ex=ex,
                on_round=lambda o: print(f"  {o.line()}"),
                checkpoint=self._save,
            )
        except KeyboardInterrupt:
            # 中断要立刻生效（驱动层刻意不吞它），会话已经逐轮存过
            print("\n[yellow]已中断自动轮询。会话已保存，可继续用 /poll 或回车逐轮跑。[/yellow]")
            self._refresh_completer()
            return

        print(f"\n{ex.verdict()}")
        total_a = sum(o.new_assets for o in history)
        total_f = sum(o.new_findings for o in history)
        print(f"  合计 {len(history)} 轮：+{total_a} 资产、+{total_f} 发现")
        self._refresh_completer()

    # ── 视图 ──────────────────────────────────────────────────────
    def _status(self) -> None:
        s = self.session
        print(f"\n{s.status_line()}")
        if s.result.fingerprints:
            print(f"指纹：{s.result.fingerprints[0].summary()}")
        print(f"模型：{s.model.summary()}" if s.model.resources else "模型：尚未建模")
        tok = "已获取" if s.credentials.get("token") else "未获取"
        print(f"凭证：{tok}")
        if self.agent_on:
            print(f"Agent：{len(self.tools)} 个工具，对话历史 {self.agent.history_len()} 条消息")
            calls = self.runner.calls if self.runner else []
            if calls:
                ok = sum(1 for c in calls if c["status"] == "ok")
                refused = sum(
                    1 for c in calls if c["status"] in ("blocked", "badargs", "missing", "unknown")
                )
                failed = sum(1 for c in calls if c["status"] in ("error", "timeout"))
                print(f"工具调用：{len(calls)} 次（成功 {ok}、被拒绝 {refused}、失败 {failed}）")
        if s.turns:
            last = s.turns[-1]
            print(f"上一轮：{last.phase.label}（+{last.new_assets} 资产、+{last.new_findings} 发现）")

    def _assets(self, kind: str) -> None:
        from collections import Counter

        assets = self.session.result.assets
        if not assets:
            print("（无资产，先跑一轮信息收集）")
            return
        c = Counter(a.kind for a in assets)
        print(f"\n资产 {len(assets)} 项：")
        for k, v in c.most_common():
            print(f"  {k:10} {v}")
        if kind:
            shown = [a for a in assets if a.kind == kind][:40]
            print(f"\n--- {kind}（{len(shown)}）---")
            for a in shown:
                print(f"  {a.value[:100]}")

    def _findings(self, show_dismissed: bool = False) -> None:
        """列出发现。**编号与 Agent 排除误报时引用的是同一套顺序**（见 _finding_rows）。"""
        rows = self._finding_rows(show_dismissed=show_dismissed)
        if not rows:
            print("（暂无发现）")
            return
        active = self.session.result.active_findings()
        dismissed = self.session.result.dismissed_findings()
        head = f"\n发现 {len(active)} 条有效"
        if dismissed:
            head += f"（另有 {len(dismissed)} 条已排除）"
        print(head + "：")
        from core.state import Severity

        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO):
            group = [(i, f) for i, f in rows if f.severity is sev]
            if not group:
                continue
            print(f"\n  [{sev.label}] {len(group)} 项")
            for i, f in group[:10]:
                flag = " [已排除]" if f.dismissed else ""
                print(f"    {i}. {f.poc_id}: {f.name}{flag}")
                print(f"       {f.matched_at[:90]}")
                if f.dismissed and f.dismiss_reason:
                    print(f"       排除原因：{f.dismiss_reason[:70]}")
        if dismissed and not show_dismissed:
            print("\n  （已排除项由 Agent 的 dismiss_finding 工具管理，可撤销）")

    def _finding_rows(self, *, show_dismissed: bool = False) -> list[tuple[int, object]]:
        """``[(编号, Finding)]``。编号**始终按含已排除的全表算**。

        为什么编号要含已排除项：编号是用户和模型引用一条发现的唯一抓手，
        必须与它是否被排除无关。若按"当前可见的列表"编号，排除一条之后
        后面所有编号都会平移，之前记下的编号就指向别的漏洞了。
        """
        from core.state import Severity as _S

        full = sorted(
            self.session.result.findings, key=lambda x: x.severity.rank, reverse=True
        )
        rows = [(i + 1, f) for i, f in enumerate(full)]
        return rows if show_dismissed else [(i, f) for i, f in rows if f.active]

