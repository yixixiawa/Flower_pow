"""发现台账：列表、按编号定位、公开暴露复核、误报排除与撤销。

这里的编号（``[1] [2] ...``）是模型、CLI、报告三条入口共用的寻址方式，
顺序在 :meth:`_finding_list` 一处定义，改了会让"刚排除的那条"对不上号。
"""

from __future__ import annotations


from core import exclusions
from core.state import Finding, dismiss_finding, restore_finding


class FindingMixin:
    """见模块说明。"""

    # ── 报告类 ────────────────────────────────────────────────────

    @staticmethod
    def _finding_list(session, *, include_dismissed: bool = False) -> list[Finding]:
        """列表顺序 = ``/findings`` 与 ``findings`` 工具里那个编号的顺序。

        **只在这一处定序**：编号在列表里出现、又在 dismiss_finding 里被引用，
        两边各排一次迟早会错位（一个按严重度排、一个按入库顺序排），
        用户照着编号排除就会删错东西。
        """
        fs = sorted(
            session.result.findings, key=lambda x: x.severity.rank, reverse=True
        )
        if not include_dismissed:
            fs = [f for f in fs if f.active]
        return fs

    @classmethod
    def resolve_finding(cls, session, ref: str) -> tuple[Finding | None, str]:
        """把用户/模型给的引用解析成一条发现。返回 ``(Finding|None, 错误说明)``。

        接受三种写法：
        * **编号**（``3``）——按 :meth:`_finding_list` 的顺序，与列表里显示的一致；
        * **完整 poc_id**（``path-backup-file``）；
        * **唯一子串**（``backup``）——只在唯一命中时才接受，命中多条就报错，
          绝不替用户猜（猜错了就是删错一条真实漏洞）。
        """
        r = (ref or "").strip()
        if not r:
            return None, "ref 不能为空：给编号（见 findings 列表）或 poc_id"

        if r.isdigit():
            fs = cls._finding_list(session, include_dismissed=True)
            n = int(r)
            if not 1 <= n <= len(fs):
                return None, (
                    f"编号 {n} 超出范围（共 {len(fs)} 条，含已排除）；"
                    "先用 findings 看当前清单"
                )
            return fs[n - 1], ""

        allf = session.result.findings
        exact = [f for f in allf if f.poc_id == r]
        if len(exact) == 1:
            return exact[0], ""
        if len(exact) > 1:
            # 同一个 poc_id 命中多个位置是常态（同一路径扫描器在多条 URL 上命中），
            # 这时必须用编号或完整 matched_at 指定，不能随便挑一条。
            return None, (
                f"poc_id「{r}」对应 {len(exact)} 条发现，无法确定是哪条；"
                "请用 findings 里的编号指定"
            )

        sub = [f for f in allf if r.lower() in f.poc_id.lower()]
        if len(sub) == 1:
            return sub[0], ""
        if len(sub) > 1:
            names = "、".join(f.poc_id for f in sub[:6])
            return None, f"「{r}」匹配到 {len(sub)} 条（{names}…），请用编号或完整 poc_id"
        return None, f"找不到匹配「{r}」的发现；先用 findings 看清单"

    async def _h_check_public_finding(
        self, session, ref: str = "", apply: bool = True
    ) -> str:
        return await self.check_public(session, ref=ref, apply=apply)

    async def check_public(self, session, *, ref: str = "", apply: bool = True) -> str:
        """回源站根目录核验发现的"公开性"，够强就自动判为误报。

        为什么要回源取证而不是看命中的 URL 本身：**命中的 URL 只能告诉你
        "这里有个东西"，告诉你"它是不是有意公开的"**。判断依据在根目录那边——
        首页自述、首页链接、sitemap、robots。公开演示站是最典型的一类：
        站点本身就建给人看，"泄露"的配置与接口文档属于设计而非漏洞。

        ``ref="all"``（或空）核验全部有效发现。返回值里明确区分三档，
        让用户知道**哪些被自动排除了、哪些只是疑似**——只报告"已排除 N 条"
        会让人误以为剩下的都确认过。
        """
        from detectors.public_check import PublicResourceChecker

        if not (session.target or "").strip():
            return "核验失败：会话还没有目标，先用 set_target 设定。"

        if (ref or "").strip().lower() in ("", "all", "*"):
            targets = session.result.active_findings()
            label = "全部有效发现"
        else:
            f, err = self.resolve_finding(session, ref)
            if f is None:
                return f"核验失败：{err}"
            targets = [f]
            label = f"{f.poc_id}"

        if not targets:
            return "当前没有有效发现需要核验。"

        checker = PublicResourceChecker(self.cfg.scan, verbose=False)
        try:
            verdicts = await checker.check_many(session.target, targets)
        finally:
            await checker.aclose()

        public = [v for v in verdicts if v.auto_dismissible]
        suspect = [v for v in verdicts if v.confidence == "suspect"]
        weak = [v for v in verdicts if v.confidence == "weak"]
        clean = [v for v in verdicts if v.confidence == "none"]

        lines = [f"公开性核验（{label}，共 {len(verdicts)} 条）："]

        dismissed = 0
        if public:
            lines.append(f"\n  ★ 判定为公开资源、{'已自动排除' if apply else '建议排除'}：")
            for v in public:
                lines.append(f"    · {v.describe()}")
            if apply:
                by_key = {
                    (x.poc_id, x.matched_at): x for x in session.result.findings
                }
                for v in public:
                    f = by_key.get((v.poc_id, v.matched_at))
                    if f is None or not f.active:
                        continue
                    out = self.dismiss(
                        session, finding=f, reason=v.reason_text()
                    )
                    if not out.startswith("排除失败"):
                        dismissed += 1

        if suspect:
            lines.append(
                "\n  ? 疑似公开（中等证据），**未自动排除**——证据够强才自动删，"
                "建议人工确认："
            )
            for v in suspect:
                lines.append(f"    · {v.describe()}")
        if weak:
            lines.append("\n  · 仅有个别公开特征，**未自动排除**：")
            for v in weak:
                lines.append(f"    · {v.describe()}")

        if clean:
            lines.append(f"\n  — 无公开特征，保持为有效发现：{len(clean)} 条")

        lines.append(
            f"\n  小计：自动排除 {dismissed} 条 / 疑似待确认 {len(suspect) + len(weak)} 条 / "
            f"保持有效 {len(clean)} 条"
        )
        if dismissed:
            lines.append(
                "  被排除的项会出现在报告的「已排除的发现（误报复核）」附录里，"
                "附证据说明，可用 dismiss_finding(ref=…, undo=true) 撤销。"
            )
        return "\n".join(lines)

    async def _h_findings(
        self, session, severity: str = "all", include_dismissed: bool = False
    ) -> str:
        fs = self._finding_list(session, include_dismissed=include_dismissed)
        if severity and severity != "all":
            want = severity.lower()
            fs = [f for f in fs if f.severity.value == want]
        active = session.result.active_findings()
        dismissed = session.result.dismissed_findings()
        if not fs:
            extra = (
                f"（已排除的误报另有 {len(dismissed)} 条，"
                "传 include_dismissed=true 可查看）"
                if dismissed and not include_dismissed
                else f"（过滤条件：{severity}）"
            )
            return f"当前没有发现 {extra}"

        # 编号始终按**含已排除**的全表算，这样无论是否过滤，
        # 同一个编号指向的永远是同一条发现。
        full = self._finding_list(session, include_dismissed=True)
        idx = {id(f): i + 1 for i, f in enumerate(full)}
        lines = [
            f"发现 {len(active)} 条有效"
            + (f"（另有 {len(dismissed)} 条已排除，未计入）" if dismissed else "")
            + f"，下表 {len(fs)} 条："
        ]
        for f in fs[:30]:
            flag = "　[已排除]" if f.dismissed else ""
            lines.append(f"  [{idx.get(id(f), '?')}] [{f.severity.label}] {f.poc_id} {f.name}{flag}")
            lines.append(f"    位置：{f.matched_at[:110]}")
            if f.dismissed and f.dismiss_reason:
                lines.append(f"    排除原因：{f.dismiss_reason[:120]}")
            elif f.rationale:
                lines.append(f"    研判：{f.verdict}({f.confidence:.2f}) {f.rationale[:120]}")
        lines.append("  排除误报：dismiss_finding(ref=<编号>, reason=<依据>)")
        return "\n".join(lines)

    async def _h_dismiss_finding(
        self,
        session,
        ref: str = "",
        reason: str = "",
        undo: bool = False,
        purge: bool = False,
        scope: str = "finding",
    ) -> str:
        return self.dismiss(
            session, ref=ref, reason=reason, undo=undo, purge=purge, scope=scope
        )

    @classmethod
    def dismiss(
        cls,
        session,
        *,
        ref: str = "",
        reason: str = "",
        undo: bool = False,
        purge: bool = False,
        scope: str = "finding",
        finding: Finding | None = None,
    ) -> str:
        """把一条发现标记为误报并排除（或撤销 / 彻底删除）。**同步核心逻辑**。

        为什么把逻辑放在同步方法里、让 ``_h_dismiss_finding`` 当薄壳：
        模型走 tools、脚本走 CLI，两条入口必须是同一套语义。
        各写一遍的下场是"模型能排除、命令行不能"或者"排除范围不一致"——
        这类不一致极难发现，因为每条入口单看都自洽。

        ``finding`` 用于**精确指定对象**（批量核验时同一 poc_id 可能命中多个位置，
        用 ``ref`` 走编号解析会被"匹配到多条"挡住）。给了 ``finding`` 就不解析 ``ref``。

        为什么默认"标记"而不是"删除"：报告必须能解释"这条为什么没列出来"。
        硬删会连"谁在什么时候因为什么判的误报"一起丢掉，而这份复核记录本身
        就是交付物的一部分（客户会问"上次报的 XX 怎么没了"）。
        真不想留痕时传 ``purge=True``。
        """
        if finding is not None:
            f, err = finding, ""
        else:
            f, err = cls.resolve_finding(session, ref)
        if f is None:
            return f"排除失败：{err}"

        if undo:
            restore_finding(f)
            # 撤销必须连持久化排除项一起删，否则下一轮扫描又按清单把它标回来，
            # 用户看到的现象是"撤销根本没生效"。
            n = exclusions.remove(session.target, f.poc_id, f.matched_at)
            if not n and scope == "poc":
                n = exclusions.remove(session.target, f.poc_id, "")
            tail = f"（同步撤销了 {n} 条持久化排除项）" if n else ""
            return (
                f"已撤销误报标记：[{f.severity.label}] {f.name}{tail}\n"
                f"  位置：{f.matched_at}\n"
                f"  当前有效发现 {len(session.result.active_findings())} 条、"
                f"已排除 {len(session.result.dismissed_findings())} 条。"
            )

        if purge:
            before = len(session.result.findings)
            session.result.findings = [
                x for x in session.result.findings if x is not f
            ]
            # 彻底删除也要落排除清单——否则下一轮扫描它又回来了，
            # 用户会觉得"删了没用"。
            stored, _msg = exclusions.add(
                session.target, f.poc_id, f.matched_at, "已彻底删除（purge）",
                scope=scope,
            )
            return (
                f"已彻底删除：[{f.severity.label}] {f.name}\n"
                f"  位置：{f.matched_at}\n"
                f"  会话内发现 {before} → {len(session.result.findings)} 条。\n"
                f"  {'已写入排除清单，同一目标重扫不会再报出。' if stored else '⚠ 排除清单写入失败，重扫可能再次报出。'}\n"
                f"  注意：彻底删除**不留复核痕迹**，报告的「误报复核」附录里不会出现这条。"
                f"想让报告能解释「这条为什么没列出来」，请改用不带 purge 的标记。"
            )

        r = (reason or "").strip()
        if not r:
            return (
                "排除失败：reason 不能为空。"
                "报告里会列出「误报排除的复核记录」，没有依据的排除等于不可复核。"
                "例如：reason=公开演示站点，站点内容本就公开。"
            )
        dismiss_finding(f, r)
        stored, msg = exclusions.add(
            session.target, f.poc_id, f.matched_at, r, scope=scope
        )
        tail = (
            "已写入持久化排除清单，同一目标重扫不会再把这条当有效发现报出。"
            if stored
            else f"⚠ 持久化失败（{msg}），本次标记只在当前会话内有效。"
        )
        return (
            f"已排除为误报：[{f.severity.label}] {f.name}\n"
            f"  位置：{f.matched_at}\n"
            f"  原因：{r}\n"
            f"  {tail}\n"
            f"  当前有效发现 {len(session.result.active_findings())} 条、"
            f"已排除 {len(session.result.dismissed_findings())} 条。\n"
            f"  撤销用 dismiss_finding(ref='{ref}', undo=true)。"
        )
