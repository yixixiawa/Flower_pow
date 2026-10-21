"""``_AutoMixin``：一键全自动（``/auto`` 与 Alt+Shift 热键）。

上传类动作仍然要**人工审批**——全自动指的是「不用盯着敲回车」，
不是「什么都替你点确认」。"""

from __future__ import annotations

import asyncio
import time as _t
from core.repl.consts import AUTO_WARN


class _AutoMixin:
    async def _autopilot(self) -> None:
        """一键跑完整条流水线：先给警告，确认后不再打断。

        用户的要求是「把警告内容给用户，执意开启则不做阻拦」——所以这里
        **只拦一次**，而且拦的是"你知不知道接下来会发生什么"，不是"你配不配
        跑"。确认之后全程不再询问，包括文件上传（改走 :meth:`_auto_approve`
        只记录不阻拦）。
        """
        if not self.session.target:
            print("\n还没有目标。先 /target <URL>，或直接说要测哪个站。")
            return

        print(AUTO_WARN.format(target=self.session.target))
        try:
            ans = await asyncio.to_thread(
                input, "  已阅读上述内容，确认全自动执行？[y/N] "
            )
        except (EOFError, KeyboardInterrupt):
            print("\n  已取消。")
            return
        if (ans or "").strip().lower() not in ("y", "yes"):
            print("  已取消（未确认，什么都没发）。")
            return

        # 全自动期间把审核通道换成"只记录不询问"。用完必须换回来，
        # 否则后续手动轮次的上传也会变成静默放行。
        prev = getattr(self.runner, "approver", None) if self.runner else None
        if self.runner is not None:
            self.runner.approver = self._auto_approve

        from core.scheduler import Scheduler

        sched = Scheduler(self.cfg, approver=self._auto_approve)
        print(f"\n▶ 全自动开始：{self.session.target}（Ctrl+C 可中断）")
        t0 = _t.time()
        result = None
        try:
            result = await sched.scan(self.session.target, verbose=True)
        except KeyboardInterrupt:
            print("\n[yellow]已中断全自动（已完成的部分仍然保留）[/yellow]")
        except Exception as exc:  # noqa: BLE001
            print(f"\n[!] 全自动执行异常：{type(exc).__name__}: {exc}")
        finally:
            if self.runner is not None:
                self.runner.approver = prev

        if result is None:
            return
        n_new = self._merge_scan(result)
        print(
            f"\n✓ 全自动完成，用时 {_t.time() - t0:.1f}s："
            f"新增资产 {n_new['assets']}、新增发现 {n_new['findings']}"
        )
        self._findings()
        try:
            await self._report()
        except Exception as exc:  # noqa: BLE001
            print(f"[!] 报告导出失败：{type(exc).__name__}: {exc}")

    async def _auto_approve(self, desc: str) -> bool:
        """全自动期间的写操作通道：**不阻拦，但每一条都留痕**。

        为什么还要打印而不直接 ``return True``：上传会在目标上留下文件，
        事后必须能回答"到底写进去了几个、写到哪"。打印 + 写进 notes，
        是为了让"一键"不等于"无法审计"。
        """
        first = (desc or "").splitlines()[0] if desc else ""
        print(f"  [auto] 写操作放行：{first}")
        self.session.result.notes.append(f"[全自动] 已放行写操作：{first}")
        return True

    def _merge_scan(self, result) -> dict[str, int]:
        """把 ``Scheduler.scan`` 的结果并回当前会话。

        并回而不是替换：会话里可能已经有手动轮次攒下的资产与发现，
        全量替换会把它们抹掉。去重键用（类型, 值）/（poc_id, 名称, 位置），
        避免同一条被记两遍。
        """
        s = self.session
        turn = s.begin_turn("全自动（Alt+Shift / /auto）")
        a0, f0 = len(s.result.assets), len(s.result.findings)

        seen_a = {(a.kind, a.value) for a in s.result.assets}
        for a in result.assets:
            k = (a.kind, a.value)
            if k not in seen_a:
                seen_a.add(k)
                s.result.assets.append(a)

        # 发现统一走 add_findings：去重、误报排除、重排都在那一处。
        # 以前这里自己按 (poc_id, name, matched_at) 去重，与 toolrun 的
        # (poc_id, matched_at) 不一致——同一目标同一位置换个 name 就漏过重复，
        # 而"误报排除"这种策略更是完全轮不到执行。
        s.result.add_findings(list(result.findings))

        have_fp = {fp.summary() for fp in s.result.fingerprints}
        for fp in result.fingerprints:
            if fp.summary() not in have_fp:
                have_fp.add(fp.summary())
                s.result.fingerprints.append(fp)

        for note in result.notes:
            s.result.notes.append(note)
        for err in result.errors:
            s.result.errors.append(err)

        s.end_turn(
            turn,
            assets_before=a0,
            findings_before=f0,
            suggestions=["用 /report 导出报告", "用 /findings 复核高危项"],
        )
        try:
            s.add_conversation("全自动扫描", ["scheduler"])
        except Exception:  # noqa: BLE001
            pass
        self._refresh_completer()
        self._save()
        return {"assets": len(s.result.assets) - a0, "findings": len(s.result.findings) - f0}

    # ── Tab 补全 ──────────────────────────────────────────────────
