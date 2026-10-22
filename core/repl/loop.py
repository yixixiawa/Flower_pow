"""``_LoopMixin``：主循环与命令分发。

``_handle`` 是**唯一**的命令入口：拿到 ``/xxx`` 拆成命令与参数再分派，
未知命令、人话、阶段推进、剧本模式下一轮都在这里分流。"""

from __future__ import annotations

from core.completer import Completer, HOTKEY_FULL_AUTO, PromptReader
from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)
from core.repl.consts import HELP
from core.repl.consts import BANNER
from core.repl.consts import BANNER_AGENT
from core.repl.consts import PHASE_ALIAS
from core.repl.consts import NATURAL
from core.repl.consts import _call_name


class _LoopMixin:
    async def loop(self) -> Session:
        print(BANNER_AGENT if self.agent_on else BANNER)
        if self.session.target:
            print(f"\n目标：{self.session.target}")
        else:
            print("\n目标：尚未设定（直接说要测哪个站即可）")
        print(f"阶段：{self.session.phase.label} —— {self.session.phase.goal}")
        if self.agent_on:
            print(f"模型：{self.cfg.llm.model} @ {self.cfg.llm.base_url}（流式）")
            if self.llm and getattr(self.llm, "tool_note", ""):
                print(f"  ⚠ {self.llm.tool_note}")
        else:
            print("模式：剧本模式（未配置 API Key，或用 /agent off 关闭了 Agent）")
            print("  [dim]提示：/key 可随时补上 API Key 以启用对话式 Agent[/dim]")

        if self.agent_on and self.kickoff:
            await self._kickoff()

        while True:
            try:
                tag = "agent" if self.agent_on else f"轮 {self.session.turn_no}·{self.session.phase.label}"
                raw = self.reader.read(f"\n[{tag}] > ")
                # Alt+Shift 热键：走全自动，不进命令分发
                if raw == HOTKEY_FULL_AUTO:
                    await self._autopilot()
                    continue
                raw = raw.strip()
                if raw:
                    self._push_history(raw)
            except (EOFError, KeyboardInterrupt):
                print("\n（退出）")
                break
            if not raw:
                await self._on_enter()
                continue
            if raw.lower() in ("/quit", "/exit", "quit", "exit", "q"):
                break
            try:
                keep = await self._handle(raw)
            except KeyboardInterrupt:
                print("\n[yellow]已中断本轮[/yellow]")
                keep = True
            except Exception as exc:  # noqa: BLE001
                print(f"[!] 命令执行异常：{type(exc).__name__}: {exc}")
                keep = True
            if not keep:
                break

        p = self._save()
        if p is None:
            print("\n（本次会话没有任何内容，未保存）")
        else:
            print(f"\n会话已保存：{p}")
        return self.session

    # ── 开场 / 回车 ───────────────────────────────────────────────

    async def _kickoff(self) -> None:
        """进入会话时先让模型开口（**默认不调用**，见 ``kickoff`` 参数）。

        这段开场白是模型自己写的，每次启动都不一样，且往往在用户还没说话时
        就刷屏一大段（"我是渗透测试操作员……请告诉我这次要测哪个目标"）。
        它不提供任何用户没要求的信息，还白白消耗一轮 token，因此改为
        **需要时才开**：``--kickoff`` 或 ``/kickoff``。
        """
        if self.session.target:
            prompt = (
                f"本次会话目标已设定为 {self.session.target}。"
                f"请先说明你打算怎么开展这一轮测试，然后开始执行。"
            )
        else:
            prompt = (
                "请用两三句话介绍你能做什么（强调你会调用本机真实工具拿事实），"
                "然后问我这次要测哪个目标。不要调用任何工具。"
            )
        await self._run_agent(prompt)

    async def _on_enter(self) -> None:
        if self.agent_on:
            await self._run_agent("继续。基于当前状态判断下一步该做什么，然后执行。")
        else:
            await self._advance_and_run()

    async def _run_agent(self, text: str) -> None:
        before = self.runner.calls if self.runner else []
        n_before = len(before)
        try:
            out = await self.agent.send(text)
        except KeyboardInterrupt:
            print("\n[yellow]已中断[/yellow]")
            out = ""
        except Exception as exc:  # noqa: BLE001
            print(f"\n[!] Agent 执行异常：{type(exc).__name__}: {exc}")
            out = ""
        # 给这一轮起标题并记录用了哪些工具（报告与回溯都需要）。
        # 这里曾经写 c["name"]，而 ToolRunner 记的是 "tool" —— 键名不一致导致
        # **每轮 Agent 跑完都 KeyError: 'name'**，而且异常被上面的 except 之外的
        # 这层 try 吞掉了一半，症状是"对话能跑但标题/工具清单丢"。统一走 _call_name。
        used = []
        if self.runner and len(self.runner.calls) > n_before:
            used = sorted({_call_name(c) for c in self.runner.calls[n_before:]} - {""})
        try:
            self.session.add_conversation(self._make_title(text, out or "", used), used)
        except Exception:  # noqa: BLE001
            pass
        self._refresh_completer()
        self._save()

    # ── 命令分发 ──────────────────────────────────────────────────
    async def _handle(self, raw: str) -> bool:
        low = raw.lower()

        if low in ("/help", "/?", "help"):
            print(HELP)
            return True
        if low == "/status":
            self._status()
            return True
        if low.startswith("/assets"):
            parts = raw.split()
            self._assets(parts[1] if len(parts) > 1 else "")
            return True
        if low in ("/findings", "/f"):
            self._findings()
            return True
        if low in ("/turns", "/history"):
            self._turns()
            return True
        if low in ("/model", "/business"):
            self._model()
            return True
        if low.startswith("/phase"):
            parts = raw.split()
            if len(parts) < 2 or parts[1].lower() not in PHASE_ALIAS:
                print("用法：/phase recon|model|exploit|iterate")
                return True
            self.session.set_phase(PHASE_ALIAS[parts[1].lower()])
            print(f"阶段切换为：{self.session.phase.label} —— {self.session.phase.goal}")
            return True
        if low == "/next":
            await self._advance_and_run()
            return True
        if low == "/run":
            await self.planner.run_turn(self.session, f"{self.session.phase.label}（重复）")
            self._save()
            return True
        if low.startswith("/poll"):
            await self._poll(raw)
            return True
        if low == "/report":
            await self._report()
            return True
        if low in ("/kickoff", "/hello"):
            if self.agent_on:
                await self._kickoff()
            else:
                print("当前不是 Agent 模式，无需开场")
            return True
        if low == "/chats":
            self._chats()
            return True
        if low.startswith("/title"):
            parts = raw.split(maxsplit=2)
            if len(parts) < 3:
                print("用法：/title <编号> <新标题>")
                self._chats()
            else:
                try:
                    self._set_title(int(parts[1]), parts[2])
                except ValueError:
                    print("编号必须是数字（用 /chats 看有哪些）")
            return True
        if low in ("/sessions", "/ls"):
            self._sessions()
            return True
        if low.startswith("/resume"):
            parts = raw.split()
            self._resume(parts[1] if len(parts) > 1 else "")
            return True
        if low.startswith("/backfill"):
            self._backfill()
            return True
        if low in ("/clean", "/purge"):
            self._clean_sessions()
            return True

        # ── 本次新增 ──────────────────────────────────────────────
        if low.startswith("/agent"):
            parts = raw.split()
            want = parts[1].lower() if len(parts) > 1 else ("off" if self.agent_on else "on")
            self._toggle_agent(want not in ("off", "0", "classic", "剧本"))
            return True
        if low.startswith("/target"):
            parts = raw.split(maxsplit=1)
            if len(parts) < 2:
                print(f"当前目标：{self.session.target or '（未设定）'}")
                return True
            self._set_target(parts[1].strip())
            return True
        if low in ("/tools", "/tool"):
            self._tools()
            return True
        if low.startswith("/key"):
            self._set_key()
            return True
        if low == "/auto":
            await self._autopilot()
            return True
        if low in ("/reset", "/clear"):
            self._reset(raw)
            return True

        # ── 自然语言 ──────────────────────────────────────────────
        if self.agent_on:
            await self._run_agent(raw)
            return True
        for name, kws in NATURAL.items():
            if any(k in raw for k in kws):
                self.session.set_phase(PHASE_ALIAS[name])
                await self.planner.run_turn(self.session, raw)
                self._save()
                return True
        print(f"未识别：{raw}（输入 /help 看命令，或直接回车跑下一轮）")
        return True

    # ── 模式与配置 ────────────────────────────────────────────────

