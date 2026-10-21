"""``chat`` —— 交互式测试会话（含 --classic 固定剧本模式）。

自动轮询 / 一次性轮次两种驱动方式都在这里；模型不可用时 ``--classic``
也能跑完整流程。"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
import typer
from rich.table import Table
from cli.app import app
from cli.app import console
from cli.app import err
from cli.boot import _cfg
from cli.boot import _apply_model
from cli.boot import _print_model_warnings


# ── chat：交互式测试会话 ──────────────────────────────────────────


@app.command()
def chat(
    target: str = typer.Argument(None, help="目标 URL，如 https://example.com；省略则进会话后再给"),
    config: str = typer.Option(None, "--config", "-c", help="配置文件路径"),
    user: str = typer.Option(None, "--user", "-u", help="测试账号（走通业务流用，可选）"),
    password: str = typer.Option(
        None, "--password", "-p", help="测试密码（给了 user 才需要）"
    ),
    phase: str = typer.Option("recon", "--phase", help="起始阶段：recon|model|exploit|iterate"),
    resume: bool = typer.Option(False, "--resume", help="恢复最近一次会话（忽略 target）"),
    auto: int = typer.Option(
        0, "--auto", help="非交互：自动推进 N 轮后退出（用于批量跑流程）"
    ),
    poll: bool = typer.Option(
        False,
        "--poll",
        help="非交互：自动连续跑轮，**穷尽了才停**（连续 2 轮无新增资产/发现/建模项）",
    ),
    classic: bool = typer.Option(
        False, "--classic", help="不进 AI Agent，使用固定剧本模式"
    ),
    no_boot: bool = typer.Option(
        False, "--no-boot", help="跳过初始化体检（工具探测/依赖检查/索要 Key）"
    ),
    kickoff: bool = typer.Option(
        False, "--kickoff", help="启动后先让模型自我介绍一轮（默认不说，直接进提示符）"
    ),
    model: str = typer.Option(
        None, "--model", "-m", help="覆盖模型，如 deepseek-v4-pro（见 models 命令）"
    ),
    deep_model: str = typer.Option(
        None, "--deep-model", help="建模/报告用的强模型，如 deepseek-v4-pro"
    ),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """进入交互式测试会话。

    默认是 **AI Agent 模式**：你说人话，模型调用本机工具（nmap、dirsearch、
    内置采集器…）去拿真实证据，再给判断。加 ``--classic`` 则退回固定剧本：
    第 1 轮信息收集 → 第 2 轮业务建模 → 第 3 轮渗透测试 → 之后反复迭代。
    """
    from core.repl import run_repl
    from core.session import Phase, Session, latest_session, purge_empty_sessions

    cfg = _cfg(config)
    _apply_model(cfg, model, deep_model)

    boot = None
    if not no_boot:
        from core.bootstrap import run_bootstrap

        boot = run_bootstrap(
            cfg,
            console,
            interactive=bool(sys.stdin and sys.stdin.isatty()) and not auto,
            verify_key=not auto,
        )
    _print_model_warnings(cfg)

    if resume:
        base = Path(cfg.data_dir) / "sessions"
        # 先清历史遗留空壳，否则「最近一次」可能指向一个什么都没记的空会话。
        gone = purge_empty_sessions(base)
        if gone:
            console.print(f"[dim]已清理 {len(gone)} 个空会话[/dim]")
        prev = latest_session(base)
        if prev is None:
            err.print("[yellow]没有可恢复的会话[/yellow]")
            raise typer.Exit(1)
        session = prev
        console.print(f"[cyan]已恢复会话 {session.session_id}：{session.status_line()}[/cyan]")
        if session.history:
            console.print(
                f"[cyan]  已恢复对话历史 {len(session.history)} 条"
                f"（{session.history_turns} 轮提问）[/cyan]"
            )
        # 顺手回填：老快照里手工登记的发现常常只有请求没有响应
        # （旧版 record_finding 把说明截断后又当响应体存了），
        # 而当时的真实响应还在 history 里——补上再导报告才完整。
        from core.backfill import backfill_findings

        stat = backfill_findings(
            session, evidence_dir=str(getattr(cfg.scan, "evidence_dir", "") or "")
        )
        if stat["filled"]:
            console.print(
                f"[cyan]  已从会话历史回填 {stat['filled']} 条发现的原始报文"
                f"（缺响应的共 {stat['candidates']} 条）[/cyan]"
            )
    else:
        alias = {
            "recon": Phase.RECON, "model": Phase.MODEL,
            "exploit": Phase.EXPLOIT, "iterate": Phase.ITERATE,
        }
        session = Session(target=target or "", phase=alias.get(phase.lower(), Phase.RECON))
        if user:
            pwd = password or typer.prompt("测试密码", hide_input=True)
            session.credentials["username"] = user
            session.credentials["password"] = pwd

    if auto or poll:
        from core.planner import Planner

        planner = Planner(cfg, verbose=verbose)
        if poll:
            asyncio.run(_poll_rounds(planner, session, cfg))
        else:
            asyncio.run(_auto_rounds(planner, session, auto, cfg))
        _print_session_summary(session)
        return

    use_agent = (not classic) and cfg.llm.enabled and bool(cfg.llm.api_key)
    try:
        asyncio.run(
            run_repl(
                cfg,
                session,
                agent=use_agent,
                probes=boot.env.externals if boot else None,
                # 默认不开场：那段"我是渗透测试操作员…"每次都不一样且刷屏。
                # 恢复会话时更不该开场——历史已回填，让模型再自我介绍一遍既
                # 答非所问又多烧一轮 token。
                kickoff=kickoff and not (resume and session.history),
            )
        )
    except KeyboardInterrupt:
        console.print("[yellow]\n已中断（会话已保存）[/yellow]")


async def _auto_rounds(planner, session, rounds: int, cfg) -> None:
    """非交互模式：自动推进**固定 N 轮**，每轮结束推进阶段。

    固定轮数用这个；"跑到穷尽"用 :func:`_poll_rounds`。
    """
    from pathlib import Path as _P

    for i in range(rounds):
        await planner.run_turn(session)
        session.save(_P(cfg.data_dir) / "sessions")
        if i + 1 < rounds:
            session.advance()


async def _poll_rounds(planner, session, cfg) -> None:
    """非交互模式：自动连续跑轮，**穷尽了才停**。

    与 :func:`_auto_rounds` 只差在"什么时候停"：这里交给
    :class:`core.progress.Exhaustion` 判定（连续 2 轮无新增资产/发现/建模项），
    外加 ``scan.auto_max_rounds`` 作为安全阀。两个驱动共用同一套判定，
    也共用 :func:`core.progress.poll_until_done` 的循环——REPL 的 ``/poll``
    走的是同一条路，行为不会出现两套。
    """
    from pathlib import Path as _P

    from core.progress import Exhaustion, RoundOutcome, poll_until_done

    cap = int(getattr(cfg.scan, "auto_max_rounds", 12) or 0)
    ex = Exhaustion(max_rounds=cap)
    limit = f"{cap} 轮" if cap else "不限轮数"
    console.print(
        f"\n自动轮询：最多 {limit}，"
        f"连续 {ex.idle_limit} 轮没有任何新增即判定穷尽。"
    )

    async def one_round(no: int) -> RoundOutcome:
        a0 = len(session.result.assets)
        f0 = len(session.result.findings)
        m0 = len(session.model.resources)
        t0 = time.perf_counter()
        if no > 1:
            session.advance()
        t = await planner.run_turn(session)
        return RoundOutcome(
            no=no,
            new_assets=len(session.result.assets) - a0,
            new_findings=len(session.result.findings) - f0,
            new_model=len(session.model.resources) - m0,
            suggestions=list(getattr(t, "suggestions", []) or []),
            elapsed=time.perf_counter() - t0,
        )

    _kind, history = await poll_until_done(
        one_round,
        ex=ex,
        on_round=lambda o: console.print(f"  {o.line()}"),
        checkpoint=lambda: session.save(_P(cfg.data_dir) / "sessions"),
    )
    console.print(ex.verdict())
    console.print(
        f"[dim]合计 {len(history)} 轮："
        f"+{sum(o.new_assets for o in history)} 资产、"
        f"+{sum(o.new_findings for o in history)} 发现[/dim]"
    )


def _print_session_summary(session) -> None:
    from core.state import Severity

    console.print("\n" + session.status_line())
    fs = session.result.findings
    if fs:
        table = Table(title=f"发现 {len(fs)} 项")
        table.add_column("等级")
        table.add_column("编号")
        table.add_column("名称")
        table.add_column("命中位置", overflow="fold")
        for f in sorted(fs, key=lambda x: x.severity.rank, reverse=True)[:30]:
            table.add_row(f.severity.label, f.poc_id, f.name[:28], f.matched_at[:60])
        console.print(table)
    if session.turns:
        console.print("\n轮次：")
        for t in session.turns:
            console.print(
                f"  第{t.no}轮 [{t.phase.label}] {t.elapsed:.1f}s "
                f"+{t.new_assets}资产 +{t.new_findings}发现：{'、'.join(t.actions[:4])}"
            )


