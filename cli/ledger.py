"""发现台账与网络：``sessions`` / ``findings`` / ``proxy``。"""

from __future__ import annotations

from pathlib import Path
import typer
from rich.table import Table
from cli.app import app
from cli.app import console
from cli.app import err
from cli.boot import _cfg


# ── sessions / report ─────────────────────────────────────────────


@app.command()
def sessions(
    limit: int = typer.Option(15, "--limit", "-n"),
    clean: bool = typer.Option(
        False, "--clean", help="先删掉空会话（没目标、没对话、没结果）"
    ),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """列出历史扫描会话。"""
    from core.session import list_sessions, purge_empty_sessions

    cfg = _cfg(config)
    base = Path(cfg.data_dir) / "sessions"

    if clean:
        gone = purge_empty_sessions(base)
        if gone:
            console.print(f"[dim]已清理 {len(gone)} 个空会话[/dim]")
        else:
            console.print("[dim]没有空会话需要清理[/dim]")

    items = list_sessions(base, limit=limit)
    if not items:
        console.print("[yellow]暂无历史会话[/yellow]")
        return

    t = Table(title=f"历史会话（{len(items)} 条）")
    t.add_column("会话", overflow="fold")
    t.add_column("目标", overflow="fold")
    t.add_column("发现", justify="right")
    t.add_column("资产", justify="right")
    for name, s in items:
        # 显示「目录名」而不是纯 id：目录名是 日期_标题，一眼能认出是哪次对话
        # （用 --resume <会话名> 即可续跑）。
        label = name
        title = (s.conversations[0].title if s.conversations else "").strip()
        if title and title not in label:
            label = f"{label}\n[dim]{title}[/dim]"
        t.add_row(
            label,
            s.target or "—",
            str(sum(s.counts().values())),
            str(len(s.result.assets)),
        )
    console.print(t)
    console.print("[dim]用 --resume <会话名> 或会话内 /resume <Tab> 续跑[/dim]")
    console.print("[dim]--clean 可清掉空会话；会话内 /clean 同理[/dim]")


@app.command()
def findings(
    ref: str = typer.Argument(None, help="要判为误报的编号或 poc_id（留空则只列出）"),
    reason: str = typer.Option("", "--reason", "-r", help="判定为误报的依据（排除时必填）"),
    undo: bool = typer.Option(False, "--undo", help="撤销误报排除"),
    purge: bool = typer.Option(False, "--del", help="彻底删除（不留复核痕迹）"),
    scope_poc: bool = typer.Option(
        False, "--poc", help="按 POC 整体排除（该 POC 在本目标上全不可信）"
    ),
    session: str = typer.Option(
        "latest", "--session", "-s", help="会话名或 id，默认取最近一次"
    ),
    excluded: bool = typer.Option(
        False, "--excluded", "-e", help="查看已持久化的误报排除清单"
    ),
    auto: bool = typer.Option(
        False, "--auto", help="回源站根目录核验公开性，站点自己公开的自动排除"
    ),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出（便于脚本消费）"),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """查看已保存会话的发现，并把误报排除掉（跨会话生效）。

    **为什么要有这个命令**：报告里混进误报是常态，而最典型的一类——
    「公开演示站点」（站点本就建给人看，暴露的配置/默认账号/接口文档属于
    设计而非漏洞）——自动探针判断不了，只能人工排除。会话内可以让模型
    调用 ``dismiss_finding`` 工具，但出了会话（或者要批量复核一批历史会话）
    就需要命令行入口。

    排除项按**目标**落盘（``data/exclusions.json``），同一目标重扫会自动套用，
    不用每轮手工删一遍。

    示例：

    \b
      flower_pow findings                      # 列出最近会话的有效发现
      flower_pow findings 3 -r "公开演示站点"   # 把编号 3 判为误报
      flower_pow findings backup --undo        # 按 poc_id 撤销
      flower_pow findings 3 --del              # 彻底删除
      flower_pow findings --excluded           # 看排除清单
    """
    import json as _json

    from core.session import list_sessions, latest_session
    from core.tools import ToolRunner

    cfg = _cfg(config)
    base = Path(cfg.data_dir) / "sessions"

    if session in ("", "latest"):
        sess = latest_session(base)
    else:
        sess = None
        for name, s in list_sessions(base, limit=200):
            if session in (name, s.session_id):
                sess = s
                break
        if sess is None:
            err.print(f"[red]找不到会话 {session!r}[/red]（用 flower_pow sessions 看清单）")
            raise typer.Exit(1)

    if sess is None:
        err.print("[yellow]没有可用的历史会话[/yellow]")
        raise typer.Exit(1)

    # ── 排除清单视图 ─────────────────────────────────────────────
    if excluded:
        from core import exclusions

        if as_json:
            console.print_json(
                _json.dumps(
                    {"store": str(exclusions.store_path()),
                     "hosts": [{"host": h, "count": n} for h, n in exclusions.summary()]},
                    ensure_ascii=False,
                )
            )
            return
        items = exclusions.entries(sess.target)
        console.print(f"[cyan]排除清单[/cyan] {exclusions.store_path()}")
        console.print(f"目标 {sess.target or '—'} 下 {len(items)} 条")
        if not items:
            console.print("[dim]（该目标暂无排除项）[/dim]")
            return
        t = Table(title="已排除（重扫自动套用）")
        t.add_column("POC", overflow="fold")
        t.add_column("范围", overflow="fold")
        t.add_column("原因", overflow="fold")
        for e in items:
            where = "该 POC 全部命中" if not e.get("matched_at") else str(e["matched_at"])
            t.add_row(str(e.get("poc_id") or ""), where, str(e.get("reason") or "—"))
        console.print(t)
        return

    # ── 公开性核验（回源取证）────────────────────────────────────
    if auto:
        import asyncio

        from core.tools import ToolRunner

        runner = ToolRunner(cfg, {}, ".")
        try:
            out = asyncio.run(runner.check_public(sess, ref="all"))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                out = loop.run_until_complete(runner.check_public(sess, ref="all"))
            finally:
                loop.close()
        console.print(out)
        saved = sess.save(Path(cfg.data_dir) / "sessions")
        console.print(f"[dim]会话已保存：{saved}[/dim]")
        return

    # ── 排除动作 ─────────────────────────────────────────────────
    if ref:
        out = ToolRunner.dismiss(
            sess,
            ref=ref,
            reason=reason,
            undo=undo,
            purge=purge,
            scope="poc" if scope_poc else "finding",
        )
        ok = not out.startswith("排除失败")
        (console if ok else err).print(out)
        if ok:
            saved = sess.save(Path(cfg.data_dir) / "sessions")
            console.print(f"[dim]会话已保存：{saved}[/dim]")
        else:
            raise typer.Exit(1)
        return

    # ── 默认：列出发现 ───────────────────────────────────────────
    active = sess.result.active_findings()
    dismissed = sess.result.dismissed_findings()
    full = sorted(sess.result.findings, key=lambda x: x.severity.rank, reverse=True)
    idx = {id(f): i + 1 for i, f in enumerate(full)}

    if as_json:
        console.print_json(
            _json.dumps(
                {
                    "target": sess.target,
                    "session": sess.session_id,
                    "active": len(active),
                    "excluded": len(dismissed),
                    "findings": [
                        {
                            "no": idx[id(f)],
                            "poc_id": f.poc_id,
                            "name": f.name,
                            "severity": f.severity.value,
                            "matched_at": f.matched_at,
                            "dismissed": f.dismissed,
                            "dismiss_reason": f.dismiss_reason,
                        }
                        for f in full
                    ],
                },
                ensure_ascii=False,
            )
        )
        return

    if not full:
        console.print("[yellow]该会话没有发现[/yellow]")
        return

    t = Table(title=f"发现（{len(active)} 条有效，{len(dismissed)} 条已排除）")
    t.add_column("#", justify="right")
    t.add_column("等级")
    t.add_column("POC", overflow="fold")
    t.add_column("位置", overflow="fold")
    t.add_column("状态")
    for f in full:
        status = "[dim]已排除[/dim]" if f.dismissed else "有效"
        t.add_row(str(idx[id(f)]), f.severity.label, f.poc_id,
                  f.matched_at[:70], status)
    console.print(t)
    console.print(
        '[dim]排除误报：flower_pow findings <编号> -r "<依据>"'
        "　｜　看排除清单：--excluded[/dim]"
    )


@app.command()
def proxy(
    target: str = typer.Option(
        None, "--target", "-t",
        help="测某个具体目标会走哪个代理（留空则只探测本机代理）",
    ),
    config: str = typer.Option(None, "--config", "-c", help="配置文件路径"),
) -> None:
    """查看本机代理检测结果与请求级代理决策。

    渗透机上常挂着 Burp / Clash 的代理。这个命令把两件事分开讲清楚：

    * 本机**有没有**代理、来源是什么（环境变量 / Windows 系统代理）
    * 扫描某个目标时**会不会**真的走代理（默认全部走代理）
    """
    from core.proxy import build_client_kwargs, detect_proxy

    cfg = _cfg(config)
    sc = cfg.scan

    info = detect_proxy()
    console.print("[bold]本机代理检测[/bold]")
    console.print(f"  配置 proxy        : {sc.proxy or '（未设置）'}")
    console.print(f"  自动探测开关       : {'开' if sc.proxy_autodetect else '关'}")
    console.print(f"  探测结果           : {info.describe()}")
    if info.raw:
        console.print(f"  原始取值           : {info.raw}")
    for n in info.notes:
        console.print(f"  [dim]注：{n}[/dim]")
    if sc.no_proxy:
        console.print(f"  直连例外（配置）    : {', '.join(sc.no_proxy)}")
    console.print(
        "  内网/本机直连       : "
        + ("是（proxy_local_direct）" if getattr(sc, "proxy_local_direct", False)
           else "否（默认全部走代理）")
    )

    if not info.found and not sc.proxy:
        console.print(
            "[yellow]未检测到代理，所有请求直连。[/yellow]\n"
            "[dim]如需走代理：设 POCS_PROXY 环境变量，"
            "或在 config.yaml 的 scan.proxy 里写死。[/dim]"
        )
        raise typer.Exit(0)

    if target:
        from urllib.parse import urlparse

        console.print("\n[bold]请求级决策[/bold]")
        kw = build_client_kwargs(sc, target)
        chosen = kw.get("proxy")
        host = urlparse(target if "://" in target else f"http://{target}").hostname or ""
        try:
            in_no_proxy = bool(sc.no_proxy) and host in sc.no_proxy
        except Exception:  # noqa: BLE001
            in_no_proxy = False
        console.print(f"  目标               : {target}")
        if chosen:
            console.print(f"  决策               : [green]走代理 {chosen}[/green]")
        else:
            # 直连的理由要说清，否则用户会误判"代理没生效"
            if in_no_proxy:
                why = "命中直连例外 scan.no_proxy"
            elif not (getattr(sc, "proxy", None) or "").strip():
                why = "本机未检测到代理"
            else:
                why = "内网/本机目标且开启了 proxy_local_direct"
            console.print(f"  决策               : [cyan]直连[/cyan]（{why}）")
        console.print(
            "[dim]注：端口扫描优先走 SOCKS5 / HTTP CONNECT 隧道，"
            "代理不支持时自动降级直连。[/dim]"
        )
    else:
        console.print(
            "\n[dim]加 --target http://x.com 可查看该目标会走哪个代理。[/dim]"
        )


