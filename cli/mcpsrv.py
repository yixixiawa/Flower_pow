"""``mcp`` —— MCP Server 的启动与接入。

为什么是一个带子命令的组
------------------------
以前只有"启动 server"一件事，所以是单命令。但**接入客户端**（写 ``mcp.json``
+ 算信任指纹）才是最容易出错的一步——手改 JSON、手算 sha256，配错了客户端
静默不加载、也不报错。把它做成子命令，一条命令就能装好：

==============================  ===============================================
``flower_pow mcp``              **启动** stdio server（客户端拉起的就是这条）
``flower_pow mcp install``      写进 WorkBuddy / Claude / Cursor 配置 + 信任指纹
``flower_pow mcp status``       看注册了没、指纹客户端认不认
``flower_pow mcp uninstall``    删条目与信任记录
==============================  ===============================================

**无参数必须仍然启动 server**：客户端配置里写的就是 ``[flower_pow.py, mcp]``，
这条形状一变，所有已信任配置的指纹都会失配。所以用 ``invoke_without_command``，
只在 ``ctx.invoked_subcommand is None`` 时起进程。
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.table import Table

from cli.app import app
from cli.app import console
from cli.app import err

mcp_app = typer.Typer(
    name="mcp",
    help="MCP Server：启动（默认）/ install 注册到客户端 / status / uninstall",
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=False,
)


# ── 启动（旧行为，形状不能变）──────────────────────────────────


@mcp_app.callback()
def mcp_root(
    ctx: typer.Context,
    transport: str = typer.Option(
        "stdio", "--transport", "-t", help="传输方式：stdio（默认，客户端拉起）| http"
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="http 传输监听地址"),
    port: int = typer.Option(8765, "--port", help="http 传输监听端口"),
) -> None:
    """启动 MCP Server（不带子命令时）。"""
    if ctx.invoked_subcommand is not None:
        return
    _serve(transport, host, port)


def _serve(transport: str, host: str, port: int) -> None:
    try:
        from mcp_server.server import main as serve
    except ModuleNotFoundError as exc:
        err.print(
            f"[red]缺少 MCP 依赖[/red]：{exc.name}\n"
            "[dim]安装：[/dim].venv/Scripts/python.exe -m pip install 'mcp>=2'"
        )
        raise typer.Exit(1) from None

    if (transport or "").strip().lower() == "stdio":
        err.print(
            "[dim]MCP Server 已启动（stdio）。这个进程由客户端拉起，"
            "不要在这里等输出——日志都走 stderr。[/dim]"
        )
    else:
        console.print(f"[green]MCP Server[/green] http://{host}:{port}/mcp")
    serve(transport=transport, host=host, port=port)


# ── install / status / uninstall ──────────────────────────────


def _targets(client: str):
    """解析 ``--client``；写错时给可选项而不是抛栈。"""
    from mcp_server import registry

    try:
        targets = registry.pick_clients(client)
    except registry.RegistryError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from None
    return registry, targets


def _parse_env(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items or []:
        if "=" not in raw:
            err.print(f"[red]--env 需要 KEY=VALUE 形式[/red]：{raw!r}")
            raise typer.Exit(2)
        k, v = raw.split("=", 1)
        k = k.strip()
        if not k:
            err.print(f"[red]--env 的变量名不能为空[/red]：{raw!r}")
            raise typer.Exit(2)
        out[k] = v
    return out


@mcp_app.command("install")
def mcp_install(
    client: str = typer.Option(
        "workbuddy", "--client", "-c", help="workbuddy | claude | cursor | all（可逗号分隔）"
    ),
    name: str = typer.Option("flower_pow", "--name", help="在客户端里显示的 server 名"),
    python: str = typer.Option("", "--python", help="拉起 server 的解释器，默认当前 python"),
    script: str = typer.Option("", "--script", help="flower_pow.py 路径，默认本仓库根目录"),
    env: list[str] = typer.Option(
        None, "--env", "-e", help="额外环境变量 KEY=VALUE，可重复（会影响信任指纹）"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="只算不改，先看清会写什么"),
    no_check: bool = typer.Option(False, "--no-check", help="跳过目标解释器的 mcp 依赖检查"),
) -> None:
    """把本项目的 MCP Server 注册进客户端（写配置 + 登记信任指纹）。

    一条命令替代"手改两处 JSON + 手算 sha256"：

        flower_pow mcp install                  # 装到 WorkBuddy（默认）
        flower_pow mcp install -c all           # WorkBuddy + Claude + Cursor
        flower_pow mcp install --dry-run        # 先看会写成什么
    """
    registry, targets = _targets(client)

    py = python or sys.executable
    root = Path(__file__).resolve().parent.parent
    sp = Path(script) if script else (root / "flower_pow.py")

    if not Path(py).is_file():
        err.print(f"[red]解释器不存在[/red]：{py}")
        raise typer.Exit(2)
    if not sp.is_file():
        err.print(f"[red]找不到入口脚本[/red]：{sp}")
        raise typer.Exit(2)

    py_path = Path(py).resolve()
    entry = registry.entry_for(str(py_path), str(sp.resolve()), _parse_env(env))

    if not no_check and not dry_run:
        if not registry.mcp_dependency_ok(str(py_path)):
            err.print(
                f"[yellow]注意[/yellow]：{py} 里 import 不到 mcp，装完也起不来。\n"
                f"[dim]补救：[/dim]\"{py}\" -m pip install 'mcp>=2'"
            )

    table = Table(title="MCP 接入" + ("（干跑，未写盘）" if dry_run else ""))
    table.add_column("客户端")
    table.add_column("动作")
    table.add_column("配置文件", overflow="fold")
    table.add_column("信任")
    table.add_column("备份", overflow="fold")

    hints: list[str] = []
    failures = 0
    changed = False
    for c in targets:
        try:
            res = registry.install(c, name, entry, dry_run=dry_run)
        except registry.RegistryError as exc:
            failures += 1
            table.add_row(c.label, "[red]失败[/red]", str(exc).splitlines()[0], "—", "—")
            err.print(f"[red]{exc}[/red]")
            continue
        except OSError as exc:
            failures += 1
            table.add_row(c.label, "[red]写盘失败[/red]", str(c.config), "—", "—")
            err.print(f"[red]{c.config} 写不进去：{exc}[/red]")
            continue

        act = {
            "created": "[green]新建[/green]",
            "updated": "[yellow]已更新[/yellow]",
            "unchanged": "[dim]无变化[/dim]",
        }[res.action]
        trust = "—"
        if c.approvals is not None:
            trust = "[green]已登记[/green]" if res.trusted else "[yellow]未登记[/yellow]"
        table.add_row(
            c.label,
            act,
            str(c.config),
            trust,
            str(res.backup) if res.backup else "—",
        )
        changed = changed or res.action != "unchanged"
        if c.restart_hint and not dry_run:
            hints.append(f"{c.label}：{c.restart_hint}")

    console.print(table)
    console.print(
        f"[dim]条目[/dim] {entry['command']} «{' '.join(entry['args'])}»\n"
        f"[dim]指纹[/dim] {registry.fingerprint(entry['command'], entry['args'], entry.get('env'))[:16]}…"
    )
    if hints:
        head = "下一步" if (changed or dry_run) else "下一步（配置没变，面板里仍看不到就重启一次）"
        console.print(f"\n[yellow]{head}[/yellow]")
        for h in dict.fromkeys(hints):
            console.print(f"  · {h}")
        console.print("  · 重启后在客户端的 MCP / 连接器面板里应能看到 " + name)
    if failures:
        raise typer.Exit(1)


@mcp_app.command("status")
def mcp_status(
    client: str = typer.Option(
        "workbuddy", "--client", "-c", help="workbuddy | claude | cursor | all"
    ),
    name: str = typer.Option("flower_pow", "--name", help="server 名"),
) -> None:
    """查看注册状态：条目在不在、指纹算出来多少、客户端认不认。"""
    registry, targets = _targets(client)

    table = Table(title=f"MCP 状态 · {name}")
    table.add_column("客户端")
    table.add_column("注册")
    table.add_column("信任")
    table.add_column("命令", overflow="fold")
    table.add_column("指纹")

    for c in targets:
        try:
            st = registry.inspect(c, name)
        except registry.RegistryError as exc:
            table.add_row(c.label, "[red]配置坏[/red]", "—", str(exc).splitlines()[0], "—")
            continue
        if not st.registered:
            table.add_row(c.label, "[dim]未注册[/dim]", "—", "—", "—")
            continue
        e = st.entry or {}
        cmd = f"{e.get('command', '')} «{' '.join(e.get('args') or [])}»"
        if c.approvals is None:
            trust = "[dim]不需要[/dim]"
        elif st.trusted:
            trust = "[green]已信任[/green]"
        else:
            trust = "[red]未信任（客户端会静默跳过）[/red]"
        table.add_row(c.label, "[green]已注册[/green]", trust, cmd, st.fingerprint[:16] + "…")

    console.print(table)
    console.print("[dim]修：flower_pow mcp install  ·  删：flower_pow mcp uninstall[/dim]")


@mcp_app.command("uninstall")
def mcp_uninstall(
    client: str = typer.Option(
        "workbuddy", "--client", "-c", help="workbuddy | claude | cursor | all"
    ),
    name: str = typer.Option("flower_pow", "--name", help="server 名"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只报会删什么，不动盘"),
) -> None:
    """删掉条目和该 server 的全部信任记录（改前自动备份）。"""
    registry, targets = _targets(client)

    for c in targets:
        try:
            res = registry.uninstall(c, name, dry_run=dry_run)
        except registry.RegistryError as exc:
            err.print(f"[red]{c.label}：{exc}[/red]")
            continue
        bits = []
        bits.append("条目已删" if res.removed_entry else "条目本来就没有")
        if res.removed_trusts:
            bits.append(f"{res.removed_trusts} 条信任记录已删")
        if res.backup:
            bits.append(f"备份 {res.backup}")
        style = "dim" if dry_run else ""
        console.print(f"[{style}]{c.label}：{'；'.join(bits)}[/{style}]" if style else f"{c.label}：{'；'.join(bits)}")
    if not dry_run:
        console.print("[dim]记得重启客户端，否则它内存里的旧配置还在[/dim]")


app.add_typer(mcp_app, name="mcp")
