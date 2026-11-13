"""``mcp`` —— 以 MCP Server 形式暴露工具，供 WorkBuddy / Claude 等客户端接入。

默认 stdio 传输：客户端把进程拉起来，用标准输入输出走 JSON-RPC。
为什么单独一个子命令：MCP server 是**常驻进程**，与其它一次性命令的生命周期
完全不同；混在 scan/chat 里会让人误以为它跑完就退出。
"""

from __future__ import annotations

import typer

from cli.app import app
from cli.app import console
from cli.app import err


@app.command("mcp")
def mcpserve(
    transport: str = typer.Option(
        "stdio", "--transport", "-t", help="传输方式：stdio（默认，客户端拉起）| http"
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="http 传输监听地址"),
    port: int = typer.Option(8765, "--port", help="http 传输监听端口"),
) -> None:
    """启动 MCP Server（stdio），把扫描器暴露成一组工具。"""
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
