"""Typer 应用对象与全局控制台。

``app`` 是所有命令的唯一注册表——各命令模块 ``from cli.app import app``
后用 ``@app.command()`` 注册自己，所以这个文件必须**先于**所有命令模块导入。"""

from __future__ import annotations

import typer
from rich.console import Console
from core.state import POC, ScanResult, Severity, safe_name


app = typer.Typer(
    name="flower-pow",
    help="AI Agent 驱动的 Web 漏洞扫描器：子域发现 → 侦察 → RAG 召回 → 工具调用 → 证据研判。",
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


