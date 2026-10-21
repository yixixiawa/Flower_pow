"""``models`` —— 可选模型清单与切换。"""

from __future__ import annotations

import typer
from rich.table import Table
from cli.app import app
from cli.app import console
from cli.boot import _cfg
from cli.boot import _apply_model
from cli.boot import _print_model_warnings


# ── models：模型清单 ──────────────────────────────────────────────


@app.command()
def models(
    config: str = typer.Option(None, "--config", "-c"),
    model: str = typer.Option(
        None, "--model", "-m", help="试算某个模型名会解析成什么（不改配置）"
    ),
    deep_model: str = typer.Option(None, "--deep-model", help="试算深度任务模型名"),
    aliases: bool = typer.Option(True, "--aliases/--no-aliases", help="显示简写对照表"),
) -> None:
    """列出可用模型、当前选型与名称对照。

    模型名这事容易踩坑：**注册表之外的名字一律会被原样发给服务端**，
    而厂商对已下线的模型名不报错、只静默换模型。所以这里把"官方名 /
    实际服务模型 / 简写"一次讲清，并用 --model 支持先试算再改配置。
    """
    from llm.models import ROLE_DEEP, ROLE_FAST, describe_shorthand, describe_table

    cfg = _cfg(config)
    _apply_model(cfg, model, deep_model)

    t = Table(title="官方模型")
    t.add_column("模型名", style="cyan", no_wrap=True)
    t.add_column("说明")
    t.add_column("实际由谁提供", style="dim")
    t.add_column("默认用于")
    for name, label, served_by, role in describe_table():
        t.add_row(name, label, served_by, role)
    console.print(t)

    # 当前选型
    role_model = {
        ROLE_FAST: cfg.llm.model,
        ROLE_DEEP: cfg.llm.deep_model or f"{cfg.llm.model}（未单独指定）",
    }
    cur = Table(title="当前配置", show_header=False)
    cur.add_column("项", style="cyan")
    cur.add_column("值")
    cur.add_row("base_url", cfg.llm.base_url)
    cur.add_row("高频任务模型", role_model[ROLE_FAST])
    cur.add_row("深度任务模型", role_model[ROLE_DEEP])
    cur.add_row("思考链", "关闭" if cfg.llm.disable_thinking else f"开启（{cfg.llm.reasoning_effort}）")
    cur.add_row("API Key", "已配置" if cfg.llm.api_key else "[yellow]未配置[/yellow]")
    cur.add_row(
        "覆盖方式",
        "config.yaml 的 llm.model / llm.deep_model，"
        "或 CLI --model / --deep-model，或环境变量 DEEPSEEK_MODEL",
    )
    console.print(cur)

    _print_model_warnings(cfg)

    if aliases:
        a = Table(title="简写对照")
        a.add_column("写法", style="cyan", no_wrap=True)
        a.add_column("解析为", style="cyan")
        for short, target in describe_shorthand():
            a.add_row(short, target)
        console.print(a)
        console.print(
            "[dim]注意：注册表之外的名字会被[/dim]"
            "[yellow]原样发给服务端[/yellow][dim]。厂商对已下线的模型名不报错，"
            "只会静默换成别的模型提供服务——所以启动时会打印警告，"
            "看到警告就说明该改配置了。[/dim]"
        )


