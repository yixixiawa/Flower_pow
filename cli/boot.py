"""无参数入口：初始化体检 → 要 API Key → 进对话。

探测本机能调用的外部工具、检查依赖与 POC 索引、必要时索要 Key（写 ``.env``）。
模型选择与代理提示也在这层。"""

from __future__ import annotations

import asyncio
import sys
import typer
from core.config_loader import BANNER, Config, load_config
from cli.app import app
from cli.app import console
from cli.app import err


def _cfg(path: str | None = None) -> Config:
    return load_config(path)


def _reconfigure_console_utf8() -> None:
    """交互场景下把 stdin/stdout 固定成 UTF-8（幂等，非交互直接跳过）。

    Windows 中文机器上 Python 默认给 stdin/stdout 分配 cp936（GBK），
    而新版控制台/终端实际跑 UTF-8——编码错配时中文按错误编码解码，
    症状就是「首字节丢失、要打两次才生效」。在这里修而不是在各读取
    点修，是因为三条输入路径**共享同一个 sys.stdin**：PromptReader
    （msvcrt getwch / POSIX 裸模式）、上传审核的 ``input()``
    （cli/probe.py、core/repl/history.py）、密码框 getpass
    （chat.py 的 typer.prompt(hide_input=True)）。入口统一 reconfigure
    一次三条全受益，不会出现"修了主输入、审核路径照样丢字节"。

    只在 isatty 时动手：管道/CI 场景 stdout 编码由调用方决定，
    强行改 UTF-8 会破坏管道契约（重定向到文件时按 UTF-8 写才是
    可预期的）。try/except 兜住 AttributeError（老 Python 没有
    reconfigure）与 OSError（流已被包装/关闭），静默跳过不影响运行。
    """
    if not (sys.stdin and sys.stdin.isatty()):
        return
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


# ── 无参数入口：初始化 → 体检 → 要 Key → 进对话 ─────────────────────


@app.callback(invoke_without_command=True)
def _boot(
    ctx: typer.Context,
    config: str = typer.Option(None, "--config", "-c", help="配置文件路径"),
    api_key: str = typer.Option(
        None, "--api-key", help="直接提供 API Key（跳过交互输入，写不写盘由 --save-key 决定）"
    ),
    save_key: bool = typer.Option(
        True, "--save-key/--no-save-key", help="把 API Key 写入 .env 以便下次自动读取"
    ),
    no_probe: bool = typer.Option(
        False, "--no-probe", help="跳过外部工具版本探测（只做 which 检测，更快）"
    ),
    classic: bool = typer.Option(
        False, "--classic", help="不进 AI Agent，直接使用固定剧本模式"
    ),
    kickoff: bool = typer.Option(
        False, "--kickoff", help="启动后先让模型自我介绍一轮（默认直接进提示符）"
    ),
) -> None:
    """不带子命令运行时：初始化环境，然后进入 AI Agent 对话。

    完整流程是「体检 → 要 Key → 对话」，因为用户敲下 ``python flower_pow.py``
    时想要的是"开始干活"，而不是先读一遍 --help 再自己拼命令。
    """
    if ctx.invoked_subcommand is not None:
        return
    _run_default(config, api_key or "", save_key, no_probe, classic, kickoff)


def _run_default(
    config: str | None,
    api_key: str,
    save_key: bool,
    no_probe: bool,
    classic: bool,
    kickoff: bool = False,
) -> None:
    from core.bootstrap import run_bootstrap
    from core.repl import run_repl
    from core.session import Session

    # 先修编码再碰 stdin：后面 bootstrap 索要 Key、REPL 读中文输入、
    # 上传审核 input() 全都依赖这一步（详见函数注释里的三路径说明）。
    _reconfigure_console_utf8()

    cfg = _cfg(config)
    interactive = bool(sys.stdin and sys.stdin.isatty())

    boot = run_bootstrap(
        cfg,
        console,
        skip_probe=no_probe,
        interactive=interactive,
        api_key=api_key if save_key else "",
        verify_key=True,
    )
    if boot.env.missing_deps:
        err.print("[red]运行依赖不完整，无法启动。请先安装 requirements.txt[/red]")
        raise typer.Exit(1)

    _print_model_warnings(cfg)
    _print_proxy_notice(cfg)

    use_agent = (not classic) and boot.can_chat
    if classic:
        console.print("[dim]按 --classic 要求进入固定剧本模式[/dim]")
    elif not boot.can_chat:
        console.print(
            "\n[yellow]未配置可用的 API Key，进入剧本模式。[/yellow]"
            "扫描、RAG、报告都正常，只是没有对话式 Agent。"
            "\n[dim]  会话中输入 /key 可随时补上 API Key 并切到 Agent。[/dim]"
        )

    console.print()
    session = Session(target="")
    try:
        asyncio.run(
            run_repl(cfg, session, agent=use_agent, probes=boot.env.externals, kickoff=kickoff)
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]已中断（会话已保存）[/yellow]")


def _apply_model(cfg: Config, model: str | None, deep_model: str | None = None) -> None:
    """命令行模型覆盖。

    一律经 :func:`llm.models.normalize` 处理，**不直接把字符串塞进配置**——
    简写要归一化，注册表外的名字要报警告。用户填了已下线的名字时服务端会
    静默换模型，只有这里提前发现得了。警告统一挂到
    ``cfg.llm.model_warnings``，由各命令在启动时打印。
    """
    from llm.models import normalize

    # 只在真有覆盖时才清空——否则会把 load_config 收集到的警告一并擦掉，
    # 而"配置里写了已下线模型名"恰恰是最该提醒的情况（这个 bug 真发生过：
    # models 命令下警告凭空消失，因为命令行没传 --model 却照清不误）。
    if model or deep_model is not None:
        cfg.llm.model_warnings.clear()

    if model:
        cfg.llm.model, warn = normalize(model)
        if warn:
            cfg.llm.model_warnings.append(warn)
    if deep_model is not None:
        if deep_model:
            cfg.llm.deep_model, warn2 = normalize(deep_model)
            if warn2:
                cfg.llm.model_warnings.append(warn2)
        else:
            cfg.llm.deep_model = ""


def _print_model_warnings(cfg: Config) -> None:
    for w in cfg.llm.model_warnings:
        console.print(f"[yellow]⚠ {w}[/yellow]")


def _print_proxy_notice(cfg: Config) -> None:
    """启动时告知代理状态。

    为什么值得单独打一行：渗透机挂 Burp / Clash 时，用户最怕的是
    "我以为流量走代理了，结果全是直连，Burp 里啥也看不到"。
    这里把**所有目标（含内网/本机）都走代理**这件事说清楚，
    免得用户以为"开了代理端口就扫描不到"。
    """
    sc = cfg.scan
    if not sc.proxy:
        return
    source = "配置指定" if not sc.proxy_autodetect else "自动探测"
    tail = "全部目标走代理（含内网/本机），端口扫描经 SOCKS5/CONNECT 隧道"
    console.print(f"[dim]代理：{sc.proxy}（{source}）· {tail}[/dim]")


