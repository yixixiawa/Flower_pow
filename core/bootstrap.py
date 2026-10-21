"""初始化引导——用户敲下 ``python flower_pow.py`` 之后发生的事。

为什么要有这一步
----------------
这个工具的形态是"把机器上已有的能力组织起来"，所以**第一次运行必须如实
说清楚三件事**：

1. 这台机器现在到底有什么（装了哪些外部工具、依赖是否齐、索引在不在）
2. 还缺什么（缺的东西不致命，会退回内置实现）
3. 要连大模型，得先给一把钥匙

顺序不能反：先把体检做完再问 API Key。反过来先要 Key，用户会以为
"这个工具只是个壳，没有模型就没法用"——其实除了对话，扫描链路全都能跑。

Key 的落点
----------
写进 ``.env``（已在 .gitignore 里），同时注入当前进程的 ``os.environ``，
下次启动由 :func:`core.config_loader.load_config` 自动读回。

**不写 config.yaml**：配置文件的典型用法是要提交进仓库的，Key 放进去
迟早会被 commit 出去一次。环境变量 + .gitignore 是唯一不用靠"记得"来
保证安全的方案。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_loader import BANNER, Config
from core.envfile import DEFAULT_ENV_PATH, mask, set_env_value
from core.tools import (
    EnvReport,
    probe_deps,
    probe_external,
    wordlist_path,
    write_wordlist,
)

ENV_KEY_NAME = "DEEPSEEK_API_KEY"


@dataclass
class BootstrapResult:
    """初始化结果，调用方据此决定进对话还是降级。"""

    env: EnvReport
    api_key: str = ""
    key_source: str = ""        # env | dotenv | config | prompted | arg | none
    key_verified: bool = False
    skip_llm: bool = False
    aborted: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def can_chat(self) -> bool:
        return bool(self.api_key) and not self.skip_llm and not self.aborted


# ── 体检 ──────────────────────────────────────────────────────────────


def run_checks(cfg: Config, *, skip_probe: bool = False) -> EnvReport:
    """收集环境现状。**只读**，不修改任何东西。"""
    rep = EnvReport()
    rep.python = f"{sys.version.split()[0]}"
    rep.platform = f"{sys.platform}"

    rep.deps = probe_deps()
    if skip_probe:
        rep.externals = []
    else:
        #探测结果与清单错误分开收：YAML 写错不该让体检崩掉，
        # 但也不能静默吞掉——那正是"我明明配了却不认"的来源。
        externals, tool_errs = probe_external()
        rep.externals = externals
        rep.tool_errors = tool_errs

    # POC 库与索引
    from detectors.poc_loader import filter_executable, load_poc_map
    from kb.indexer import VectorStore

    try:
        pocs, _errs = load_poc_map(cfg.rag.poc_dir)
        rep.poc_count = len(pocs)
        exec_pocs, _skip = filter_executable(list(pocs.values()), cfg.scan.readonly)
        rep.index_note = f"可执行 {len(exec_pocs)} 条"
    except Exception as exc:  # noqa: BLE001
        rep.index_note = f"加载失败：{type(exc).__name__}"

    db = Path(cfg.rag.db_dir) / "poc_index.json"
    store = VectorStore.load(db) if db.is_file() else None
    rep.index_ok = store is not None
    if store is not None:
        rep.index_note += f" / 索引 {len(store)} 条"

    # Key 来源判定
    if os.environ.get(ENV_KEY_NAME):
        rep.api_key_set = True
        rep.api_key_source = "环境变量" if not Path(DEFAULT_ENV_PATH).is_file() else "环境变量或 .env"
    elif cfg.llm.api_key:
        rep.api_key_set = True
        rep.api_key_source = "config.yaml"

    wl = wordlist_path(".")
    rep.wordlist_path = str(wl) if wl.is_file() else ""

    # 自定义工具清单：文件在就在报出来（含"这份文件存在但一个工具都没解析出来"
    # 这种最容易被忽略的情况——用户以为登记成功了，其实全部被跳过）
    from core.tools import USER_TOOLS_FILE, load_user_tools

    uf = Path(USER_TOOLS_FILE)
    if uf.is_file():
        rep.user_tools_file = str(uf)
        try:
            _tools, errs = load_user_tools(uf)
            rep.user_tools_count = len(_tools)
            rep.tool_errors.extend(errs)
        except Exception as exc:  # noqa: BLE001
            rep.tool_errors.append(f"{uf} 读取失败：{type(exc).__name__}: {exc}")
    return rep


# ── 展示 ──────────────────────────────────────────────────────────────


def _icon(ok: bool) -> str:
    return "[green]✓[/green]" if ok else "[yellow]✗[/yellow]"


def print_report(cfg: Config, rep: EnvReport, console: Console) -> None:
    """把体检结果打成表。信息密度要够，但不能糊成一团。"""
    head = Table.grid(padding=(0, 2))
    head.add_column(style="cyan")
    head.add_column()
    head.add_row("目标目录", str(Path.cwd()))
    head.add_row("Python", f"{rep.python}  ({rep.platform})")
    head.add_row("模型", f"{cfg.llm.model}" + (f" / 深度 {cfg.llm.deep_model}" if cfg.llm.deep_model else ""))
    head.add_row("服务端", cfg.llm.base_url)
    console.print(Panel(head, title="环境", border_style="cyan", expand=False))

    # 外部工具
    if rep.externals:
        t = Table(title=f"本机可调用工具（{len(rep.found_externals)}/{len(rep.externals)} 可用）")
        t.add_column("", width=2)
        t.add_column("工具", style="cyan", no_wrap=True)
        t.add_column("用途", style="dim")
        t.add_column("版本", no_wrap=True)
        t.add_column("路径", style="dim", overflow="fold")
        for p in rep.externals:
            t.add_row(
                _icon(p.found),
                p.spec.key,
                p.spec.category,
                p.status,
                p.path or "—",
            )
        console.print(t)
        if not rep.found_externals:
            console.print(
                "[dim]  没探测到外部工具不影响使用：端口/路径/JS/接口采集都有内置实现。[/dim]"
            )
        blocked = [p.spec.key for p in rep.found_externals if p.spec.intrusive]
        if blocked and cfg.scan.readonly:
            console.print(
                f"[dim]  其中 [yellow]{', '.join(blocked)}[/yellow] 属攻击性工具，"
                f"只读模式下会被拒绝执行。[/dim]"
            )

    # 依赖 / POC / 索引
    t2 = Table(title="运行组件")
    t2.add_column("", width=2)
    t2.add_column("项", style="cyan")
    t2.add_column("状态")
    for d in rep.deps:
        ver = f" {d.version}" if d.version else ""
        t2.add_row(_icon(d.ok), f"{d.module}（{d.label}）", ("已就绪" + ver) if d.ok else "[red]缺失[/red]")
    t2.add_row(
        _icon(rep.poc_count > 0),
        "POC 库",
        f"{rep.poc_count} 条 — {rep.index_note}" if rep.poc_count else "[red]未加载[/red]",
    )
    # 自定义工具清单：必须显式展示。否则用户改了 YAML 却看不到任何反馈，
    # 只能凭"tools 命令里还是没有它"来猜问题出在哪。
    t2.add_row(
        _icon(rep.user_tools_count > 0),
        "自定义工具清单",
        f"{rep.user_tools_count} 项 @ {rep.user_tools_file}"
        if rep.user_tools_file
        else "[dim]未创建（装了新工具可在这里登记）[/dim]",
    )
    t2.add_row(
        _icon(rep.index_ok),
        "向量索引",
        "已就绪" if rep.index_ok else "[yellow]未构建（初始化时会自动生成）[/yellow]",
    )
    t2.add_row(
        _icon(bool(rep.wordlist_path)),
        "外部工具字典",
        rep.wordlist_path or "[yellow]未生成[/yellow]",
    )
    t2.add_row(
        _icon(rep.api_key_set),
        "API Key",
        f"已配置（来源：{rep.api_key_source}）" if rep.api_key_set else "[yellow]未配置[/yellow]",
    )
    console.print(t2)

    if rep.missing_deps:
        console.print(
            "[red]⚠ 缺少运行依赖：[/red]"
            + ", ".join(d.module for d in rep.missing_deps)
            + "\n  [dim]先执行：.venv\\\\Scripts\\\\python.exe -m pip install -r requirements.txt[/dim]"
        )
# 清单错误必须打印并指明修哪一行——静默跳过就是"配了不认"的根源
    for e in rep.tool_errors:
        console.print(f"[yellow]![/yellow] 自定义工具清单：{e}")


# ── API Key ───────────────────────────────────────────────────────────


def _read_secret(prompt: str) -> str:
    """读一行密钥输入。

    ``getpass`` 在非 tty（管道、CI）里会退化甚至告警，所以先判 isatty。
    输入不回显是硬要求——终端里留下的 Key 会被 history / 录屏 / 截图带走。
    """
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            from getpass import getpass

            return getpass(prompt).strip()
        except Exception:  # noqa: BLE001
            pass
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _looks_wrong(key: str, base_url: str) -> str:
    if key.startswith("sk-") or len(key) >= 20:
        return ""
    if "deepseek" in (base_url or "").lower():
        return f"DeepSeek 的 Key 通常以 sk- 开头，你输入的长度只有 {len(key)}。"
    return f"这个 Key 看起来偏短（{len(key)} 字符），确认无误吗？"


def _verify_key(cfg: Config, console: Console) -> bool:
    """真发一次极短的请求验证 Key。比"保存后才发现错"友好得多。"""
    from llm.client import LLMClient

    llm = LLMClient(cfg.llm)
    if not llm.available:
        return False
    try:
        with console.status("[dim]正在验证 API Key…[/dim]", spinner="dots"):
            out = llm.ask("你是连通性探测器。", "回复两个字：正常", max_tokens=16)
        if out:
            console.print(f"[green]✓[/green] Key 可用，模型 {cfg.llm.model} 已连通。")
            return True
        console.print("[yellow]![/yellow] 模型返回了空内容，但连接是通的。")
        return True
    except Exception as exc:  # noqa: BLE001
        blob = f"{type(exc).__name__}: {exc}"
        low = blob.lower()
        if "401" in low or "invalid" in low or "auth" in low or "unauthor" in low:
            console.print(f"[red]✗ Key 被服务端拒绝：[/red]{blob[:200]}")
        elif "connect" in low or "timeout" in low or "resolve" in low or "ssl" in low:
            console.print(
                f"[yellow]![/yellow] 无法连接服务端（{cfg.llm.base_url}）：{blob[:160]}\n"
                f"  [dim]Key 已保存。可能是网络/代理问题，稍后重试即可。[/dim]"
            )
            return True
        else:
            console.print(f"[red]✗ 验证失败：[/red]{blob[:200]}")
        return False


def ensure_api_key(
    cfg: Config,
    rep: EnvReport,
    console: Console,
    *,
    interactive: bool = True,
    verify: bool = True,
    preset: str = "",
) -> tuple[str, str, bool]:
    """确保拿到一把可用的 Key。返回 ``(key, 来源, 是否验证通过)``。

    已配置的情况**不再多问**——用户跑第二次时不该被重复索要同一个东西。
    只有在验证失败时才提示"要重新输入吗"。
    """
    if preset:
        cfg.llm.api_key = preset
        os.environ[ENV_KEY_NAME] = preset
        note = _looks_wrong(preset, cfg.llm.base_url)
        if note:
            console.print(f"[yellow]![/yellow] {note}")
        ok = _verify_key(cfg, console) if verify else True
        return preset, "命令行参数", ok

    if rep.api_key_set:
        ok = _verify_key(cfg, console) if verify else True
        if ok:
            return cfg.llm.api_key, rep.api_key_source, True
        if not interactive:
            return cfg.llm.api_key, rep.api_key_source, False
        console.print(
            "  [yellow]现有 Key 验证未通过。[/yellow]直接回车保留，或粘贴新的 Key 覆盖。"
        )
    elif not interactive:
        rep.api_key_set = False
        return "", "none", False

    # ── 交互输入 ──────────────────────────────────────────────────
    console.print()
    console.rule("[bold cyan]连接大模型", style="cyan")
    console.print(
        "[dim]  扫描链路（侦察/RAG/验证/报告）不依赖大模型也能跑。\n"
        "  但交互式 AI Agent 需要模型来驱动工具调用，所以要先给一把 Key。\n"
        f"  Key 会写入 {Path(DEFAULT_ENV_PATH).resolve()}（已在 .gitignore 中，不会进 git）。[/dim]"
    )

    for attempt in range(3):
        key = _read_secret("请输入API-KEY：")
        if not key:
            if rep.api_key_set or cfg.llm.api_key:
                console.print("[dim]  保持原有配置。[/dim]")
                return cfg.llm.api_key, rep.api_key_source, False
            console.print(
                "[yellow]  未输入。[/yellow]将以「无大模型」模式运行："
                "扫描、RAG、报告照常，只是没有对话式 Agent。\n"
                "  [dim]随时可以用 /key 命令补上。[/dim]"
            )
            return "", "none", False

        note = _looks_wrong(key, cfg.llm.base_url)
        if note:
            console.print(f"[yellow]  ! {note}[/yellow]")

        cfg.llm.api_key = key
        os.environ[ENV_KEY_NAME] = key
        ok = _verify_key(cfg, console) if verify else True
        if ok or attempt == 2:
            if not ok:
                console.print("[yellow]  仍要保存吗？[/yellow]已验证失败，保存后对话可能不可用。")
                if (input("  保存？[y/N] ").strip().lower() not in ("y", "yes")):
                    continue
            path = set_env_value(
                ENV_KEY_NAME,
                key,
                DEFAULT_ENV_PATH,
                comment="flower_pow 本地密钥（已被 .gitignore 排除，请勿提交）",
            )
            console.print(f"[green]✓[/green] 已写入 {path.resolve()}  （{mask(key)}）")
            return key, "本次输入", ok

        console.print("[yellow]  请重新输入（直接回车可跳过）。[/yellow]")

    return "", "none", False


# ── 初始化主流程 ──────────────────────────────────────────────────────


def run_bootstrap(
    cfg: Config,
    console: Console,
    *,
    skip_probe: bool = False,
    interactive: bool = True,
    verify_key: bool = True,
    api_key: str = "",
    quiet: bool = False,
) -> BootstrapResult:
    """完整初始化：体检 → 必要修补 → 要 Key → 就绪。"""
    if not quiet:
        console.print(Panel(BANNER.strip("\n"), style="cyan", expand=False))

    rep = run_checks(cfg, skip_probe=skip_probe)

    # 索引缺失就顺手建好：放在这里而不是等第一次 RAG 调用，
    # 是因为构建 25 条 POC 的索引只要一两秒，而"第一次检索时卡住 3 秒"
    # 用户会以为是网络慢。
    if not rep.index_ok and rep.poc_count:
        from kb.indexer import build_index, dump_index_stats

        with console.status("[dim]正在构建 POC 向量索引…[/dim]", spinner="dots"):
            try:
                store, _errs = build_index(
                    cfg.rag.poc_dir,
                    Path(cfg.rag.db_dir) / "poc_index.json",
                    dim=cfg.rag.dim,
                    boost_terms=cfg.rag.boost_terms,
                )
                rep.index_ok = True
                rep.index_note += f" / 新建索引 {dump_index_stats(store)}"
            except Exception as exc:  # noqa: BLE001
                rep.index_note += f" / 索引构建失败 {type(exc).__name__}"

    # 内置字典导出成文件，供 gobuster / ffuf 这类必须给 -w 的工具使用
    if not rep.wordlist_path:
        if (p := write_wordlist(".")) is not None:
            rep.wordlist_path = str(p)

    if not quiet:
        print_report(cfg, rep, console)

    key, source, verified = ensure_api_key(
        cfg, rep, console, interactive=interactive, verify=verify_key, preset=api_key
    )

    res = BootstrapResult(env=rep, api_key=key, key_source=source, key_verified=verified)
    if not key:
        res.skip_llm = True
    if rep.missing_deps:
        res.skip_llm = True
        res.notes.append("缺少运行依赖，已禁用大模型相关功能")
    return res


__all__ = ["BootstrapResult", "run_bootstrap", "run_checks", "print_report", "ensure_api_key"]
