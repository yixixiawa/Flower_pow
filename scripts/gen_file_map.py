# -*- coding: utf-8 -*-
"""生成 doc/auxiliary/FILE_MAP.md：项目架构 + 文件职责 + 引用关系。

扫描全部源码（排除 .venv / .backup / .git），AST 解析 import 与模块
docstring，构建 双向引用图后渲染 Markdown。

职责摘要直接取自模块 docstring 的首句——项目里 148 个模块全部有 docstring，
所以这份地图**不含手写描述**，改完代码重跑一次即可刷新。
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "doc" / "auxiliary" / "FILE_MAP.md"
# 根目录再放一份，方便直接打开；两处内容始终一致（同一个脚本产出）。
OUT_ROOT = ROOT / "FILE_MAP.md"

# 顶层包（可被 import 的项目模块根）
TOP_PKGS = {"core", "cli", "collectors", "detectors", "kb", "llm",
            "output", "scripts", "poc", "flower_pow", "mcp_server"}

# 注意：`output/` 不能整体跳过——它既是**运行时产物目录**（证据 / 报告，
# gitignore），也含有**源码**（`output/evidence.py`、`output/report/*.py`，
# 入库）。rglob 只找 `*.py`，产物里的 .md/.json/.http 天然不会被收进来，
# 所以这里只排真正该排的目录。
SKIP_DIRS = {".venv", ".git", ".backup", ".workbuddy", "data",
             "reports", "doc", "docs", "__pycache__", ".pytest_cache"}


def iter_py() -> list[Path]:
    out = []
    for p in sorted(ROOT.rglob("*.py")):
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        out.append(p)
    return out


def module_name(p: Path) -> str:
    rel = p.relative_to(ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def display_name(p: Path) -> str:
    """表格显示用真实相对路径，包的 __init__.py 不伪装成 <pkg>.py。"""
    return p.relative_to(ROOT).as_posix()


def summary_of(path: Path) -> str:
    """从模块 docstring 提取一行职责摘要。

    取第一段里最像"说明句"的那一行，去掉 Sphinx 标记与反引号，截断到 60 字。
    docstring 缺失时返回占位符（正常情况下一个都不会有）。
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return "（无法解析）"
    doc = ast.get_docstring(tree) or ""
    for raw in doc.splitlines():
        line = raw.strip()
        if not line or line.startswith("---") or line.startswith("==="):
            continue
        # 包门面（__init__.py）的 docstring 常常只是 "flower_pow." 这种
        # 无信息量的一行，遇到就直接跳过，继续往后找有意义的句子。
        if line.rstrip(".").lower() in {m.lower() for m in TOP_PKGS}:
            continue
        # 跳过 "``_LoopMixin``：主循环与命令分发。" 这类下划线开头的角色标注
        # 后的空行、以及纯标记行
        clean = re.sub(r":[a-z]+:`([^`]+)`", r"\1", line)
        clean = re.sub(r"``([^`]+)``", r"\1", clean)
        clean = re.sub(r"\*\*([^*]+)\*\*", r"\1", clean)
        clean = clean.strip(" ：:")
        if len(clean) < 6:
            continue
        if len(clean) > 60:
            clean = clean[:60].rstrip() + "…"
        return clean
    # 包门面的 docstring 常常只有一行 "flower_pow."，没有信息量，
    # 上面已被跳过；这里给个说明白职责的兜底文案，而不是回显文件名。
    if path.name == "__init__.py":
        return f"`{path.parent.name}/` 包门面：只做 re-export，无独立逻辑"
    return "（无 docstring）"


def imports_of(path: Path) -> list[str]:
    """AST 解析：本项目内部 import（返回模块名或包名）。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in TOP_PKGS:
                    found.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:  # 相对导入
                base = module_name(path).split(".")
                base = base[: len(base) - node.level]
                mod = ".".join(base + (node.module.split(".") if node.module else []))
                top = mod.split(".")[0]
                if top in TOP_PKGS:
                    found.add(mod)
            elif node.module:
                top = node.module.split(".")[0]
                if top in TOP_PKGS:
                    found.add(node.module)
    return sorted(found)


def cli_commands() -> list[tuple[str, str, str]]:
    """解析 cli/ 下的 @app.command()，返回 (命令名, 文件, 说明)。"""
    out: list[tuple[str, str, str]] = []
    for p in sorted((ROOT / "cli").glob("*.py")):
        if p.name == "app.py":
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorated = False
            for dec in node.decorator_list:
                call = dec.func if isinstance(dec, ast.Call) else dec
                name = getattr(call, "attr", getattr(call, "id", ""))
                if name == "command":
                    decorated = True
            if not decorated:
                continue
            doc = (ast.get_docstring(node) or "").splitlines()
            desc = ""
            for line in doc:
                s = line.strip()
                if s:
                    desc = re.sub(r"``([^`]+)``", r"\1", s)
                    break
            if len(desc) > 50:
                desc = desc[:50].rstrip() + "…"
            out.append((node.name, p.relative_to(ROOT).as_posix(), desc))
    return sorted(out)


def yaml_rules() -> list[tuple[str, str, str]]:
    """解析 poc/*.yaml，返回 (类别, 文件名, 名称/描述)。"""
    out: list[tuple[str, str, str]] = []
    for p in sorted((ROOT / "poc").glob("*.yaml")):
        cat = p.stem.split("__")[0]
        desc = ""
        try:
            import yaml  # 延迟导入：仅本函数需要
            d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            desc = str(d.get("description") or d.get("name") or "")
        except Exception:  # noqa: BLE001 - 摘要失败不影响地图生成
            desc = ""
        if len(desc) > 46:
            desc = desc[:46].rstrip() + "…"
        out.append((cat, p.name, desc))
    return out


def _git_md_state() -> tuple[set[str], set[str]]:
    """返回 (已跟踪的 md, 被 gitignore 的 md)。

    三态比"入库/不入库"两态诚实：新建但还没 `git add` 的文件既不是已跟踪，
    也不该被说成"被忽略"——那会让人以为它永远进不了库。
    """
    tracked: set[str] = set()
    ignored: set[str] = set()
    try:
        import subprocess

        out = subprocess.run(
            ["git", "ls-files", "*.md"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            tracked = {x.strip().replace("\\", "/") for x in out.stdout.splitlines() if x.strip()}
        # 逐条问 check-ignore 太慢；用**位置参数**一次问完。
        # 不要用 `--stdin`：实测该模式下批量喂路径会统一返回「都没被忽略」
        # （单条直查却能命中），是 git 版本相关的坑。
        cands = [p.relative_to(ROOT).as_posix() for p in _md_paths()]
        if cands:
            res = subprocess.run(
                ["git", "check-ignore", "--", *cands],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            if res.returncode in (0, 1):  # 0=有被忽略的, 1=一个都没被忽略
                ignored = {x.strip().replace("\\", "/") for x in res.stdout.splitlines() if x.strip()}
    except Exception:  # noqa: BLE001 - 地图生成不该因为没 git 就失败
        pass
    return tracked, ignored


def _md_paths() -> list[Path]:
    """根目录 *.md + docs/ 与 doc/ 下的 Markdown，去重且排除地图自身。"""
    out: list[Path] = []
    seen: set[str] = set()
    for pattern in ("*.md", "docs/*.md", "doc/**/*.md"):
        for p in sorted(ROOT.glob(pattern)):
            if not p.is_file():
                continue
            rel = p.relative_to(ROOT).as_posix()
            if rel in seen or p.name == "FILE_MAP.md":
                continue      # 地图不给自己做条目，纯噪音
            seen.add(rel)
            out.append(p)
    return out


def iter_docs() -> list[tuple[Path, str]]:
    """收集文档并标注入库状态：已提交 / 未跟踪 / 被忽略。"""
    tracked, ignored = _git_md_state()
    out: list[tuple[Path, str]] = []
    for p in _md_paths():
        rel = p.relative_to(ROOT).as_posix()
        if rel in tracked:
            state = "是（已提交）"
        elif rel in ignored:
            state = "否（gitignore）"
        else:
            state = "**未提交**（新文件）"
        out.append((p, state))
    return out


def doc_title(p: Path) -> str:
    """取 Markdown 的说明句。

    优先正文首段而不是 H1——`# flower_pow` 这种标题只有项目名，
    说了等于没说；正文第一句才讲清"这个文件是干什么的"。
    """
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "（无法读取）"
    heading = ""
    for line in lines:
        s = line.strip()
        if not s or s.startswith("---") or s.startswith(">"):
            continue
        if s.startswith("#"):
            if not heading:
                heading = s.lstrip("#").strip()
            continue
        # 只去掉 Markdown 标记符号，**保留**标识符里的下划线——
        # 用 [*`_] 一刀切会把 flower_pow 删成 flowerpow。
        clean = s.replace("**", "").replace("`", "").strip(" >")
        if len(clean) >= 8:
            return clean[:56].rstrip() + "…" if len(clean) > 56 else clean
    return heading[:56] or "（无标题）"


def main() -> int:
    files = iter_py()
    mods: dict[str, Path] = {}
    for p in files:
        mods[module_name(p)] = p

    def top_of(m: str) -> str:
        """按**物理路径**首段判归属。

        不能用模块名里的点来判断：包门面（``core/__init__.py``）的模块名就是
        包名 ``core``，不含点，会被误判成根目录文件——那样每个包的 ``__init__``
        都会从自己的小节里消失，跑到根目录去。
        """
        parts = mods[m].relative_to(ROOT).parts
        return parts[0] if len(parts) > 1 else "(根目录)"

    # 依赖图
    deps: dict[str, set[str]] = defaultdict(set)     # 谁 -> import 谁
    rdeps: dict[str, set[str]] = defaultdict(set)    # 谁 <- 被谁 import

    def resolve(name: str) -> str | None:
        """import 名 -> 实际模块/包名（容忍导子符号时的前缀匹配）。"""
        if name in mods:
            return name
        # from core.tools import ToolRunner -> core.tools 是包
        while "." in name:
            name = name.rsplit(".", 1)[0]
            if name in mods:
                return name
        return None

    for mod, p in mods.items():
        for imp in imports_of(p):
            tgt = resolve(imp)
            if tgt and tgt != mod:
                deps[mod].add(tgt)
                rdeps[tgt].add(mod)

    lines: list[str] = []
    w = lines.append

    src = [m for m in mods if top_of(m) != "scripts"]
    tests = [m for m in mods if top_of(m) == "scripts"]
    total_lines = sum(
        len(mods[m].read_text(encoding="utf-8").splitlines()) for m in mods
    )
    src_lines = sum(
        len(mods[m].read_text(encoding="utf-8").splitlines()) for m in src
    )

    w("# flower_pow 文件地图（架构 + 文件职责 + 引用关系）")
    w("")
    w("> **本文件由 `scripts/gen_file_map.py` 自动生成**，数据来源为 AST 解析的")
    w("> 真实 import 语句与模块 docstring——正文不含手写描述，改完代码重跑一次即可刷新。")
    w("")
    w(f"共 **{len(mods)}** 个 Python 文件 / **{total_lines}** 行："
      f"源码 {len(src)} 个（{src_lines} 行）+ `scripts/` 测试与工具 {len(tests)} 个。")
    w("")
    w("> 记法：引用表（§4/§5）里的 `core.repl` 这类**包名**指该包的 `__init__.py` 门面；")
    w("> §2 表格里显示的是真实相对路径。职责摘要取自模块 docstring 首句。")
    w("")

    # ---------- 速览：各层规模 ----------
    w("## 速览：各层规模与分工")
    w("")
    w("| 层 | 位置 | 文件 | 行数 | 干什么 |")
    w("|---|---|---:|---:|---|")

    def count(pred) -> tuple[int, int]:
        """返回 (文件数, 行数)。分组必须互斥，否则总数会重复统计。"""
        members = [m for m in mods if pred(m)]
        n = sum(len(mods[m].read_text(encoding="utf-8").splitlines()) for m in members)
        return len(members), n

    is_core_sub = lambda m: m.startswith(
        ("core.tools", "core.state", "core.session", "core.repl", "core.completer",
         "core.scheduler")
    )
    # 包门面（core / cli / kb … 的 __init__.py）的模块名就是包名本身，
    # 所以要用 "m == pkg or m.startswith(pkg + '.')" 才算在某一层里。
    in_pkg = lambda pkg: (lambda m: m == pkg or m.startswith(pkg + "."))

    LAYERS = [        ("CLI 入口", "`flower_pow.py`",
         lambda m: m == "flower_pow", "Typer 应用装配"),
        ("命令层", "`cli/`",
         in_pkg("cli"), "19 个子命令的实现"),
        ("MCP 接入层", "`mcp_server/`",
         in_pkg("mcp_server"), "把扫描器包成 MCP Server（10 个工具，供外部客户端调用）"),
        ("编排层", "`core/`（顶层）",
         lambda m: (m == "core" or m.startswith("core.")) and not is_core_sub(m),
         "Agent / Planner 三种驱动 + 代理·隧道·配置"),
        ("调度层", "`core/scheduler/`",
         in_pkg("core.scheduler"), "一次性扫描流水线（侦察→召回→验证→研判→报告）"),
        ("工具层", "`core/tools/`",
         in_pkg("core.tools"), "工具声明 → 探测 → 归一 → 执行（安全边界）"),
        ("采集层", "`collectors/`",
         in_pkg("collectors"), "端口 / 路径 / OpenAPI / JS / 子域枚举"),
        ("验证层", "`detectors/`",
         in_pkg("detectors"), "POC 执行与高危探针"),
        ("检索层", "`kb/`",
         in_pkg("kb"), "向量索引 + BM25 → 召回 → LLM 重排"),
        ("模型层", "`llm/`",
         in_pkg("llm"), "OpenAI 兼容客户端 + 提示词模板"),
        ("产物层", "`output/`",
         in_pkg("output"), "证据落盘 + JSON/MD/HTML 报告"),
        ("状态层", "`core/state/` `core/session/`",
         lambda m: m.startswith(("core.state", "core.session")),
         "数据模型事实来源 + 会话状态"),
        ("终端层", "`core/repl/` `core/completer/`",
         lambda m: m.startswith(("core.repl", "core.completer")),
         "交互终端（prompt_toolkit 输入）"),
        ("测试层", "`scripts/`",
         in_pkg("scripts"), "可独立执行的回归脚本（不用 pytest）"),
    ]
    for label, path, pred, duty in LAYERS:
        cnt, n = count(pred)
        if not cnt:
            continue
        w(f"| {label} | {path} | {cnt} | {n} | {duty} |")
    w("")

    # ---------- 0. 全局架构 ----------
    w("## 0. 全局架构：一条扫描请求怎么流过去")
    w("")
    w("```")
    w("flower_pow.py            CLI 入口（typer），触发注册 + 调起 Typer")
    w("   │")
    w(f"   ├─ cli/*              {len(cli_commands())} 个子命令的实现（scan / chat / kb / probe / ledger …）")
    w("   ├─ mcp_server/*       MCP Server：进程常驻，10 个工具走标准协议（与 CLI 并列的接入面）")
    w("   │                     server(工具声明) → services(纯函数) → jobs(后台扫描线程)")
    w("   ├─ core/bootstrap.py  环境体检：外部工具、依赖、索引、API Key")
    w("   ├─ core/config_loader.py  配置：环境变量 > config.yaml > 默认值")
    w("   │")
    w("   ▼")
    w("core/scheduler/        一次性扫描编排（五阶段 mixin：recon/match/verify/report）")
    w("core/planner.py        剧本模式（固定四阶段，可复现不烧 token）")
    w("core/agent.py          交互式 Agent（模型决定调什么工具，流式输出）")
    w("   │")
    w("   ├─ collectors/*       资产采集（端口/路径/OpenAPI/JS/子域/dirsearch）")
    w("   ├─ kb/*               向量索引（余弦+BM25）→ 召回 → LLM 重排；CVE 情报；知识沉淀")
    w("   ├─ detectors/*        POC 验证（HTTP/鉴权/高危探针/JS 逻辑）+ 公开性核验")
    w("   ├─ core/tools/*       工具层：声明(builtins/external) → 探测(probe)")
    w("   │                     → 归一(args) → 执行(runner/*，唯一安全边界)")
    w("   ├─ llm/*              OpenAI 兼容客户端 + 模型注册表 + 提示词模板")
    w("   └─ output/*           证据落盘 + JSON / Markdown / HTML 报告")
    w("")
    w("core/state/*            数据模型事实来源（枚举/POC/Finding/Evidence/ScanResult）")
    w("core/session/*          会话状态（Phase/Turn/ConversationTurn + 落盘/脱敏）")
    w("core/repl/*             交互终端（命令分发 mixin）+ core/completer/* prompt_toolkit 输入")
    w("```")
    w("")
    w("| 驱动 | 入口 | 特点 |")
    w("|---|---|---|")
    w("| 一次性扫描 | `core.scheduler.Scheduler.scan()` | 五阶段流水线，跑完出报告 |")
    w("| 交互式 Agent | `core.agent.Agent` + `core.tools.runner.ToolRunner` | 模型自由发挥，流式输出 |")
    w("| 剧本模式 | `core.planner.Planner` | 固定四阶段，可复现、不烧 token |")
    w("")

    # ---------- 1. 分包架构与职责 ----------
    w("## 1. 分包结构与文件职责")
    w("")
    PKG_DESC = {
        "(根目录)": "CLI 入口（各包的 `__init__` 门面归各自包）",
        "cli": "CLI 子命令实现（typer）",
        "mcp_server": "MCP Server（协议适配 / 后台任务 / 服务层纯函数）",
        "core": "编排 / 状态 / 工具 / 会话 / 交互",
        "collectors": "资产采集层",
        "detectors": "验证层（POC 执行与探针）",
        "kb": "检索与知识（向量索引 / 情报 / 沉淀）",
        "llm": "大模型接入（客户端 / 注册表 / 提示词）",
        "output": "证据落盘与报告渲染（源码入库，产物 gitignore）",
        "scripts": "测试与工具脚本（无 pytest，直接跑）",
    }
    # core 内部再按子包细分——这些子包各有独立职责，混在一张表里看不清
    SUBPKG_DESC = {
        "core/completer": "终端输入层（prompt_toolkit：补全 / 历史 / 语法高亮）",
        "core/repl": "交互终端（命令分发 mixin，Ctrl+C 双语义）",
        "core/scheduler": "扫描调度器（五阶段 mixin）",
        "core/session": "会话状态与落盘脱敏",
        "core/state": "数据模型事实来源",
        "core/tools": "工具声明 / 探测 / 归一",
        "core/tools/runner": "工具执行（唯一安全边界）",
    }
    order = ["(根目录)", "cli", "mcp_server", "core", "collectors",
             "detectors", "kb", "llm", "output", "scripts"]

    def subpkg_of(m: str, path: Path) -> str | None:
        """core 下的文件归属哪个子包（按物理目录判定，最长匹配优先）。"""
        if not m.startswith("core"):
            return None
        rel = path.relative_to(ROOT).as_posix()
        parts = rel.split("/")
        for depth in (3, 2):  # core/tools/runner → core/tools
            if len(parts) >= depth:
                cand = "/".join(parts[:depth])
                if cand in SUBPKG_DESC:
                    return cand
        return None

    def emit_table(members: list[str]) -> None:
        w("| 文件 | 职责（docstring 首句） | 行数 | 被引用 |")
        w("|---|---|---:|---:|")
        for m in sorted(members, key=lambda x: (x.count(".") == 0, x)):
            n = len(mods[m].read_text(encoding="utf-8").splitlines())
            w(f"| `{display_name(mods[m])}` | {summary_of(mods[m])} | {n} | {len(rdeps.get(m, ()))} |")
        w("")

    for pkg in order:
        members = [m for m in mods if top_of(m) == pkg]
        if not members:
            continue
        title = "根目录" if pkg == "(根目录)" else pkg + "/"
        w(f"### `{title}` —— {PKG_DESC[pkg]}（{len(members)} 个文件）")
        w("")

        if pkg == "core":
            # core 顶层散文件
            loose = [m for m in members if subpkg_of(m, mods[m]) is None]
            subs: dict[str, list[str]] = defaultdict(list)
            for m in members:
                sp = subpkg_of(m, mods[m])
                if sp:
                    subs[sp].append(m)
            w("**core 顶层散文件**")
            w("")
            emit_table(loose)
            for sp in sorted(subs):
                w(f"**`{sp}/`** —— {SUBPKG_DESC[sp]}（{len(subs[sp])} 个文件）")
                w("")
                emit_table(subs[sp])
            continue

        emit_table(members)

    # ---------- 2. CLI 命令清单 ----------
    w("## 2. CLI 子命令清单")
    w("")
    cmds = cli_commands()
    w(f"`flower_pow <命令>` 共 **{len(cmds)}** 个子命令，全部由 `@app.command()` 注册在 `cli/app.py` 的 Typer 实例上。")
    w("")
    w("| 命令 | 实现文件 | 说明 |")
    w("|---|---|---|")
    for name, f, desc in cmds:
        w(f"| `{name}` | `{f}` | {desc} |")
    w("")

    # ---------- 3. 非代码资产 ----------
    w("## 3. 非代码资产：规则 / 配置 / 数据")
    w("")
    w("### 3.1 POC 检测规则（`poc/*.yaml`）")
    w("")
    rules = yaml_rules()
    cats = defaultdict(list)
    for cat, fn, desc in rules:
        cats[cat].append((fn, desc))
    w(f"共 **{len(rules)}** 条规则，分 **{len(cats)}** 类。规则是 YAML 声明，")
    w("由 `core/state/poc.py` 解析、`detectors/poc_loader.py` 装载，`kb/indexer.py` 自动索引进向量库。")
    w("")
    w("| 类别 | 条数 | 规则文件 |")
    w("|---|---:|---|")
    for cat in sorted(cats):
        names = "、".join(f"`{fn}`" for fn, _ in cats[cat])
        w(f"| `{cat}` | {len(cats[cat])} | {names} |")
    w("")
    w("### 3.2 配置与环境")
    w("")
    w("| 文件 | 作用 |")
    w("|---|---|")
    w("| `config.yaml` | 主配置：`scan` / `rag` / `llm` + 输出与数据目录（项数见文件内注释） |")
    w("| `.env.example` | 环境变量键名清单（**只有键名，无值**，入库供新人对照） |")
    w("| `.env` | 真实密钥（API Key），gitignore，**永不入库** |")
    w("| `data/tools.local.yaml` | 自定义外部工具清单（配置而非产物，入库） |")
    w("| `data/exclusions.json` | 排除规则（路径 / 参数 / 主机黑名单） |")
    w("| `requirements.txt` / `pyproject.toml` | 7 个直接依赖（httpx / openai / typer / rich / pydantic / PyYAML / prompt_toolkit）；`mcp` 为**可选**依赖，不装主程序照常跑 |")
    w("")
    w("### 3.3 运行时目录（全部 gitignore，属派生物）")
    w("")
    w("| 目录 | 内容 |")
    w("|---|---|")
    w("| `data/sessions/` | 会话快照（落盘的对话历史） |")
    w("| `data/vector_db/` | 向量索引（ChromaDB / 内存索引产物） |")
    w("| `data/intel/` | CVE 情报缓存 |")
    w("| `data/recon/` | 侦察中间产物（含 token 等敏感文件，**禁止入库**） |")
    w("| `data/wordlists/` | 目录爆破字典 |")
    w("| `output/` | 证据落盘 + 报告产物（`output/report/*.py` 是源码，入库） |")
    w("| `reports/` | 交付用报告（HTML / MD / JSON） |")
    w("")

    w("### 3.4 文档资产（Markdown）")
    w("")
    docs = iter_docs()
    if docs:
        w("| 文件 | 行数 | 入库 | 作用（正文首句） |")
        w("|---|---:|---|---|")
        for p, state in docs:
            rel = p.relative_to(ROOT).as_posix()
            n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
            w(f"| `{rel}` | {n} | {state} | {doc_title(p)} |")
    else:
        w("（无）")
    w("")
    w("> 仓库只保留 `README.md` 一份对外说明：根目录 `/*.md` 被 `.gitignore` 挡住")
    w("> （`!README.md` 显式放行），`doc/` 同理；`docs/` 放 SDD 的需求/设计文档。")
    w("> 标「**未提交**」的是刚建好还没 `git add` 的，不是被忽略。")
    w("")

    # ---------- 4. 引用关系：谁 import 谁 ----------
    w("## 4. 引用关系（正向：每个文件 import 了谁）")
    w("")
    for m in sorted(mods):
        d = sorted(deps.get(m, ()))
        if not d:
            continue
        w(f"- **`{m}`** → " + "、".join(f"`{x}`" for x in d))
    w("")

    # ---------- 5. 引用关系：谁被谁 import ----------
    w("## 5. 引用关系（反向：每个文件被谁 import）")
    w("")
    for m in sorted(mods):
        r = sorted(rdeps.get(m, ()))
        if not r:
            w(f"- `{m}` —— 无内部调用方（入口 / 叶子 / 测试）")
            continue
        w(f"- **`{m}`** ← " + "、".join(f"`{x}`" for x in r))
    w("")

    # ---------- 6. 关键枢纽 ----------
    w("## 6. 关键枢纽（被引用最多的 15 个文件）")
    w("")
    hub = sorted(mods, key=lambda m: -len(rdeps.get(m, ())))[:15]
    w("| 文件 | 职责 | 被引用 |")
    w("|---|---|---:|")
    for m in hub:
        w(f"| `{m}` | {summary_of(mods[m])} | {len(rdeps.get(m, ()))} |")
    w("")
    w("> 枢纽文件是改动的高危区：改签名要全文搜索调用方；反向引用表（§5）就是调用方清单。")
    w("")

    # ---------- 7. 测试体系 ----------
    w("## 7. 测试体系")
    w("")
    w("项目**不用 pytest**——测试是可独立执行的脚本，由 `scripts/run_tests.py` 统一收集：")
    w("")
    w("```")
    w("scripts/run_tests.py   收集 scripts/*_test.py，逐个以 stdin=DEVNULL 执行")
    w("                     单脚本 300s 超时，正则 (\\d+)\\s*/\\s*(\\d+)\\s*通过 提取断言数")
    w("                     FAIL 前缀行判失败")
    w("```")
    w("")
    w(f"`scripts/` 下共 {len(tests)} 个 Python 文件，其中 `*_test.py` 为测试脚本。")
    w("")

    # ---------- 8. 附录 ----------
    w("## 8. 附录：想加一种新的漏洞检测，要动哪些文件")
    w("")
    w("| 步骤 | 改哪里 |")
    w("|---|---|")
    w("| 1. 写检测规则 | 新增 `poc/<category>__<name>.yaml` |")
    w("| 2. 需要新类别 | `core/state/enums.py` 的 `Category` 枚举 |")
    w("| 3. 需要专用验证逻辑 | `detectors/` 新增类继承 `Detector`，实现 `verify()` |")
    w("| 4. 需要新采集能力 | `collectors/` 新增采集器 |")
    w("| 5. 暴露给 Agent | `core/tools/builtins.py` 加 `BuiltinTool` + `core/tools/runner/` 对应 mixin 加 `_h_xxx()` |")
    w("| 6. 能被检索到 | `kb/indexer.py` 自动索引新 YAML（`index` 命令重建） |")
    w("| 7. 补测试 | `scripts/` 下新增 `*_test.py`（会自动被 `run_tests.py` 收集） |")
    w("| 8. 暴露给 MCP 客户端 | `mcp_server/services.py` 加纯函数 → `mcp_server/server.py` 加 `@server.tool()` 包装 |")
    w("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    OUT.write_text(body, encoding="utf-8")
    OUT_ROOT.write_text(body, encoding="utf-8")
    print(f"written: {OUT}")
    print(f"written: {OUT_ROOT}  ({len(lines)} lines, {len(mods)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
