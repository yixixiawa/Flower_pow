# -*- coding: utf-8 -*-
"""生成 doc/auxiliary/FILE_MAP.md：项目架构 + 文件间引用关系。

扫描全部源码（排除 .venv / .backup / .git），AST 解析 import，
构建 双向 引用图后渲染 Markdown。
"""
from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "doc" / "auxiliary" / "FILE_MAP.md"

# 顶层包（可被 import 的项目模块根）
TOP_PKGS = {"core", "cli", "collectors", "detectors", "kb", "llm",
            "output", "scripts", "poc", "flower_pow"}

SKIP_DIRS = {".venv", ".git", ".backup", ".workbuddy", "output", "data",
             "reports", "doc", "__pycache__", ".pytest_cache"}


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


def main() -> int:
    files = iter_py()
    mods: dict[str, Path] = {}
    for p in files:
        mods[module_name(p)] = p

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

    w("# flower_pow 文件地图（架构 + 引用关系）")
    w("")
    w("> **本文件由 `scripts/gen_file_map.py` 自动生成**，数据来源为 AST 解析的")
    w("> 真实 import 语句——`引用` 一节没有手写内容，改完代码重跑一次即可刷新。")
    w("")
    src = [m for m in mods if not m.startswith("scripts.")]
    tests = [m for m in mods if m.startswith("scripts.")]
    w(f"共 {len(mods)} 个 Python 文件：源码 {len(src)} 个 + `scripts/` 测试与工具 {len(tests)} 个。")
    w("")
    w("> 记法：引用表（§2/§3）里的 `core.repl` 这类**包名**指该包的 `__init__.py` 门面；")
    w("> §1 表格里显示的是真实相对路径。")

    # ---------- 0. 全局架构 ----------
    w("## 0. 全局架构：一条扫描请求怎么流过去")
    w("")
    w("```")
    w("flower_pow.py            CLI 入口（typer），触发注册 + 调起 Typer")
    w("   │")
    w("   ├─ cli/*              18 个子命令的实现（scan / chat / kb / probe / ledger …）")
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
    w("core/state/*            数据模型事实来源（枚举/POC/ Finding/Evidence/ScanResult）")
    w("core/session/*          会话状态（Phase/Turn/ConversationTurn + 落盘/脱敏）")
    w("core/repl/*             交互终端（命令分发 mixin）+ core/completer/* 自实现行编辑")
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
    pkg_of = lambda m: m.split(".")[0] if "." in m else "(根目录)"
    order = ["(根目录)", "cli", "core", "collectors", "detectors", "kb", "llm", "scripts"]
    PKG_DESC = {
        "(根目录)": "CLI 入口 + 各顶层包的 __init__ 门面",
        "cli": "CLI 子命令实现（typer）",
        "core": "编排 / 状态 / 工具 / 会话 / 交互",
        "collectors": "资产采集层",
        "detectors": "验证层（POC 执行与探针）",
        "kb": "检索与知识（向量索引 / 情报 / 沉淀）",
        "llm": "大模型接入（客户端 / 注册表 / 提示词）",
        "scripts": "测试与工具脚本（无 pytest，直接跑）",
    }
    for pkg in order:
        members = [m for m in mods if pkg_of(m) == pkg]
        if not members:
            continue
        title = "根目录" if pkg == "(根目录)" else pkg + "/"
        w(f"### `{title}` —— {PKG_DESC[pkg]}（{len(members)} 个文件）")
        w("")
        w("| 文件 | 行数 | 被引用次数 |")
        w("|---|---:|---:|")
        for m in sorted(members, key=lambda x: (x.count(".") == 0, x)):
            n = len(mods[m].read_text(encoding="utf-8").splitlines())
            w(f"| `{display_name(mods[m])}` | {n} | {len(rdeps.get(m, ()))} |")
        w("")

    # ---------- 2. 引用关系：谁 import 谁 ----------
    w("## 2. 引用关系（正向：每个文件 import 了谁）")
    w("")
    for m in sorted(mods):
        d = sorted(deps.get(m, ()))
        if not d:
            continue
        w(f"- **`{m}`** → " + "、".join(f"`{x}`" for x in d))
    w("")

    # ---------- 3. 引用关系：谁被谁 import ----------
    w("## 3. 引用关系（反向：每个文件被谁 import）")
    w("")
    for m in sorted(mods):
        r = sorted(rdeps.get(m, ()))
        if not r:
            w(f"- `{m}` —— 无内部调用方（入口 / 叶子 / 测试）")
            continue
        w(f"- **`{m}`** ← " + "、".join(f"`{x}`" for x in r))
    w("")

    # ---------- 4. 关键枢纽 ----------
    w("## 4. 关键枢纽（被引用最多的 15 个文件）")
    w("")
    hub = sorted(mods, key=lambda m: -len(rdeps.get(m, ())))[:15]
    w("| 文件 | 被引用 |")
    w("|---|---:|")
    for m in hub:
        w(f"| `{m}` | {len(rdeps.get(m, ()))} |")
    w("")
    w("> 枢纽文件是改动的高危区：改签名要全文搜索调用方；反向引用表（§3）就是调用方清单。")
    w("")

    # ---------- 5. 附录 ----------
    w("## 5. 附录：想加一种新的漏洞检测，要动哪些文件")
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
    w("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"written: {OUT}  ({len(lines)} lines, {len(mods)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
