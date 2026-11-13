# -*- coding: utf-8 -*-
"""生成 INVOKE_MAP.md：函数级调用关系图（谁调用谁，AST 静态解析）。

FILE_MAP.md 回答"文件之间谁 import 谁"；本脚本往下钻一层，回答
"**函数/方法之间谁调用谁**"——改签名前查调用方、排查死代码、看热点
枢纽函数，都用这份。

解析方式（纯静态，不执行代码）
------------------------------
1. 收集全部函数/方法定义（含类内方法与嵌套函数），限定名形如
   ``core.tools.runner.files.FileMixin._h_write_file``。
2. 走每个函数体内的 ``ast.Call``，把调用点解析回项目内定义：
   * **精确边**：
     - 同模块函数直接按名命中（``local()``）；
     - ``from core.x import y`` 的符号表（``helper()`` → core.x.helper）；
     - ``self.method()`` → 本类方法；本模块内有同名方法时退而命中本模块；
     - ``Module.func()`` → import 表指到目标模块的模块级函数。
   * **模糊边**（标记 ``≈``）：属性名/名字恰好与全项目**唯一**一个定义同名，
     但没有可证的 import/self 证据。是线索不是结论。
   * 同名定义多于一个且无更强证据时**直接放弃**——宁可少一条边，不造假边。
3. 动态派发（``getattr``、框架回调、detector 的多态 ``verify()``、CLI 的
   typer 入口）静态分析天然看不见，报告中这些会显示为"无调用方"，
   §2 孤儿清单已剔除方法与脚本入口，但读表时要心里有数。

用法
----
    python scripts/gen_invoke_map.py                     # 生成 INVOKE_MAP.md（根目录 + doc/auxiliary/）
    python scripts/gen_invoke_map.py --who-calls verify  # 查：谁调用名字含 verify 的函数 / 它调用谁
"""
from __future__ import annotations

import ast
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "doc" / "auxiliary" / "INVOKE_MAP.md"
OUT_ROOT = ROOT / "INVOKE_MAP.md"

TOP_PKGS = {"core", "cli", "collectors", "detectors", "kb", "llm",
            "output", "scripts", "poc", "flower_pow", "mcp_server"}

SKIP_DIRS = {".venv", ".git", ".backup", ".workbuddy", "data",
             "reports", "doc", "docs", "__pycache__", ".pytest_cache"}

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef

# 模糊解析的**禁词**：这些名字同时是 Python 内置类型/容器/IO 的常见方法
# （``.all()``、``.close()``、``str.count()``、``list.index()``、``.json()``…）。
# 它们做**精确**解析（self/import/同模块）不受影响；但走"全项目唯一同名"
# 的模糊通道时全是假边——热点表曾被 JobRegistry.all（实为 set.all()）、
# Authenticator.close（实为文件句柄 close()）污染。模糊通道直接跳过。
FUZZY_STOP: frozenset[str] = frozenset({
    "all", "any", "close", "count", "index", "keys", "values", "items",
    "get", "set", "add", "update", "pop", "join", "split", "strip",
    "lstrip", "rstrip", "format", "json", "copy", "clear", "read",
    "write", "open", "exists", "next", "find", "filter", "group",
    "run", "start", "stop", "walk", "log", "name", "load", "loads",
    "dump", "dumps", "seek", "tell", "flush", "send", "recv",
    "connect", "bind", "listen", "sleep", "wait", "text", "content",
    "key", "value", "url", "path", "iter", "items_values",
})


@dataclass
class Func:
    """项目内一个函数/方法定义。"""

    qname: str            # core.tools.runner.files.FileMixin._h_write_file
    module: str
    name: str
    cls: str | None       # 所属类名（模块级函数为 None）
    file: str             # 相对根目录的 posix 路径
    line: int
    is_method: bool       # 类方法（嵌套函数不算）
    nested: bool = False  # 定义在另一个函数体内——作用域死在函数内

    @property
    def short(self) -> str:
        """显示用：类名.方法名（带模块会被表头行盖掉，缩短一截）。"""
        return f"{self.cls}.{self.name}" if self.cls else self.name


@dataclass
class Graph:
    funcs: dict[str, Func]                        # qname -> Func
    calls: dict[str, dict[str, int]]              # caller -> callee -> 调用点数
    callers: dict[str, set[str]]                  # callee <- 调用方集合
    fuzzy: set[tuple[str, str]]                   # 模糊边 (caller, callee)
    unresolved: int = 0                           # 解析失败的调用点数（诊断用）


# ── 定义收集 ──────────────────────────────────────────────────────

def iter_py(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        out.append(p)
    return out


def module_name(root: Path, p: Path) -> str:
    rel = p.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def collect_defs(tree: ast.Module, module: str, file: str
                 ) -> tuple[dict[str, Func], dict[str, FuncNode]]:
    """收集模块内全部函数定义。返回 (qname -> Func, qname -> AST 节点)。

    类链（``cls_chain``）与函数链（``func_chain``）**分开记**：把函数链混进
    类链会把"函数里定义的函数"误判成方法（首版就栽在这——嵌套函数拿到的
    depth 与真方法一样，``nested`` 判定全部失效）。
    """
    funcs: dict[str, Func] = {}
    nodes: dict[str, FuncNode] = {}

    def walk(body, cls_chain: tuple[str, ...], func_chain: tuple[str, ...]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qname = ".".join([module, *cls_chain, *func_chain, node.name])
                funcs[qname] = Func(
                    qname=qname, module=module, name=node.name,
                    cls=cls_chain[-1] if cls_chain else None,
                    file=file, line=node.lineno,
                    is_method=bool(cls_chain) and not func_chain,
                    nested=bool(func_chain),
                )
                nodes[qname] = node
                walk(node.body, cls_chain, func_chain + (node.name,))
            elif isinstance(node, ast.ClassDef):
                walk(node.body, cls_chain + (node.name,), func_chain)

    walk(tree.body, (), ())
    return funcs, nodes


# ── import 符号表（项目内）────────────────────────────────────────

def import_symbols(path: Path, module: str, root: Path = ROOT) -> dict[str, str]:
    """本项目内部 import 的局部名 -> 目标（符号全路径或模块名）。

    ``from core.x import y as z`` → ``z: "core.x.y"``；
    ``import core.x.y as w`` → ``w: "core.x.y"``。

    "本项目内部"的判定：顶层名在 :data:`TOP_PKGS` 里，**或者** root 下真的
    存在同名目录/文件——只认写死的 TOP_PKGS 清单会漏掉根目录新增的包
    （测试 fixture 的 ``pkg`` 首版就这么被跳过，import 全空、精确边退化成模糊边）。
    """
    def _is_internal(top: str) -> bool:
        if top in TOP_PKGS:
            return True
        return (root / top).is_dir() or (root / f"{top}.py").is_file()

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return {}
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if not _is_internal(top):
                    continue
                if a.asname:
                    out[a.asname] = a.name
                else:
                    # import core.x → 局部名是 core，指到 core（属性调用兜底用）
                    out[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:  # 相对导入
                base = module.split(".")
                base = base[: len(base) - node.level]
                target = ".".join(base + (node.module or "").split("."))
            else:
                target = node.module or ""
            if not _is_internal(target.split(".")[0]):
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                # from pkg.b import helper → "pkg.b.helper"（符号全路径，
                # 也可能是子模块：from pkg import mod → "pkg.mod"）
                out[a.asname or a.name] = f"{target}.{a.name}"
    return out


# ── 调用点解析 ────────────────────────────────────────────────────

class Resolver:
    """把 ``ast.Call`` 解析回项目内定义。宁可漏，不可错。"""

    def __init__(self, funcs: dict[str, Func]) -> None:
        self.funcs = funcs
        # 名字索引只收**顶层定义**（模块级函数 + 类方法）。嵌套函数的作用域
        # 死在定义它的函数体内，别人调不到——参与全局同名匹配只会造假边。
        self.by_name: dict[str, list[str]] = defaultdict(list)
        self.nested_by_name: dict[str, list[str]] = defaultdict(list)
        for q, f in funcs.items():
            (self.nested_by_name if f.nested else self.by_name)[f.name].append(q)
        self.module_funcs: dict[str, dict[str, str]] = defaultdict(dict)
        for q, f in funcs.items():
            if not f.is_method and not f.nested:
                self.module_funcs[f.module].setdefault(f.name, q)

    def _unique_or_same_module(self, name: str, module: str) -> list[str]:
        cands = self.by_name.get(name, [])
        if not cands:
            return []
        if len(cands) == 1:
            return cands
        same = [q for q in cands if self.funcs[q].module == module]
        return same  # 同模块有就用同模块的；没有就放弃（同名歧义不造边）

    def resolve(self, call: ast.Call, module: str, cls: str | None,
                imports: dict[str, str],
                caller: str = "") -> list[tuple[str, str]]:
        """返回 [(callee_qname, kind)]，kind ∈ exact/self/fuzzy。"""
        f = call.func
        if isinstance(f, ast.Name):
            n = f.id
            # ① 同模块模块级函数
            hit = self.module_funcs.get(module, {}).get(n)
            if hit:
                return [(hit, "exact")]
            # ② import 符号表：from core.x import y → y() 即 core.x.y()
            #    符号表里存的是**符号全路径**（"pkg.b.helper"），它本身可能是
            #    "模块.符号"（from pkg.b import helper）也可能是"子模块"
            #    （from pkg import mod）——两种都试：先整串当模块名查，
            #    再剥掉最后一段当来源模块查。
            tgt_mod = imports.get(n)
            if tgt_mod:
                for cand_mod in (tgt_mod, tgt_mod.rsplit(".", 1)[0]):
                    hit = self.module_funcs.get(cand_mod, {}).get(n)
                    if hit:
                        return [(hit, "exact")]
            # ③ 同作用域的嵌套函数：callee 是 caller 限定名的直接子级
            #    （def outer(): def inner(): ... inner() → outer.inner）
            if caller:
                for q in self.nested_by_name.get(n, ()):
                    if q.startswith(caller + "."):
                        return [(q, "exact")]
            # ④ 全项目唯一同名 → 模糊边（禁词除外）
            cands = self.by_name.get(n, [])
            if len(cands) == 1 and n not in FUZZY_STOP:
                return [(cands[0], "fuzzy")]
            return []

        if isinstance(f, ast.Attribute):
            attr = f.attr
            if attr.startswith("__") and attr.endswith("__"):
                return []
            cands = self.by_name.get(attr, [])
            if not cands:
                return []
            # ① self.method() → 优先本类，退到本模块
            if isinstance(f.value, ast.Name) and f.value.id == "self" and cls:
                own = [q for q in cands
                       if self.funcs[q].module == module and self.funcs[q].cls == cls]
                if own:
                    return [(q, "self") for q in own]
                same = [q for q in cands if self.funcs[q].module == module]
                if same:
                    return [(q, "self") for q in same]
            # ② Module.func()：value 是 import 表里的模块名
            if isinstance(f.value, ast.Name):
                tgt_mod = imports.get(f.value.id)
                if tgt_mod:
                    hit = self.module_funcs.get(tgt_mod, {}).get(attr)
                    if hit:
                        return [(hit, "exact")]
            # ③ 全项目唯一同名 → 模糊边（属性链太常见，唯有唯一才敢连；
            #    容器/IO 方法名禁词直接放弃——.close()/.count() 这类假边雪崩）
            if len(cands) == 1 and attr not in FUZZY_STOP:
                return [(cands[0], "fuzzy")]
            return []

        return []


def build_graph(root: Path = ROOT) -> Graph:
    files = iter_py(root)
    funcs: dict[str, Func] = {}
    nodes: dict[str, FuncNode] = {}
    trees: dict[str, ast.Module] = {}
    mod_of: dict[str, str] = {}
    file_of: dict[str, str] = {}
    imports: dict[str, dict[str, str]] = {}
    for p in files:
        mod = module_name(root, p)
        mod_of[mod] = mod
        file_of[mod] = p.relative_to(root).as_posix()
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        trees[mod] = tree
        f, n = collect_defs(tree, mod, file_of[mod])
        funcs.update(f)
        nodes.update(n)
        imports[mod] = import_symbols(p, mod, root)

    r = Resolver(funcs)
    calls: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    callers: dict[str, set[str]] = defaultdict(set)
    fuzzy: set[tuple[str, str]] = set()
    unresolved = 0

    for qname, fn in nodes.items():
        f = funcs[qname]
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            hits = r.resolve(node, f.module, f.cls, imports.get(f.module, {}),
                             caller=qname)
            if not hits:
                # 调用了名字，但解析不出项目内定义（内置/外部库/歧义）
                if isinstance(node.func, (ast.Name, ast.Attribute)):
                    unresolved += 1
                continue
            for callee, kind in hits:
                if callee == qname:
                    continue  # 自递归不算关系边
                calls[qname][callee] += 1
                callers[callee].add(qname)
                if kind == "fuzzy":
                    fuzzy.add((qname, callee))
    return Graph(funcs=funcs, calls=calls, callers=callers,
                 fuzzy=fuzzy, unresolved=unresolved)


# ── 渲染 ─────────────────────────────────────────────────────────

def render(g: Graph, root: Path = ROOT) -> str:
    lines: list[str] = []
    w = lines.append

    n_edges = sum(sum(c.values()) for c in g.calls.values())
    n_pairs = sum(len(c) for c in g.calls.values())
    w("# flower_pow 调用地图（函数级：谁调用谁）")
    w("")
    w("> **本文件由 `scripts/gen_invoke_map.py` 自动生成**，纯 AST 静态解析，")
    w("> 正文不含手写描述，改完代码重跑一次即可刷新。")
    w("")
    w(f"共 **{len(g.funcs)}** 个函数/方法定义，解析出 **{n_pairs}** 条调用关系"
      f"（{n_edges} 个调用点），其中模糊边 **{len(g.fuzzy)}** 条（标 `≈`）。")
    w("")
    w("> 记法：`mod.Class.method` / `mod.func`；`A ≈ B` 表示 B 是全项目唯一同名"
      "> 定义但无可证的 import/self 证据，是**线索不是结论**。")
    w("> **动态派发看不见**：`getattr`、typer 回调、detector 多态 `verify()`、")
    w("> runner 的 `_h_*` 分发都走运行时绑定，静态分析显示为\"无调用方\"属正常。")
    w("")

    # ── §1 热点 ──
    w("## 1. 热点函数（被调用最多 20）")
    w("")
    w("改动这些函数的签名要全文核对调用方——下面第二列就是清单。")
    w("")
    w("| 函数 | 调用方数 | 调用方 |")
    w("|---|---:|---|")
    hot = sorted(g.callers, key=lambda q: -len(g.callers[q]))[:20]
    for q in hot:
        cs = sorted(g.callers[q])
        w(f"| `{q}` | {len(cs)} | " + "、".join(f"`{c}`" for c in cs[:6])
          + (f" 等 {len(cs)} 个" if len(cs) > 6 else "") + " |")
    w("")

    # ── §2 孤儿 ──
    w("## 2. 无调用方的模块级函数（疑似死代码）")
    w("")
    w("只列**模块级函数**（方法大量走动态派发，不在此列；`scripts/` 测试入口、")
    w("生成器脚本与 `main` 不算孤儿）。列出前先确认不是被动态调用。")
    w("")
    orphans = [
        q for q, f in sorted(g.funcs.items())
        if (not f.is_method and not g.callers.get(q)
            and not f.name.startswith("_") and f.name not in ("main",)
            and f.module.split(".")[0] != "scripts"
            and not f.file.startswith("Code/"))
    ]
    if orphans:
        for q in orphans:
            w(f"- `{q}`（`{g.funcs[q].file}:{g.funcs[q].line}`）")
    else:
        w("（无）")
    w("")

    # ── §3 分文件调用关系 ──
    w("## 3. 分文件调用关系")
    w("")
    w("每个函数两行：`← 调用方`（谁调它）/ `→ 被调`（它调谁，含 `≈` 模糊边）。")
    w("只列**至少有一条边**的函数；一个边都没有的不占版面。")
    w("")

    by_file: dict[str, list[str]] = defaultdict(list)
    for q, f in g.funcs.items():
        if g.calls.get(q) or g.callers.get(q):
            by_file[f.file].append(q)

    pkg_of = lambda fp: fp.split("/")[0] if "/" in fp else "(根目录)"
    order = ["flower_pow.py", "cli", "mcp_server", "core", "collectors",
             "detectors", "kb", "llm", "output", "scripts", "Code", "(根目录)"]
    PKG_TITLE = {
        "(根目录)": "根目录", "Code": "Code/（批量检测驱动）",
    }

    for pkg in sorted({pkg_of(fp) for fp in by_file},
                      key=lambda p: order.index(p) if p in order else 99):
        files_in = sorted(fp for fp in by_file if pkg_of(fp) == pkg)
        title = PKG_TITLE.get(pkg, pkg + "/")
        total = sum(len(by_file[fp]) for fp in files_in)
        w(f"### {title}（{len(files_in)} 个文件 / {total} 个有调用关系的函数）")
        w("")
        for fp in files_in:
            w(f"#### `{fp}`")
            w("")
            for q in sorted(by_file[fp]):
                f = g.funcs[q]
                ins = sorted(g.callers.get(q, ()))
                outs = sorted(g.calls.get(q, ()))
                w(f"- **`{q}`**（L{f.line}）")
                if ins:
                    w("  - ← " + "、".join(
                        f"`{c}`" + (" ≈" if (c, q) in g.fuzzy else "") for c in ins))
                else:
                    w("  - ← （无静态调用方——入口/动态派发/孤儿）")
                if outs:
                    w("  - → " + "、".join(
                        f"`{c}`" + (" ≈" if (q, c) in g.fuzzy else "")
                        for c in outs))
        w("")

    return "\n".join(lines) + "\n"


# ── 查询模式 ─────────────────────────────────────────────────────

def who_calls(g: Graph, needle: str) -> str:
    """名字含 needle 的函数：谁调用它 / 它调用谁。"""
    hits = [q for q in sorted(g.funcs) if needle.lower() in q.lower()]
    if not hits:
        return f"项目内没有名字含 {needle!r} 的函数/方法"
    out = []
    for q in hits:
        f = g.funcs[q]
        ins = sorted(g.callers.get(q, ()))
        outs = sorted(g.calls.get(q, ()))
        out.append(f"{q} （{f.file}:{f.line}）")
        out.append("  ← 被谁调用：" + (
            "、".join(f"{c}" + (" ≈" if (c, q) in g.fuzzy else "") for c in ins)
            or "（无静态调用方）"))
        out.append("  → 调用了谁：" + (
            "、".join(f"{c}" + (" ≈" if (q, c) in g.fuzzy else "") for c in outs)
            or "（无项目内调用）"))
    return "\n".join(out)


def main(argv: list[str]) -> int:
    query = None
    if "--who-calls" in argv:
        i = argv.index("--who-calls")
        if i + 1 >= len(argv):
            print("用法：--who-calls <函数名（支持子串）>")
            return 2
        query = argv[i + 1]
    g = build_graph(ROOT)
    if query:
        print(who_calls(g, query))
        return 0
    body = render(g, ROOT)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(body, encoding="utf-8")
    OUT_ROOT.write_text(body, encoding="utf-8")
    n_pairs = sum(len(c) for c in g.calls.values())
    print(f"written: {OUT}")
    print(f"written: {OUT_ROOT}  ({len(g.funcs)} 函数, {n_pairs} 条调用关系, "
          f"{len(g.fuzzy)} 模糊, {g.unresolved} 未解析调用点)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
