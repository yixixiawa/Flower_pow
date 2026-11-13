"""从 ``core/repl`` 各 mixin 的源码 AST 生成 ``core/repl/_contract.py``。

为什么需要：``Repl`` 由七个 mixin + ``_ReplBase`` 多继承拼成，成员彼此分散，
而静态分析器（Pylance/pyright）解析属性时是**按单个 class 独立进行**的——它看
``_LoopMixin`` 只看到 ``object``，于是 ``self.agent_on`` / ``self.cfg`` / ``self._save``
全部报 ``Cannot access attribute ... is unknown``。运行期走的是 ``Repl`` 的 MRO 与
实例 ``__dict__``，一切正常，所以这是纯静态噪音。

本脚本把「所有 mixin 提供的成员」抽成一份只在 ``TYPE_CHECKING`` 下存在的契约类，
各 mixin 在类型检查阶段继承它：

* 运行期 ``_Base = object``，MRO 与实例行为**零改动**；
* 类型检查期签名与实现**逐字一致**，不会引入 override 不兼容。

签名不手写、全部来自 AST，因此改完代码重跑一次即可刷新——与
``scripts/gen_file_map.py`` 同一套思路。

用法::

    .venv/Scripts/python.exe scripts/gen_repl_contract.py
"""

from __future__ import annotations

import ast
import copy
import pathlib
import sys

REPL_DIR = pathlib.Path(__file__).resolve().parent.parent / "core" / "repl"
TARGET = REPL_DIR / "_contract.py"

# 契约里给实例属性补的类型（其余一律 Any）。只写确有收益的几个，
# 免得把需要收窄的地方写死成 Any 之后反而查不出问题。
ATTR_TYPES = {
    "cfg": "Config",
    "session": "Session",
    "kickoff": "bool",
    "reader": "PromptReader",
    "tools": "list",
    "probes": "list",
}


def _sig(node: ast.AST) -> str:
    """把函数节点还原成"签名 + ``...`` 体"的源码片段（保留装饰器）。

    没写返回注解的一律补 ``-> Any``：``...`` 体在静态分析里会被推成 ``None``，
    属性/方法一旦被当成 ``None``，调用处又会刷出新的 unknown 告警。
    """
    clone = copy.deepcopy(node)
    clone.body = [ast.Expr(value=ast.Constant(value=Ellipsis))]
    if clone.returns is None:
        clone.returns = ast.Name(id="Any", ctx=ast.Load())
    return ast.unparse(clone)


def _indent(text: str) -> str:
    return "\n".join("    " + line if line.strip() else line for line in text.splitlines())


def _annotation_names(func: ast.AST) -> set[str]:
    """只取**注解**里出现的名字（不看函数体——体里全是局部变量名）。"""
    names: set[str] = set()
    nodes: list[ast.AST] = []
    for arg in (
        list(getattr(func.args, "posonlyargs", []))
        + list(func.args.args)
        + list(func.args.kwonlyargs)
    ):
        if arg.annotation is not None:
            nodes.append(arg.annotation)
    for extra in (func.args.vararg, func.args.kwarg):
        if extra is not None and extra.annotation is not None:
            nodes.append(extra.annotation)
    if func.returns is not None:
        nodes.append(func.returns)
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                base: ast.AST = sub
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    names.add(base.id)
    return names


def main() -> int:
    files = sorted(
        p for p in REPL_DIR.glob("*.py")
        if p.name not in ("__init__.py", "_contract.py")
    )

    imports: dict[str, str] = {}      # 名字 -> import 语句
    members: dict[str, str] = {}      # 成员名 -> 源码片段
    attrs: dict[str, str] = {}        # 实例属性 -> 注解文本
    need: set[str] = {"TYPE_CHECKING", "Any"}
    owner: dict[str, str] = {}
    conflicts: list[str] = []

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module != "__future__":
                for alias in node.names:
                    name = alias.asname or alias.name
                    line = f"from {'.' * node.level}{node.module or ''} import {alias.name}"
                    if alias.asname:
                        line += f" as {alias.asname}"
                    imports.setdefault(name, line)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    line = f"import {alias.name}"
                    if alias.asname:
                        line += f" as {alias.asname}"
                    imports.setdefault(name, line)

        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            if not cls.name.startswith("_") or cls.name == "_ReplContract":
                continue
            for stmt in cls.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if stmt.name.startswith("__"):
                        continue  # __init__ 等由 _ReplBase 提供，不复制
                    if stmt.name in members:
                        if members[stmt.name] != _sig(stmt) and stmt.name not in conflicts:
                            conflicts.append(stmt.name)
                        continue
                    members[stmt.name] = _sig(stmt)
                    owner[stmt.name] = path.name
                    need |= _annotation_names(stmt)
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    need |= _annotation_names(stmt.annotation)
                elif isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        if (
                            isinstance(tgt, ast.Attribute)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == "self"
                        ):
                            attrs.setdefault(tgt.attr, ATTR_TYPES.get(tgt.attr, "Any"))
                elif isinstance(stmt, ast.AugAssign):
                    pass

    # 方法体里也可能出现 self.x = ...（常见于 _build_agent 之类），一并收进来
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id == "self"
            ):
                name = node.targets[0].attr
                if name.startswith("__"):
                    continue
                attrs.setdefault(name, ATTR_TYPES.get(name, "Any"))

    # 成员名与属性名撞车时以方法为准（方法优先，属性声明会被覆盖）
    for name in list(attrs):
        if name in members:
            attrs.pop(name)

    # 属性注解里的类型名同样要进 import 表（ATTR_TYPES 用的是字符串）
    for text in set(attrs.values()):
        try:
            expr = ast.parse(text, mode="eval")
        except SyntaxError:
            continue
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                need.add(sub.id)

    import builtins as _builtins

    builtin_names = set(dir(_builtins))
    unresolved = sorted(
        n for n in need
        if n not in imports and n not in {"TYPE_CHECKING", "Any"} and n not in builtin_names
    )

    used_imports = sorted(
        {line for name, line in imports.items() if name in need}
    )

    lines: list[str] = [
        '"""``_ReplContract``：mixin 的类型契约——**只在类型检查期存在**。',
        "",
        "本文件由 ``scripts/gen_repl_contract.py`` 自动生成，**不要手改**。",
        "改完 ``core/repl`` 下的代码后重跑那个脚本即可刷新。",
        "",
        "背景：``Repl`` 由七个 mixin + ``_ReplBase`` 多继承拼成，成员互相分散；",
        "静态分析器按单个 class 独立解析属性，因此各 mixin 里的 ``self.xxx`` 会被判",
        "成 unknown（运行期完全正常）。各 mixin 在类型检查阶段继承本契约即可消掉误报，",
        "运行期 ``_Base`` 仍是 ``object``，MRO 与实例行为不受影响。",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import TYPE_CHECKING, Any",
        "",
        "if TYPE_CHECKING:",
    ]
    for line in used_imports:
        lines.append(f"    {line}")
    if used_imports:
        lines.append("")
    lines.append("    class _ReplContract:")
    # ast.unparse 产出的函数片段本身就相对列 0（体缩进 4 空格），
    # 整块再统一缩进 4 格就落进 class 体内。
    body: list[str] = []
    for name in sorted(attrs):
        body.append(f"{name}: {attrs[name]}")
    if attrs and members:
        body.append("")
    for name in sorted(members):
        body.append(members[name])
        body.append("")
    for chunk in body or ["pass"]:
        for piece in chunk.splitlines():
            lines.append(f"        {piece}" if piece.strip() else "")
    lines.append("")

    TARGET.write_text("\n".join(lines), encoding="utf-8")

    print(f"已生成 {TARGET.relative_to(TARGET.parent.parent.parent)}")
    print(f"  成员（方法/属性）: {len(members)}   实例属性: {len(attrs)}   导入: {len(used_imports)}")
    if unresolved:
        print(f"  [!] 注解里出现但没找到 import 的名字：{unresolved}")
    if conflicts:
        print(f"  [!] 同名不同签名的成员（取首个）：{conflicts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
