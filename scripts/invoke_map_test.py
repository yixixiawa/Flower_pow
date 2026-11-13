# -*- coding: utf-8 -*-
"""gen_invoke_map.py（函数级调用地图）的回归测试。

覆盖：
  1. 定义收集：模块级函数 / 类方法 / 嵌套函数，限定名与行号
  2. 精确边：同模块直调 / from-import 符号 / self.method / Module.func
  3. 模糊边：全项目唯一同名属性调用（标 ≈）；同名歧义不造边
  4. 自递归不算边；外部调用（未解析）计数
  5. 渲染：热点表 / 孤儿清单 / 分文件节 / 模糊标记出现在正文
  6. --who-calls 查询：命中子串、列出调用方与被调方

运行：.venv/Scripts/python.exe scripts/invoke_map_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.gen_invoke_map import (  # noqa: E402
    FUZZY_STOP,
    build_graph,
    render,
    who_calls,
)


def write(tmp: Path, rel: str, text: str) -> None:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


FIXTURE = {
    "pkg/__init__.py": "",
    "pkg/a.py": '''"""模块 a。"""
from pkg.b import helper

def entry():
    """入口。"""
    helper()
    return local()

def local():
    """本地函数。"""
    return entry()

def orphan_one():
    """无人调用（孤儿）。"""
''',
    "pkg/b.py": '''"""模块 b。"""
class B:
    def go(self):
        return self.step()

    def step(self):
        return 1

def helper():
    return B().go()
''',
    "pkg/c.py": '''"""模块 c：模糊边与歧义场景。"""
import os

def fuzzy_caller():
    """helper 在全项目唯一 → 模糊边。"""
    return helper()

def ambiguous():
    """name 在 a/b 都有同名 → 造不出边，但自身仍被 entry 调。"""
    return 1

def uses_builtin():
    """外部调用只计数。"""
    return os.path.join("x", "y")

def with_nested():
    """嵌套函数：作用域死在本函数内。"""
    def inner_unique():
        return 1
    return inner_unique()

def calls_nested_from_outside():
    """名字只存在于 with_nested 作用域 → 解析不出边。"""
    return inner_unique()

def self_recursive():
    """自递归不算边。"""
    return self_recursive()
''',
}


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    tmp = Path(tempfile.mkdtemp())
    for rel, text in FIXTURE.items():
        write(tmp, rel, text)

    g = build_graph(tmp)

    print("场景1 定义收集")
    check("pkg.a.entry" in g.funcs, "模块级函数按 module.name 收集")
    check("pkg.b.B.go" in g.funcs, "类方法带类链收集")
    check(g.funcs["pkg.b.B.go"].cls == "B" and g.funcs["pkg.b.B.go"].is_method,
          "方法的 cls/is_method 正确")
    check(g.funcs["pkg.a.entry"].line > 0, "记录了定义行号")

    print("场景2 精确边")
    check("pkg.b.helper" in g.calls["pkg.a.entry"],
          "from-import 符号直调 → 精确边")
    check("pkg.a.local" in g.calls["pkg.a.entry"], "同模块直调 → 精确边")
    check("pkg.a.entry" in g.calls["pkg.a.local"], "反向调用也被收集")
    check("pkg.b.B.step" in g.calls["pkg.b.B.go"], "self.method → 精确边")
    check("pkg.b.B.go" in g.calls["pkg.b.helper"], "Module 内类实例化后的属性调用")

    print("场景3 模糊边与歧义")
    check("pkg.b.helper" in g.calls["pkg.c.fuzzy_caller"],
          "全项目唯一同名 → 模糊边建立")
    check(("pkg.c.fuzzy_caller", "pkg.b.helper") in g.fuzzy, "模糊边被打上 ≈ 标记")
    check(("pkg.a.entry", "pkg.b.helper") not in g.fuzzy, "import 证据的边不算模糊")
    check(not g.calls.get("pkg.c.ambiguous"),
          "无调用方歧义函数不产生边（name 歧义时放弃）")
    check(not g.calls.get("pkg.c.calls_nested_from_outside"),
          "跨作用域调嵌套函数不造边（作用域外不可见）")
    check("pkg.c.with_nested.inner_unique" in g.funcs, "嵌套函数仍被收集（可作调用者）")
    check("pkg.c.self_recursive" not in g.calls.get("pkg.c.self_recursive", {}),
          "自递归不算边")

    print("场景4 未解析与孤儿")
    check(g.unresolved >= 1, "外部调用（os.path.join 等）计入 unresolved")
    body = render(g, tmp)
    check("orphan_one" in body, "孤儿函数出现在渲染正文")
    check("疑似死代码" in body, "孤儿清单小节存在")
    check("热点函数" in body, "热点小节存在")
    check("分文件调用关系" in body, "分文件小节存在")
    # helper 被 entry（精确）和 fuzzy_caller（模糊）调用 → 进热点
    check("| `pkg.b.helper` |" in body, "热点表列出被多次调用的函数")

    print("场景5 查询模式")
    txt = who_calls(g, "helper")
    check("pkg.a.entry" in txt and "pkg.c.fuzzy_caller" in txt,
          "who_calls 列出两类调用方")
    check("pkg.b.B.go" in txt, "who_calls 列出被调方")
    check("≈" in txt, "模糊调用方带 ≈ 标记")
    check("没有名字含" in who_calls(g, "no_such_name_xyz"), "查不到时明确提示")

    print("场景6 真实项目跑通（冒烟）")
    g2 = build_graph()
    n_pairs = sum(len(c) for c in g2.calls.values())
    check(len(g2.funcs) > 500, f"真实项目函数量合理，实={len(g2.funcs)}")
    check(n_pairs > 1000, f"真实项目调用关系量合理，实={n_pairs}")
    bad_fuzzy = [(a, b) for (a, b) in g2.fuzzy if g2.funcs[b].name in FUZZY_STOP]
    check(not bad_fuzzy, f"模糊边不含容器/IO 方法禁词，实={bad_fuzzy[:3]}")
    hot_names = {g2.funcs[q].name for q in
                 sorted(g2.callers, key=lambda x: -len(g2.callers[x]))[:10]}
    check(not hot_names & {"all", "close", "count", "index", "json"},
          f"热点前十不含典型假边名（all/close/count/index/json），实={hot_names}")
    check("pkg" not in {f.module.split('.')[0] for f in g2.funcs.values()},
          "真实项目不含测试 fixture 的包")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
