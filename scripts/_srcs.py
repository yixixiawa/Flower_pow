"""源码读取助手——供「源码里有没有 X」这类静态断言使用。

拆包前，一个模块就是一个 ``.py`` 文件，测试直接读它就行。拆成包之后
（``core/scheduler.py`` → ``core/scheduler/*.py``）继续按文件路径读会
FileNotFoundError；如果改成只读门面，又会变成**假通过**——门面只剩
几十行装配，断言「这里面的源码包含 X」根本看不到真正的实现。

所以统一走 :func:`module_source`：给包名就把包内全部模块拼起来，
给文件路径就照旧读取。两种形态对调用方是同一个函数。

本模块以 ``_`` 开头且不带 ``_test`` 后缀，不会被 run_tests.py 收集。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def module_source(dotted: str) -> str:
    """``core.scheduler`` → 该模块源码全文。

    单文件读文件；包则把包内全部 ``.py`` 按文件名顺序拼起来。
    """
    p = ROOT / dotted.replace(".", "/")
    single = p.with_suffix(".py")
    if single.is_file():
        return single.read_text(encoding="utf-8")
    if p.is_dir():
        return "\n".join(f.read_text(encoding="utf-8") for f in sorted(p.glob("*.py")))
    raise FileNotFoundError(f"{dotted} 既不是 .py 也不是包目录：{p}")


def cli_source() -> str:
    """入口装配 + ``cli/`` 包全部源码。"""
    parts = [(ROOT / "flower_pow.py").read_text(encoding="utf-8")]
    for p in sorted((ROOT / "cli").glob("*.py")):
        parts.append(p.read_text(encoding="utf-8"))
    return "\n".join(parts)
