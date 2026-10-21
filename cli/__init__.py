"""CLI 装配层——只负责「按顺序导入各命令模块」。

各命令模块在**导入时**用 ``@app.command()`` 把命令注册到 :data:`cli.app.app` 上。
所以：

1. :mod:`cli.app` 必须最先导入（它定义 ``app`` 本身）；
2. 下面这些 import 的**顺序就是** ``flower_pow --help`` 里的命令显示顺序——
   想改显示顺序改这里，别去动各模块。

各模块职责
==========
=====================  ==========================================================
``app``      Typer 应用对象 + 全局控制台（``console`` / ``err``）
``boot``     无参入口：体检 → 要 Key → 进对话
``scan``     一次性完整扫描
``chat``     交互式会话（含 ``--classic`` 固定剧本）
``kb``       ``index`` / ``knowledge`` / ``pocs``
``ask``      ``ask`` / ``intel``
``engines``  ``engines`` / ``jsaudit``
``probe``    ``exploit`` / ``tools`` / ``discover``
``models``   模型清单与切换
``subs``     子域批量发现与下探
``ledger``   ``sessions`` / ``findings`` / ``proxy``
``initcmd``  生成 ``.env`` 模板
``summary``  扫描结果摘要打印
=====================  ==========================================================
"""

from __future__ import annotations

from cli.app import app, console, err

# ↓ 顺序即 --help 的显示顺序，不要重排
from cli import boot  # noqa: E402,F401  —— 无参入口（@app.callback）
from cli import scan  # noqa: E402,F401
from cli import chat  # noqa: E402,F401
from cli import kb  # noqa: E402,F401
from cli import ask  # noqa: E402,F401
from cli import engines  # noqa: E402,F401
from cli import probe  # noqa: E402,F401
from cli import models  # noqa: E402,F401
from cli import subs  # noqa: E402,F401
from cli import ledger  # noqa: E402,F401
from cli import initcmd  # noqa: E402,F401
from cli import summary  # noqa: E402,F401

__all__ = ["app", "console", "err"]
