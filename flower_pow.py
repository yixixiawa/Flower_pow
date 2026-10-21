"""flower_pow —— AI Agent 驱动的 Web 漏洞扫描器 + 子域批量发现。

最快上手（推荐）::

    python flower_pow.py

不带任何参数时会先做一次**初始化体检**：探测本机能调用的外部工具
（nmap / dirsearch / nuclei…）、检查依赖与 POC 索引、必要时索要 API Key
（写入 ``.env``，不会进 git），然后直接进入与模型的流式对话——
由模型调用本机工具去拿事实，而不是靠猜。

其它用法::

    python flower_pow.py chat https://目标        # 指定目标进 Agent 会话
    python flower_pow.py chat https://目标 --classic  # 走固定剧本（无模型也能跑）
    python flower_pow.py scan http://目标         # 一次性扫描
    python flower_pow.py index                    # 重建 POC 向量索引
    python flower_pow.py pocs --grep env          # 查看 POC 库
    python flower_pow.py engines                  # 查看引擎/采集器状态
    python flower_pow.py ask http://目标#struts2   # 只做 RAG 检索，不发请求
    python flower_pow.py intel CVE-2021-44228     # 查外部 CVE 情报

⚠️ 仅用于**已获得书面授权**的目标。默认只读。

本文件只做两件事：**触发命令注册** + **调起 Typer**。
18 个命令的实现都在 :mod:`cli` 包里（无参数入口、扫描、会话、POC 库、
检索、引擎、探针、模型、子域、台账、初始化共 13 个模块）。
拆分的原因很直接：原来这个文件 2209 行，加一个命令就要在几百行的
帮助文本里翻找——而且 ``--help`` 的输出顺序由导入顺序决定，
想让命令分组就得整段整段地搬。
"""

from __future__ import annotations

# 关键：**import 即注册**。cli/__init__.py 按固定顺序导入各命令模块，
# 各模块在导入时执行 `@app.command()`，所以这里的 import 不能删、不能改顺序。
from cli import app

__all__ = ["app", "main"]


def main() -> None:
    app()


if __name__ == "__main__":
    main()
