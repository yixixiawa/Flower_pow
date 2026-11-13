"""flower_pow 的 MCP 壳——把扫描能力暴露成 MCP 工具，供 WorkBuddy / Claude 等客户端接入。

为什么单独一个包，而不是塞进 ``cli/``
------------------------------------
CLI 是"一次性命令 + 终端打印"，MCP 是"常驻进程 + 结构化返回 + 任务状态机"。
两种生命周期硬塞在一起会带来两个后果：``cli`` 的导入链背上 mcp 依赖（没装 mcp
的人连 ``--help`` 都跑不起来），命令表里多出一堆只对 server 有意义的入口。
所以这里单独成包，``cli/mcpsrv.py`` 只负责挂一个 ``mcp`` 子命令。

依赖是**可选**的
----------------
``mcp`` 不在主依赖里（主程序刻意保持 7 个直接依赖）。没装时 ``import mcp_server``
不报错，只有真正启动 server 才提示缺什么、怎么装：

    .venv/Scripts/python.exe -m pip install "mcp>=2"

本包的文件分工
--------------
=====================  ==========================================================
``services``           纯函数层：配置加载、结果序列化、POC / 知识库 / 会话查询
``jobs``               后台扫描任务：起线程跑 Scheduler，可轮询、可取消
``server``             MCPServer 实例、工具声明、``main()`` 启动入口
=====================  ==========================================================
"""

from __future__ import annotations

__all__ = ["main", "__version__"]

__version__ = "0.1.0"


def main(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8765) -> None:
    """启动 MCP Server（转发到 :func:`mcp_server.server.main`）。"""
    from mcp_server.server import main as _serve

    _serve(transport=transport, host=host, port=port)
