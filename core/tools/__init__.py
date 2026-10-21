"""工具层：注册表 + 执行器。

这个扫描器的价值不在于"自己重新实现了多少检测逻辑"，而在于**把机器上
已经存在的能力组织起来**。本包就是那层组织：

* 声明"有哪些工具"——内置（:mod:`~core.tools.builtins`）与外部
  （:mod:`~core.tools.external`）收敛成同一套 JSON Schema
* 探测"这台机器实际能调用什么"——:mod:`~core.tools.probe`
* 归一"模型给的参数"——:mod:`~core.tools.args`
* 执行"模型要求的动作"并且**只在那里设闸门**——:mod:`~core.tools.runner`

模块分派
--------
======================  ====================================================
``catalog`` 概览         本模块的公开导出（``from core.tools import ...``）
``external``            外部 CLI 的声明 + 内置清单 + ``data/tools.local.yaml``
``builtins``            内置能力声明表（:data:`~core.tools.builtins.BUILTINS`）
``probe``               探测（PATH / 版本 / 依赖）与环境体检报告
``args``                参数类型归一 + 喂给 LLM 的 schema 生成
``wordlist``            内置字典导出成文件（外部工具需要 ``-w``）
``pathscan``            PATH 可执行文件清点与"未登记"差集
``runner/``             :class:`~core.tools.runner.ToolRunner`——唯一的安全边界
======================  ====================================================

对外只暴露这一层：调用方写 ``from core.tools import ToolRunner``，
不必知道某个东西住在哪个子模块里。
"""


from __future__ import annotations

from core.tools.args import (
    describe_externals,
    llm_schemas,
    normalize_args,
    spec_for,
    tool_help_text,
)
from core.tools.builtins import BUILTINS, BuiltinTool
from core.tools.external import (
    EXTERNAL_TOOLS,
    USER_TOOLS_FILE,
    ExternalTool,
    all_external_tools,
    load_user_tools,
    write_user_tools_template,
)
from core.tools.pathscan import scan_path_executables, unregistered_executables
from core.tools.probe import (
    BUILTIN_DEPS,
    DepStatus,
    EnvReport,
    Probe,
    probe_deps,
    probe_external,
)
from core.tools.runner import MAX_TOOL_OUTPUT, ToolBlocked, ToolRunner
from core.tools.wordlist import wordlist_path, write_wordlist


__all__ = [
    # 外部工具
    "ExternalTool", "EXTERNAL_TOOLS", "USER_TOOLS_FILE",
    "load_user_tools", "all_external_tools", "write_user_tools_template",
    # 内置工具
    "BuiltinTool", "BUILTINS", "spec_for",
    # 探测与体检
    "Probe", "DepStatus", "EnvReport", "BUILTIN_DEPS",
    "probe_external", "probe_deps",
    # 参数与 schema
    "normalize_args", "llm_schemas", "describe_externals", "tool_help_text",
    # 字典
    "wordlist_path", "write_wordlist",
    # PATH 发现
    "scan_path_executables", "unregistered_executables",
    # 执行器
    "ToolRunner", "ToolBlocked", "MAX_TOOL_OUTPUT",
]
