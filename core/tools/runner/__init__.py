r"""工具执行器——把模型的 tool_call 变成真实动作。

安全边界（这一层是唯一的安全边界）
----------------------------------
模型可以要求执行任何东西，所以**所有约束都必须落在这里**，不能指望
提示词里那句"请勿越权"。三条闸门：

1. **只读模式**。``readonly=true`` 时 ``intrusive`` 类工具（sqlmap、hydra、
   nikto、masscan）一律不执行。这不是"提示"，是直接拒绝执行。
2. **参数白名单**。外部工具只接受注册表里声明过的选项，写文件类选项
   （``-o`` / ``-O`` / ``--output``）全部不在白名单里。
3. **不用 shell**。``subprocess`` 一律传 argv 数组、``shell=False``。
   没有 shell 就没有重定向、管道、命令替换——参数里的 ``&`` ``|`` 只是
   普通字符（URL 查询串本来就带``&``，误拦反而会挡掉正常请求）。

另有一道与白名单无关的兜底：**外部工具参数里的文件路径必须位于项目目录内
且存在**，防止模型把 ``-o C:\Windows\...`` 之类当成"某个选项漏了白名单"的缺口。

为什么不用 shell=True + 黑名单：黑名单永远漏。argv 直传是结构性免疫。

模块分派
--------
======================  ==========================================================
``base``                骨架：常量 / 初始化 / ``execute`` / ``_spill`` /
                        编排 / 会话合并（唯一的安全边界）
``recon``               侦察类 handler（http_request、recon_*、js_audit...）
``intel``               检索类 handler（rag_search、poc_list、cve_intel）
``verify``              业务与验证类 handler（login、authz_probe、run_pipeline）
``report``              发现台账 handler（findings、dismiss_finding...）
``evidence``            证据登记 handler（record_finding、backfill_evidence）
``export``              报告导出 handler（export_report）
``files``               文件操作 handler（read_file、write_file...）
``external``            外部 CLI 执行与 argv 闸门
======================  ==========================================================

:class:`ToolRunner` 由上述 mixin 多继承组装。对外只需要知道这一个名字：
``from core.tools import ToolRunner``。
"""

from __future__ import annotations

from core.tools.runner.base import MAX_TOOL_OUTPUT, ToolBlocked, _ToolRunnerBase
from core.tools.runner.evidence import EvidenceMixin
from core.tools.runner.export import ExportMixin
from core.tools.runner.external import ExternalMixin
from core.tools.runner.files import FileMixin
from core.tools.runner.intel import IntelMixin
from core.tools.runner.recon import ReconMixin
from core.tools.runner.report import FindingMixin
from core.tools.runner.verify import VerifyMixin


class ToolRunner(
    ReconMixin,
    IntelMixin,
    VerifyMixin,
    FindingMixin,
    EvidenceMixin,
    ExportMixin,
    FileMixin,
    ExternalMixin,
    _ToolRunnerBase,
):
    """内置工具 + 外部进程的统一执行入口。

    各职责见同级模块；本类只把它们拼在一起，不新增任何实现。
    ``ToolRunner.dismiss`` / ``ToolRunner.resolve_finding`` 是类方法，
    供 ``/fp`` 与 CLI 直接复用同一套发现寻址逻辑。
    """


__all__ = ["ToolRunner", "ToolBlocked", "MAX_TOOL_OUTPUT"]
