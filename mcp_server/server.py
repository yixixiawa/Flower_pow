"""MCPServer 实例、工具声明与启动入口。

设计取舍
--------
* **工具全部同步**：扫描本身已经拆成后台任务，工具只需要"起任务 / 查状态"，
  几百毫秒就返回；用 async 反而要在 MCP 的事件循环里再开线程，得不偿失。
* **返回 dict**：客户端能拿到结构化结果，同时 SDK 会自动附一份文本表示，模型两侧都能读。
* **不打印**：stdout 是协议通道。所有诊断都用返回值表达。
* **工具名不加前缀**：MCP 客户端本来就会按 server 名分组，再加 ``fp_`` 只是噪音。

工具清单
--------
=================  ==========================================================
``doctor``         环境体检（依赖 / 外部工具 / POC 库 / 索引 / 代理 / 只读）
``poc_list``       POC 清单，可按语义检索
``poc_show``       单条 POC 全文（含原始 YAML）
``kb_search``      POC 库 + 沉淀知识双路召回
``sessions``       最近会话快照
``findings``       某个会话的发现清单
``scan_start``     起一次扫描（立即返回 job_id）
``scan_status``    查任务状态、进度日志与结果
``scan_cancel``    取消任务
``report``         把已完成任务的报告落盘
=================  ==========================================================
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_server import __version__
from mcp_server.jobs import JobRegistry
from mcp_server.services import (
    doctor as _doctor,
    kb_search as _kb_search,
    load_cfg,
    poc_list as _poc_list,
    poc_show as _poc_show,
    session_findings as _session_findings,
    sessions as _sessions,
)

JOBS = JobRegistry()

server = MCPServer(
    name="flower_pow",
    title="flower_pow 漏洞扫描器",
    version=__version__,
    instructions=(
        "flower_pow 是 Web 漏洞扫描器（侦察 → RAG 召回规则 → 验证 → LLM 研判 → 报告）。\n"
        "典型流程：`doctor` 看清环境 → `scan_start` 起任务拿 job_id → "
        "`scan_status` 轮询（扫描是分钟级后台任务，**不要在一次调用里等结果**）→ "
        "`findings` 看命中 → `report` 落盘。\n"
        "`poc_list` / `poc_show` / `kb_search` 用来了解「这个目标有什么可测的」。\n"
        "扫描默认只读（scan.readonly=true），写操作类探针需要用户在配置里显式放开。"
    ),
)


# ── 体检与知识 ────────────────────────────────────────────────────


@server.tool()
def doctor(config: str = "") -> dict[str, Any]:
    """环境体检：依赖、外部工具、POC 库与向量索引、代理、只读模式。

    第一次接入或扫描结果异常时先跑这个：90% 的"扫不出东西"是 Key 缺失、索引过期、
    或者目标被代理挡住。不会返回 API Key 本身，只说明有没有配置。
    """
    return _doctor(load_cfg(config))


@server.tool()
def poc_list(query: str = "", limit: int = 40, config: str = "") -> dict[str, Any]:
    """列出 POC 规则库；传 query 时按语义相关度检索。

    - 不传 query：按危害等级排序，看库里有什么。
    - 传 query（如 "spring actuator 未授权"）：走向量召回，看针对某类目标该跑什么。
    """
    return _poc_list(load_cfg(config), query=query, limit=max(1, int(limit)))


@server.tool()
def poc_show(poc_id: str, config: str = "") -> dict[str, Any]:
    """查看单条 POC 的完整定义与原始 YAML。

    排查"这条规则为什么没命中"时用它：看 request 路径、match 条件、intrusive 标记。
    """
    return _poc_show(load_cfg(config), poc_id)


@server.tool()
def kb_search(query: str, k: int = 8, config: str = "") -> dict[str, Any]:
    """同时检索 POC 库与历史沉淀知识。

    POC 侧回答"有什么规则可跑"，knowledge 侧回答"这个站上次测出过什么"。
    写扫描计划前先查一次，能省掉大量重复劳动。
    """
    return _kb_search(load_cfg(config), query, k=max(1, int(k)))


# ── 会话与发现 ────────────────────────────────────────────────────


@server.tool()
def sessions(limit: int = 10, config: str = "") -> dict[str, Any]:
    """最近的会话快照（每次扫描/对话结束都会落一份），用于回溯历史结果。

    每条含标题、目标、阶段、更新时间（epoch + 文本）、对话轮数与发现/资产数，
    便于挑选要恢复/复查的那一次。``limit<=0`` 表示返回全部。
    """
    return _sessions(load_cfg(config), limit=int(limit))


@server.tool()
def findings(session_id: str = "", limit: int = 60, config: str = "") -> dict[str, Any]:
    """某个会话的发现清单；不传 session_id 时取最新一次。

    返回按危害排序的发现摘要（含 matched_at、研判理由、是否被误报排除）。
    """
    return _session_findings(load_cfg(config), session_id=session_id, limit=max(1, int(limit)))


# ── 扫描任务 ──────────────────────────────────────────────────────


@server.tool()
def scan_start(
    target: str,
    top_k: int = 0,
    no_ai: bool = False,
    no_rag: bool = False,
    save_evidence: bool = False,
    config: str = "",
) -> dict[str, Any]:
    """起一次扫描，**立即返回 job_id**，用 scan_status 轮询。

    参数：
    - target：目标 URL，可省略协议头（自动补 http://）
    - top_k：RAG 召回条数，0 = 用配置默认
    - no_ai / no_rag：临时关闭 LLM 研判 / RAG 召回（省钱、排障用）
    - save_evidence：把命中项的原始请求响应落盘到 output/evidence/
    """
    t = (target or "").strip()
    if not t:
        return {"error": "target 不能为空"}
    try:
        job = JOBS.start(
            t,
            config=config,
            top_k=top_k,
            no_ai=no_ai,
            no_rag=no_rag,
            save_evidence=save_evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "job_id": job.job_id,
        "target": job.target,
        "state": job.state,
        "next": f"用 scan_status(job_id='{job.job_id}') 轮询，通常每 10–30 秒看一次",
    }


@server.tool()
def scan_status(job_id: str) -> dict[str, Any]:
    """查任务状态：state / 用时 / 最近日志 / 完成后的完整结果摘要。

    state 取值：pending / running / done / failed / cancelled。
    还在 running 时只有 log_tail，用来判断卡在哪一阶段。
    """
    job = JOBS.get(job_id)
    if job is None:
        return {"error": f"没有 job_id 为 {job_id!r} 的任务（进程重启后任务表会清空）"}
    return job.summary()


@server.tool()
def scan_cancel(job_id: str) -> dict[str, Any]:
    """取消一个正在跑的任务。已落盘的会话快照与日志会保留。"""
    job = JOBS.get(job_id)
    if job is None:
        return {"error": f"没有 job_id 为 {job_id!r} 的任务"}
    ok = job.cancel()
    return {"job_id": job.job_id, "requested": ok, "state": job.state}


@server.tool()
def report(job_id: str, fmt: str = "md") -> dict[str, Any]:
    """把已完成任务的报告写到 output/ 下，返回文件路径。

    fmt：md | html | all | json。
    """
    job = JOBS.get(job_id)
    if job is None:
        return {"error": f"没有 job_id 为 {job_id!r} 的任务"}
    return job.report(fmt=fmt)


# ── 启动 ──────────────────────────────────────────────────────────


def _enter_project_root() -> str:
    """切到项目根目录，返回切换结果说明。

    为什么必须切：``load_config`` 用的是相对路径 ``config.yaml`` / ``./poc`` /
    ``./data``。客户端拉起 server 时的 CWD 是不确定的（WorkBuddy、Claude Desktop
    各按自己的规则给），不切就会**静默**用默认配置 + 空 POC 目录扫一遍——不报错，
    但结果毫无意义，这种"看起来正常"的失败最难查。
    """
    root = Path(__file__).resolve().parent.parent
    if not (root / "config.yaml").is_file():
        return f"未找到 config.yaml（{root}），沿用当前目录 {Path.cwd()}"
    if Path.cwd() != root:
        os.chdir(root)
        return f"工作目录已切到项目根：{root}"
    return f"工作目录：{root}"


def main(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8765) -> None:
    """启动 MCP Server。

    默认 stdio：客户端（WorkBuddy / Claude Desktop）拉起进程后用标准输入输出通信。
    ``transport="http"`` 时走 streamable-http，供容器化/远程部署用。

    所有诊断信息走 stderr——stdout 是协议通道。
    """
    note = _enter_project_root()
    print(f"[mcp] {note}", file=sys.stderr)

    kind = (transport or "stdio").strip().lower()
    if kind in ("http", "streamable-http", "streamable_http"):
        server.run("streamable-http", host=host, port=int(port))
        return
    server.run("stdio")


if __name__ == "__main__":  # pragma: no cover - 手工调试用
    main()
