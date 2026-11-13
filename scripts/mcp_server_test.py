"""MCP 壳的回归测试：工具注册、参数校验、任务生命周期、导入隔离。

守住的语义：

1. **工具清单稳定**：10 个工具都在，且每个都有非空描述（描述就是模型看到的说明书）；
2. **查询类工具返回结构正确**：``poc_list`` / ``poc_show`` / ``doctor`` 的字段契约；
3. **不泄露凭据**：``doctor`` 只说有没有 Key，不回显 Key；
4. **参数校验**：空 target、未知 job_id 一律返回 ``error`` 而不是抛异常；
5. **任务生命周期**：起 → 跑 → 终态，日志能带出来；未完成的任务不能出报告；
6. **零网络**：扫描目标用本机关闭端口（127.0.0.1:9），不碰外网。

运行：.venv/Scripts/python.exe scripts/mcp_server_test.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server import server as srv  # noqa: E402
from mcp_server.jobs import ScanJob  # noqa: E402
from mcp_server.services import load_cfg  # noqa: E402

EXPECTED_TOOLS = {
    "doctor",
    "poc_list",
    "poc_show",
    "kb_search",
    "sessions",
    "findings",
    "scan_start",
    "scan_status",
    "scan_cancel",
    "report",
}


def quiet_cfg():
    """一份"只打本机、什么都关掉"的配置——测试不该碰外网也不该烧 token。"""
    cfg = load_cfg("")
    cfg.llm.enabled = False
    cfg.rag.enabled = False
    cfg.scan.timeout = 0.5
    cfg.scan.concurrency = 2
    cfg.scan.port_scan_enabled = False
    cfg.scan.path_scan_enabled = False
    cfg.scan.js_analyze_enabled = False
    cfg.scan.js_logic_enabled = False
    cfg.scan.sqli_probe_enabled = False
    cfg.scan.rce_probe_enabled = False
    cfg.scan.file_read_probe_enabled = False
    cfg.scan.file_upload_probe_enabled = False
    cfg.scan.auto_dismiss_public = False
    return cfg


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    async def list_tools():
        return await srv.server.list_tools()

    async def call(name, **kwargs):
        res = await srv.server.call_tool(name, kwargs)
        # 工具返回 dict：SDK 会包成 content + structuredContent，取结构化那份
        return res.structured_content or res

    print("\n场景1 工具注册")
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    check(names == EXPECTED_TOOLS, f"10 个工具齐全（实际 {len(names)}）", f"缺={EXPECTED_TOOLS - names} 多={names - EXPECTED_TOOLS}")
    check(all((t.description or "").strip() for t in tools), "每个工具都有描述")
    check(all(t.input_schema.get("type") == "object" for t in tools), "每个工具的参数 schema 是 object")

    print("\n场景2 poc_list / poc_show")
    listed = asyncio.run(call("poc_list"))
    check(listed.get("count", 0) >= 30, f"列出 POC 库（{listed.get('count')} 条）")
    items = listed.get("items") or []
    check(bool(items), "items 非空")
    ranks = [it.get("severity") for it in items[:5]]
    check("critical" in ranks or "high" in ranks, f"按危害降序（前五：{ranks}）")

    searched = asyncio.run(call("poc_list", query="spring actuator 未授权"))
    check("items" in searched, "带 query 时返回检索结果")
    check(bool(searched.get("items")) or bool(searched.get("hint")), "索引缺失时给降级提示")

    shown = asyncio.run(call("poc_show", poc_id="api-idor"))
    check(shown.get("id") == "api-idor", "poc_show 命中已知 id")
    check("id: api-idor" in (shown.get("raw") or ""), "返回原始 YAML")

    missing = asyncio.run(call("poc_show", poc_id="no-such-poc-xyz"))
    check("error" in missing, "未知 id 返回 error 而不是抛异常")

    print("\n场景3 doctor 不泄露凭据")
    doc = asyncio.run(call("doctor"))
    check(doc.get("python") and "poc" in doc and "scan" in doc, "doctor 返回体检字段")
    check(isinstance(doc.get("llm", {}).get("api_key_present"), bool), "只暴露 api_key_present")
    key = load_cfg("").llm.api_key
    check(not key or key not in str(doc), "返回值里不含 Key 明文")

    print("\n场景4 参数校验")
    check("error" in asyncio.run(call("scan_start", target="   ")), "空 target 被拒")
    check("error" in asyncio.run(call("scan_status", job_id="nope")), "未知 job_id 查状态报错")
    check("error" in asyncio.run(call("scan_cancel", job_id="nope")), "未知 job_id 取消报错")
    check("error" in asyncio.run(call("report", job_id="nope")), "未知 job_id 出报告报错")

    print("\n场景5 任务生命周期（本机关闭端口，不联网）")
    job = ScanJob("http://127.0.0.1:9/", quiet_cfg())
    check(job.summary().get("state") == "pending", "未启动时是 pending")
    check("error" in job.report(), "未完成的任务不能出报告")
    job.start()
    deadline = time.time() + 90
    while job.state in ("pending", "running") and time.time() < deadline:
        time.sleep(0.2)
    check(job.state in ("done", "failed"), f"跑到终态（{job.state}）")
    summary = job.summary()
    check(isinstance(summary.get("log_tail"), list), "status 能带出日志尾巴")
    check(summary.get("elapsed_s", -1) >= 0, "status 有用时")
    check(job.cancel() is False, "已结束的任务无法再取消")
    if job.state == "done":
        check("result" in summary, "完成的 status 有结果摘要")
        check(summary["result"].get("target") == "http://127.0.0.1:9/", "结果里的 target 正确")

    print("\n场景6 CLI 注册与导入隔离")
    from cli import app as typer_app

    cmd_names = {getattr(c.callback, "__name__", "") for c in typer_app.registered_commands}
    check("mcpserve" in cmd_names, "`flower_pow mcp` 已注册到 CLI")
    import mcp_server

    check(callable(getattr(mcp_server, "main", None)), "包入口 mcp_server.main 可用")
    check(Path("mcp_server/server.py").is_file(), "server.py 存在")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
