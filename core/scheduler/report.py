"""``_ReportMixin``：报告导出 + 自身描述。

``describe()`` 给 ``flower_pow engines`` 用来展示这条流水线在做什么。"""

from __future__ import annotations

from pathlib import Path
from core.state import (
    Asset,
    Category,
    Finding,
    POC,
    ScanResult,
    Severity,
    dismiss_finding,
)


class _ReportMixin:
    def report(self, result: ScanResult, fmt: str = "all", verbose: bool = True) -> list[Path]:
        """生成 JSON / Markdown / HTML 报告。"""
        from output.report import write_html, write_json, write_markdown

        outdir = Path(self.cfg.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)

        ai_body = ""
        if self.llm.available and result.findings:
            ai_body = self.llm.write_report(result)
            if not ai_body:
                result.notes.append("LLM 报告生成失败，已输出模板报告")

        # 报告生成本身也是一次 LLM 调用（走深度模型），必须计入统计——
        # scan() 的 finally 里那次快照发生在报告生成之前，不刷新的话
        # 报告里的"LLM 调用 N 次"会永远少一次，且看不到深度模型被用过。
        result.llm_stats = self.llm.stats()

        paths = [write_json(result, outdir, ai_body)]
        if fmt in ("md", "all"):
            paths.append(write_markdown(result, outdir, ai_body))
        if fmt in ("html", "all"):
            paths.append(write_html(result, outdir, ai_body))
        if verbose:
            for p in paths:
                self._log(f"[5/5] 输出: {p}", verbose)
        return paths

    # ── 小工具 ────────────────────────────────────────────────────
    @staticmethod
    def _log(msg: str, verbose: bool = True) -> None:
        if verbose:
            print(msg)

    def describe(self) -> str:
        """当前能力概览——给 CLI ``engines`` 命令用。"""
        from core.tools import describe_externals, probe_external

        lines = [
            f"扫描引擎：内置 httpx（并发 {self.cfg.scan.concurrency}，"
            f"超时 {self.cfg.scan.timeout}s，"
            f"{'只读' if self.cfg.scan.readonly else '⚠ 允许写操作'}）",
            f"RAG：{'启用' if self.cfg.rag.enabled else '禁用'}"
            f"（top_k={self.cfg.rag.top_k}，min_score={self.cfg.rag.min_score}，"
            f"目录 {self.cfg.rag.poc_dir}）",
            f"LLM 重排：{'启用' if self.cfg.rag.rerank_with_llm else '禁用'}",
            f"LLM：{self.llm.model_for('fast')}"
            + (
                f" / 深度任务 {self.llm.model_for('deep')}"
                if self.cfg.llm.deep_model
                else ""
            )
            + f" @ {self.cfg.llm.base_url}"
            if self.llm.available
            else "LLM：未配置（设置 DEEPSEEK_API_KEY 启用重排与研判）",
            f"采集器：端口扫描 {'on' if self.cfg.scan.port_scan_enabled else 'off'}"
            f"（top {self.cfg.scan.port_scan_top}）、"
            f"JS 资产分析 {'on' if self.cfg.scan.js_analyze_enabled else 'off'}、"
            f"JS 逻辑审计 {'on' if getattr(self.cfg.scan, 'js_logic_enabled', True) else 'off'}、"
            f"路径爆破 {'on' if self.cfg.scan.path_scan_enabled else 'off'}",
            "一次性高危探针（每个接口只尝试 1 次，命中即停、出错即跳过）："
            + "、".join(
                n
                for n, f in (
                    ("SQL注入(仅取版本号)", "sqli_probe_enabled"),
                    ("RCE/模板注入", "rce_probe_enabled"),
                    ("任意文件读取", "file_read_probe_enabled"),
                    ("任意文件上传", "file_upload_probe_enabled"),
                )
                if getattr(self.cfg.scan, f, False)
            )
            + f"（上限 {getattr(self.cfg.scan, 'probe_max_ops', 40)} 个接口）",
            f"外部工具：{describe_externals(probe_external()[0])}",
        ]
        return "\n".join(lines)


