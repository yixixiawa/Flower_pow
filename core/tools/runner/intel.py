"""情报检索类工具：RAG 知识库检索、本地 POC 清单、CVE 情报。

检索器（向量库）是懒加载的：没配知识库时构造就会失败，而这个失败不该
拖垮整个启动流程，所以推迟到第一次调用。
"""

from __future__ import annotations

from pathlib import Path


class IntelMixin:
    """见模块说明。"""

    # ── 检索类 ────────────────────────────────────────────────────

    def _get_retriever(self):
        if self._retriever is None:
            from kb.retriever import Retriever

            retr, _errs = Retriever.from_config(self.cfg.rag, self.poc_map, verbose=False)
            self._retriever = retr
        return self._retriever

    async def _h_rag_search(self, session, query: str = "", top_k: int = 8) -> str:
        from core.state import Fingerprint, ScanResult

        retr = self._get_retriever()
        if retr is None:
            return "索引不可用（POC 库为空或索引构建失败）"
        q = query or session.target
        sr = ScanResult(target=q, fingerprints=[Fingerprint(target=q, title=q)])
        out = retr.retrieve(sr, top_k=max(1, min(int(top_k or 8), 30)))
        if not out.results:
            return f"无匹配（检索词：{q}）"
        lines = [f"检索词「{q}」→ {len(out.results)} 条："]
        for r in out.results:
            lines.append(
                f"  {r.final_score:.3f}  {r.poc.id}  {r.poc.name}  [{r.poc.severity.label}]"
                + (f"  依据：{r.reason}" if r.reason else "")
            )
        return "\n".join(lines)

    async def _h_poc_list(self, session, grep: str = "") -> str:
        items = list(self.poc_map.values())
        if grep:
            low = grep.lower()
            items = [
                p for p in items
                if low in p.id.lower() or low in p.name.lower()
                or any(low in t for t in p.tags)
                or any(low in a for a in p.applies_to)
            ]
        if not items:
            return f"POC 库共 {len(self.poc_map)} 条，无匹配「{grep}」"
        lines = [f"匹配 {len(items)} / 共 {len(self.poc_map)} 条："]
        for p in sorted(items, key=lambda x: x.severity.rank, reverse=True)[:40]:
            lines.append(f"  {p.id:34} {p.severity.label:8} {p.name}")
        return "\n".join(lines)

    async def _h_cve_intel(self, session, cve: str = "") -> str:
        from kb.intel import get_intel

        if not cve:
            return "缺少 cve 参数"
        try:
            store = get_intel(str(Path(self.cfg.data_dir) / "intel"))
            info = store.lookup(cve.upper())
        except Exception as exc:  # noqa: BLE001
            return f"情报查询失败（可能无网络）：{type(exc).__name__}: {exc}"
        if not info:
            return f"未找到 {cve} 的情报"
        return (
            f"{cve.upper()}：CVSS {info.cvss}（{info.severity or '-'}）"
            f" | CISA KEV {'在野利用' if info.kev else '否'}"
            f" | EPSS {info.epss if info.epss is not None else '-'}"
            f" | 公开 PoC {'有' if info.has_poc else '无'}"
            f" | Nuclei 模板 {'有' if info.has_nuclei else '无'}\n"
            f"{(info.description or '')[:400]}"
        )
