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

    async def _h_search_assets(self, session, query: str = "", limit: int = 50) -> str:
        """网络空间测绘检索：统一入口，内部按优先级路由已配置平台。

        Agent 只看到这一个工具（不暴露 fofa/quake/hunter/zoomeye 各自入口，
        那会让它在四五个相似工具里反复试错）。没配 key 的平台自动跳过，
        单平台失败只记 errors 不影响其余——降级不崩。
        """
        from collectors.asset_search import platforms_available, platforms_missing, search_assets

        if not (query or "").strip():
            return "缺少 query 参数：给检索词（如 domain=\"example.com\"）或留空用会话目标"
        avail = platforms_available()
        if not avail:
            return (
                "未配置任何网络空间测绘平台凭据，无法检索。\n"
                "  在 .env 或环境变量里配置（配了几个用几个）：\n"
                "    QUAKE_KEY=...              （360 Quake，推荐先配）\n"
                "    FOFA_EMAIL=... FOFA_KEY=...（FOFA，两个都要）\n"
                "    HUNTER_KEY=...             （奇安信 Hunter）\n"
                "    ZOOMEYE_KEY=...            （知道创宇 ZoomEye）\n"
                "  配置后重启生效。"
            )
        assets, errors = await search_assets(
            query, cfg=self.cfg.scan, target=session.target, limit=limit
        )
        if not assets:
            detail = "；".join(errors) if errors else "各平台均无结果"
            return f"资产搜索无结果（{detail}）"
        added = self._merge_assets(session, assets)
        by_platform: dict[str, int] = {}
        for a in assets:
            p = str((a.meta or {}).get("platform") or "?")
            by_platform[p] = by_platform.get(p, 0) + 1
        lines = [
            f"检索「{query}」→ {len(assets)} 条资产（新增入库 {added}）："
            + "、".join(f"{p} {n}" for p, n in sorted(by_platform.items())),
        ]
        for a in assets[:40]:
            t = (a.meta or {}).get("title") or ""
            ip = (a.meta or {}).get("ip") or ""
            extra = "  ".join(x for x in (f"[{t[:40]}]" if t else "", f"({ip})" if ip else "") if x)
            lines.append(f"  {a.kind:9} {a.value[:100]}{extra}")
        if len(assets) > 40:
            lines.append(f"  …（另 {len(assets) - 40} 条已入库，用 session_state 查看）")
        if errors:
            lines.append("  平台降级：" + "；".join(errors))
        if platforms_missing():
            lines.append(
                "  未配置的平台（结果可能不全）："
                + "、".join(platforms_missing())
                + "，在 .env 里补 key 可扩大覆盖面"
            )
        return "\n".join(lines)
