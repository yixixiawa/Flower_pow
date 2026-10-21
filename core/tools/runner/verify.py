"""业务与验证类工具：登录、越权探测、多探测器流水线。

登录会写入会话凭证（后续请求自动带上），越权探测则对比"带凭证/不带凭证"
两次响应——这一类的结果必须有人（或模型）看过再定性，工具只给原始对比。
"""

from __future__ import annotations




class VerifyMixin:
    """见模块说明。"""

    # ── 业务 / 验证类 ─────────────────────────────────────────────

    async def _h_login(self, session, url: str = "", username: str = "", password: str = "") -> str:
        from core.auth import Authenticator

        target = self._target_of(session, url)
        if not username or not password:
            return "缺少 username / password"
        api = [a for a in session.result.assets if a.kind == "api"]
        if not api:
            return "还没有接口清单，无法定位登录端点——请先调用 recon_openapi"
        session.credentials["username"] = username
        session.credentials["password"] = password
        auth = Authenticator(self.cfg.scan, verbose=False)
        try:
            res = auth.login(target.rstrip("/") + "/", api, username, password)
        finally:
            auth.close()
        if res.ok:
            session.credentials["token"] = res.token
            notes = "；".join(res.notes)
            warn = "\n⚠ 该站验证码为纯文本 SVG，可被零成本自动识别（服务端选错了验证码载体）。" if res.captcha_kind == "svg" else ""
            return f"登录成功：{res.endpoint}\n{notes}\n已取得 Token，后续可做带凭证的越权测试。{warn}"
        return f"登录未成功：{'；'.join(res.notes) or res.raw[:200]}"

    async def _h_authz_probe(self, session, url: str = "", limit: int = 60) -> str:
        from detectors.api_authz import ApiAuthzDetector

        target = self._target_of(session, url)
        base = target.rstrip("/") + "/"
        api = [a for a in session.result.assets if a.kind == "api"]
        if not api:
            return "无接口资产——请先调用 recon_openapi 拿到接口清单"
        ops = [a.meta for a in api]
        lim = max(1, min(int(limit or 60), 500))
        token = session.credentials.get("token", "")
        uid = session.credentials.get("uid", "")
        det = ApiAuthzDetector(self.cfg.scan, self.poc_map)
        parts: list[str] = []
        new_total = 0
        try:
            f1, n1 = await det.probe_missing_auth(base, ops, limit=lim)
            new_total += self._merge_findings(session, f1)
            parts.append(f"未授权访问：探测 {n1} 个接口 → {len(f1)} 项命中（新增 {self._last_merged}）")
            if token:
                f2, n2 = await det.probe_idor(base, ops, token, limit=lim)
                new_total += self._merge_findings(session, f2)
                parts.append(f"越权/IDOR：探测 {n2} 个接口 → {len(f2)} 项命中（新增 {self._last_merged}）")
                f3, n3 = await det.probe_sensitive(base, ops, token, uid, limit=lim)
                new_total += self._merge_findings(session, f3)
                parts.append(f"敏感字段出网：探测 {n3} 个接口 → {len(f3)} 项命中（新增 {self._last_merged}）")
            else:
                parts.append("未取得凭证，跳过越权与敏感字段两类（可先调用 login）")
        finally:
            await det.aclose()
        parts.append(f"本轮共发起 {det.checked} 次请求，失败 {det.failed_requests} 次；会话新增发现 {new_total} 项")
        return "\n".join(parts)

    async def _h_run_pipeline(self, session, url: str = "") -> str:
        from core.scheduler import Scheduler

        target = self._target_of(session, url)
        sched = Scheduler(self.cfg)
        res = await sched.scan(target, verbose=False)
        a = self._merge_assets(session, res.assets)
        f = self._merge_findings(session, res.findings)
        session.result.notes.extend(res.notes)
        session.result.errors.extend(res.errors)
        lines = [
            f"完整流水线完成：{target}",
            f"POC 库 {res.pocs_loaded} → 召回 {res.pocs_selected} → 执行 {res.pocs_executed}",
            f"耗时 {res.duration:.1f}s | RAG {'on' if res.rag_enabled else 'off'} | LLM {'on' if res.llm_enabled else 'off'}",
            f"并入会话：新增资产 {a}、新增发现 {f}",
        ]
        top = sorted(res.findings, key=lambda x: x.severity.rank, reverse=True)[:15]
        if top:
            lines.append("主要发现：")
            for x in top:
                lines.append(
                    f"  [{x.severity.label}] {x.poc_id} {x.name} → {x.matched_at[:80]}"
                    + (f"（研判：{x.verdict}）" if x.verdict else "")
                )
        return "\n".join(lines)
