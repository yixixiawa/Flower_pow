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
        from core.session.redact import redact

        target = self._target_of(session, url)
        if not username or not password:
            return "缺少 username / password"
        api = [a for a in session.result.assets if a.kind == "api"]
        if not api:
            base = target.rstrip("/")
            # 授权只来自登记（guardschedule3.md）：路径关键词不直接授权。
            # 没有清单时给出两条**登记路径**，登记后 AUTH_BOOTSTRAP 才放行。
            return (
                "还没有接口清单，且登记表里没有该目标的登录入口。授权只来自登记，两条登记路径：\n"
                "1) REPL 里执行 /auth register <登录URL>（用户逐条确认，持久化到 "
                "data/policy/auth_endpoints.yaml）；\n"
                "2) 或在 config.yaml 的 policy.auth_endpoints 里加一条 "
                "{target: <主机>, kind: login, url: <路径>}。\n"
                f"登记后即可 http_request(url=\"{base}/<已登记路径>\", method=\"POST\", "
                "body={\"username\":\"...\",\"password\":\"...\"})，或重新调用 login。\n"
                "3) 不知道端点就先 recon_openapi / recon_js 拿清单——清单里的认证端点"
                "自动算已登记。"
            )

        # 逐请求闸门：Authenticator 实际发出的每一个请求（验证码 GET、登录
        # POST）都要过 AUTH_BOOTSTRAP 的请求级判定。**频率只在这里计一次**
        # （guardschedule5 第三章）：工具级意图判定不计配额，否则同一登录
        # 会被扣两次。验证码 GET 不计数（只对凭证提交计数）。
        def precheck(req_url: str, method: str, body: str = "") -> str:
            ctx = self._policy_ctx(session, req_url)
            d = self.policy_guard.check_auth(
                req_url, method=method, body=body, ctx=ctx,
            )
            return "" if d.allowed else d.reason

        session.credentials["username"] = username
        session.credentials["password"] = password
        auth = Authenticator(self.cfg.scan, verbose=False, precheck=precheck)
        try:
            res = auth.login(target.rstrip("/") + "/", api, username, password)
        finally:
            auth.close()
        if res.ok:
            session.credentials["token"] = res.token
            # 凭据值一律脱敏：登录响应可能把 token/密码回显在 notes/raw 里，
            # 工具输出会进对话历史、报告与知识库。
            notes = redact("；".join(res.notes))
            warn = "\n⚠ 该站验证码为纯文本 SVG，可被零成本自动识别（服务端选错了验证码载体）。" if res.captcha_kind == "svg" else ""
            return (
                f"登录成功：{res.endpoint}\n{notes}\n"
                f"已取得 Token（值不在此回显），后续可做带凭证的越权测试。\n"
                f"注意：登录成功**不会**放行后续请求——写操作/导出/删除仍受权限矩阵约束。{warn}"
            )
        return f"登录未成功：{redact('；'.join(res.notes) or res.raw[:200])}"

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
        from policy.enforcer import active_scan_check, scoped_scan_config

        target = self._target_of(session, url)
        # 统一策略入口（P1-10）：完整流水线与 Agent 逐请求闸门同一份 policy
        allowed, msg = active_scan_check(self.cfg, target)
        if not allowed:
            return f"【已拦截】（策略）{msg}"
        cfg, note = scoped_scan_config(self.cfg, target)
        sched = Scheduler(cfg)
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
