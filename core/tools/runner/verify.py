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
            # 没有接口清单**不等于**不能登录：认证语义写在路径末段时
            # （/login、/auth/login、/admin-api/system/auth/login、/oauth/token）
            # AUTH_BOOTSTRAP 直接识别，不需要先跑 recon_openapi。
            # 但 login 工具本身要靠清单挑端点，所以这里给出可直接执行的两条路。
            return (
                "还没有接口清单，login 工具无法自动挑选端点。两条路都不需要先 recon_openapi：\n"
                f"1) 已知标准端点就直接发请求：http_request(url=\"{base}/login\", method=\"POST\", "
                "body={\"username\":\"...\",\"password\":\"...\"})——AUTH_BOOTSTRAP 按 URL 路径末段"
                "识别 login/refresh/logout（方法须为 POST，参数须是认证字段）；\n"
                "2) 不知道端点就先 recon_openapi / recon_js 拿清单，再调用 login 自动挑选。\n"
                "常见约定：/login、/api/login、/auth/login、/admin-api/system/auth/login、"
                "/oauth/token、/api/v1/user/login。"
            )

        # 逐请求闸门：Authenticator 实际发出的每一个请求（验证码 GET、登录
        # POST）都要过 AUTH_BOOTSTRAP 的请求级判定。工具级意图已在
        # _policy_gate 里计过频率，这里 count_rate=False 避免一次登录算两次。
        def precheck(req_url: str, method: str, body: str = "") -> str:
            ctx = self._policy_ctx(session, req_url)
            d = self.policy_guard.check_auth(
                req_url, method=method, body=body, ctx=ctx, count_rate=False,
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
