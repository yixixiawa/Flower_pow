"""证据登记：把模型手工验证的结果变成报告能用的原始报文。

要解决的是"模型验证完、隔几轮才登记"这个时序问题：那时的响应早已不在
上下文里。两条对策——

1. :meth:`_remember_exchange` 记住最近 30 次**真实发出**的请求，
   登记时按 URL 精确匹配自动附上响应；
2. :meth:`backfill_evidence` 从会话历史里把当时的工具结果还原回来。

两条都坚持**精确匹配**：把 A 接口的响应挂到 B 漏洞上，比没有响应更糟——
那等于在报告里放伪造证据。
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from core.state import Category, Evidence, Finding, Severity


class EvidenceMixin:
    """见模块说明。"""

    # 手工登记时单字段的体积上限。这**不是**"内容截断"：
    # 旧代码在 500/400/800 字符处砍掉说明与证据，报告必然残缺（真实事故：
    # 34 条手工发现全部卡在 500 字符边界，模型写的研判与复现步骤直接丢失）。
    # 这里的 20KB 是防呆——防的是模型把整份数据库 dump 塞进一条发现，
    # 把会话快照撑到加载不动。正常内容永远碰不到它。
    _MANUAL_FIELD_CAP = 20000

    @staticmethod
    def _scope_host(url: str) -> str:
        """从 URL 或裸主机里取出主机名；取不到返回空串。

        模型登记时``matched_at`` 常常只写主机（``1.2.3.4:8080``）或
        ``http://a.com/x``，两种形态都要认，所以没 scheme 时补一个再解析。
        """
        raw = (url or "").strip()
        if not raw:
            return ""
        if "://" not in raw:
            raw = f"http://{raw}"
        try:
            host = urlparse(raw).hostname or ""
        except ValueError:
            return ""
        return host.strip().lower()

    def _check_target_scope(self, session, matched_at: str) -> str:
        """校验"登记的漏洞"是否属于"当前会话的目标"，串线则返回拦截文案。

        只拦**形态不一致**的明显串线：目标是域名却登记 IP，或目标是 IP
        却登记域名。同形态不同主机（子域名、多主机业务）一律放行——
        那是正常业务形态，拦了会误伤。
        """
        target = getattr(session, "target", "") or ""
        target_host = self._scope_host(target)
        match_host = self._scope_host(matched_at)
        if not target_host or not match_host:
            return ""

        try:
            is_target_ip = bool(ipaddress.ip_address(target_host))
        except ValueError:
            is_target_ip = False
        try:
            is_match_ip = bool(ipaddress.ip_address(match_host))
        except ValueError:
            is_match_ip = False

        if is_match_ip == is_target_ip:
            return ""

        if is_target_ip:
            return (
                f"【已拦截】当前会话的目标是 IP（{target_host}），"
                f"你登记的却是域名（{match_host}）。"
                "为防止报告串线，请先使用 /target 切换到该域名后再登记，"
                "或把matched_at 改回当前目标。"
            )
        return (
            f"【已拦截】你尝试在一个域名为目标（{target_host}）的会话中，"
            f"登记 IP（{match_host}）的漏洞。"
            "为了防止报告串线，请先使用 "
            f"/target http://{match_host} 切换目标后再登记，"
            "或把 matched_at 改回当前目标。"
        )

    async def _h_record_finding(
        self,
        session,
        name: str = "",
        severity: str = "medium",
        matched_at: str = "",
        evidence: str = "",
        remediation: str = "",
        category: str = "other",
        cve: str = "",
        payload: str = "",
        expected: str = "",
        response: str = "",
    ) -> str:
        """登记一条手工验证的漏洞。

        为什么必须有这个工具：自动探针只跑通用 payload，遇到需要特定
        闭合语法的注入、需要 null byte 的路径穿越、需要特定 header 的
        越权时**必然打不中**。模型自己用 curl/http_request 验证出来了，
        但结果只存在对话里——``findings`` 列表和报告都看不到，等于白测。

        ``response`` 是**原始响应报文**（Burp 式：状态行 + 响应头 + 空行 +
        响应体）。为什么单独要这一个参数：报告 PoC 段直接把它贴进
        ``<<< 响应:``，交付方才能照着复现。没有它，报告里那条发现就只有
        请求没有响应——而这恰恰是"报告内容不完整"的常见成因。
        模型没传时，会自动附上**最近一次同 URL 的 http_request 响应**
        （只认 URL 精确/同主机同路径匹配，绝不模糊配对）。

        ``payload`` 可以是：
        * 单行 payload（``GET /api/x?id=1'--``）；
        * 整段原始请求（请求行 + 头 + 空行 + 体）——会被拆成结构化字段，
          报告里就是一份可粘贴到 Burp Repeater 的完整请求。
        """
        import hashlib

        from core.rawmsg import (
            RawRequest,
            RawResponse,
            parse_raw_request,
            parse_raw_response,
            split_exchange,
            unescape_md,
        )

        # 先清洗再校验：模型常从 Markdown 里复制，``\``` ``\*`` 会一起带过来，
        # 报告里就出现一堆反斜杠。清洗不能改语义，只去转义与行尾空格。
        name = unescape_md(name)
        matched_at = unescape_md(matched_at).strip()
        evidence = unescape_md(evidence)
        remediation = unescape_md(remediation)
        cve = unescape_md(cve)
        expected = unescape_md(expected).strip()
        payload_raw = unescape_md(payload).strip()
        response_raw = unescape_md(response).strip()

        # ── 目标归属校验：防止"漫天乱飞后回主域名登记" ───────────
        # 模型很容易跑去测了别的 IP（顺手扫到的邻居、SSRF 里反射出来的
        # 内部地址、别的目标），回来却用当前目标的主域名登记。于是报告里
        # 出现一条"某域名上的漏洞"，而证据实际来自另一个系统——串线。
        # 这里只拦**形态不一致**（域名 vs IP）的明显串线；同形态不同主机
        # 不拦（子域名/多主机业务很常见，拦了会误伤正常流程）。
        scope_msg = self._check_target_scope(session, matched_at)
        if scope_msg:
            return scope_msg

        if not name.strip():
            return "登记失败：name 不能为空"
        if not matched_at.strip():
            return "登记失败：matched_at 不能为空（无法复现的漏洞不应入库）"
        if not evidence.strip():
            return (
                "登记失败：evidence 不能为空。"
                "报告里每条发现都要有原始报文/回显作为依据，"
                "没有证据的判断只是猜测。请把响应片段或对比结果填进来。"
            )
        if not payload_raw:
            return (
                "登记失败：payload 不能为空。"
                "手工验证的漏洞没有 POC 定义，payload 是对方复现的唯一依据。"
                "请填写实际发出的请求，例如："
                "GET /rest/products/search?q=test')) UNION SELECT 1--"
            )

        # ── 原始报文解析：请求 / 响应各归各位 ─────────────────────
        req = parse_raw_request(payload_raw) if payload_raw else RawRequest()
        resp = RawResponse()
        if response_raw:
            # 模型可能把请求+响应一起塞进 response（从 Burp 直接复制粘贴的
            # 常见形态），也可能只给响应。split_exchange 两种都认。
            req_text, resp_text = split_exchange(response_raw)
            if req_text:
                maybe = parse_raw_request(req_text)
                if maybe.ok:
                    # 请求原文比单行 payload 信息全（含全部头与请求体），优先用
                    req = maybe
                    payload_raw = req_text
                elif not payload_raw:
                    payload_raw = req_text
            resp = parse_raw_response(resp_text) if resp_text else RawResponse()

        # 没有原始响应时，试着用最近一次真实请求的响应补上。
        # 只做精确匹配：把别的接口的响应挂到这条漏洞上，比没有响应更糟。
        attached_from = ""
        cached = None
        if resp.status_code is None and not resp.body:
            cached = self._find_recent_exchange(matched_at)
            if cached:
                resp = RawResponse(
                    ok=True,
                    status_code=cached.get("status_code"),
                    headers=dict(cached.get("response_headers") or {}),
                    body=cached.get("body") or "",
                )
                attached_from = "最近一次同 URL 的 http_request"

        method = req.method or (
            "POST" if payload_raw.upper().startswith(("POST", "PUT", "PATCH", "DELETE"))
            else "GET"
        )
        if req.ok:
            # 直接用**原文**而不是重新拼装：解析会把头名归一成小写，
            # 报告里的请求要能原样粘回 Burp，大小写不能动。
            request_text = payload_raw or req.as_text()
        elif cached and cached.get("request_line"):
            request_text = str(cached["request_line"])
        else:
            request_text = self._request_text_for(matched_at, method)

        body = resp.body or ""

        def _clip(text: str, field: str) -> str:
            if len(text) <= self._MANUAL_FIELD_CAP:
                return text
            return text[: self._MANUAL_FIELD_CAP] + (
                f"\n…（{field} 超过 {self._MANUAL_FIELD_CAP} 字符，"
                f"已截断；这是防呆上限，正常内容不会碰到）"
            )

        cat_map = {
            "sqli": Category.CONTENT_MATCH, "sql": Category.CONTENT_MATCH,
            "xss": Category.CONTENT_MATCH, "idor": Category.API_AUTHZ,
            "authz": Category.API_AUTHZ, "ssrf": Category.API_AUTHZ,
            "lfi": Category.FILE_OP, "rce": Category.RCE,
            "file": Category.FILE_OP, "info": Category.HEADER_CHECK,
            "info_disclosure": Category.HEADER_CHECK,
            "header": Category.HEADER_CHECK, "path": Category.PATH_PROBE,
            "cve": Category.CVE_PROBE,
        }
        cat = cat_map.get(str(category).lower(), Category.PATH_PROBE)
        try:
            sev = Severity.parse(severity)
        except Exception:  # noqa: BLE001
            sev = Severity.MEDIUM

        # poc_id 用 manual_ 前缀：与探针登记的区分开，便于报告里识别来源
        poc_id = f"manual_{str(category).lower()}_{abs(hash(name)) % 10000:04d}"
        ev = Evidence(
            url=matched_at.strip(),
            method=method,
            request_line=request_text,
            status_code=resp.status_code,
            request_headers=dict(req.headers or {}),
            response_headers=dict(resp.headers or {}),
            body_excerpt=body[:8000],
            body_size=len(body.encode("utf-8", "replace")),
            poc_id=poc_id,
            poc_name=f"手工验证：{name.strip()}",
            payload_sent=payload_raw,
            expected=expected,
            # matched_pattern 只留给探针的"命中依据"：手工登记的判定依据
            # 就是 evidence，放到 description 里，别在两个字段里各存一遍
            # （报告里会变成"说明"和"实际命中"两段一模一样的话）。
            matched_pattern="",
        )
        # 完整响应体只在运行期保留，不进会话快照（见 Evidence.full_body）
        ev.full_body = body[:65536]

        # 命中即落盘 Burp 式完整报文：报告 PoC 段读的就是这个文件。
        # 与探针路径共用 persist_evidence，保证两条路径格式一致。
        from detectors.base import persist_evidence

        persist_evidence(
            (getattr(self.cfg.scan, "evidence_dir", "") or ""),
            ev,
            require_status=False,
        )

        f = Finding(
            poc_id=poc_id,
            name=name.strip(),
            severity=sev,
            category=cat,
            description=_clip(evidence.strip(), "说明"),
            remediation=_clip(remediation.strip(), "修复建议"),
            matched_at=matched_at.strip(),
            evidence=ev,
            verdict="true_positive",
            confidence=1.0,
            rationale="模型手工验证（record_finding）",
            detector="manual",
            cve=[c.strip() for c in (cve or "").split(",") if c.strip()],
            tags=["manual", str(category).lower()],
        )
        added = self._merge_findings(session, [f])
        if not added:
            return f"该发现已存在（{poc_id} @ {matched_at[:60]}），未重复登记"

        out = [
            f"已登记：[{sev.label}] {name.strip()}",
            f"  位置：{matched_at.strip()}",
            f"  payload：{payload_raw[:120]}",
        ]
        if ev.status_code is not None:
            src = f"（来自{attached_from}）" if attached_from else ""
            art = f"，报文已落盘 {ev.artifact}" if ev.artifact else ""
            out.append(
                f"  原始响应：HTTP {ev.status_code}，{ev.body_size} 字节{src}{art}"
            )
        else:
            out.append(
                "  ⚠ 本条**没有原始响应报文**：报告 PoC 段只有请求，对方无法比对。"
                "登记时把 http_request 返回的响应整段传给 response 参数"
                "（未传时会尝试用最近一次同 URL 的响应，这次没匹配上；"
                "如刚请求过，把 http_request 的**完整 URL**（含 query）"
                "原样复制到 matched_at 再登记一次）。"
            )
        out += [
            f"  当前会话共 {len(session.result.findings)} 项发现。",
            "  提醒：继续登记其余手工验证的漏洞，全部登记完再调用 export_report。",
        ]
        return "\n".join(out)

    @staticmethod
    def _request_text_for(url: str, method: str) -> str:
        """按 URL 重建一行请求（模型只给了 URL 时的兜底）。

        刻意**不猜**请求头与请求体：编出来的 Host/UA 会让报告看起来更"完整"，
        但那不是当时真实发出的请求，等于伪造证据。
        """
        from urllib.parse import urlparse

        u = urlparse(url)
        if u.scheme and u.netloc:
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            return f"{method} {path} HTTP/1.1\nHost: {u.netloc}"
        return f"{method} {url} HTTP/1.1"

    def _find_recent_exchange(self, url: str) -> dict | None:
        """按 URL 在最近的真实请求里找一条。

        匹配顺序：完整 URL（忽略大小写与末尾斜杠）→ 同主机同路径（忽略 query）。
        **不做模糊匹配**：宁可回填不上，也不能把别的接口的响应挂到这条漏洞上。
        """
        from urllib.parse import urlparse

        def norm(u: str) -> str:
            return (u or "").strip().rstrip("/").lower()

        target = norm(url)
        if not target:
            return None
        for item in reversed(self._recent_http):
            if norm(str(item.get("url") or "")) == target:
                return item
        tu = urlparse(url if "://" in url else f"http://{url}")
        for item in reversed(self._recent_http):
            cu = urlparse(str(item.get("url") or ""))
            if (
                cu.scheme == tu.scheme
                and (cu.hostname or "").lower() == (tu.hostname or "").lower()
                and (cu.path or "").rstrip("/") == (tu.path or "").rstrip("/")
            ):
                return item
        return None

    def _remember_exchange(self, ev: Evidence) -> None:
        """记住最近几次真实请求的报文，供 record_finding 自动附响应。

        存的是**当时那一刻**的字段快照：模型可能先验证（http_request）、
        隔几轮再登记（record_finding），中间会话状态会变。
        """
        try:
            self._recent_http.append(
                {
                    "url": ev.url,
                    "method": ev.method,
                    "request_line": ev.request_line,
                    "status_code": ev.status_code,
                    "response_headers": dict(ev.response_headers or {}),
                    "body": ev.full_body or ev.body_excerpt or "",
                    "body_size": ev.body_size,
                    "elapsed_ms": ev.elapsed_ms,
                }
            )
        except Exception:  # noqa: BLE001
            return
        del self._recent_http[: -self._RECENT_HTTP_KEEP]

    async def _h_backfill_evidence(self, session, **_: Any) -> str:
        """从会话历史回填发现的原始报文（老报告缺响应时用）。

        典型场景：用户说"这份报告的 PoC 只有请求没有响应"。那些发现是旧版
        ``record_finding`` 登记的（说明被截断、还冒充了响应体），但**当时
        真实发过的 http_request 结果还在对话历史里**——补上它比重跑一遍
        扫描便宜得多。
        """
        from core.backfill import backfill_findings

        stat = backfill_findings(
            session, evidence_dir=str(getattr(self.cfg.scan, "evidence_dir", "") or "")
        )
        lines = [
            f"历史里识别到 {stat['exchanges']} 次真实请求；"
            f"缺响应的发现 {stat['candidates']} 条，已回填 {stat['filled']} 条。"
        ]
        if stat["filled"]:
            if any(it.get("truncated") for it in stat["items"]):
                lines.append(
                    "  其中部分正文是当时的预览截断版（工具结果里只有这么多），"
                    "报告会如实标注截断；要完整响应只能重新请求一次。"
                )
            else:
                lines.append("  回填的正文是完整响应，报告 PoC 段可直接比对。")
            lines.append("  重新调用 export_report 即生效（PoC 段会出现 <<< 响应:）。")
        elif stat["candidates"]:
            lines.append(
                "  未匹配上：历史里没有同 URL 的请求记录。会话历史只保留最近"
                "若干轮，早期轮次可能已被裁掉——那就只能重新请求验证。"
            )
        else:
            lines.append("  当前发现都不缺响应，无需回填。")
        return "\n".join(lines)
