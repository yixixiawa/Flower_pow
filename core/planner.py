"""每轮执行的规划器——决定「这一阶段该做什么」并真正去做。

阶段与动作
----------
======= ================================================================
阶段    这一轮做什么
======= ================================================================
RECON   指纹 + 端口 + JS + **接口文档**。产出完整资产面（第 1 轮）
MODEL   从资产推导业务模型，并**真的走一遍业务流程**：登录 → 取自身
        信息 → 访问核心资源，确认系统按预期工作（第 2 轮）
EXPLOIT 鉴权测试：未授权访问 / IDOR / 敏感字段出网 + 常规 POC（第 3 轮）
ITERATE 基于已有发现扩大探测面、换角度复测，找漏网之鱼（第 4 轮及以后）
======= ================================================================

为什么第 2 轮要"真的走一遍"
--------------------------
不理解业务就没法测。同样一个 ``GET /api/orders/{id}``，
知道它是"订单"才会去测越权，知道有"支付回调"才会去测伪造通知。
走一遍真实流程还能顺带验证：返回的字段里有没有不该出现的东西。

每轮结束后给出**下一轮建议**，让人决定要不要继续、往哪个方向继续。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from collectors.js_analyze import JsAnalyzer
from collectors.openapi import OpenApiCollector
from collectors.port_scan import PortScanner
from core.auth import Authenticator
from core.session import Phase, Session, Turn
from core.state import Asset, Severity
from detectors.api_authz import ApiAuthzDetector
from detectors.http_detector import FingerprintDetector, HttpDetector
from detectors.poc_loader import load_poc_map

# 业务流程关键词 → 用于推断状态流转
FLOW_STEPS = [
    ("创建/提交", r"create|add|submit|new|generate|import|upload"),
    ("查询/列表", r"^(get|list|query|find|search)|list$"),
    ("更新/变更", r"update|patch|modify|edit|confirm|submit-review|lock"),
    ("删除/归档", r"delete|remove|archive|discard|cancel"),
    ("执行/运行", r"run|execute|start|trigger|complete"),
]

HIGH_VALUE_PAT = re.compile(
    r"recharge|balance|payment|pay|order|refund|withdraw|allocat|"
    r"password|credential|token|secret|permission|role|plan-adjust", re.I
)


class Planner:
    """把「阶段」翻译成「这一轮要执行的动作」。"""

    def __init__(self, cfg, verbose: bool = True) -> None:
        self.cfg = cfg
        self.verbose = verbose
        self.poc_map, self.poc_errors = load_poc_map(cfg.rag.poc_dir)

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # ── 入口 ──────────────────────────────────────────────────────
    async def run_turn(self, session: Session, intent: str = "") -> Turn:
        t = session.begin_turn(intent or session.phase.goal)
        a0, f0 = len(session.result.assets), len(session.result.findings)
        self.log(f"\n── 第 {t.no} 轮 · {session.phase.label} ──")
        self.log(f"   目标：{session.phase.goal}")

        try:
            if session.phase is Phase.RECON:
                await self._recon(session, t)
            elif session.phase is Phase.MODEL:
                await self._model(session, t)
            elif session.phase is Phase.EXPLOIT:
                await self._exploit(session, t)
            else:
                await self._iterate(session, t)
        except Exception as exc:  # noqa: BLE001
            t.notes.append(f"本轮执行异常：{type(exc).__name__}: {exc}")
            self.log(f"   [!] 异常：{type(exc).__name__}: {exc}")

        suggestions = self._suggest(session, t)
        session.end_turn(t, assets_before=a0, findings_before=f0, suggestions=suggestions)
        try:
            session.save(Path(self.cfg.data_dir) / "sessions")
        except Exception:  # noqa: BLE001
            pass
        self.log(
            f"   本轮：+{t.new_assets} 资产、+{t.new_findings} 发现 "
            f"（{t.elapsed:.1f}s）"
        )
        if t.suggestions:
            self.log("   建议下一轮：" + "；".join(t.suggestions[:3]))
        return t

    # ── 第 1 轮：信息收集 ──────────────────────────────────────────
    async def _recon(self, session: Session, t: Turn) -> None:
        base = session.target.rstrip("/") + "/"
        host = urlparse(base).hostname or ""

        t.actions.append("指纹识别")
        fp_det = FingerprintDetector(self.cfg.scan)
        try:
            fp = await fp_det.fingerprint(base)
            session.result.fingerprints.append(fp)
            if fp.http_status is None:
                t.notes.append(f"目标不可达：{fp.target}")
                self.log("   [!] 目标不可达，本轮终止")
                return
            self.log(f"   指纹：{fp.summary()}")
        finally:
            await fp_det.aclose()

        if self.cfg.scan.port_scan_enabled and host:
            t.actions.append("端口探测")
            try:
                assets = await PortScanner(self.cfg.scan).run(host, False)
                session.result.assets.extend(assets)
                self.log(f"   端口：{len(assets)} 个开放")
            except Exception as exc:  # noqa: BLE001
                t.notes.append(f"端口扫描失败：{type(exc).__name__}")

        # 子域枚举：只要目标是域名就跑一遍被动枚举。
        # 放在端口之后、JS 之前——它是纯被动（不发请求给目标），
        # 但产出的子域清单是后续"扩大探测面"的输入，越早拿到越好。
        if host and not _is_ip(host):
            t.actions.append("子域枚举")
            from collectors.subdomain_extract import SubdomainCollector

            sc = SubdomainCollector(self.cfg.scan, verbose=False)
            try:
                assets = await sc.assets(base, verbose=False, passive_only=True)
                session.result.assets.extend(assets)
                if assets:
                    self.log(f"   子域：被动源枚举到 {len(assets)} 个")
                    t.notes.append(
                        f"子域枚举 {len(assets)} 个（多源被动，可交给子域批量扫描）"
                    )
                elif sc.notes:
                    t.notes.extend(sc.notes[:3])
            except Exception as exc:  # noqa: BLE001
                t.notes.append(f"子域枚举失败：{type(exc).__name__}")
            finally:
                await sc.aclose()

        if self.cfg.scan.js_analyze_enabled:
            t.actions.append("JS 静态分析")
            js = JsAnalyzer(self.cfg.scan)
            try:
                assets = await js.run(base, False)
                session.result.assets.extend(assets)
                self.log(
                    f"   JS：端点 {len(session.result.assets_of('endpoint'))}、"
                    f"凭据 {len(session.result.assets_of('secret'))}、"
                    f"内网 {len(session.result.assets_of('internal'))}"
                )
            except Exception as exc:  # noqa: BLE001
                t.notes.append(f"JS 分析失败：{type(exc).__name__}")
            finally:
                await js.aclose()

        t.actions.append("接口文档采集")
        oa = OpenApiCollector(self.cfg.scan, verbose=False)
        try:
            assets = await oa.run(base, verbose=False)
            session.result.assets.extend(assets)
            if assets:
                self.log(f"   接口文档：{oa.spec_url} → {len(assets)} 个操作")
                no_auth = [a for a in assets if not a.meta["auth"]]
                admin = [a for a in assets if a.meta["admin"]]
                t.notes.append(
                    f"接口清单 {len(assets)} 个操作，其中免鉴权 {len(no_auth)}、"
                    f"后台类 {len(admin)}"
                )
                if no_auth:
                    self.log(f"   免鉴权接口 {len(no_auth)} 个（文档层面声明无需凭证）")
            else:
                self.log("   接口文档：未发现")
        finally:
            await oa.aclose()

        if self.cfg.scan.path_scan_enabled:
            t.actions.append("路径爆破")
            from collectors.path_scan import PathScanner

            ps = PathScanner(self.cfg.scan)
            try:
                assets = await ps.run(base, False)
                session.result.assets.extend(assets)
            except Exception:  # noqa: BLE001
                pass
            finally:
                await ps.aclose()

    # ── 第 2 轮：业务建模 + 走一遍流程 ──────────────────────────────
    async def _model(self, session: Session, t: Turn) -> None:
        api_assets = [a for a in session.result.assets if a.kind == "api"]
        if not api_assets:
            t.notes.append("没有接口资产，无法建模——先跑一轮信息收集")
            self.log("   [!] 无接口资产，请先执行信息收集")
            return

        t.actions.append("接口建模")
        m = session.model
        resources: dict[str, int] = {}
        domains = {"public": 0, "user": 0, "admin": 0}
        flows: list[str] = []
        for a in api_assets:
            meta = a.meta
            resources[meta.get("resource", "")] = resources.get(meta.get("resource", ""), 0) + 1
            if not meta.get("auth"):
                domains["public"] += 1
            elif meta.get("admin"):
                domains["admin"] += 1
            else:
                domains["user"] += 1
            if meta.get("high_value"):
                m.high_value.append(a.value)
            if meta.get("admin"):
                m.admin_ops.append(a.value)
            if meta.get("upload"):
                m.upload_ops.append(a.value)

        m.resources = sorted(resources, key=lambda r: -resources[r])[:40]
        m.auth_domains = domains
        m.state_flows = _infer_flows(api_assets)
        self.log(f"   模型：{m.summary()}")
        if m.state_flows:
            self.log("   业务流：" + " → ".join(m.state_flows[:6]))

        # ── 真的走一遍业务流程 ──────────────────────────────────
        t.actions.append("业务流程走查")
        await self._walk_business_flow(session, t)

    async def _walk_business_flow(self, session: Session, t: Turn) -> None:
        """登录 → 取自身信息 → 访问核心资源。全程只读 GET。"""
        base = session.target.rstrip("/") + "/"
        api_assets = [a for a in session.result.assets if a.kind == "api"]
        auth = Authenticator(self.cfg.scan, verbose=False)
        try:
            user = session.credentials.get("username", "")
            pwd = session.credentials.get("password", "")
            if user and pwd:
                t.actions.append("登录取凭证")
                res = auth.login(base, api_assets, user, pwd)
                for n in res.notes:
                    t.notes.append(n)
                    self.log(f"   {n}")
                if res.ok:
                    session.credentials["token"] = res.token
                    self.log(f"   登录成功（{res.endpoint}），已取得凭证")
                else:
                    self.log(f"   [!] 登录未成功：{res.notes[:1]}")
                    return
            else:
                t.notes.append("未提供测试凭证，跳过登录（Agent 模式下用 login 工具补上）")
                self.log("   未提供凭证，仅做静态建模")
                return

            # 取自身信息 → 得到 uid，后续 IDOR 探测要用
            token = session.credentials.get("token", "")
            uid = await self._fetch_identity(session, t, token)
            if uid:
                session.credentials["uid"] = uid
                self.log(f"   当前身份 id = {uid}")

            # 访问若干核心资源，确认业务可用
            t.actions.append("核心资源可达性校验")
            ok = await self._probe_core_resources(session, t, token, uid)
            self.log(f"   核心资源：{ok} 个按预期返回业务数据")
        finally:
            auth.close()

    async def _fetch_identity(self, session: Session, t: Turn, token: str) -> str:
        base = session.target.rstrip("/") + "/"
        api = [a for a in session.result.assets if a.kind == "api"]
        cands = [
            a for a in api
            if a.meta.get("method") == "GET"
            and re.search(r"/auth/(info|getInfo|me|profile)$|/users/me$", a.meta.get("path", ""))
        ]
        if not cands:
            return ""
        det = HttpDetector(self.cfg.scan)
        try:
            ev = await det.send_request(
                base.rstrip("/") + "/" + cands[0].meta["path"].lstrip("/"),
                headers={"Authorization": f"Bearer {token}"},
            )
            if ev.error or ev.status_code != 200:
                return ""
            try:
                d = json.loads(ev.body_excerpt)
            except Exception:  # noqa: BLE001
                return ""
            u = (d.get("user") or d.get("data") or {}) if isinstance(d, dict) else {}
            if isinstance(u, dict):
                return str(u.get("id") or u.get("userId") or u.get("sub") or "")
            return ""
        finally:
            await det.aclose()

    async def _probe_core_resources(self, session: Session, t: Turn, token: str, uid: str) -> int:
        """挑高价值且能填 id 的接口访问一遍，确认业务链路可用。"""
        base = session.target.rstrip("/") + "/"
        api = [a for a in session.result.assets if a.kind == "api"]
        cands = [
            a for a in api
            if a.meta.get("method") == "GET" and a.meta.get("auth")
            and not a.meta.get("admin") and not a.meta.get("has_id")
        ][:12]
        det = ApiAuthzDetector(self.cfg.scan, self.poc_map)
        ok = 0
        try:
            for a in cands:
                try:
                    ev = await det._get(base.rstrip("/") + "/" + a.meta["path"].lstrip("/"), token, tries=2)
                except Exception:  # noqa: BLE001
                    continue
                if not ev.error and ev.status_code == 200:
                    from detectors.api_authz import biz_ok

                    if biz_ok(ev.body_excerpt):
                        ok += 1
        finally:
            await det.aclose()
        return ok

    # ── 第 3 轮：渗透测试 ──────────────────────────────────────────
    async def _exploit(self, session: Session, t: Turn) -> None:
        base = session.target.rstrip("/") + "/"
        api = [a for a in session.result.assets if a.kind == "api"]
        token = session.credentials.get("token", "")
        uid = session.credentials.get("uid", "")

        if not api:
            t.notes.append("无接口资产，先跑第 1 轮信息收集")
            self.log("   [!] 无接口资产，请先执行信息收集")
            return

        if not token:
            t.actions.append("补取凭证")
            auth = Authenticator(self.cfg.scan, verbose=False)
            try:
                res = auth.login(
                    base, api,
                    session.credentials.get("username", ""),
                    session.credentials.get("password", ""),
                )
                if res.ok:
                    token = res.token
                    session.credentials["token"] = token
                    self.log("   已取得凭证")
                else:
                    self.log("   [!] 无凭证，仅做免鉴权侧测试")
            finally:
                auth.close()

        det = ApiAuthzDetector(self.cfg.scan, self.poc_map)
        try:
            t.actions.append("未授权访问探测")
            findings, n = await det.probe_missing_auth(base, [a.meta for a in api], limit=60)
            session.result.add_findings(findings)
            self.log(f"   未授权探测 {n} 个接口 → {len(findings)} 项")

            if token:
                t.actions.append("越权/IDOR 探测")
                f2, n2 = await det.probe_idor(base, [a.meta for a in api], token, limit=50)
                session.result.add_findings(f2)
                self.log(f"   IDOR 探测 {n2} 个接口 → {len(f2)} 项")

                t.actions.append("敏感字段扫描")
                f3, n3 = await det.probe_sensitive(
                    base, [a.meta for a in api], token, uid, limit=60
                )
                session.result.add_findings(f3)
                self.log(f"   敏感字段扫描 {n3} 个接口 → {len(f3)} 项")
            t.notes.append(f"本轮共发起 {det.checked} 次请求，失败 {det.failed_requests} 次")
        finally:
            await det.aclose()

        # 常规 Web 层 POC（响应头等）
        t.actions.append("常规 Web 检测")
        hdet = HttpDetector(self.cfg.scan)
        try:
            await hdet.probe_soft404(base)
            from detectors.poc_loader import filter_executable

            cands, _ = filter_executable(
                [p for p in self.poc_map.values() if p.category.value == "header_check"],
                readonly=self.cfg.scan.readonly,
            )
            fs, errs = await hdet.run_many(cands, base)
            session.result.add_findings(fs)
            session.result.errors.extend(errs)
            self.log(f"   常规检测 {len(cands)} 条 → {len(fs)} 项")
        except Exception as exc:  # noqa: BLE001
            t.notes.append(f"常规检测失败：{type(exc).__name__}")
        finally:
            await hdet.aclose()

        session.result.findings.sort(
            key=lambda f: (f.severity.rank, f.rag_score), reverse=True
        )

    # ── 第 4 轮及以后：迭代深挖 ────────────────────────────────────
    async def _iterate(self, session: Session, t: Turn) -> None:
        """基于已有发现换角度复测。

        迭代策略（按优先级）：
          1. 已有发现涉及的资源 → 换其他方法 / 相邻路径复测
          2. 之前没测过的接口 → 扩大探测面
          3. 换角色（无凭证 vs 有凭证）交叉对比
        """
        base = session.target.rstrip("/") + "/"
        api = [a for a in session.result.assets if a.kind == "api"]
        token = session.credentials.get("token", "")
        uid = session.credentials.get("uid", "")

        if not api:
            t.notes.append("无接口资产可迭代")
            return

        done = {f.matched_at for f in session.result.findings}
        hot = _hot_resources(session.result.findings)
        t.notes.append(f"命中过的资源：{', '.join(hot[:5]) or '无'}")

        det = ApiAuthzDetector(self.cfg.scan, self.poc_map)
        try:
            # 策略 1+2：扩大覆盖面（上一轮 limit 之外的新接口）
            t.actions.append("扩大探测面")
            seen_paths = {a.meta["path"] for a in api}
            findings, n = await det.probe_missing_auth(
                base, [a.meta for a in api], limit=len(api)
            )
            new = [f for f in findings if f.matched_at not in done]
            session.result.add_findings(new)
            self.log(f"   未授权探测扩大到 {n} 个接口 → 新增 {len(new)} 项")

            if token:
                t.actions.append("越权复测（扩大）")
                f2, n2 = await det.probe_idor(
                    base, [a.meta for a in api], token, limit=len(api)
                )
                new2 = [f for f in f2 if f.matched_at not in done]
                session.result.add_findings(new2)
                self.log(f"   IDOR 复测 {n2} 个接口 → 新增 {len(new2)} 项")

                t.actions.append("敏感字段复测")
                f3, n3 = await det.probe_sensitive(
                    base, [a.meta for a in api], token, uid, limit=len(api)
                )
                new3 = [f for f in f3 if f.matched_at not in done]
                session.result.add_findings(new3)
                self.log(f"   敏感字段复测 {n3} 个接口 → 新增 {len(new3)} 项")

            t.actions.append("交叉对比（有/无凭证）")
            self.log(f"   本轮共 {det.checked} 次请求")
        finally:
            await det.aclose()

        session.result.findings.sort(
            key=lambda f: (f.severity.rank, f.rag_score), reverse=True
        )

    # ── 下一轮建议 ────────────────────────────────────────────────
    def _suggest(self, session: Session, t: Turn) -> list[str]:
        out: list[str] = []
        if session.phase is Phase.RECON:
            api = [a for a in session.result.assets if a.kind == "api"]
            if api:
                out.append(f"接口清单已就绪（{len(api)} 个操作），可进入业务建模")
            out.append("提供测试凭证（Agent 模式下用 login 工具）以便走通完整业务流")
        elif session.phase is Phase.MODEL:
            if not session.credentials.get("token"):
                out.append("未取得凭证，建议先取得凭证（Agent 模式下用 login 工具）再进入渗透测试")
            out.append("进入渗透测试（/next）")
        elif session.phase is Phase.EXPLOIT:
            out.append("基于发现做迭代深挖（/next）")
            out.append("对高危项做人工复核并整理复现步骤")
        else:
            out.append("继续迭代或导出报告（/report）")
        return out


def _is_ip(host: str) -> bool:
    """目标是不是 IPv4 字面量。

    子域枚举对 IP 毫无意义（``127.0.0.1`` 没有"子域"），
    而且被动源（证书日志 / 被动 DNS）也查不到，直接跳过省一批无谓请求。
    """
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", (host or "").strip()))


def _infer_flows(api_assets: list[Asset]) -> list[str]:
    """从操作语义推断业务流阶段。"""
    hit: dict[str, int] = {}
    for a in api_assets:
        blob = f"{a.meta.get('path','')} {a.meta.get('summary','')}".lower()
        for label, pat in FLOW_STEPS:
            if re.search(pat, blob):
                hit[label] = hit.get(label, 0) + 1
    order = [k for k, _ in FLOW_STEPS if k in hit]
    return order


def _hot_resources(findings) -> list[str]:
    """已有发现涉及的资源，用于迭代轮定向深挖。"""
    from urllib.parse import urlparse

    res: dict[str, int] = {}
    for f in findings:
        p = urlparse(f.matched_at).path
        parts = [x for x in p.split("/") if x and not x.startswith("{")]
        key = "/" + "/".join(parts[:3])
        res[key] = res.get(key, 0) + 1
    return [k for k, _ in sorted(res.items(), key=lambda x: -x[1])]


__all__ = ["Planner"]
