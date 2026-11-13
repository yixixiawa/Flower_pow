"""接口鉴权检测器——第 3 轮渗透测试的主力。

三条检查线，各自对应 poc/api_authz__*.yaml：

* ``api-missing-auth``　声明了鉴权却不带凭证也能读 → 未授权访问
* ``api-idor``　　　　　换掉资源 id 仍能读 → 越权 / IDOR
* ``api-sensitive-field``　响应体里出现凭据材料 → 敏感字段出网

两条必须记住的实现约束
----------------------
**1. 不能只看 HTTP 状态码。** 不少站点（含 NestJS 系）所有响应恒为 200，
鉴权失败是 ``{"code":401}``。按状态码判定会把一切误判为"可访问"。
判定必须落到业务码 + 响应体是否真有数据（见 :func:`biz_ok`）。

**2. 网络抖动必须重试。** 目标链路偶发 TCP RST（实测约 30%），
不重试会把抖动误判成"接口鉴权生效"，产生假阴性——这比假阳性更危险，
因为假阴性会让人以为系统没问题。

只读约束：GET 全量探测；POST 只探「查询型」接口。
不少后端（尤其国内惯例）查询接口也走 POST（``POST /api/user/detail``
＋ ``{"id": ...}``），只发 GET 会整类漏掉。POST 探测的边界：

* 请求体只填 **id 类字段**（``orderId`` / ``user_id`` …），其余字段一律不带，
  让服务端的参数校验替我们挡住副作用；
* 路径/摘要命中 :data:`WRITE_RE`（创建/支付/删除/审批…）的 POST **一律跳过**；
* PUT/DELETE 仍然不发。
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import secrets
import uuid
from typing import Iterable

from core.state import Evidence, Finding, POC, Severity
from detectors.base import Detector
from detectors.poc_loader import load_poc_map

# 不应出网的凭据类字段
SENSITIVE_RE = re.compile(
    r"passwordHash|\"password\"\s*:\s*\"|password_hash|\"salt\"\s*:|"
    r"privateKey|accessKeySecret|secretKey|apiSecret|\"token\"\s*:\s*\"ey",
    re.I,
)

# 业务码里表示"成功"的值
OK_CODES = {200, 0, "200", "0"}
# 只有这些键说明是纯错误响应，没有携带数据
ERROR_ONLY_KEYS = {"code", "msg", "message", "success", "timestamp", "path", "error", "statusCode"}

# POST 探测的黑名单：路径/摘要命中任一关键词的 POST 接口一律不发。
# 往创建/支付/删除类接口塞探测体，轻则留脏数据，重则造成资金/状态变更——
# 这比漏报更不可接受。GET 不受此名单约束（GET 天然无副作用，命中了也只是 405）。
WRITE_RE = re.compile(
    r"create|add\b|insert|save|update|edit|modify|del(?:ete)?\b|remove|"
    r"upload|import|export|submit|apply|cancel|audit|approv|reject|review|"
    r"bind|unbind|enable|disable|reset|toggle|switch|move|batch|"
    r"login|logout|register|signin|signup|passwd|password|"
    r"pay|refund|transfer|withdraw|recharge|send|push|notice",
    re.I,
)


def _is_id_field(name: str) -> bool:
    """判断 body 字段名是否是 id 类（``orderId`` / ``user_id`` / ``owner``…）。"""
    n = str(name).strip().lower().replace("_", "")
    return n.endswith("id") or n == "owner"


def post_body(meta: dict, id_value: str = "") -> str:
    """按接口元数据构造 POST 探测体（JSON 字符串）。

    只填 id 类字段：查询型 POST（``POST /api/order/detail`` ＋ ``{"orderId":..}``）
    是国内后端的常见形态，空体只会换来参数校验错误，等于白跑。
    其余字段一律不带——不带值的服务端校验会挡住创建类副作用，这是
    "探测不改动业务数据"边界在 POST 上的落点。没有 id 类字段就发空对象。
    """
    fields = meta.get("body_fields") or []
    id_fields = [f for f in fields if _is_id_field(f)]
    if id_fields and id_value:
        return json.dumps({str(f): id_value for f in id_fields})
    return "{}"


def join_url(base: str, path: str) -> str:
    """拼接 base 与 path，避免 ``//api/...`` 双斜杠（详见 core.auth.join_url）。"""
    return base.rstrip("/") + "/" + path.lstrip("/")


def biz_ok(text: str) -> bool:
    """判断响应是否代表「真的拿到了数据」。

    这是 IDOR / 越权判定的**唯一**依据，误判会直接变成漏洞结论，所以两个方向
    都要准：

      - **假阳性**（空壳当成功）→ 把 ``{"code":200,"data":null}`` 报成 IDOR 漏洞
      - **假阴性**（有数据当失败）→ 漏掉真实越权

    判定分两层：

      1. **业务码**：有 ``code`` 字段时必须属于成功值（无 ``code`` 则跳过——
         裸 REST 接口很常见）
      2. **有效载荷**：递归探测是否存在**非空叶子**。空对象、空列表、
         ``null``、``""``、``0``、``false`` 全部不算数据。
         这一层必须递归——真实响应常是 ``{"data":{"list":[...]}}``，
         只看顶层会把真实数据判成空壳。
    """
    try:
        d = json.loads(text)
    except Exception:  # noqa: BLE001
        return False

    if isinstance(d, dict):
        code = d.get("code")
        if code is not None:
            # 字符串业务码（"0"/"200"）与数字混用是常态，统一转 str 比对
            if str(code) not in {str(c) for c in OK_CODES}:
                return False
        # code 成功时，载荷可能直接摊在顶层，也可能在 data/result 等包裹里
        if _has_payload({k: v for k, v in d.items() if str(k).lower() not in ERROR_ONLY_KEYS}):
            return True
        # 只有错误字段 → 纯错误响应
        return False
    return _has_payload(d)


def _has_payload(obj: object, _depth: int = 0) -> bool:
    """递归判断 ``obj`` 里是否存在有意义的（非空）叶子值。

    深度上限 8 层：超过就返回 False 而不是无限递归——防的是畸形/攻击性响应
    构造出的环或超深结构，宁可漏报也不能把扫描器自己搞挂。
    """
    if _depth > 8:
        return False
    if obj is None or isinstance(obj, bool):
        # ``false`` / ``true``：布尔本身不携带数据（如 ``"success": true``）
        return False
    if isinstance(obj, (int, float)):
        return obj != 0  # 0 视作空（常见于"数量为 0"的成功响应）
    if isinstance(obj, str):
        return bool(obj.strip())
    if isinstance(obj, (list, tuple, set)):
        return any(_has_payload(v, _depth + 1) for v in obj)
    if isinstance(obj, dict):
        return any(_has_payload(v, _depth + 1) for v in obj.values())
    return False


def fill_path(path: str, value: str) -> str | None:
    """把路径参数填成给定值。含非 id 类占位符的返回 None（不猜参数）。"""
    slots = re.findall(r"\{([^}]+)\}", path)
    if not slots:
        return path
    if not all(re.search(r"(^id$|id$|userId|owner)", s, re.I) for s in slots):
        return None
    out = path
    for s in slots:
        out = out.replace("{" + s + "}", value)
    return out


class ApiAuthzDetector(Detector):
    """基于接口清单做鉴权验证。"""

    name = "api_authz"

    def __init__(self, cfg, poc_map: dict[str, POC] | None = None) -> None:
        super().__init__(cfg)
        self.poc_map = poc_map or {}
        self.checked = 0
        self.failed_requests = 0

    # ── 请求（带重试）──────────────────────────────────────────────
    async def _send(
        self, url: str, method: str = "GET", token: str | None = None,
        body: str = "", tries: int = 3,
    ) -> Evidence:
        """GET/POST 统一出口：带可选凭证、JSON 体与网络抖动重试。"""
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body and method.upper() != "GET":
            headers["Content-Type"] = "application/json"
        ev = Evidence(url=url, method=method)
        for i in range(tries):
            ev = await self.send_request(
                url, method=method, headers=headers or None, body=body
            )
            if not ev.error:
                return ev
            if i + 1 < tries:
                await asyncio.sleep(0.6 + i * 1.2)
        self.failed_requests += 1
        return ev

    async def _get(self, url: str, token: str | None = None, tries: int = 3) -> Evidence:
        return await self._send(url, "GET", token=token, tries=tries)

    async def _post(
        self, url: str, token: str | None = None, body: str = "{}", tries: int = 3
    ) -> Evidence:
        return await self._send(url, "POST", token=token, body=body, tries=tries)

    def _poc(self, pid: str, fallback_name: str, sev: Severity) -> POC:
        p = self.poc_map.get(pid)
        if p is not None:
            return p
        return POC(
            id=pid, name=fallback_name, category=__import__(
                "core.state", fromlist=["Category"]).Category.API_AUTHZ,
            severity=sev, description=fallback_name,
        )

    # ── 1. 未授权访问 ──────────────────────────────────────────────
    async def probe_missing_auth(
        self, base: str, ops: Iterable[dict], limit: int = 60, concurrency: int = 5
    ) -> tuple[list[Finding], int]:
        """不带凭证访问「文档声明需要鉴权」的 GET / 查询型 POST 接口。"""
        poc = self._poc("api-missing-auth", "接口未授权可访问", Severity.HIGH)
        targets = self._rank(ops, only_auth=True, methods=("GET", "POST"))[:limit]
        sem = asyncio.Semaphore(concurrency)

        async def one(meta: dict) -> Finding | None:
            url = join_url(base, meta["path"])
            async with sem:
                if str(meta.get("method", "GET")).upper() == "POST":
                    # 未授权阶段没有可信 id，探测体保持空对象
                    ev = await self._post(url)
                else:
                    ev = await self._get(url)
            self.checked += 1
            if ev.error or ev.status_code != 200:
                return None
            if not biz_ok(ev.body_excerpt):
                return None
            f = self.make_finding(poc, ev, 0.0, extra_tags=["unauthenticated"])
            f.description = (
                f"{poc.description}\n\n"
                f"接口：{meta['method']} {meta['path']}"
                + (f"（{meta['summary']}）" if meta.get("summary") else "")
                + f"\n不带任何凭证直接请求即返回业务数据（HTTP {ev.status_code}）。"
            )
            return f

        results = await asyncio.gather(*[one(m) for m in targets])
        return [r for r in results if r is not None], len(targets)

    # ── 2. IDOR / 越权 ────────────────────────────────────────────
    async def probe_idor(
        self,
        base: str,
        ops: Iterable[dict],
        token: str,
        limit: int = 50,
        concurrency: int = 5,
        seed: int | None = None,
        candidate_ids: list[str] | None = None,
    ) -> tuple[list[Finding], int]:
        """带着自己的凭证访问「别人的」资源 id。

        ``seed`` / ``candidate_ids`` 用于**可复现性**：

          - 都不传（默认）→ 用 ``secrets`` 取随机 UUID。同一目标多次跑 ID 不同，
            避免被基于行为基线的 WAF 识别成"这个客户端一直在扫固定 ID"。
          - 传 ``seed``（如 ``seed=20261006``）→ 同一 seed 必得同一 ID，用于
            复现历史结果、写测试、对比多次扫描的差异。
          - 传 ``candidate_ids`` → 直接指定要试的 ID，可从业务侧捞真实存在的
            他人 ID（比随机 UUID 命中率高得多）。
        """
        poc = self._poc("api-idor", "接口越权读取他人资源（IDOR）", Severity.HIGH)
        cands = [
            m for m in self._rank(ops, only_auth=True, methods=("GET", "POST"))
            if self._idor_candidate(m)
        ]
        cands = cands[:limit]
        others = self._idor_ids(seed=seed, candidate_ids=candidate_ids)
        sem = asyncio.Semaphore(concurrency)

        async def one(meta: dict) -> Finding | None:
            filled = fill_path(meta["path"], others[0])
            if filled is None:
                return None
            url = join_url(base, filled)
            async with sem:
                if str(meta.get("method", "GET")).upper() == "POST":
                    ev = await self._post(url, token, body=post_body(meta, others[0]))
                else:
                    ev = await self._get(url, token)
            self.checked += 1
            if ev.error or ev.status_code != 200 or len(ev.body_excerpt) < 40:
                return None
            if not biz_ok(ev.body_excerpt):
                return None
            f = self.make_finding(poc, ev, 0.0, extra_tags=["idor"])
            f.description = (
                f"{poc.description}\n\n"
                f"接口：{meta['method']} {meta['path']}\n"
                f"用非本人资源 id `{others[0]}` 请求，仍返回业务数据"
                f"（HTTP {ev.status_code}），说明服务端未校验资源归属。"
            )
            return f

        results = await asyncio.gather(*[one(m) for m in cands])
        return [r for r in results if r is not None], len(cands)

    @staticmethod
    def _idor_candidate(meta: dict) -> bool:
        """能否对这条接口做 IDOR：资源 id 可被替换成「别人的」。

        两条通道任一满足即可：路径占位符是 id 类（``/api/users/{id}``），
        或查询型 POST 的 **body 字段里有 id 类**（``POST /api/order/detail``
        ＋ ``{"orderId":..}``——POST-only 接口的资源标识在体里，只看路径
        会把这类整块漏掉）。
        """
        if meta.get("has_id"):
            return True
        if str(meta.get("method", "")).upper() != "POST":
            return False
        return any(_is_id_field(f) for f in (meta.get("body_fields") or []))

    @staticmethod
    def _idor_ids(
        seed: int | None = None, candidate_ids: list[str] | None = None
    ) -> list[str]:
        """生成用于 IDOR 探测的「他人」资源 ID 列表。

        优先级：``candidate_ids`` > ``seed``（可复现）> 默认随机（躲行为检测）。
        用 ``secrets`` 而非 ``random`` 是因为这是**安全测试**：ID 不可预测性
        直接关系到探测是否有效，用伪随机会被关联分析还原出规律。
        """
        if candidate_ids:
            return [str(x).strip() for x in candidate_ids if str(x).strip()]
        if seed is not None:
            return [str(uuid.UUID(int=random.Random(seed).getrandbits(128)))]
        return [str(uuid.UUID(int=secrets.randbits(128)))]

    # ── 3. 敏感字段出网 ────────────────────────────────────────────
    async def probe_sensitive(
        self, base: str, ops: Iterable[dict], token: str, uid: str = "",
        limit: int = 60, concurrency: int = 5,
    ) -> tuple[list[Finding], int]:
        """已登录视角遍历自身资源接口（GET / 查询型 POST），找响应体里的凭据字段。"""
        poc = self._poc("api-sensitive-field", "接口响应体回传敏感字段", Severity.MEDIUM)
        targets = self._rank(ops, only_auth=True, methods=("GET", "POST"))[:limit]
        sem = asyncio.Semaphore(concurrency)

        async def one(meta: dict) -> Finding | None:
            path = fill_path(meta["path"], uid) if meta.get("has_id") else meta["path"]
            if path is None:
                return None
            url = join_url(base, path)
            async with sem:
                if str(meta.get("method", "GET")).upper() == "POST":
                    ev = await self._post(url, token, body=post_body(meta, uid))
                else:
                    ev = await self._get(url, token)
            self.checked += 1
            if ev.error or ev.status_code != 200:
                return None
            m = SENSITIVE_RE.search(ev.body_excerpt)
            if not m:
                return None
            f = self.make_finding(poc, ev, 0.0, extra_tags=["disclosure"])
            f.description = (
                f"{poc.description}\n\n"
                f"接口：{meta['method']} {meta['path']}\n"
                f"响应体中命中字段 `{m.group(0)}`。"
            )
            return f

        results = await asyncio.gather(*[one(m) for m in targets])
        return [r for r in results if r is not None], len(targets)

    # ── 排序：高价值优先 ────────────────────────────────────────────
    # 身份/自身信息类接口必须排在最前：它们直接返回用户对象，
    # 是 passwordHash 这类凭据字段出网的高发区。
    # 实测踩坑：ftitle.studio 上 `/api/auth/info` 按纯关键词打分排在
    # 第 81 位（因为路径里没有 user/pay/log 等词），被 limit=60 挤出，
    # 导致第 3 轮漏掉了已确认存在的凭据泄露。加了身份权重后进入前 10。
    _IDENTITY = ("auth", "/info", "getinfo", "/me", "profile", "whoami")
    _VALUABLE = (
        "user", "admin", "log", "balance", "order", "pay", "config",
        "price", "plan", "account", "allocat", "usage", "secret", "token",
        "credential", "permission", "role",
    )

    @classmethod
    def _rank(
        cls, ops: Iterable[dict], only_auth: bool = True,
        methods: Iterable[str] = ("GET",),
    ) -> list[dict]:
        """按价值排序的候选接口。

        ``methods`` 限定探测的 HTTP 方法集合；POST 额外过 :data:`WRITE_RE`
        写操作黑名单——查询型 POST 才进队列，创建/支付/删除类一律不发。
        """
        allowed = {str(m).upper() for m in methods}
        out = []
        for m in ops:
            if only_auth and not m.get("auth", True):
                continue      # 文档层面本就公开的不测
            method = str(m.get("method", "GET")).upper()
            if method not in allowed:
                continue      # 方法不在本批探测范围
            if method == "POST" and WRITE_RE.search(
                f"{m.get('path', '')} {m.get('summary', '')}"
            ):
                continue      # 写操作类 POST：探测体可能触发业务变更，跳过
            if "{" in m.get("path", "") and not m.get("has_id"):
                continue      # 路径参数不是 id 类，填不了就不猜
            blob = f"{m.get('path','')} {m.get('summary','')}".lower()
            score = sum(1 for k in cls._VALUABLE if k in blob)
            if any(k in blob for k in cls._IDENTITY):
                score += 5
            out.append((score, m))
        out.sort(key=lambda x: (-x[0], x[1].get("path", "")))
        return [m for _, m in out]

    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list[Finding]:
        """接口类 POC 不走单条 verify（需要接口清单），这里返回空。"""
        return []


def load_api_pocs(poc_dir: str = "./poc") -> dict[str, POC]:
    pm, _ = load_poc_map(poc_dir)
    return pm


__all__ = ["ApiAuthzDetector", "biz_ok", "fill_path", "SENSITIVE_RE", "WRITE_RE", "post_body"]
