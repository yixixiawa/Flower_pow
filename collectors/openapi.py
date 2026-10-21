"""OpenAPI / Swagger 接口文档采集器——第 1 轮信息收集的主力。

为什么把它做成采集器而不是一次性脚本
------------------------------------
**接口文档是最准确的资产清单。** 目录爆破是在猜，而文档是目标自己承认的东西：
有多少接口、每个接口要什么参数、哪些需要鉴权、哪些是后台专用。

实测对比（ftitle.studio）：目录爆破命中个位数路径，而文档直接给出
**404 条路径 / 507 个操作**，并且明确标出了 47 个后台管理接口。
这份清单同时是第 2 轮建模的输入和第 3 轮测试的用例集。

产出的每个操作都是一个 ``Asset(kind="api")``，meta 里带着后续阶段要用的判断依据：
``auth``（文档是否声明鉴权）、``admin``（是否后台）、``has_id``（是否按 id 取资源，
即 IDOR 候选）、``remote_url``（是否接受远程 URL，即 SSRF 候选）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from core.state import Asset

# 各框架的规范文件常见位置。Swagger UI 是 SPA，HTML 里取不到数据，
# 只能按框架约定逐个探测。
SPEC_CANDIDATES = [
    "/api/docs-json",          # NestJS 默认
    "/api/docs/json",
    "/api-json",               # NestJS 另一种配置
    "/api/swagger.json",
    "/api/v2/api-docs",        # Springfox
    "/v3/api-docs",            # springdoc
    "/v2/api-docs",
    "/openapi.json",           # FastAPI / 通用
    "/api/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/docs/swagger.json",
]

METHODS = ("get", "post", "put", "patch", "delete")

# 后台 / 管理语义关键词
ADMIN_RE = re.compile(r"admin|后台|manage|management|sys(config|tem)|internal", re.I)
# 资金 / 凭据 / 权限 —— 越权后果最严重的一类
HIGH_VALUE_RE = re.compile(
    r"recharge|balance|payment|pay|order|refund|withdraw|invoice|"
    r"password|credential|token|secret|key|permission|role|user|account|plan|allocat",
    re.I,
)
# 接受远程 URL 的参数名 —— SSRF 候选
REMOTE_URL_RE = re.compile(r"^(url|uri|src|link|target|remote|fetch|callback|webhook)$", re.I)


@dataclass
class Operation:
    """一个 API 操作（方法 + 路径）。"""

    method: str
    path: str
    summary: str = ""
    tags: list[str] = None  # type: ignore[assignment]
    auth: bool = True          # 文档是否声明了 security
    params: list[str] = None   # type: ignore[assignment]
    body_fields: list[str] = None  # type: ignore[assignment]

    @property
    def id(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def resource(self) -> str:
        """资源归类：/api/users/{id}/balance → /api/users"""
        parts = [p for p in self.path.split("/") if p and not p.startswith("{")]
        return "/" + "/".join(parts[:3]) if parts else self.path

    @property
    def has_id(self) -> bool:
        return "{" in self.path

    @property
    def is_admin(self) -> bool:
        blob = f"{self.path} {self.summary} {' '.join(self.tags or [])}"
        return bool(ADMIN_RE.search(blob))

    @property
    def is_high_value(self) -> bool:
        blob = f"{self.path} {self.summary}"
        return bool(HIGH_VALUE_RE.search(blob))

    @property
    def is_upload(self) -> bool:
        blob = f"{self.path} {self.summary}".lower()
        return "upload" in blob or "import" in blob or "proxy" in blob

    def to_asset(self) -> Asset:
        return Asset(
            kind="api",
            value=self.id,
            meta={
                "method": self.method.upper(),
                "path": self.path,
                "summary": self.summary,
                "tags": self.tags or [],
                "auth": self.auth,
                "admin": self.is_admin,
                "high_value": self.is_high_value,
                "has_id": self.has_id,
                "upload": self.is_upload,
                "resource": self.resource,
                "params": self.params or [],
                "body_fields": self.body_fields or [],
            },
            source="openapi",
        )


class OpenApiCollector:
    """下载并解析 OpenAPI 规范，产出 API 资产清单。"""

    def __init__(self, cfg, verbose: bool = False) -> None:
        self.cfg = cfg
        self.verbose = verbose
        self.spec_url: str = ""
        self.spec: dict = {}
        self._client: httpx.AsyncClient | None = None
        self._base_url: str = ""   # 代理决策需要知道目标主机

    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            from core.proxy import build_client_kwargs

            # 代理决策收敛到 core/proxy.py：内网/本机直连，公网走代理。
            self._client = httpx.AsyncClient(
                **build_client_kwargs(self.cfg, self._base_url)
            )
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── 探测 ──────────────────────────────────────────────────────
    async def find_spec(self, base_url: str) -> str:
        """探测规范文件地址。判断依据是 content-type 含 json 且体积够大。"""
        base = base_url if base_url.endswith("/") else base_url + "/"
        origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
        for cand in SPEC_CANDIDATES:
            url = urljoin(origin, cand)
            try:
                r = await self.client().get(url)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code != 200:
                continue
            ct = (r.headers.get("content-type") or "").lower()
            if "json" not in ct and "yaml" not in ct:
                continue
            text = r.text
            if len(text) < 200:
                continue
            # 必须是真的 OpenAPI：有 paths 或 swagger/openapi 字段
            if '"paths"' not in text and "'paths'" not in text:
                continue
            self.spec_url = url
            return url
        return ""

    async def fetch(self, base_url: str) -> bool:
        """下载规范。失败返回 False（文档不可达不是错误，只是少一个资产源）。"""
        url = await self.find_spec(base_url)
        if not url:
            return False
        try:
            r = await self.client().get(url)
            self.spec = json.loads(r.text)
        except Exception:  # noqa: BLE001
            return False
        return bool(self.spec.get("paths"))

    # ── 解析 ──────────────────────────────────────────────────────
    def operations(self) -> list[Operation]:
        """把规范解析成操作列表。"""
        if not self.spec:
            return []
        paths = self.spec.get("paths") or {}
        schemas = (self.spec.get("components") or {}).get("schemas") or {}
        out: list[Operation] = []
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for m, op in item.items():
                if m not in METHODS or not isinstance(op, dict):
                    continue
                params = [
                    str(p.get("name") or "")
                    for p in (op.get("parameters") or [])
                    if isinstance(p, dict)
                ]
                body_fields: list[str] = []
                rb = (op.get("requestBody") or {}).get("content") or {}
                for _ct, c in rb.items():
                    if not isinstance(c, dict):
                        continue
                    sch = c.get("schema") or {}
                    ref = str(sch.get("$ref") or "").split("/")[-1]
                    if ref and ref in schemas:
                        body_fields.extend((schemas[ref].get("properties") or {}).keys())
                    body_fields.extend((sch.get("properties") or {}).keys())
                out.append(
                    Operation(
                        method=m,
                        path=path,
                        summary=str(op.get("summary") or ""),
                        tags=[str(t) for t in (op.get("tags") or [])],
                        auth=bool(op.get("security")),
                        params=[p for p in params if p],
                        body_fields=sorted(set(body_fields)),
                    )
                )
        return out

    # ── 采集器统一入口 ────────────────────────────────────────────
    async def run(self, base_url: str, verbose: bool = False) -> list[Asset]:
        """产出 API 资产列表，并把规范落盘供后续轮次复用。"""
        verbose = verbose or self.verbose
        self._base_url = base_url
        await self.aclose()   # 目标变了就换客户端，代理决策跟着变
        ok = await self.fetch(base_url)
        if not ok:
            if verbose:
                print("      OpenAPI：未发现可访问的接口文档（跳过）")
            return []
        ops = self.operations()
        assets = [o.to_asset() for o in ops]
        self.save_spec(base_url)
        if verbose:
            no_auth = sum(1 for a in assets if not a.meta["auth"])
            admin = sum(1 for a in assets if a.meta["admin"])
            print(
                f"      OpenAPI：{self.spec_url} → "
                f"{len(assets)} 个操作（免鉴权 {no_auth}、后台 {admin}）"
            )
        return assets

    def save_spec(self, base_url: str) -> Path | None:
        host = urlparse(base_url).netloc.replace(":", "_").replace(".", "_")
        p = Path("data/recon") / f"openapi_{host}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.spec, ensure_ascii=False), encoding="utf-8")
        return p


def load_operations(session_dir: str | Path, host: str) -> list[Operation]:
    """从落盘的规范重建操作列表（第 2/3 轮用，避免重复下载）。"""
    return []


def spec_path(host: str) -> Path:
    return Path("data/recon") / f"openapi_{host.replace(':', '_').replace('.', '_')}.json"


__all__ = ["OpenApiCollector", "Operation", "SPEC_CANDIDATES", "spec_path"]
