"""登录与凭证获取——由接口清单驱动，而不是写死某个站的路径。

登录端点、字段名、是否需要验证码，全部从 OpenAPI 资产里推导：

* 登录端点：路径含 ``login`` 的 POST 操作
* 验证码端点：路径含 ``captcha`` 的 GET 操作
* 字段名：取该操作 requestBody 的 schema 属性（username / email / password / code / uuid）

这样换一个目标也能用，而不是为某个站写死一套。

验证码处理
----------
若验证码是 **SVG**（字符明文写在 ``<text>`` 标签里），直接正则还原。
这不是"破解"，而是记录一个事实：以纯文本 SVG 下发验证码，
等于把答案和题目一起发给客户端，任何人都能零成本自动识别。
若站点因此被自动化滥用，根因在服务端选错了验证码载体。
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

import httpx

from core.state import Asset

LOGIN_RE = re.compile(r"login|signin|sign-in|authenticate", re.I)
CAPTCHA_RE = re.compile(r"captcha|verify.?code|validate.?code", re.I)
SVG_TEXT_RE = re.compile(r"<text[^>]*>(.*?)</text>", re.S)

# 登录响应里 token 可能出现的字段名
TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "idToken")


@dataclass
class AuthResult:
    ok: bool
    token: str = ""
    endpoint: str = ""
    captcha_endpoint: str = ""
    captcha_kind: str = ""          # svg | image | none
    # 用 default_factory 而不是 None + __post_init__ 兜底：后者让类型标注
    # 写谎（``list[str]`` 实际可能是 None），静态检查与 IDE 补全会跟着错
    notes: list[str] = field(default_factory=list)
    raw: str = ""


def join_url(base: str, path: str) -> str:
    """拼接 base 与 path，避免 ``//api/...`` 双斜杠。

    实测踩坑：base 已带尾斜杠而 OpenAPI 的 path 又以前导 ``/`` 开头时，
    直接相加会拼出 ``https://host//api/auth/login``，服务端返回
    ``Cannot POST //api/auth/login-by-identifier``——这种 404 看起来像
    "接口不存在"，实际是自己把 URL 拼错了。
    """
    return base.rstrip("/") + "/" + path.lstrip("/")


def _find_token(obj, depth: int = 0) -> str:
    """递归找 JWT（三段式且中段能解出 JSON）。"""
    if depth > 5:
        return ""
    if isinstance(obj, str):
        parts = obj.split(".")
        if len(parts) == 3:
            try:
                seg = parts[1]
                seg += "=" * (-len(seg) % 4)
                json.loads(base64.urlsafe_b64decode(seg))
                return obj
            except Exception:  # noqa: BLE001
                return ""
        return ""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in TOKEN_KEYS and isinstance(v, str) and v.count(".") == 2:
                return v
        for v in obj.values():
            t = _find_token(v, depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj[:5]:
            t = _find_token(v, depth + 1)
            if t:
                return t
    return ""


def pick_login_endpoint(assets: list[Asset]) -> Asset | None:
    """挑一个最合适的登录端点。优先"业务前端"入口（通常无需 channel 头）。"""
    cands = [
        a for a in assets
        if a.kind == "api" and a.meta.get("method") == "POST" and LOGIN_RE.search(a.meta.get("path", ""))
    ]
    if not cands:
        return None
    # 带 identifier / login-by 的通常是通用入口，优先；纯 /login 次之
    def score(a: Asset) -> int:
        p = a.meta.get("path", "").lower()
        s = 0
        if "identifier" in p:
            s += 2
        if "auth" in p:
            s += 1
        if "legacy" in p or "兼容" in (a.meta.get("summary") or ""):
            s -= 1
        return -s
    cands.sort(key=score)
    return cands[0]


def pick_captcha_endpoint(assets: list[Asset]) -> Asset | None:
    cands = [
        a for a in assets
        if a.kind == "api" and a.meta.get("method") == "GET" and CAPTCHA_RE.search(a.meta.get("path", ""))
    ]
    return cands[0] if cands else None


class Authenticator:
    """按接口清单元数据完成登录。"""

    def __init__(self, cfg, verbose: bool = False) -> None:
        self.cfg = cfg
        self.verbose = verbose
        self._c: httpx.Client | None = None
        self._base_url: str = ""   # 代理决策需要知道目标主机

    def client(self) -> httpx.Client:
        if self._c is None or self._c.is_closed:
            from core.proxy import build_client_kwargs

            # 代理决策收敛到 core/proxy.py：内网/本机直连，公网走代理。
            kw = build_client_kwargs(self.cfg, self._base_url)
            # build_client_kwargs 为 httpx.AsyncClient 设计，这里同步客户端同样吃这些键
            self._c = httpx.Client(**kw)
        return self._c

    def close(self) -> None:
        if self._c and not self._c.is_closed:
            self._c.close()

    def _get(self, url: str, tries: int = 4):
        for i in range(tries):
            try:
                return self.client().get(url)
            except Exception:  # noqa: BLE001 —— 链路偶发 RST
                if i + 1 == tries:
                    return None
        return None

    def _post(self, url: str, payload: dict, headers: dict | None = None, tries: int = 4):
        for i in range(tries):
            try:
                return self.client().post(url, json=payload, headers=headers)
            except Exception:  # noqa: BLE001
                if i + 1 == tries:
                    return None
        return None

    # ── 验证码 ────────────────────────────────────────────────────
    def fetch_captcha(self, base: str, endpoint: str) -> tuple[str, str, str]:
        """返回 (uuid, code, kind)。失败时 code 为空。"""
        r = self._get(join_url(base, endpoint))
        if r is None or r.status_code != 200:
            return "", "", "none"
        try:
            d = r.json()
        except Exception:  # noqa: BLE001
            return "", "", "none"
        img = d.get("img") or d.get("data") or d.get("captcha") or ""
        uuid_ = str(d.get("uuid") or d.get("id") or d.get("key") or "")
        if not img:
            return uuid_, "", "none"
        try:
            raw = base64.b64decode(str(img).split(",")[-1])
        except Exception:  # noqa: BLE001
            return uuid_, "", "none"
        head = raw[:200].lstrip().lower()
        if head.startswith(b"<svg") or head.startswith(b"<?xml") or b"<svg" in head:
            text = raw.decode("utf-8", "ignore")
            code = "".join(SVG_TEXT_RE.findall(text)).strip()
            return uuid_, code, "svg"
        return uuid_, "", "image"

    # ── 登录 ──────────────────────────────────────────────────────
    def login(
        self, base: str, assets: list[Asset], username: str, password: str
    ) -> AuthResult:
        self._base_url = base   # 代理决策依据（内网直连 / 公网走代理）
        ep = pick_login_endpoint(assets)
        if ep is None:
            return AuthResult(False, notes=["接口清单里找不到登录端点"])
        fields = [str(f).lower() for f in (ep.meta.get("body_fields") or [])]
        cap = pick_captcha_endpoint(assets)

        # 账号字段：清单里有 username 就用，否则 email，否则猜
        if "username" in fields:
            user_key = "username"
        elif "email" in fields:
            user_key = "email"
        elif "phone" in fields:
            user_key = "phone"
        else:
            user_key = "username"

        payload: dict = {user_key: username, "password": password}
        out = AuthResult(False, endpoint=ep.meta.get("path", ""))

        if cap is not None:
            out.captcha_endpoint = cap.meta.get("path", "")
            uuid_, code, kind = self.fetch_captcha(base, cap.meta["path"])
            out.captcha_kind = kind
            if kind == "svg" and code:
                out.notes.append(
                    f"验证码为纯文本 SVG，已由脚本直接还原为 {code!r}"
                    f"（无需 OCR —— 该验证码对自动化无效）"
                )
            elif kind == "image":
                out.notes.append("验证码为位图，无法自动识别，需人工输入")
            if uuid_ and "uuid" in fields:
                payload["uuid"] = uuid_
            if code and "code" in fields:
                payload["code"] = code

        r = self._post(join_url(base, ep.meta["path"]), payload)
        if r is None:
            out.notes.append("登录请求失败（网络）")
            return out
        out.raw = r.text[:400]
        try:
            d = r.json()
        except Exception:  # noqa: BLE001
            d = {}
        tok = _find_token(d)
        if tok:
            out.ok = True
            out.token = tok
        else:
            out.notes.append(f"登录未返回令牌：{r.text[:160]}")
        return out


__all__ = ["Authenticator", "AuthResult", "pick_login_endpoint", "pick_captcha_endpoint"]
