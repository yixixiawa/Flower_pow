"""AUTH_BOOTSTRAP：受限的**认证初始化**能力（登录 / 刷新 / 登出）。

为什么不是一条矩阵规则
======================
权限矩阵原文恰好十条，**没有 AUTH 行**——提交凭证不是矩阵授权过的能力。
为登录造一条 "认证操作 L0/L1" 就是"为通过分类器而扩大允许范围"，也是
本轮明令禁止的"全局放宽 AUTH"。

所以这里不是"给 AUTH 开一个等级"，而是一条**独立、自带十条前置条件、
单次生效**的受限通道：

1. 当前会话必须已绑定 ``target_id``；
2. 目标环境必须**明确**（``unknown`` 一律拒绝，不猜）；
3. 必须在**测试背景**下（production 不是测试背景，不做凭证提交）；
4. 请求 URL 必须命中**已登记**的认证入口——登记来源只有两个：接口清单
   （``entries_for`` 从 OpenAPI 资产推导）与登记表（config.yaml
   ``policy.auth_endpoints`` / REPL ``/auth register``）。**路径关键词
   识别不授权**（guardschedule3.md）：末段含 login 只产生候选提示；
   只认这四类，改密码/建用户/批量撤销令牌不算；
5. HTTP 方法必须与接口定义一致（登记时记下的那个方法）；
6. 请求参数必须符合认证接口结构（字段 ⊆ 接口声明 ∪ 认证字段词表，
   且必须带凭证字段）；
6b. 本次请求**不能带更高风险语义**（guardschedule5 第二章）：路径/参数/
   请求体/POC/历史里出现删除、批量删除、上传、命令执行、SQL 注入、
   定时任务或导出信号，就回矩阵按更高风险判——AUTH 是用途分类，
   不是风险豁免；登记"这是登录端点"也不能把一个删除接口变成认证动作；
7. 登录频率受限（滑动窗口 + 最小间隔）——**一次真正发出的凭证提交计一次**，
   工具级意图判定不计（两处都计等于同一请求扣两次配额）；
8. 敏感凭证不进日志/工具输出/审计明文（脱敏在调用方统一做）；
9. **登录成功不产生任何"已登录"放行状态**——本模块没有 session 级开关；
10. 后续请求照旧走 ``api_policy`` + ``request_guard``（本模块不参与）。

第 9 条是设计上的硬约束：:func:`check` 是**纯函数**，只在当次返回
``ALLOW``，不写任何全局/会话状态（唯一的可变状态是频率计数的滑动窗口，
它只会让后续请求**更难**通过）。

EXPORT / 数据外带 / 认证管理类操作（改密码、建用户、发 token 给第三方）
不在这条通道内：它们要么没有矩阵授权，要么路径不会命中"已登记认证入口"，
因此照旧 UNKNOWN/DENY。**不要**把整个 AUTH 分类塞进 L0/L1。
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from policy.api_policy import Environment
from policy.request_guard import auth_risk_review, in_scope

__all__ = [
    "AUTH_COMMAND",
    "AUTH_LEVEL",
    "AuthDecision",
    "AuthEndpoint",
    "AuthKind",
    "AuthRateLimiter",
    "AUTH_FIELD_VOCAB",
    "IMPLICIT_KEYWORDS",
    "IMPLICIT_METHODS",
    "IMPLICIT_SEGMENTS",
    "entries_for",
    "implicit_endpoint",
    "body_keys",
    "check",
    "check_intent",
    "configure_rate_limit",
    "reset_rate_limits",
    "rate_limiter",
]

# 决策的展示口径：不是矩阵等级，而是一条独立通道。审计与拒绝文本都带它，
# 便于复盘时区分"矩阵拒绝"与"认证初始化拒绝"。
AUTH_COMMAND = "认证初始化"
AUTH_LEVEL = "AUTH_BOOTSTRAP"


class AuthKind:
    LOGIN = "login"
    REFRESH = "refresh"
    LOGOUT = "logout"
    CAPTCHA = "captcha"     # 登录所需的验证码读取（只读 GET，仍需精确匹配登记入口）

    ALL = (LOGIN, REFRESH, LOGOUT, CAPTCHA)


# ── 认证字段词表 ──────────────────────────────────────────────────
# 参数结构校验的**兜底边界**：接口清单（OpenAPI）声明了 body_fields 时以
# 声明为准（并允许词表内的通用字段）；没声明时只按词表判。
# 词表之外的一律视为"不符合认证接口结构" → 拒绝（不猜）。
AUTH_FIELD_VOCAB: frozenset[str] = frozenset({
    "username", "user", "user_name", "account", "identifier", "login", "loginname",
    "email", "phone", "mobile", "tel", "password", "passwd", "pwd", "pass",
    "code", "captcha", "captcha_code", "verify_code", "validate_code", "uuid",
    "key", "imgcode", "grant_type", "refresh_token", "client_id", "client_secret",
    "scope", "device_id", "device", "remember", "remember_me", "login_type",
    "channel", "type", "platform", "timestamp", "nonce", "sign",
})

# 凭证字段：登录必须至少带一个（否则不是"提交凭证"而是随便一个 POST）
_CRED_FIELDS: frozenset[str] = frozenset({
    "username", "user", "user_name", "account", "identifier", "login", "loginname",
    "email", "phone", "mobile", "tel", "password", "passwd", "pwd", "pass",
    "code", "captcha", "captcha_code", "verify_code", "imgcode",
})

# 刷新令牌必须带的东西
_REFRESH_FIELDS: frozenset[str] = frozenset({"refresh_token", "grant_type", "token"})

# 认证入口识别（顺序即优先级：验证码 > 登出 > 刷新 > 登录）
_CAPTCHA_RE = re.compile(r"captcha|verify[-_]?code|validate[-_]?code|imgcode", re.I)
_LOGOUT_RE = re.compile(r"logout|sign[-_]?out|revoke", re.I)
_REFRESH_RE = re.compile(r"refresh|renew|/token(?:$|[/?#])", re.I)
_LOGIN_RE = re.compile(r"login|sign[-_]?in|authenticate|sso", re.I)


def _kind_of_path(path: str) -> str:
    p = path or ""
    if _CAPTCHA_RE.search(p):
        return AuthKind.CAPTCHA
    if _LOGOUT_RE.search(p):
        return AuthKind.LOGOUT
    if _REFRESH_RE.search(p):
        return AuthKind.REFRESH
    if _LOGIN_RE.search(p):
        return AuthKind.LOGIN
    return ""


def _join(target: str, path: str) -> str:
    """拼接目标与接口路径（避免 ``//api`` 双斜杠，与 core.auth.join_url 同义）。"""
    if "://" in (path or ""):
        return path
    return (target or "").rstrip("/") + "/" + (path or "").lstrip("/")


# ── 路径关键词识别：**候选识别，不授权**（guardschedule3.md） ────────
#
# 第十一轮曾把"末段含 login"做成代码级自动授权（路径自证直接放行）。
# 规范第三节明令禁止"根据 URL 包含 login 等关键词直接授权"，第 107-108
# 行附录也写明：``implicit_endpoint() 改成只提供候选识别，不直接授权；
# 末段含 login 自动登记 删除``。
#
# 所以这里的函数只回答一个问题："这个 URL **看起来**像哪类认证端点？"
# 返回值只用于两个地方：
#   * 拒绝理由里的候选提示（告诉用户怎么登记）——
#     :func:`policy.auth_registry.candidate_hint`；
#   * ``check_intent`` 之外没有任何授权路径。
# 它的返回值**永远不能**变成 ALLOW，也不能替代登记表。
#
# 识别口径保持宽松（末段**包含**认证动词即认——``loginByPassword`` /
# ``doLogin`` / ``login.json`` 都算，路径中任一段整段等于认证动词也算，
# ``/oauth/token`` 看父段）：识别得准，提示才有用。授权交给登记表。
IMPLICIT_SEGMENTS: dict[str, str] = {
    "login": AuthKind.LOGIN,
    "log-in": AuthKind.LOGIN,
    "signin": AuthKind.LOGIN,
    "sign-in": AuthKind.LOGIN,
    "sign_in": AuthKind.LOGIN,
    "authenticate": AuthKind.LOGIN,
    "refresh": AuthKind.REFRESH,
    "refresh-token": AuthKind.REFRESH,
    "refresh_token": AuthKind.REFRESH,
    "refreshtoken": AuthKind.REFRESH,
    "logout": AuthKind.LOGOUT,
    "log-out": AuthKind.LOGOUT,
    "signout": AuthKind.LOGOUT,
    "sign-out": AuthKind.LOGOUT,
    "sign_out": AuthKind.LOGOUT,
}

#: 末段**包含**这些子串即认（不区分大小写）。顺序即优先级。
#: ``revoke`` / ``renew`` 刻意不收：``revokeAll`` / ``renewAll`` 是批量
#: 认证管理操作（撤销全部令牌），不属于单次认证初始化。
IMPLICIT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("logout", AuthKind.LOGOUT),
    ("signout", AuthKind.LOGOUT),
    ("sign_out", AuthKind.LOGOUT),
    ("sign-out", AuthKind.LOGOUT),
    ("refresh", AuthKind.REFRESH),
    ("authenticate", AuthKind.LOGIN),
    ("signin", AuthKind.LOGIN),
    ("sign_in", AuthKind.LOGIN),
    ("sign-in", AuthKind.LOGIN),
    ("login", AuthKind.LOGIN),
)

#: 末段以这些后缀结尾 → 是**查询/列表**接口，不是认证动作。
#: ``/auth/login-history``、``/login-logs/list`` 这类即使含 login 也不认。
_READONLY_SUFFIXES: tuple[str, ...] = (
    "history", "logs", "log", "records", "record", "list", "page", "query",
)

#: 末段是 ``token`` 时才算 OAuth2 令牌端点的父段（``/oauth/token``）。
#: 裸 ``/api/token`` 不算——那可能是查令牌信息，不是刷新。
_TOKEN_PARENTS: frozenset[str] = frozenset({"oauth", "oauth2", "auth", "sso"})

#: 路径自证时的**语义默认方法**。
#:
#: 只收录 login / refresh / logout：这三类在真实系统里（Spring Security 表单、
#: OAuth2 令牌端点、芋道 admin-api、DRF）无一例外是 POST。验证码读取则既有
#: GET（图片码）也有 POST（芋道 ``/captcha/get`` 带 scene），语义方法不唯一，
#: 因此**不参与**路径自证——它只在接口清单明确登记时可用（方法以清单为准）。
IMPLICIT_METHODS: dict[str, str] = {
    AuthKind.LOGIN: "POST",
    AuthKind.REFRESH: "POST",
    AuthKind.LOGOUT: "POST",
}


@dataclass(frozen=True, slots=True)
class AuthEndpoint:
    """一条认证入口（**已登记**或**路径自证**两种来源）。

    ``url`` 是绝对 URL（目标 + 接口路径），``method`` 是允许的方法：
    登记入口取接口定义，自证入口取语义默认（login/refresh/logout = POST）。
    精确匹配用 :func:`policy.request_guard.in_scope` 双向比对——它不是
    字符串前缀比较，编码/点段/默认端口在比对前已摊平。

    ``source`` 记录这条入口**从哪来**（``openapi`` 接口清单 / ``config``
    静态策略配置 / ``user`` 用户确认登记）：授权事实必须可追溯，
    审计与拒绝理由里要能一眼看出"是谁说的这是登录端点"。
    默认空串 = 调用方没标注来源（历史构造点兼容），不影响任何判定。
    """

    kind: str
    url: str
    method: str
    fields: frozenset[str] = frozenset()
    source: str = ""

    def matches(self, url: str, method: str) -> bool:
        if (method or "").upper() != (self.method or "").upper():
            return False
        return in_scope(url, self.url) and in_scope(self.url, url)

    def same_url(self, url: str) -> bool:
        return in_scope(url, self.url) and in_scope(self.url, url)


def entries_for(target: str, assets: Iterable[Any]) -> tuple[AuthEndpoint, ...]:
    """从**接口清单**推导已登记的认证入口。

    只认四类路径（login / refresh / logout / captcha），并且要求接口资产
    带 ``method``——方法就是接口定义，后续请求的方法必须与它一致。
    同一个 URL 只登记一条（先到先得，顺序稳定）。
    """
    out: list[AuthEndpoint] = []
    seen: set[str] = set()
    for a in assets or ():
        if getattr(a, "kind", "") != "api":
            continue
        meta = getattr(a, "meta", None) or {}
        path = str(meta.get("path") or "")
        method = str(meta.get("method") or "").upper()
        if not path or not method:
            continue
        kind = _kind_of_path(path)
        if not kind:
            continue
        url = _join(target, path)
        key = f"{method} {url}".lower()
        if key in seen:
            continue
        seen.add(key)
        fields = frozenset(
            str(f).strip().lower() for f in (meta.get("body_fields") or []) if str(f).strip()
        )
        out.append(AuthEndpoint(kind=kind, url=url, method=method,
                                fields=fields, source="openapi"))
    return tuple(out)


def _kind_from_words(text: str) -> str:
    """末段词形 → 认证类型（子串匹配，不区分大小写）。"""
    low = (text or "").lower()
    for word, kind in IMPLICIT_KEYWORDS:
        if word in low:
            return kind
    return ""


def implicit_endpoint(url: str) -> AuthEndpoint | None:
    """从 URL 路径**识别候选**认证入口——只识别，不授权。

    ⚠️ 本函数的结果**不能**作为放行依据（guardschedule3.md：路径关键词
    不直接授权）。它的唯一用途是：请求因 ENDPOINT_UNREGISTERED 被拒时，
    在拒绝理由里告诉用户"这个 URL 看起来像哪类认证端点、怎么登记"。
    真正的授权来源只有两个：接口清单（recon_openapi）与登记表
    （config.yaml ``policy.auth_endpoints`` / REPL ``/auth register``）。

    识别口径（保持宽松，识别得准提示才有用）：

    * 末段**包含**认证动词即认——``loginByPassword`` / ``doLogin`` /
      ``login.json`` / ``adminLogin`` 都算登录候选；
    * 末段以只读后缀结尾（history/logs/list/records/page/query）不算——
      ``/auth/login-history`` 是查询接口；
    * 路径中**任一段整段等于**认证动词也算（``/api/login/do``）；
    * ``/oauth/token`` 这类令牌端点单独认（只看父段）。

    返回的 :class:`AuthEndpoint` 方法固定为语义默认（login/refresh/logout
    = POST），``fields`` 为空。
    """
    try:
        path = urlsplit(url or "").path or ""
    except ValueError:
        return None
    segs = [s for s in path.strip("/").split("/") if s]
    if not segs:
        return None
    last = segs[-1].lower()
    stem = last.split(".", 1)[0]          # login.json / login.do → login
    parent = segs[-2].lower() if len(segs) > 1 else ""

    kind = ""
    if stem.endswith(_READONLY_SUFFIXES):
        # 末段是查询/列表后缀：这条路径是"读记录"，不是认证动作。
        # 直接返回，不再走后面的父段规则——否则 /api/login/records 会
        # 因为父段是 login 又被认成登录入口。
        return None
    kind = _kind_from_words(stem) or IMPLICIT_SEGMENTS.get(stem, "")
    if not kind:
        # 动作放在下一段：/api/login/do、/user/signin/submit
        for seg in reversed(segs[:-1]):
            word = seg.lower().split(".", 1)[0]
            if word in IMPLICIT_SEGMENTS:
                kind = IMPLICIT_SEGMENTS[word]
                break
    if not kind and last == "token" and parent in _TOKEN_PARENTS:
        kind = AuthKind.REFRESH

    method = IMPLICIT_METHODS.get(kind, "")
    if not kind or not method:
        return None
    return AuthEndpoint(kind=kind, url=url, method=method)


# ── 参数结构解析 ──────────────────────────────────────────────────


def body_keys(body: str = "", params: dict[str, Any] | None = None) -> set[str]:
    """请求体/参数里的**字段名**集合（只取名字，不取值——值可能是密码）。

    支持 JSON 对象与 ``a=1&b=2`` 表单；两者都能解析时取并集。解析不出
    字段名时返回空集（调用方据此判"结构不可判" → 拒绝）。
    """
    keys: set[str] = set()
    for k in (params or {}):
        name = str(k).strip().lower()
        if name:
            keys.add(name)
    text = (body or "").strip()
    if not text:
        return keys
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        obj = None
    if isinstance(obj, dict):
        for k in obj:
            name = str(k).strip().lower()
            if name:
                keys.add(name)
        return keys
    if "=" in text:
        for pair in re.split(r"[&\n]", text):
            name = pair.split("=", 1)[0].strip().lower()
            if name and re.fullmatch(r"[a-z0-9_.\-\[\]]{1,64}", name):
                keys.add(name)
    return keys


# ── 频率限制 ──────────────────────────────────────────────────────


class AuthRateLimiter:
    """登录频率限制：滑动窗口 + 最小间隔（按 会话|目标|入口 分桶）。

    只统计**真正放行的**凭证提交（被结构校验挡下的请求根本没发出去，
    不占配额）。它唯一的作用是让后续请求更难通过，不构成任何放行状态。
    """

    def __init__(self, max_attempts: int = 5, window: float = 60.0,
                 min_interval: float = 0.5) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.window = max(1.0, float(window))
        self.min_interval = max(0.0, float(min_interval))
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, str]:
        now = time.monotonic()
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.max_attempts:
                wait = max(1, int(self.window - (now - dq[0])))
                return False, (
                    f"认证请求频率超限（{self.max_attempts} 次 / {int(self.window)}s），"
                    f"请 {wait}s 后重试"
                )
            if dq and (now - dq[-1]) < self.min_interval:
                return False, f"认证请求过于频繁（最小间隔 {self.min_interval}s）"
            dq.append(now)
            return True, ""

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_DEFAULT_LIMITER = AuthRateLimiter()


def rate_limiter() -> AuthRateLimiter:
    return _DEFAULT_LIMITER


def configure_rate_limit(
    *, max_attempts: int | None = None, window: float | None = None,
    min_interval: float | None = None,
) -> AuthRateLimiter:
    """调整默认限流器（测试与运维用；只影响频率，不影响任何授权判定）。"""
    lim = _DEFAULT_LIMITER
    with lim._lock:  # noqa: SLF001 —— 同模块内的受控调整
        if max_attempts is not None:
            lim.max_attempts = max(1, int(max_attempts))
        if window is not None:
            lim.window = max(1.0, float(window))
        if min_interval is not None:
            lim.min_interval = max(0.0, float(min_interval))
    return lim


def reset_rate_limits() -> None:
    _DEFAULT_LIMITER.reset()


# ── 判定 ──────────────────────────────────────────────────────────


@dataclass(slots=True)
class AuthDecision:
    """一次 AUTH_BOOTSTRAP 判定的结论（不是矩阵等级，不带任何放行状态）。"""

    decision: str                  # ALLOW / DENY
    kind: str = ""
    endpoint: str = ""
    code: str = ""                 # 机器可读的拒绝原因码
    reason: str = ""
    signals: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def _deny(code: str, reason: str, *, kind: str = "", endpoint: str = "") -> AuthDecision:
    return AuthDecision("DENY", kind=kind, endpoint=endpoint, code=code, reason=reason)


def _preconditions(
    *, url: str, target_id: str, bound_target: str, environment: str,
) -> AuthDecision | None:
    """条件 ①-③：会话绑定目标 / 请求在范围内 / 环境明确且在测试背景。

    返回 ``None`` 表示通过。条件顺序刻意写成"先拒绝后允许"。
    """
    # ① 会话绑定目标
    if not (target_id or "").strip() or not (bound_target or "").strip():
        return _deny(
            "SESSION_UNBOUND",
            "当前会话未绑定目标（target_id 为空）：认证初始化必须先 set_target，"
            "不能对未声明的对象提交凭证",
        )

    # 目标范围：登录请求必须打在绑定目标上（同一把 in_scope 尺子）
    if not in_scope(url, bound_target):
        return _deny(
            "OUT_OF_SCOPE",
            f"认证请求超出绑定目标范围（{bound_target}）：{url}",
        )

    # ② 环境必须明确
    env = (environment or "").strip()
    if not env or env == Environment.UNKNOWN:
        return _deny(
            "ENV_UNKNOWN",
            "目标环境未判定（unknown）：认证初始化不接受环境未知的请求——"
            "请在 config.yaml 的 policy.environments 里绑定该目标的环境",
        )

    # ③ 测试背景（production 也要提交凭证的诉求不在本通道内）
    if env not in Environment.TEST_ENVS:
        return _deny(
            "TEST_CONTEXT",
            f"目标环境为 {env}，不是测试背景：认证初始化仅允许在 "
            f"{'/'.join(Environment.TEST_ENVS)} 下进行（生产环境不做凭证提交）",
        )
    return None


def check_intent(
    *,
    kind: str = AuthKind.LOGIN,
    target_id: str = "",
    bound_target: str = "",
    environment: str = "",
    entries: Iterable[AuthEndpoint] = (),
    session_id: str = "",
    credentials_present: bool = False,
    limiter: AuthRateLimiter | None = None,
    count_rate: bool = False,
) -> AuthDecision:
    """**工具级**判定：这次"登录/刷新/登出"的意图本身是否被允许。

    与 :func:`check`（请求级）分工：

    * 工具级（本函数）——会话绑定 + 环境 + 测试背景 + "该类入口已登记"。
      它不指定具体 URL：``login`` 工具的入参是"目标"，真实端点由接口清单
      解析（可能不止一个 login 入口）。**不消耗频率配额**：这里还没有任何
      请求要发出去，计数留到真正发出的那一枪（:func:`check`）。
    * 请求级（:func:`check`）——具体 URL 必须精确命中登记入口、方法一致、
      参数符合结构，并**计一次**频率（凭证提交）。

    两道都必须通过，任何一道拒绝即拒绝。工具级通过**不代表**请求级会通过。

    ``count_rate=True`` 只用于"单独给意图限流"的场景（本项目没有这样的
    调用方）：工具级与请求级都计数会让同一登录扣两次配额。
    """
    pre = _preconditions(
        url=bound_target or "", target_id=target_id,
        bound_target=bound_target, environment=environment,
    )
    if pre is not None:
        return pre

    if kind not in AuthKind.ALL:
        return _deny(
            "UNKNOWN_KIND",
            f"不是认证初始化类型：{kind}（只认 login/refresh/logout/captcha）",
            kind=kind,
        )

    found = [e for e in (entries or ()) if e.kind == kind]
    first_url = found[0].url if found else ""

    # 条件 ④（入口存在性）在意图级**必须成立**：路径关键词自证已按
    # guardschedule3.md 删除——授权只来自登记（接口清单 or 登记表）。
    # 没有任何已登记的该类入口，这次认证操作就没有发起的依据。
    # 允许用 `REPL /auth register` / config.yaml policy.auth_endpoints
    # 或 recon_openapi 产生登记。
    if not found:
        return _deny(
            "ENDPOINT_UNREGISTERED",
            f"没有任何已登记的 {kind} 认证入口：请先登记（REPL /auth register、"
            "config.yaml policy.auth_endpoints，或 recon_openapi 从接口清单推导）",
            kind=kind,
        )
    if kind == AuthKind.REFRESH and not credentials_present:
        return _deny(
            "NO_CREDENTIAL",
            "当前会话没有可刷新的凭证：Token 刷新必须基于本次测试已取得的凭证",
            kind=kind, endpoint=first_url,
        )
    if count_rate and kind in (AuthKind.LOGIN, AuthKind.REFRESH):
        lim = limiter or _DEFAULT_LIMITER
        bucket = f"{(session_id or '-')}|{(target_id or '-')}|intent:{kind}"
        ok, why = lim.allow(bucket)
        if not ok:
            return _deny("RATE_LIMITED", why, kind=kind, endpoint=first_url)

    entry_note = f"{len(found)} 个已登记入口"
    return AuthDecision(
        "ALLOW",
        kind=kind,
        endpoint="、".join(e.url for e in found[:3]) or first_url,
        code="OK",
        reason=(
            f"AUTH_BOOTSTRAP 允许：{kind} 意图（{entry_note}，环境 {environment}）"
            "——每个具体请求仍需命中入口并通过结构校验"
        ),
        signals=[
            f"会话绑定目标：{target_id}",
            f"环境：{environment}",
            f"入口：{entry_note}",
        ],
    )


def check(
    *,
    url: str,
    method: str = "POST",
    body: str = "",
    params: dict[str, Any] | None = None,
    entries: Iterable[AuthEndpoint] = (),
    target_id: str = "",
    bound_target: str = "",
    environment: str = "",
    session_id: str = "",
    credentials_present: bool = False,
    limiter: AuthRateLimiter | None = None,
    count_rate: bool = True,
) -> AuthDecision:
    """按十条前置条件判定这次认证初始化请求。

    **纯函数**：不写任何会话/全局放行状态；唯一的可变动作是频率计数
    （``count_rate=False`` 时连计数也不做——仅供已经计过数的调用方复核）。

    条件 ①-③ 见 :func:`_preconditions`；④ 精确命中登记入口；⑤ 方法一致；
    ⑥ 参数结构；⑦ 频率（仅凭证提交）。⑧⑨⑩ 由调用方保证：脱敏输出、
    不写放行状态、后续请求照旧过矩阵。
    """
    method_u = (method or "POST").upper()
    eps = tuple(entries or ())

    pre = _preconditions(
        url=url, target_id=target_id, bound_target=bound_target,
        environment=environment,
    )
    if pre is not None:
        return pre
    env = (environment or "").strip()

    # ④ 必须命中**已登记**的认证入口（接口清单 or 登记表）。
    #    路径关键词识别（implicit_endpoint）**不授权**——未命中时它只
    #    参与拒绝理由里的候选提示（guardschedule3.md：禁止按 URL 关键词
    #    直接授权；授权只来自登记）。
    same_url = [e for e in eps if e.same_url(url)]
    matched = next((e for e in same_url if e.matches(url, method_u)), None)
    if matched is None:
        if same_url:
            allowed_methods = "/".join(sorted({e.method for e in same_url}))
            return _deny(
                "METHOD_MISMATCH",
                f"方法 {method_u} 与认证接口定义不符（{url} 只登记了 {allowed_methods}）",
            )
        hint = ""
        try:
            from policy.auth_registry import candidate_hint

            hint = candidate_hint(url=url, bound_target=bound_target)
        except Exception:            # noqa: BLE001 —— 提示失败不影响拒绝
            hint = ""
        reason = (
            f"认证入口未登记：{method_u} {url} 不在接口清单与登记表内"
            "——提交凭证前必须先登记该端点"
        )
        if hint:
            reason = f"{reason}。{hint}"
        return _deny("ENDPOINT_UNREGISTERED", reason)
    if matched.kind not in AuthKind.ALL:
        return _deny("ENDPOINT_UNREGISTERED", f"未识别的认证入口类型：{matched.url}")

    # ④b **用途复核**（guardschedule5 第二章第 6-7 条）：登记只说明"这个
    #    URL 被谁认定成认证入口"，不说明"这次请求就是在认证"。所以执行时
    #    再按同一套信号表复核一遍：路径/参数/请求体/POC/历史里出现删除、
    #    批量删除、上传、命令执行、SQL 注入、定时任务、导出，就说明它干的
    #    不是认证的事——必须回矩阵按更高风险判（多半是 L3），不能借
    #    AUTH_BOOTSTRAP 放行。
    #    这一道专治"把 /api/users/delete 登记成 login"这类错误登记。
    risk_cmd, risk_sigs = auth_risk_review(url, body=body, params=params)
    if risk_cmd:
        return _deny(
            "ENDPOINT_RISK_MISMATCH",
            f"已登记入口 {matched.url} 的本次请求带更高风险语义（应按「{risk_cmd}」"
            "由权限矩阵判定）：认证初始化只受理登录/刷新/登出/验证码，"
            "不接受删除、批量删除、上传、命令执行、SQL 注入、定时任务或导出"
            f"——命中信号：{'；'.join(risk_sigs[:3]) or risk_cmd}",
            kind=matched.kind, endpoint=matched.url,
        )

    # ⑤⑥ 参数结构（验证码读取是只读 GET，不做凭证结构校验）
    keys = body_keys(body, params)
    if matched.kind == AuthKind.CAPTCHA:
        if method_u != "GET":
            return _deny(
                "METHOD_MISMATCH",
                f"验证码入口只允许 GET（接口定义 {matched.method}）：{matched.url}",
                kind=matched.kind, endpoint=matched.url,
            )
    elif matched.kind == AuthKind.LOGOUT:
        extra = keys - (set(matched.fields) | AUTH_FIELD_VOCAB)
        if extra:
            return _deny(
                "PARAMS_INVALID",
                f"登出参数不在认证接口结构内：{sorted(extra)}",
                kind=matched.kind, endpoint=matched.url,
            )
    else:  # LOGIN / REFRESH
        allowed = set(matched.fields) | AUTH_FIELD_VOCAB
        extra = keys - allowed
        if extra:
            return _deny(
                "PARAMS_INVALID",
                f"参数不在认证接口结构内：{sorted(extra)}"
                f"（接口声明 {sorted(matched.fields) or '未声明，按认证字段词表'}）",
                kind=matched.kind, endpoint=matched.url,
            )
        if matched.kind == AuthKind.LOGIN and not (keys & _CRED_FIELDS):
            return _deny(
                "PARAMS_INVALID",
                "登录请求缺少凭证字段（username/password/email/phone/code 等），"
                "不能作为认证初始化执行",
                kind=matched.kind, endpoint=matched.url,
            )
        if matched.kind == AuthKind.REFRESH:
            if not credentials_present:
                return _deny(
                    "NO_CREDENTIAL",
                    "当前会话没有可刷新的凭证：Token 刷新必须基于本次测试已取得的凭证",
                    kind=matched.kind, endpoint=matched.url,
                )
            if not (keys & _REFRESH_FIELDS):
                return _deny(
                    "PARAMS_INVALID",
                    f"刷新请求缺少 {sorted(_REFRESH_FIELDS)} 之一",
                    kind=matched.kind, endpoint=matched.url,
                )

    # ⑦ 频率限制（只对凭证提交计数）
    if count_rate and matched.kind in (AuthKind.LOGIN, AuthKind.REFRESH):
        lim = limiter or _DEFAULT_LIMITER
        ok, why = lim.allow(f"{(session_id or '-')}|{(target_id or '-')}|{matched.url}")
        if not ok:
            return _deny(
                "RATE_LIMITED", why, kind=matched.kind, endpoint=matched.url,
            )

    # ⑧⑨⑩ 由调用方保证：脱敏输出、不写放行状态、后续请求照旧过矩阵
    return AuthDecision(
        "ALLOW",
        kind=matched.kind,
        endpoint=matched.url,
        code="OK",
        reason=(
            f"AUTH_BOOTSTRAP 允许：{matched.kind} {method_u} {matched.url}"
            f"（已登记入口；环境 {env}，仅本次请求有效；"
            "后续请求仍走权限矩阵与 GUARD）"
        ),
        signals=[
            f"会话绑定目标：{target_id}",
            f"环境：{env}",
            f"入口：{matched.kind} {matched.url}（已登记，"
            f"来源 {matched.source or '未标注'}）",
            f"参数：{sorted(keys) if keys else '无'}",
        ],
    )
