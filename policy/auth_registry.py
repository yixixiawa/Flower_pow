"""认证入口登记表：**策略配置驱动**的授权来源（guardschedule3.md）。

为什么要有这张表
================
第十一轮把"末段含 login"做成了代码级自动授权——那违反规范第三节
"禁止根据 URL 包含 login 等关键词直接授权"。本模块把它纠正回来：

* **授权只来自登记**。一个 URL 能不能作为登录端点，不取决于它的
  名字像不像登录，而取决于它是否出现在下面两个配置来源之一：

  1. ``config.yaml`` 的 ``policy.auth_endpoints`` —— 静态策略配置，
     仓库/部署者维护，进版本控制；
  2. ``<data_dir>/policy/auth_endpoints.yaml`` —— 用户运行期经
     REPL ``/auth register`` **逐条确认**后持久化的登记（"用户确认
     接口登记"）。

* ``implicit_endpoint``（路径关键词识别）**降级为候选识别**：它只
  在拒绝理由里提示"这个 URL 看起来像登录入口、可以这样登记"，
  本身不产生任何 ALLOW。

* 接口清单（recon_openapi → ``entries_for``）仍是登记来源之一，
  由调用方与登记表合并（见 :func:`runner.base._auth_entries`）。

条目结构（与权限矩阵同风格：每条字段明确、可审计）::

    - target: "sgxmgl.fjny.edu.cn"     # host-glob，同环境绑定语义
      kind: login                      # login/refresh/logout/captcha
      url: /admin-api/system/auth/login  # 路径或绝对 URL
      method: POST                     # 可省：四类语义默认
      fields: [username, password]     # 可省：接口声明的 body 字段
      note: "芋道标准登录端点"          # 可省：登记备注（审计可读）

登记纪律（在 :func:`validate_entry` 里强制，不合规直接拒登）：

* ``kind`` 必须是四类之一；
* login/refresh/logout **固定 POST**、captcha 固定 GET（语义方法
  不开放配置——这是规范附录"固定 POST 保留"的要求）；
* ``url`` 必须是 http(s) 绝对 URL 或以 ``/`` 开头的路径，拒绝
  ``..`` / 控制字符 / 非 http 协议；
* ``target`` 不能为空，且登记进 data 文件时要求与当前会话目标
  匹配（REPL 层校验，防"登记到别的目标上"）。

本模块不做任何网络请求、不写任何放行状态——它只是把**人工确认过
的授权事实**变成机器可读的表。
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from policy.auth_bootstrap import AuthEndpoint, AuthKind

__all__ = [
    "AUTH_ENTRY_FIELDS",
    "AuthRegistryError",
    "Entry",
    "candidate_hint",
    "configure",
    "entries_for",
    "list_raw",
    "registry_path",
    "register",
    "unregister",
    "validate_entry",
]

#: 登记条目的合法字段（多余字段拒登——错别字不该被静默吞掉）。
AUTH_ENTRY_FIELDS: frozenset[str] = frozenset({
    "target", "kind", "url", "method", "fields", "note",
})

#: 四类的语义默认方法（规范附录：固定 POST 保留）。
_KIND_METHODS: dict[str, str] = {
    AuthKind.LOGIN: "POST",
    AuthKind.REFRESH: "POST",
    AuthKind.LOGOUT: "POST",
    AuthKind.CAPTCHA: "GET",
}

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class AuthRegistryError(ValueError):
    """登记条目不合法 / 登记操作失败（调用方应原样把消息回给用户）。"""


@dataclass(slots=True)
class Entry:
    """一条已登记的认证入口（规范化后的内存形态）。"""

    target: str
    kind: str
    url: str
    method: str
    fields: tuple[str, ...] = ()
    note: str = ""
    source: str = "user"          # config / user


def registry_path(cfg: Any) -> Path:
    """用户登记文件位置：``<data_dir>/policy/auth_endpoints.yaml``。

    data_dir 的取法与审计日志一致：cfg 能给就用 cfg 的，否则用项目
    根的 ``data/``。审计在 ``data/policy/audit.jsonl``，登记表就在它
    旁边——授权事实与审计留痕放在一起，复盘时一份材料看全。
    """
    root = getattr(cfg, "data_dir", "") or "data"
    return Path(root) / "policy" / "auth_endpoints.yaml"


# ── 校验 ──────────────────────────────────────────────────────────


def validate_entry(raw: dict[str, Any], *, source: str) -> Entry:
    """校验并规范化一条登记。任何不合法都抛 :class:`AuthRegistryError`。"""
    unknown = {str(k) for k in raw} - AUTH_ENTRY_FIELDS
    if unknown:
        raise AuthRegistryError(
            f"登记条目含未知字段 {sorted(unknown)}（合法字段：{sorted(AUTH_ENTRY_FIELDS)}）"
        )

    target = str(raw.get("target") or "").strip().strip("'\"")
    if not target:
        raise AuthRegistryError("登记条目缺少 target（要登记到哪个目标主机）")
    if _CTRL_RE.search(target):
        raise AuthRegistryError("target 含控制字符")

    kind = str(raw.get("kind") or "").strip().lower()
    if kind not in AuthKind.ALL:
        raise AuthRegistryError(
            f"kind 必须是 {'/'.join(AuthKind.ALL)} 之一，实际：{kind!r}"
        )

    url = str(raw.get("url") or "").strip()
    if not url:
        raise AuthRegistryError("登记条目缺少 url（认证端点路径或绝对 URL）")
    if _CTRL_RE.search(url):
        raise AuthRegistryError("url 含控制字符")
    if ".." in url:
        raise AuthRegistryError("url 含路径穿越段（..）")
    if "://" in url:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise AuthRegistryError(f"url 协议必须是 http/https，实际：{parts.scheme!r}")
        if not parts.hostname:
            raise AuthRegistryError("绝对 URL 缺少主机名")
    elif not url.startswith("/"):
        raise AuthRegistryError("url 必须是 http(s) 绝对 URL 或以 / 开头的路径")

    method = str(raw.get("method") or _KIND_METHODS[kind]).strip().upper()
    want = _KIND_METHODS[kind]
    if method != want:
        raise AuthRegistryError(
            f"{kind} 入口的方法固定为 {want}（语义方法不开放配置），实际：{method}"
        )

    fields_raw = raw.get("fields") or []
    if not isinstance(fields_raw, (list, tuple)):
        raise AuthRegistryError("fields 必须是字段名列表")
    fields = tuple(str(f).strip().lower() for f in fields_raw if str(f).strip())

    note = str(raw.get("note") or "").strip()
    if _CTRL_RE.search(note):
        raise AuthRegistryError("note 含控制字符")

    return Entry(target=target, kind=kind, url=url, method=method,
                 fields=fields, note=note[:200], source=source)


# ── 目标匹配 ──────────────────────────────────────────────────────


def _target_matches(pattern: str, bound_target: str) -> bool:
    """登记的 target 模式是否覆盖当前绑定目标。

    与环境绑定同语义：host-glob（``fnmatch``），``192.168.*``、
    ``sgxmgl.fjny.edu.cn`` 都可以。只比对 hostname（端口在 url 里
    表达，不在 target 模式里表达）。
    """
    pat = (pattern or "").strip().lower()
    if "://" in pat:
        pat = pat.split("://", 1)[1]
    pat = pat.rsplit(":", 1)[0] if pat.rsplit(":", 1)[-1].isdigit() else pat
    try:
        host = (urlsplit(bound_target or "").hostname or "").lower()
    except ValueError:
        return False
    host = host or (bound_target or "").strip().lower()
    if not host:
        return False
    return fnmatch.fnmatchcase(host, pat) or bool(host and fnmatch.fnmatchcase(pat, host))


def _join_url(bound_target: str, url: str) -> str:
    if "://" in url:
        return url
    base = (bound_target or "").rstrip("/")
    return f"{base}/{url.lstrip('/')}"


# ── 读取 ──────────────────────────────────────────────────────────


def _read_file(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthRegistryError(f"登记文件 {path} 解析失败：{exc}") from exc
    if data is None:
        return []
    if isinstance(data, dict):
        data = data.get("auth_endpoints") or []
    if not isinstance(data, list):
        raise AuthRegistryError(f"登记文件 {path} 结构不对：应为条目列表")
    return [e for e in data if isinstance(e, dict)]


def list_raw(cfg: Any) -> list[dict[str, Any]]:
    """用户登记文件里的原始条目（REPL 展示 / 测试用）。"""
    return _read_file(registry_path(cfg))


def _config_entries(cfg: Any) -> list[dict[str, Any]]:
    pcfg = getattr(cfg, "policy", None)
    raw = getattr(pcfg, "auth_endpoints", None) or [] if pcfg else []
    out: list[dict[str, Any]] = []
    for e in raw or ():
        if isinstance(e, dict):
            out.append(dict(e))
    return out


def entries_for(cfg: Any, bound_target: str) -> tuple[AuthEndpoint, ...]:
    """当前绑定目标的**已登记**认证入口（配置段 + 用户登记，合并去重）。

    只做"查表"，不做任何推断——不在表里的 URL 不是认证入口。
    """
    out: list[AuthEndpoint] = []
    seen: set[str] = set()
    for source, raws in (("config", _config_entries(cfg)),
                         ("user", list_raw(cfg))):
        for raw in raws:
            try:
                ent = validate_entry(raw, source=source)
            except AuthRegistryError:
                continue            # 坏条目不阻断其它条目；REPL 层会展示校验错误
            if not _target_matches(ent.target, bound_target):
                continue
            ep = AuthEndpoint(
                kind=ent.kind,
                url=_join_url(bound_target, ent.url),
                method=ent.method,
                fields=frozenset(ent.fields),
            )
            # AuthEndpoint 没有 source 字段（frozen slots，动它要动全部
            # 构造点）——来源进 url 的比对无关紧要，登记来源在注册表
            # 文件与 config 里本身就是事实来源。
            key = f"{ent.method} {ep.url}".lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(ep)
    return tuple(out)


# ── 登记 / 注销（REPL 用户确认通道） ───────────────────────────────


def register(
    cfg: Any, *, target: str, url: str, kind: str, method: str = "",
    fields: Iterable[str] = (), note: str = "",
) -> str:
    """用户确认登记一条认证入口（持久化到登记文件）。返回确认文本。"""
    raw: dict[str, Any] = {"target": target, "kind": kind, "url": url}
    if method:
        raw["method"] = method
    if fields:
        raw["fields"] = list(fields)
    if note:
        raw["note"] = note
    ent = validate_entry(raw, source="user")

    path = registry_path(cfg)
    data = _read_file(path)
    norm = {
        "target": ent.target, "kind": ent.kind, "url": ent.url,
        "method": ent.method,
    }
    if ent.fields:
        norm["fields"] = list(ent.fields)
    if ent.note:
        norm["note"] = ent.note
    for e in data:
        try:
            old = validate_entry(e, source="user")
        except AuthRegistryError:
            continue
        if (old.kind, old.url.lower(), old.method) == (ent.kind, ent.url.lower(), ent.method):
            return f"已登记过（target={old.target}），无需重复登记：{old.method} {old.url}"
    data.append(norm)

    path.parent.mkdir(parents=True, exist_ok=True)
    import yaml

    try:
        path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except OSError as exc:
        raise AuthRegistryError(f"登记文件写入失败（{path}）：{exc}") from exc
    fields_note = f"，fields={list(ent.fields)}" if ent.fields else ""
    return (
        f"已登记：{ent.kind} {ent.method} {ent.url}"
        f"（target={ent.target}{fields_note}）→ {path}"
    )


def unregister(cfg: Any, *, url: str, kind: str = "") -> str:
    """从用户登记文件注销一条（配置段条目不归运行期管，提示改配置）。"""
    path = registry_path(cfg)
    data = _read_file(path)
    url_l = url.strip().lower()
    kept: list[dict[str, Any]] = []
    removed: list[str] = []
    for e in data:
        try:
            old = validate_entry(e, source="user")
        except AuthRegistryError:
            kept.append(e)
            continue
        hit = old.url.lower() == url_l and (not kind or old.kind == kind)
        if hit:
            removed.append(f"{old.kind} {old.method} {old.url}")
        else:
            kept.append(e)
    if not removed:
        return f"用户登记里没有 {url}（配置段条目请直接改 config.yaml）"
    path.parent.mkdir(parents=True, exist_ok=True)
    import yaml

    try:
        path.write_text(
            yaml.safe_dump(kept, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except OSError as exc:
        raise AuthRegistryError(f"登记文件写入失败（{path}）：{exc}") from exc
    return "已注销：" + "；".join(removed)


# ── 候选提示（只提示，不授权） ─────────────────────────────────────


def candidate_hint(cfg: Any | None = None, url: str = "", bound_target: str = "") -> str:
    """URL 未登记时的**候选提示**文本（写进拒绝理由）。

    用 ``implicit_endpoint`` 的关键词识别判断"这个 URL 像不像认证
    端点"——像，就告诉用户它**看起来**是什么、怎么登记；不像，返回
    空串。这里绝不能返回 ALLOW，也不能返回 AuthEndpoint——候选不是
    授权。

    ``cfg`` 为空时用 :func:`configure` 注入的默认配置（RequestGuard
    在构造时注入），两者都没有就按项目根 ``data/`` 兜底。
    """
    from policy.auth_bootstrap import implicit_endpoint

    imp = implicit_endpoint(url)
    if imp is None:
        return ""
    for ep in entries_for(cfg or _DEFAULT_CFG, bound_target):
        if ep.kind == imp.kind:
            return ""                # 已有同类登记入口 → 被拒另有原因，不提示登记
    return (
        f"候选识别：{url} 的路径像 {imp.kind} 入口（关键词识别，不构成授权）。"
        "要启用它，请登记后重试：REPL /auth register，或写进 config.yaml "
        "policy.auth_endpoints（target/kind/url/method）"
    )


#: 模块级默认配置（RequestGuard 注入；candidate_hint 的 cfg 缺省来源）。
_DEFAULT_CFG: Any = None


def configure(cfg: Any) -> None:
    """注入默认配置（RequestGuard 构造时调用一次；测试可随时换）。"""
    global _DEFAULT_CFG
    _DEFAULT_CFG = cfg
