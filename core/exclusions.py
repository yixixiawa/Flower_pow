"""误报排除清单：把人工判定为误报的发现按**目标**持久化下来。

为什么需要这个模块
------------------
自动探针判不了"这是不是误报"。最典型的例子是**公开演示站点**：站点本身就是
建给人看的，"泄露"出来的配置、默认账号、接口文档全是有意公开的。探针看到
"敏感信息"照报不误，而这属于**设计如此**，不是漏洞。

只在当前会话里标一次不够——同一目标重扫一遍，同一条又会作为"有效发现"冒出来，
用户每轮都得手工再删一次。所以排除项必须按目标落盘、跨会话生效。

匹配粒度
--------
一条排除项 = ``(poc_id, matched_at)``；也支持**只填 poc_id**（``matched_at``
留空），表示"这个 POC 在该目标上整体不可信"——例如某个通用探针在 SPA 站点上
永远误报，逐条排除没意义。

存储格式
--------
``data/exclusions.json``（跟随 ``POCS_DATA_DIR``）::

    {
      "demo.example.com": [
        {"poc_id": "path-backup-file",
         "matched_at": "https://demo.example.com/db.sql",
         "reason": "公开演示站点，资料本就公开",
         "at": 1791234567.0}
      ]
    }

两条硬约束：

1. **原子写**（临时文件 + ``os.replace``）——中途崩溃不会留下半个 JSON，
   否则下一次启动会因为解析失败把整份排除清单丢掉。
2. **读失败一律当作"没有排除项"，绝不抛给调用方**。排除清单只是便利功能，
   不该有能力让扫描崩掉。
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

# 默认落点与 ``ScanConfig.data_dir`` 的默认值保持一致；启动时由
# ``load_config()`` 调 :func:`set_store_path` 覆盖成真实路径。
_DEFAULT_PATH = Path("./data/exclusions.json")
_path: Path = _DEFAULT_PATH

# 读缓存：(路径, mtime, 内容)。合并发现时每条都要查一次，不缓存会反复读盘。
_cache_key: tuple[str, float] | None = None
_cache_data: dict[str, list[dict]] = {}


# ── 路径 ──────────────────────────────────────────────────────────


def set_store_path(p: str | Path) -> None:
    """设置排除清单落点（由配置层调用一次）。"""
    global _path, _cache_key
    _path = Path(p)
    _cache_key = None


def store_path() -> Path:
    return _path


def _invalidate() -> None:
    global _cache_key
    _cache_key = None


# ── 归一化 ────────────────────────────────────────────────────────


def host_of(target: str) -> str:
    """把目标（URL / host / host:port）归一成一个 host 键。

    去掉 userinfo、统一小写、抹掉默认端口 80/443——``https://A.com:443/``
    与 ``a.com`` 必须落到同一条排除项上，否则用户换个写法排除就失效了。
    """
    s = (target or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "//" + s            # 让 urlparse 把它当 netloc 解析
    try:
        p = urlparse(s)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return ""
    if not host:
        return ""
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


def _key(matched_at: str) -> str:
    """匹配用的键：去空白、去尾斜杠，**只把 host 部分转小写**。

    为什么只低化 host、不整串小写：域名大小写不敏感是规范，而路径在某些
    服务器上是敏感的。整串小写会把 ``/Admin`` 和 ``/admin`` 混为一谈，
    那是在**放大**排除范围——误报排除本来就该保守，宁可少匹配不可多匹配。
    """
    s = (matched_at or "").strip()
    while s.endswith("/"):
        s = s[:-1]
    if "://" in s:
        scheme, _, rest = s.partition("://")
        host, sep, path = rest.partition("/")
        return f"{scheme.lower()}://{host.lower()}{sep}{path}"
    return s


def _same(x: str, y: str) -> bool:
    return (x or "").strip() == (y or "").strip()


# ── 读写 ──────────────────────────────────────────────────────────


def load() -> dict[str, list[dict]]:
    """读入整份排除清单。任何失败都返回空表，不抛异常。"""
    global _cache_key, _cache_data
    p = _path
    try:
        st = p.stat()
        key = (str(p), st.st_mtime)
    except OSError:
        _cache_key, _cache_data = None, {}
        return {}
    if _cache_key == key:
        return _cache_data
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001  —— 损坏/空文件一律当没有
        _cache_key, _cache_data = key, {}
        return {}
    data: dict[str, list[dict]] = {}
    if isinstance(raw, dict):
        for host, items in raw.items():
            if not isinstance(items, list):
                continue
            clean = [x for x in items if isinstance(x, dict)]
            if clean:
                data[str(host).lower()] = clean
    _cache_key, _cache_data = key, data
    return data


def _save(data: dict[str, list[dict]]) -> bool:
    """原子写。返回是否成功（失败不抛）。"""
    p = _path
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".excl-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, p)       # 同目录 rename，原子
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001
        return False
    _invalidate()
    return True


# ── 查询 ──────────────────────────────────────────────────────────


def entries(target: str) -> list[dict]:
    """该目标下的全部排除项。"""
    host = host_of(target)
    if not host:
        return []
    return list(load().get(host, []))


def match_reason(target: str, poc_id: str, matched_at: str) -> str | None:
    """命中排除清单则返回记录的原因（可能是空串），否则 ``None``。"""
    host = host_of(target)
    if not host:
        return None
    for e in load().get(host, []):
        if not _same(e.get("poc_id"), poc_id):
            continue
        e_matched = str(e.get("matched_at") or "")
        if not e_matched:                     # 只按 POC 排除 → 该 POC 全部命中
            return str(e.get("reason") or "")
        if _key(e_matched) == _key(matched_at):
            return str(e.get("reason") or "")
    return None


def is_excluded(target: str, poc_id: str, matched_at: str) -> bool:
    return match_reason(target, poc_id, matched_at) is not None


# ── 修改 ──────────────────────────────────────────────────────────


def add(
    target: str,
    poc_id: str,
    matched_at: str,
    reason: str,
    *,
    scope: str = "finding",
) -> tuple[bool, str]:
    """新增/覆盖一条排除项。返回 ``(是否写入成功, 说明)``。

    ``scope="poc"`` 表示只按 poc_id 排除（``matched_at`` 会被清空），
    用于"这个 POC 在该目标上整体不可信"。
    """
    host = host_of(target)
    if not host:
        return False, f"无法从目标 {target!r} 解析出主机名"
    if not (poc_id or "").strip():
        return False, "poc_id 不能为空"

    matched = "" if scope == "poc" else (matched_at or "").strip()
    if scope != "poc" and not matched:
        return False, "matched_at 不能为空（要按 POC 整体排除请传 scope='poc'）"

    data = load()
    items = [dict(x) for x in data.get(host, [])]
    for e in items:
        if _same(e.get("poc_id"), poc_id) and _key(str(e.get("matched_at") or "")) == _key(matched):
            e["reason"] = (reason or "").strip()
            e["at"] = time.time()
            e["scope"] = scope
            data[host] = items
            ok = _save(data)
            return ok, f"已更新排除项（{poc_id}）"
    items.append(
        {
            "poc_id": poc_id.strip(),
            "matched_at": matched,
            "reason": (reason or "").strip(),
            "at": time.time(),
            "scope": scope,
        }
    )
    data[host] = items
    ok = _save(data)
    return ok, f"已排除（{poc_id}）"


def remove(target: str, poc_id: str = "", matched_at: str | None = None) -> int:
    """删除排除项。``poc_id`` 留空表示清空该目标全部排除项。

    返回删掉的条数。
    """
    host = host_of(target)
    if not host:
        return 0
    data = load()
    items = list(data.get(host, []))
    if not items:
        return 0
    if not poc_id:
        n = len(items)
        data.pop(host, None)
        _save(data)
        return n
    keep, removed = [], 0
    for e in items:
        if not _same(e.get("poc_id"), poc_id):
            keep.append(e)
            continue
        if matched_at is None or _key(str(e.get("matched_at") or "")) == _key(matched_at):
            removed += 1
            continue
        keep.append(e)
    if removed:
        if keep:
            data[host] = keep
        else:
            data.pop(host, None)
        _save(data)
    return removed


def summary() -> list[tuple[str, int]]:
    """``[(host, 条数), ...]``，供 CLI 展示。"""
    return sorted(
        ((h, len(v)) for h, v in load().items() if v),
        key=lambda x: (-x[1], x[0]),
    )


__all__ = [
    "set_store_path",
    "store_path",
    "host_of",
    "load",
    "entries",
    "match_reason",
    "is_excluded",
    "add",
    "remove",
    "summary",
]
