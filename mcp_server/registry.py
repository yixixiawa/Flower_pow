"""把本项目的 MCP Server 注册进客户端配置——``flower_pow mcp install`` 的实现。

要解决什么
----------
接入 WorkBuddy 要手改**两处** JSON：``mcp.json`` 里加一条 ``mcpServers`` 条目，
``mcp-approvals.json`` 里加一个**信任指纹**。后者最坑：它是
``sha256(command|排序后的 args|排序后的 env 键) + "::" + server 名``，
手算不出来；而且客户端对不上就把这条 server 当成"配置被改过"，**静默不加载**
——现象是"配了但工具列表里没有"，没有任何报错。

所以把算法固化进代码：一条命令完成"写配置 + 算指纹 + 备份"。

指纹算法（:func:`fingerprint` 是唯一实现）
-------------------------------------------
三个细节都是踩出来的，别随手改：

1. ``args`` **排序后**用逗号连接——只是换 args 顺序不会让信任失效；
2. ``env`` 只取**键名**排序连接，值不参与——所以往 env 里塞密钥不影响指纹，
   但**多一个环境变量**就会要求重新信任（值的变更客户端本来就不该管）；
3. 不含 ``cwd``——客户端不算它（用两个真实条目反推验证过，
   见 ``scripts/mcp_registry_test.py`` 的固定向量）。

安全边界
--------
**绝不覆盖读不懂的配置**。目标文件不是合法 JSON、顶层不是对象、
``mcpServers`` 不是对象——一律 :class:`RegistryError` 退出，让人先手工修。
一次"顺手修好"会把里面其它 server（rea、agent-mail…）全删掉。

本模块只用标准库：装 MCP 之前也能跑 ``install``（它只是写配置，不起进程）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Mapping
from typing import Sequence

SERVERS_KEY = "mcpServers"
TRUST_SEP = "::"


class RegistryError(RuntimeError):
    """配置读不懂、路径不可写——宁可失败，也不猜着改。"""


# ── 指纹与条目 ────────────────────────────────────────────────


def fingerprint(
    command: str,
    args: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
) -> str:
    """客户端认的信任指纹。改算法等于让**所有**已信任配置失效，别动。"""
    material = "|".join(
        [
            command or "",
            ",".join(sorted(str(a) for a in (args or ()))),
            ",".join(sorted((env or {}).keys())),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def trust_key(name: str, fp: str) -> str:
    """``mcp-approvals.json`` 的键格式：``<指纹>::<server 名>``。"""
    return f"{fp}{TRUST_SEP}{name}"


def entry_for(
    python: str,
    script: str,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """拼一条 ``mcpServers`` 条目。

    ``args`` 固定是 ``[script, "mcp"]``——**别加子命令**（如 ``mcp serve``）：
    现有已信任配置就是这个形状，形状一变，用户就得重新信任一次。
    """
    entry: dict[str, Any] = {"command": python, "args": [script, "mcp"]}
    if env:
        entry["env"] = dict(env)
    return entry


# ── 客户端 ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Client:
    """一个客户端配置文件的位置与特性。"""

    key: str
    label: str
    config: Path
    approvals: Path | None = None
    restart_hint: str = ""


def clients(home: str | Path | None = None) -> dict[str, Client]:
    """已知客户端的配置路径。``home`` 可覆盖，供测试用临时目录。"""
    h = Path(home) if home else Path.home()
    out: dict[str, Client] = {
        "workbuddy": Client(
            key="workbuddy",
            label="WorkBuddy",
            config=h / ".workbuddy" / "mcp.json",
            approvals=h / ".workbuddy" / "mcp-approvals.json",
            restart_hint="需要重启 WorkBuddy：它在启动时只读一次 mcp.json，之后写的不会热加载",
        )
    }

    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA") or (h / "AppData" / "Roaming"))
        claude_cfg = appdata / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        claude_cfg = (
            h / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    else:
        claude_cfg = h / ".config" / "Claude" / "claude_desktop_config.json"

    out["claude"] = Client(
        key="claude",
        label="Claude Desktop",
        config=claude_cfg,
        restart_hint="需要完全退出并重启 Claude Desktop（不是关窗口）",
    )
    out["cursor"] = Client(
        key="cursor",
        label="Cursor",
        config=h / ".cursor" / "mcp.json",
        restart_hint="在 Cursor 里执行 Reload Window 让配置生效",
    )
    return out


def pick_clients(spec: str = "workbuddy", home: str | Path | None = None) -> list[Client]:
    """按 ``--client`` 选目标。``all`` 展开全部已知客户端。"""
    known = clients(home)
    raw = [x.strip().lower() for x in (spec or "").split(",") if x.strip()]
    if not raw:
        raw = ["workbuddy"]
    if "all" in raw:
        return list(known.values())
    missing = [k for k in raw if k not in known]
    if missing:
        raise RegistryError(
            f"不认识的客户端：{'、'.join(missing)}（可选：{'、'.join(known)}、all）"
        )
    return [known[k] for k in raw]


# ── 读写 ──────────────────────────────────────────────────────


def load_config(path: Path) -> dict[str, Any]:
    """读配置并保证 ``mcpServers`` 是对象；字段坏了抛 :class:`RegistryError`。"""
    if not path.is_file():
        return {SERVERS_KEY: {}}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistryError(f"读不了 {path}：{exc}") from exc
    if not raw.strip():
        return {SERVERS_KEY: {}}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryError(
            f"{path} 不是合法 JSON（第 {exc.lineno} 行 {exc.colno} 列）：{exc.msg}\n"
            "先手工修好再装——直接覆盖会把里面已有的其它 MCP server 一起删掉。"
        ) from exc
    if not isinstance(data, dict):
        raise RegistryError(f"{path} 顶层不是 JSON 对象，拒绝改写。")
    servers = data.setdefault(SERVERS_KEY, {})
    if not isinstance(servers, dict):
        raise RegistryError(f"{path} 里的 {SERVERS_KEY} 不是对象，拒绝改写。")
    return data


def _dump(data: Mapping[str, Any]) -> str:
    # 与客户端自己写的格式一致（2 空格缩进、结尾换行），避免每次 install 都产生
    # 一整篇 diff——用户在 git/备份里看到"全是改动"会以为出了大事。
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def backup(path: Path, stamp: str | None = None) -> Path | None:
    """改之前先留一份。文件不存在返回 ``None``（没什么可备份）。"""
    if not path.is_file():
        return None
    tag = stamp or time.strftime("%Y%m%d-%H%M%S")
    dst = path.with_name(f"{path.name}.bak-{tag}")
    shutil.copy2(path, dst)
    return dst


def _load_approvals(path: Path) -> dict[str, Any]:
    """审批表是**缓存**，坏了可以重建（备份后丢弃），不像 mcp.json 那样致命。"""
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (json.JSONDecodeError, OSError):
        return {}
    return raw if isinstance(raw, dict) else {}


# ── 三个动作 ─────────────────────────────────────────────────


@dataclass
class InstallResult:
    client: Client
    action: str  # created / updated / unchanged
    backup: Path | None
    fingerprint: str
    trusted: bool

    @property
    def ok(self) -> bool:
        return self.action in ("created", "updated", "unchanged")


@dataclass
class UninstallResult:
    client: Client
    removed_entry: bool
    removed_trusts: int
    backup: Path | None


@dataclass
class Status:
    client: Client
    registered: bool
    entry: dict[str, Any] | None
    fingerprint: str
    trusted: bool
    config_exists: bool

    @property
    def healthy(self) -> bool:
        if not self.registered:
            return False
        # 没有审批机制的客户端（claude / cursor）只要求"条目在"
        return self.trusted or self.client.approvals is None


def install(
    client: Client,
    name: str,
    entry: dict[str, Any],
    *,
    dry_run: bool = False,
    stamp: str | None = None,
) -> InstallResult:
    """写入条目 + 信任指纹。幂等：配置相同时什么都不写。"""
    data = load_config(client.config)
    servers = data[SERVERS_KEY]
    old = servers.get(name)
    if old == entry:
        action = "unchanged"
    else:
        action = "updated" if isinstance(old, dict) else "created"

    fp = fingerprint(
        str(entry.get("command") or ""),
        entry.get("args") or (),
        entry.get("env") or {},
    )

    if dry_run:
        # 干跑要能回答"现在到底行不行"，所以信任看现状而不是"假装刚写"
        trusted = client.approvals is not None and (
            trust_key(name, fp) in _load_approvals(client.approvals)
        )
        return InstallResult(client, action, None, fp, trusted)

    bak = None
    if action != "unchanged":
        bak = backup(client.config, stamp)
        servers[name] = entry
        _atomic_write(client.config, _dump(data))
    # 配置没变时不重写——否则每跑一次 install 就多一个 .bak，
    # 而用户往往只是"确认一下装没装"。

    trusted = False
    if client.approvals is not None:
        cur = _load_approvals(client.approvals)
        stale = [k for k in cur if k.split(TRUST_SEP)[-1] == name and k != trust_key(name, fp)]
        if trust_key(name, fp) in cur and not stale:
            trusted = True
        else:
            # 没登记，或留着换解释器前的旧指纹 → 重写一次（顺手清掉旧键）
            trusted = _approve(client.approvals, name, fp, stamp)
    return InstallResult(client, action, bak, fp, trusted)


def _approve(path: Path, name: str, fp: str, stamp: str | None) -> bool:
    data = _load_approvals(path)
    if path.is_file() and data == {}:
        # 原文件存在但读不出来：备份后重建（缓存坏了不值得阻塞安装）
        try:
            if path.read_text(encoding="utf-8").strip() not in ("", "{}"):
                backup(path, stamp)
        except OSError:
            pass
    # 清掉同名 server 的旧指纹，否则换解释器/换路径后旧键会一直堆着
    for key in [k for k in data if k.split(TRUST_SEP)[-1] == name]:
        data.pop(key, None)
    data[trust_key(name, fp)] = int(time.time() * 1000)
    _atomic_write(path, _dump(data))
    return True


def uninstall(
    client: Client,
    name: str,
    *,
    dry_run: bool = False,
    stamp: str | None = None,
) -> UninstallResult:
    """删条目 + 删该 server 的全部信任记录（含历史指纹）。"""
    data = load_config(client.config)
    servers = data[SERVERS_KEY]
    removed = name in servers
    bak = None
    if removed and not dry_run:
        bak = backup(client.config, stamp)
        servers.pop(name, None)
        _atomic_write(client.config, _dump(data))

    n_trust = 0
    if client.approvals is not None and client.approvals.is_file() and not dry_run:
        ap = _load_approvals(client.approvals)
        keys = [k for k in ap if k.split(TRUST_SEP)[-1] == name]
        if keys:
            backup(client.approvals, stamp)
            for k in keys:
                ap.pop(k, None)
            _atomic_write(client.approvals, _dump(ap))
            n_trust = len(keys)
    return UninstallResult(client, removed, n_trust, bak)


def inspect(client: Client, name: str) -> Status:
    """看当前状态：注册了没、指纹算出来是多少、客户端认不认。"""
    entry = load_config(client.config)[SERVERS_KEY].get(name)
    entry = entry if isinstance(entry, dict) else None
    fp = ""
    if entry:
        fp = fingerprint(
            str(entry.get("command") or ""),
            entry.get("args") or (),
            entry.get("env") or {},
        )
    trusted = False
    if fp and client.approvals is not None:
        trusted = trust_key(name, fp) in _load_approvals(client.approvals)
    return Status(
        client=client,
        registered=entry is not None,
        entry=entry,
        fingerprint=fp,
        trusted=trusted,
        config_exists=client.config.is_file(),
    )


def mcp_dependency_ok(python: str) -> bool:
    """目标解释器能不能 ``import mcp``——装了但起不来是最难查的失败。"""
    import subprocess

    try:
        r = subprocess.run(
            [python, "-c", "import mcp"],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


__all__ = [
    "Client",
    "InstallResult",
    "RegistryError",
    "SERVERS_KEY",
    "Status",
    "UninstallResult",
    "backup",
    "clients",
    "entry_for",
    "fingerprint",
    "inspect",
    "install",
    "load_config",
    "mcp_dependency_ok",
    "pick_clients",
    "trust_key",
    "uninstall",
]
