"""统一网络出口判定的**外部工具侧**：argv 解析、能力禁用、主机级授权。

"所有网络请求都要过统一 Gateway" 有两类出口，纪律不同：

1. **进程内 HTTP 客户端**（httpx）：构造参数一律走
   :func:`core.proxy.build_client_kwargs`，请求前一律走
   :class:`policy.request_guard.RequestGuard`（``check_request`` /
   ``check_builtin`` / ``check_probe``）。这条路径能看到方法、请求体、
   每一跳重定向，因此能做**逐请求**决策。
2. **外部 CLI 进程**（curl / nmap / ffuf …）：请求由**另一个进程**发出。
   ``subprocess`` 一启动，argv 之外的一切都不受控——它用什么方法、发什么
   请求体、跟到哪个主机，本程序都看不见。

第二类只能做"**启动前**判定"，依据只能来自 argv 里可解析的部分。本模块
因此定下三条不可放宽的规则：

* **不可解析的网络能力 → 禁用**。:data:`UNVERIFIABLE_NETWORK_TOOLS`
  里的工具（curl/wget）能发任意方法/请求体/重定向，argv 无法证明它
  "只发只读 GET"，也就无法保证请求过了 Gateway → **直接禁网**。
  出路是内置 ``http_request``（它逐请求过分类与矩阵判定）。
  这是"暂时禁止其网络请求能力"，不是放宽限制。
* **换主机 → 拒绝**。外部工具按**主机级**授权（工具本职就是扫该主机的
  端口/路径），但 argv 里出现的任何目标只要不是绑定目标的主机，一律
  拒绝——不允许"工具自己带了第二个目标"。
* **文件引用 → 走路径闸门**。``@file``（curl ``-H @f`` / ``-d @f``）不是
  普通字符串，必须按文件读取授权处理；绝对路径/``..``/``~`` 一律拒绝。

本模块只做**解析**，不做决策——决策在
:meth:`policy.request_guard.RequestGuard.check_tool` 里统一完成。这样
"外部工具怎么解析"只有一份实现，runner 的参数校验与策略判定不会漂移。
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

__all__ = [
    "UNVERIFIABLE_NETWORK_TOOLS",
    "VALUE_FLAGS",
    "PORT_SCAN_TOOLS",
    "is_unverifiable",
    "argv_targets",
    "host_matches",
    "target_allowed",
    "file_refs",
    "unsafe_file_ref",
    "header_value_ok",
    "looks_like_target",
    "unverifiable_reason",
]

# ── 网络能力被暂时禁用的外部工具 ──────────────────────────────────
# 判定标准只有一条：**argv 能否证明它只会发"可被策略覆盖"的请求**。
# curl/wget 可以 -X PUT、-d 任意体、-L 无限跳、-K 读配置文件、
# 甚至一次给多个 URL——这些都不是 argv 白名单能钉死的东西。
# 结论：它们无法保证"每个请求都过 Gateway" → 禁网（改用 http_request）。
UNVERIFIABLE_NETWORK_TOOLS: frozenset[str] = frozenset({"curl", "wget"})

_UNVERIFIABLE_WHY = (
    "该工具的网络请求由**外部进程**发出，方法/请求体/重定向无法被统一 "
    "Gateway 逐请求解析与分类（AUTH、L3、UNKNOWN 都可能在 argv 之外发生）。"
    "按策略暂时禁用其网络能力——请改用内置 http_request（它逐请求过分类与"
    "权限矩阵）。"
)


def is_unverifiable(tool_key: str) -> bool:
    return (tool_key or "").lower() in UNVERIFIABLE_NETWORK_TOOLS


def unverifiable_reason(tool_key: str) -> str:
    return f"{tool_key}：{_UNVERIFIABLE_WHY}"


# ── 选项 → 取值语义 ───────────────────────────────────────────────
# 这张表是"哪个参数值是什么东西"的**唯一权威**。没有它，像
# ``-H "Content-Type: application/json"`` 这样的普通 Header 会因为在
# 值里看到 ``/`` 被当成文件路径拒绝（真实踩坑）。
#
# 取值语义：
#   header   —— HTTP 头，必须符合 ``Name: value``，允许 MIME（application/json）
#   data     —— 请求体原文，``@file`` 形式才按文件处理
#   raw      —— 普通字符串（方法名、UA、Cookie、模板 id、状态码等）
#   wordlist —— 必须是项目目录内真实文件
#   template —— 路径或模板 id（nuclei 的 -t 两种都收）
#   target   —— 网络目标，由 argv_targets 收集并做主机级授权
VALUE_FLAGS: dict[str, str] = {
    # HTTP 头
    "-H": "header",
    "--header": "header",
    # 请求体原文
    "-d": "data",
    "--data": "data",
    "--data-raw": "data",
    "--data-binary": "data",
    # 目标
    "-u": "target",
    "--url": "target",
    # 字典 / 模板
    "-w": "wordlist",
    "--wordlist": "wordlist",
    "-t": "template",
    # 其余普通字符串（方法名、UA、Cookie、状态码、模板标签……）
    "-X": "raw",
    "--request": "raw",
    "-A": "raw",
    "--user-agent": "raw",
    "-e": "raw",
    "--referer": "raw",
    "-b": "raw",
    "--cookie": "raw",
    "-a": "raw",
    "--tags": "raw",
    "--severity": "raw",
    "-severity": "raw",
    "-mc": "raw",
    "-fc": "raw",
    "-fs": "raw",
    "--status-codes": "raw",
    "-x": "raw",
    "--exclude-status": "raw",
    "--exclude-text": "raw",
    "--exclude-redirect": "raw",
    "--exclude-length": "raw",
    "-p": "raw",
    "--top-ports": "raw",
    "--max-time": "raw",
    "--connect-timeout": "raw",
    "-timeout": "raw",
    "--timeout": "raw",
    "-rl": "raw",
    "-c": "raw",
    "--level": "raw",
    "--risk": "raw",
    "--technique": "raw",
    "--threads": "raw",
    "--dbms": "raw",
    "--enumerate": "raw",
    "-Tuning": "raw",
    "-maxtime": "raw",
    "-Display": "raw",
    "--format": "raw",
    "--max-threads": "raw",
    "--recursion-depth": "raw",
    "--rate": "raw",
    "--wait": "raw",
    "-l": "raw",
    "-L": "raw",
    "-P": "raw",
    "-sV": "raw",
}

# 头值：``Name: value``，值允许 ``/`` ``;`` ``=`` 等 MIME/参数分隔符。
# 显式排除 CR/LF/NUL（头注入）与控制字符。
_HEADER_NAME = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&'*+.^_`|~-"
)


def header_value_ok(value: str) -> bool:
    """``-H`` 的取值是否是合法 HTTP 头（而不是被误当成文件路径）。

    只接受 ``Name: value`` 形态：``Content-Type: application/json`` 通过，
    ``application/json``（没有头名）与 ``../../etc/passwd`` 不通过。
    """
    raw = (value or "").strip()
    if not raw or len(raw) > 2048:
        return False
    name, sep, val = raw.partition(":")
    if not sep or not name or name.strip() != name:
        return False
    if any(ch not in _HEADER_NAME for ch in name):
        return False
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in val):
        return False
    return True


def looks_like_target(value: str) -> bool:
    """这个非选项参数看起来是不是网络目标（URL 或裸主机）。"""
    a = (value or "").strip()
    if not a:
        return False
    if "://" in a:
        return True
    if a.lower() == "localhost":
        return True
    # 裸主机：含点、不含路径分隔符与空白（与 _classify_arg 的 target 判定同源）
    return "." in a and "/" not in a and "\\" not in a and " " not in a


def argv_targets(argv: list[str] | tuple[str, ...]) -> list[str]:
    """从 argv 里抽出所有**网络目标**（跳过其它选项的取值）。

    与 runner 的参数校验共用同一张 :data:`VALUE_FLAGS`，所以"哪个值算
    目标"不会在两处得出不同答案。
    """
    out: list[str] = []
    items = [str(a) for a in (argv or ())]
    i = 0
    while i < len(items):
        a = items[i]
        if a.startswith("-") and len(a) > 1:
            name, eq, val = a.partition("=")
            kind = VALUE_FLAGS.get(name) or VALUE_FLAGS.get(a)
            if kind:
                if eq and val:
                    if kind == "target" or looks_like_target(val):
                        out.append(val)
                    i += 1
                    continue
                nxt = items[i + 1] if i + 1 < len(items) else ""
                if kind == "target":
                    if nxt:
                        out.append(nxt)
                elif kind not in ("header", "data") and looks_like_target(nxt):
                    # 取值的选项被误标成普通字符串时，宁可多收集（多收集 → 拒绝，
                    # 漏收集 → 放行）。header/data 的取值是报文内容，不是目标。
                    out.append(nxt)
                i += 2
                continue
            i += 1
            continue
        if looks_like_target(a):
            out.append(a)
        i += 1
    return out


def _host_of(value: str) -> tuple[str, str]:
    """取 (hostname, scheme)，无 scheme 时按空串返回。解析失败返回空。"""
    raw = (value or "").strip()
    if not raw:
        return "", ""
    try:
        p = urlparse(raw if "://" in raw else f"//{raw}")
    except ValueError:
        return "", ""
    return (p.hostname or "").lower(), (p.scheme or "").lower()


def host_matches(target: str, bound_target: str) -> bool:
    """外部工具的目标是否与绑定目标**同一主机**（scheme/端口不参与）。

    为什么是主机级而不是完整 URL：nmap/masscan 的本职就是扫该主机的
    其它端口，``-p 1-1000`` 不该被判越界；而**换主机**就是换测试对象，
    必须拒绝。路径级/方法级的严格比对留给内置 http_request。
    """
    t_host, _ = _host_of(target)
    b_host, _ = _host_of(bound_target)
    return bool(t_host) and bool(b_host) and t_host == b_host


# 端口扫描类工具：它们的工作对象是"主机上的任意端口"，按主机级授权。
# 其它外部工具（路径枚举/模板扫/CMS 枚举）一律按 **scheme+host+port**
# 严格授权——同主机换端口也是一次不同的服务访问，不能借"同主机"放行。
PORT_SCAN_TOOLS: frozenset[str] = frozenset({"nmap", "masscan"})


def target_allowed(tool_key: str, target: str, bound_target: str) -> bool:
    """外部工具目标是否被授权（按工具能力选严格度）。

    * 端口扫描类（``PORT_SCAN_TOOLS``）→ 主机级（同主机任意端口）；
    * 其余 → 目标带 scheme 时走 ``in_scope``（scheme+host+port+路径前缀），
      裸主机（``nmap example.com`` 那种）只能按主机名比对。

    裸主机不可能带端口信息，硬套 in_scope 会把它的默认端口当成越界；
    这时按主机名比对是"能判的部分"，判不了的（端口）留给工具本身的
    参数校验——而不是放宽成"什么都行"。
    """
    if not (bound_target or "").strip() or not (target or "").strip():
        return False
    if tool_key in PORT_SCAN_TOOLS:
        return host_matches(target, bound_target)
    if "://" in target:
        from policy.request_guard import in_scope   # 延迟导入：避免模块环

        return in_scope(target, bound_target)
    return host_matches(target, bound_target)


def file_refs(argv: list[str] | tuple[str, ...]) -> list[str]:
    """argv 里所有 ``@file`` 形式的文件引用（curl/nuclei 的语法）。"""
    out: list[str] = []
    for a in (argv or ()):
        s = str(a)
        if len(s) > 1 and s.startswith("@"):
            out.append(s[1:])
    return out


def unsafe_file_ref(ref: str) -> bool:
    """文件引用是否**结构上**越界（不需要知道项目根就能判定的那部分）。

    绝对路径、``~`` 展开、盘符、``..`` 段一律算越界；项目内的相对路径
    交给 runner 的 ``_path_inside_root`` 做存在性与根目录校验。
    """
    raw = (ref or "").strip()
    if not raw or "\x00" in raw:
        return True
    if raw.startswith(("~", "/", "\\")):
        return True
    if Path(raw).is_absolute():
        return True
    parts = raw.replace("\\", "/").split("/")
    return ".." in parts
