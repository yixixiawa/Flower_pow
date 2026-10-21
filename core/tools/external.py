"""外部 CLI 工具：数据模型、内置清单、用户自定义清单。

三层含义要分清：

1. :class:`ExternalTool` —— 一个外部工具的**声明**（可执行名、参数白名单、
   是否侵入性、超时）。声明本身不代表装了。
2. :data:`EXTERNAL_TOOLS` —— 随代码走的**内置清单**，覆盖通用渗透工具。
3. ``data/tools.local.yaml`` —— **用户清单**，与内置清单合并。

为什么要留用户清单这个口子：机器上 ``httpx`` 明明在 PATH 里，但因为不在内置
清单里，探测永远返回"未安装"。**"工具存在"和"工具被登记"是两件事，
程序只认后者。** 改 YAML 即生效，不用改源码、不用重装。

* 仍然只暴露**真的存在**的工具（探测见 :mod:`core.tools.probe`），不骗模型
* 参数白名单同样在这里声明——安全闸门不允许被"配置"绕过
"""


from __future__ import annotations

import re

from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ── 外部工具目录 ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExternalTool:
    """一个外部 CLI 工具的描述。

    ``flags`` 是**允许出现的选项白名单**。不在白名单里的 ``-x`` 参数会被
    执行层直接拒绝——外部工具的参数空间太大，不做白名单等于把
    ``--script=`` 这类能加载任意脚本的开关也开放给模型。
    """

    key: str
    name: str
    bins: tuple[str, ...]
    category: str
    desc: str
    flags: tuple[str, ...] = ()
    version_args: tuple[str, ...] = ("--version",)
    needs_target: bool = True
    intrusive: bool = False
    timeout: int = 180
    example: str = ""
    note: str = ""


EXTERNAL_TOOLS: list[ExternalTool] = [
    ExternalTool(
        key="nmap",
        name="nmap",
        bins=("nmap",),
        category="端口 / 服务",
        desc="端口扫描与服务指纹。比内置 TCP connect 多出 banner 抓取与版本推断。",
        flags=(
            "-sT", "-sV", "-Pn", "-n", "-T2", "-T3", "-T4", "-F", "-p",
            "--top-ports", "--version-light", "--version-intensity", "--open",
            "-v", "--reason", "--max-retries", "--host-timeout",
        ),
        version_args=("--version",),
        example="nmap -sT -sV --version-light -Pn -n --top-ports 200 example.com",
        note="只允许把结果打到 stdout；-oN/-oX/-oG 等写文件选项已被禁用。",
    ),
    ExternalTool(
        key="dirsearch",
        name="dirsearch",
        bins=("dirsearch",),
        category="路径爆破",
        desc="目录/文件爆破。字典规模远超内置的 120 条，支持状态码与正文过滤。",
        flags=(
            "-u", "-e", "-t", "-i", "-x", "--exclude-status", "--exclude-text",
            "--exclude-redirect", "--timeout", "-w", "--plain", "-q", "--no-color",
            "--random-agent", "--max-time", "-r", "--recursion-depth", "--subdirs",
            "--full-url", "--simple-report",
        ),
        version_args=("--version",),
        example="dirsearch -u https://example.com -e php,js,bak -t 20 --plain -q --no-color",
    ),
    ExternalTool(
        key="whatweb",
        name="whatweb",
        bins=("whatweb",),
        category="指纹识别",
        desc="Web 指纹识别：框架、CMS、中间件、JS 库。识别结果可直接喂给 RAG 检索。",
        flags=("-a", "-v", "--no-errors", "--color=never", "--user-agent", "--max-threads"),
        version_args=("--version",),
        example="whatweb -a 3 -v --no-errors --color=never https://example.com",
    ),
    ExternalTool(
        key="nuclei",
        name="nuclei",
        bins=("nuclei",),
        category="模板扫描",
        desc="社区模板引擎，覆盖大量 CVE 与配置类检测。只跑只读模板。",
        flags=(
            "-u", "-t", "-tags", "-severity", "-silent", "-no-color", "-timeout",
            "-rl", "-c", "-stats", "-jsonl", "-nc", "-duc", "-ept", "-headless=false",
        ),
        version_args=("-version",),
        timeout=300,
        example="nuclei -u https://example.com -severity critical,high -silent -no-color -duc",
        note="写文件类选项（-o/-me/-je）已禁用；-headless 强制关闭。",
    ),
    ExternalTool(
        key="curl",
        name="curl",
        bins=("curl", "curl.exe"),
        category="HTTP 手工",
        desc=(
            "发单个 HTTP 请求看原始响应。适合验证某个具体猜测"
            "（例如未授权访问、响应头缺失）时抓一次完整报文。"
        ),
        flags=(
            "-I", "-i", "-s", "-S", "-k", "-L", "-X", "-H", "-d", "--data-raw",
            "--max-time", "--connect-timeout", "-A", "-b", "-u", "--compressed",
            "-v", "--http1.1", "--http2", "-w",
        ),
        version_args=("--version",),
        timeout=60,
        example="curl -i -s -k -X GET https://example.com/api/health -H 'Accept: application/json'",
        note="-o/-O（写文件）与 -T/-F（上传）已被禁用。",
    ),
    ExternalTool(
        key="gobuster",
        name="gobuster",
        bins=("gobuster",),
        category="路径爆破",
        desc="目录/DNS/VHOST 爆破。需要 -w 指定字典文件。",
        flags=(
            "-u", "-w", "-t", "-k", "-q", "--timeout", "-s", "--status-codes",
            "-b", "--exclude-length", "--no-error", "-r", "--random-agent", "-e",
        ),
        version_args=("version",),
        note="字典请用 data/wordlists/builtin.txt（初始化时已生成）。",
    ),
    ExternalTool(
        key="ffuf",
        name="ffuf",
        bins=("ffuf",),
        category="模糊测试",
        desc="高速 Web 模糊测试。需要 -w 指定字典，FUZZ 关键字替换。",
        flags=(
            "-u", "-w", "-t", "-mc", "-fc", "-fs", "-H", "-X", "-d", "-k",
            "-s", "-timeout", "-rate", "-ac", "-recursion", "-recursion-depth",
        ),
        version_args=("-V",),
        timeout=240,
        example="ffuf -u https://example.com/FUZZ -w data/wordlists/builtin.txt -mc 200,301,403 -s",
    ),
    ExternalTool(
        key="nikto",
        name="nikto",
        bins=("nikto", "nikto.pl"),
        category="综合扫描",
        desc="老牌 Web 服务器扫描器，覆盖大量已知配置问题与危险文件。",
        flags=("-h", "-Tuning", "-nointeractive", "-maxtime", "-Display", "-ask", "-nolookup"),
        version_args=("-Version",),
        intrusive=True,
        timeout=300,
        example="nikto -h https://example.com -nointeractive -maxtime 120s -ask no",
    ),
    ExternalTool(
        key="sqlmap",
        name="sqlmap",
        bins=("sqlmap", "sqlmap.py"),
        category="注入验证",
        desc="SQL 注入检测与利用。**默认被只读模式拦截。**",
        flags=(
            "-u", "--url", "--batch", "--level", "--risk", "--dbms", "-p",
            "--technique", "--timeout", "--threads", "--random-agent", "--smart",
            "--flush-session", "--answers",
        ),
        version_args=("--version",),
        intrusive=True,
        timeout=300,
        note="会向目标发送攻击性 payload，可能留下痕迹或造成数据变更。需显式关闭 readonly。",
    ),
    ExternalTool(
        key="wpscan",
        name="wpscan",
        bins=("wpscan",),
        category="CMS 专项",
        desc="WordPress 专项扫描：版本、插件、主题、用户枚举。",
        flags=("--url", "--enumerate", "-e", "--random-user-agent", "--no-banner",
               "--format", "--disable-tls-checks", "--max-threads"),
        version_args=("--version",),
        timeout=300,
    ),
    ExternalTool(
        key="hydra",
        name="hydra",
        bins=("hydra",),
        category="口令爆破",
        desc="在线口令爆破。**默认被只读模式拦截。**",
        flags=("-l", "-L", "-p", "-P", "-s", "-t", "-f", "-V"),
        version_args=("-h",),
        intrusive=True,
        timeout=180,
        note="高频登录尝试会触发目标锁定策略、制造真实业务影响。仅限授权范围内的自有环境。",
    ),
    ExternalTool(
        key="masscan",
        name="masscan",
        bins=("masscan",),
        category="端口 / 服务",
        desc="高速端口扫描（自实现 TCP 栈，需要管理员权限）。",
        flags=("-p", "--top-ports", "--rate", "--wait", "--open-only", "-Pn"),
        version_args=("--version",),
        intrusive=True,
        timeout=240,
        note="全速率扫描极易被 IDS 判定为攻击，且可能打垮小带宽链路。",
    ),
]

# ── 用户自定义外部工具清单 ───────────────────────────────────────────

# 为什么要留这个口子
# ------------------
# 上面 12 项是硬编码的**内置清单**，它只覆盖"通用渗透工具"。但每台机器
# 装的东西不一样：有人装 ProjectDiscovery 的 httpx / nuclei，有人装自研脚本。
# 如果只能改源码才能登记新工具，那么"装了个新工具但工具不认"就成了必然。
#
# 实际踩过的坑：机器上 `httpx` 明明在 PATH 里（`D:\python\Scripts\httpx`），
# 但因为它不在内置清单里，探测永远返回"未安装"——环境变量配得再对也没用。
# **"工具存在"和"工具被登记"是两件事，程序只认后者。**
#
# 做法：读 `data/tools.local.yaml`，与内置清单合并。
# * 不用改代码、不用重新安装包，改完 YAML 下一条命令就生效
# * 仍然只暴露**探测到真的存在**的工具（见 probe_external），不会骗模型
# * 参数白名单同样在这里声明——安全闸门不允许被"配置"绕过

USER_TOOLS_FILE = Path("data") / "tools.local.yaml"

# 允许登记的最小字段集。刻意不开放"任意 flags"之外的东西：
# flags 决定模型能让工具做什么，缺省时一律空元组 = 一个选项都不许传。
_USER_TOOL_FIELDS = {
    "key", "name", "bins", "category", "desc",
    "flags", "version_args", "intrusive", "timeout", "note", "example",
}


def _coerce_flags(raw: Any) -> tuple[str, ...]:
    """把 YAML 里的选项列表转成元组，并做基本形状校验。

    只接受字符串。**故意不解析逗号分隔的整串**：``"a, b"`` 这种写法
    看起来方便，但一旦某个选项本身要传逗号（``--exclude-text=a,b``）
    就彻底说不清了。宁可要求写成列表。
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if not isinstance(raw, (list, tuple)):
        raise ValueError("flags 必须是字符串列表")
    out: list[str] = []
    for x in raw:
        if not isinstance(x, str):
            raise ValueError(f"flags 里混入了非字符串项：{x!r}")
        if not x.startswith("-"):
            raise ValueError(f"flag 必须以 - 开头：{x!r}")
        out.append(x)
    return tuple(out)


def load_user_tools(path: str | Path | None = None) -> tuple[list[ExternalTool], list[str]]:
    """从 YAML 读用户自定义工具。

    返回 ``(工具列表, 错误信息列表)``。**读失败不抛异常**——用户手写
    YAML 很容易出小错（缩进、冒号），而探测失败顶多少认一个工具，
    不该让整个程序起不来。错误照实报出来，用户自己判断要不要修。
    """
    p = Path(path) if path else USER_TOOLS_FILE
    if not p.is_file():
        return [], []
    try:
        import yaml

        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        return [], [f"{p} 解析失败：{type(exc).__name__}: {exc}"]

    if not isinstance(data, dict):
        return [], [f"{p} 顶层应是字典（形如tools: [...]）"]
    items = data.get("tools")
    if items is None:
        return [], []
    if not isinstance(items, list):
        return [], [f"{p} 的 tools 字段应是列表"]

    out: list[ExternalTool] = []
    errs: list[str] = []
    for i, raw in enumerate(items, 1):
        if not isinstance(raw, dict):
            errs.append(f"{p} 第 {i} 项不是字典，已跳过")
            continue
        unknown = set(raw) - _USER_TOOL_FIELDS
        if unknown:
            errs.append(f"{p} 第 {i} 项含未知字段 {sorted(unknown)}，已忽略这些字段")
        key = str(raw.get("key") or "").strip()
        if not key:
            errs.append(f"{p} 第 {i} 项缺 key，已跳过")
            continue
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", key):
            errs.append(f"{p} 第 {i} 项 key={key!r} 含非法字符（只允许小写字母/数字/_/./-），已跳过")
            continue
        bins = raw.get("bins") or ([key] if raw.get("name") else None)
        if isinstance(bins, str):
            bins = [bins]
        if not isinstance(bins, (list, tuple)) or not bins:
            errs.append(f"{p} 第 {i} 项（{key}）缺 bins，无法探测，已跳过")
            continue
        try:
            flags = _coerce_flags(raw.get("flags"))
            vargs = _coerce_flags(raw.get("version_args")) or ("--version",)
        except ValueError as exc:
            errs.append(f"{p} 第 {i} 项（{key}）{exc}，已跳过")
            continue
        out.append(
            ExternalTool(
                key=key,
                name=str(raw.get("name") or key),
                bins=tuple(str(b) for b in bins),
                category=str(raw.get("category") or "自定义"),
                desc=str(raw.get("desc") or "用户自定义工具"),
                flags=flags,
                version_args=vargs,
                intrusive=bool(raw.get("intrusive", False)),
                timeout=int(raw.get("timeout") or 180),
                example=str(raw.get("example") or ""),
                note=str(raw.get("note") or ""),
            )
        )
    return out, errs


def all_external_tools(path: str | Path | None = None) -> tuple[list[ExternalTool], list[str]]:
    """内置清单 + 用户清单。按 key 去重，**用户定义优先**。

    去重是必需的：用户会想覆盖内置项（比如自己装的 nuclei 支持更多选项，
    想换掉内置那套 flags）。用户优先让覆盖成为可能，同时仍只留一条。
    """
    user, errs = load_user_tools(path)
    merged: dict[str, ExternalTool] = {t.key: t for t in EXTERNAL_TOOLS}
    for t in user:
        if t.key in merged:
            errs.append(f"自定义工具 {t.key!r} 与内置同名，已用自定义定义覆盖内置项")
        merged[t.key] = t
    return list(merged.values()), errs


def write_user_tools_template(root: str | Path = ".") -> Path | None:
    """首次运行时生成一份带注释的模板，告诉用户"加工具改这里"。

    没有这个文件的话，用户唯一能想到的办法就是去改 Python 源码——
    那正是这个特性要消除的。
    """
    p = Path(root) / USER_TOOLS_FILE
    if p.is_file():
        return p
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_USER_TOOLS_TEMPLATE, encoding="utf-8")
    except OSError:
        return None


_USER_TOOLS_TEMPLATE = """\
# 自定义外部工具清单
# ==================
# 装了新工具但 flower_pow.py tools 显示"未安装"？在这里登记，不用改 Python 源码。
#
# 生效方式：改完直接跑下一条命令即可（探测每次都重新读这个文件，无需重启）。
#     python flower_pow.py tools
#
# 四条规则：
# 1. key 用小写字母/数字/下划线，同名会**覆盖**内置清单里的同名项。
# 2. bins 填命令行文件名（不是目录）。程序用 shutil.which 在 PATH 里找它，
#    所以只支持能在终端直接敲起来的 CLI；IDA / Burp 这类 GUI 工具填了也没用。
# 3. flags 是**允许模型使用的选项白名单**，不在列表里的参数会被执行层拒绝。
#    留空 = 一个选项都不许传。写之前想清楚：这个开关等于交出多大权限。
#    例：--script= 能加载任意文件，就绝不能写进来。
# 4. **先确认你登记的那个命令真的是你想的那个工具**。同名不同物非常常见：
#      - `httpx` 有两个毫无关系的实现——ProjectDiscovery 的渗透工具，
#        和 Python httpx 库附带的命令行包装器（很多机器上都有）。
#        误登记会让模型拿到一个名字像扫描器、实际只会打 HTTP 请求的东西。
#      - `curl` / `wget` 在 Unix 与 Windows 上行为不同。
#    确认办法：先在终端敲 `工具名 -version` 看输出对不对，
#    再决定是否登记（登记后 tools 命令的"版本"列也会显示它，方便核对）。

tools:
  # 示例：ProjectDiscovery nuclei（模板扫描，注意用 -version 而非 --version）
  # - key: nuclei-pd
  #   name: nuclei-pd
  #   bins: [nuclei, nuclei.exe]
  #   category: 模板扫描
  #   desc: 社区模板引擎，跑只读模板。
  #   flags: [-u, -tags, -severity, -silent, -no-color, -duc, -rl, -c, -timeout]
  #   version_args: [-version]
  #   timeout: 300
  #   note: 写文件类选项（-o/-me/-je）不要加进 flags。
  #
  # 示例：自研脚本（本地绝对路径也能写进 bins）
  # - key: my-fuzzer
  #   name: my-fuzzer
  #   bins: [D:/tools/my-fuzzer.exe]
  #   category: 自研
  #   desc: 我自己写的参数模糊测试脚本。
  #   flags: [-u, -w, -t]
  #   version_args: [-h]
"""
