"""外部工具探测：把"这台机器现在到底能调用什么"如实报出来。

这一层解决的核心问题：扫描器的价值不在于"自己重新实现了多少检测逻辑"，
而在于把机器上**已经存在**的能力组织起来。

* 装了 nmap → 端口和服务指纹比内置 socket connect 准得多
* 装了 dirsearch → 字典规模比内置 120 条大两个量级
* 装了 nuclei → 直接拿到社区维护的模板库

没装也不影响跑，内置实现会自动顶上。所以初始化前必须先探测。

:class:`EnvReport` 是一次体检的完整快照，初始化界面直接消费它；
其中 ``tool_errors`` 单独存用户清单的解析错误而不混进 ``externals``——
清单写错时探测结果依然有效，混在一起会让调用方分不清"没装"和"配错了"。
"""


from __future__ import annotations

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.tools.external import ExternalTool, all_external_tools


# ── 探测 ─────────────────────────────────────────────────────────────


@dataclass
class Probe:
    """单个外部工具的探测结果。"""

    spec: ExternalTool
    found: bool
    path: str = ""
    version: str = ""
    error: str = ""

    @property
    def status(self) -> str:
        if not self.found:
            return "未安装"
        return self.version or "已安装"


@dataclass
class DepStatus:
    module: str
    label: str
    ok: bool
    version: str = ""


# 运行必需的 Python 依赖。缺任何一个都不是"降级"而是跑不起来。
BUILTIN_DEPS: list[tuple[str, str]] = [
    ("httpx", "HTTP 引擎"),
    ("openai", "LLM 客户端"),
    ("yaml", "POC YAML 解析"),
    ("pydantic", "配置校验"),
    ("rich", "终端渲染"),
    ("typer", "命令行框架"),
]


def _run_quiet(cmd: list[str], timeout: float) -> subprocess.CompletedProcess | None:
    """跑一个探测命令，绝不抛异常。

    ``CREATE_NO_WINDOW`` 是为了不让 Windows 上每探测一个工具就闪一个黑框。
    """
    kw: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
    }
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(cmd, **kw)  # noqa: S603 - 参数为固定路径+白名单，无 shell
    except Exception:  # noqa: BLE001 - 探测失败不该影响主流程
        return None


def _probe_version(spec: ExternalTool, path: str, timeout: float = 2.5) -> tuple[str, str]:
    """取版本号。取不到不算失败，只返回空串。"""
    if os.environ.get("POCS_SKIP_VERSION"):
        return "", ""
    cmd = [path, *spec.version_args]
    r = _run_quiet(cmd, timeout)
    if r is None:
        return "", "版本探测超时"
    blob = f"{r.stdout or ''}\n{r.stderr or ''}".strip()
    if not blob:
        return "", ""
    # 版本号通常在输出第一行里，抠第一个 x.y[.z] 片段
    import re

    first = blob.splitlines()[0].strip()
    m = re.search(r"\d+\.\d+(?:\.\d+)*", first) or re.search(r"\d+\.\d+(?:\.\d+)*", blob)
    return (m.group(0) if m else first[:32]), ""


def probe_external(
    keys: list[str] | None = None,
    timeout: float = 2.5,
    max_workers: int = 8,
    versions: bool = True,
    user_file: str | Path | None = None,
) -> tuple[list[Probe], list[str]]:
    """并发探测外部工具。

    并发是必要的：十几个工具串行探测、每个最多 2.5s，最坏情况用户要盯着
    半分钟黑屏。并发后总耗时约等于最慢的那一个。

    探测的是**内置清单 + 用户清单**的合并结果。只扫内置清单的话，
    用户装了什么新工具都发现不了——这就是"配了环境变量仍检测不到"的原因。

    ``versions=False`` 时只做 ``shutil.which``（毫秒级）——适合"只想确认
    有没有装"的场景，比如 CI 里跑冒烟测试。

    返回 ``(探测结果, 错误信息)``。
    """
    specs, errs = all_external_tools(user_file)
    if keys:
        specs = [s for s in specs if s.key in keys]

    def work(spec: ExternalTool) -> Probe:
        path = ""
        for b in spec.bins:
            if found := shutil.which(b):
                path = found
                break
        if not path:
            return Probe(spec=spec, found=False)
        if not versions:
            return Probe(spec=spec, found=True, path=path)
        ver, err = _probe_version(spec, path, timeout)
        return Probe(spec=spec, found=True, path=path, version=ver, error=err)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(work, specs)), errs


def probe_deps() -> list[DepStatus]:
    """检查运行必需的 Python 依赖。"""
    import importlib

    out: list[DepStatus] = []
    for mod, label in BUILTIN_DEPS:
        try:
            m = importlib.import_module(mod)
            out.append(DepStatus(mod, label, True, getattr(m, "__version__", "")))
        except Exception:  # noqa: BLE001
            out.append(DepStatus(mod, label, False, ""))
    return out


# ── 环境体检报告 ──────────────────────────────────────────────────────


@dataclass
class EnvReport:
    """一次完整的环境体检结果，初始化界面直接消费它。"""

    python: str = ""
    platform: str = ""
    deps: list[DepStatus] = field(default_factory=list)
    externals: list[Probe] = field(default_factory=list)
    # 自定义工具清单（data/tools.local.yaml）的解析错误。
    # 单独存一份而不混进 externals：清单写错时 externals 仍然是有效的探测
    # 结果，两者语义不同，混在一起会让调用方分不清"没装"和"配错了"。
    tool_errors: list[str] = field(default_factory=list)
    user_tools_file: str = ""
    user_tools_count: int = 0
    index_ok: bool = False
    index_note: str = ""
    poc_count: int = 0
    api_key_set: bool = False
    api_key_source: str = ""
    wordlist_path: str = ""

    @property
    def missing_deps(self) -> list[DepStatus]:
        return [d for d in self.deps if not d.ok]

    @property
    def found_externals(self) -> list[Probe]:
        return [p for p in self.externals if p.found]

    @property
    def ready(self) -> bool:
        """能进入对话的最低条件：依赖齐 + POC 库可用。"""
        return not self.missing_deps and self.poc_count > 0
