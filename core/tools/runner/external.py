"""外部 CLI 的执行通道：argv 校验与真正的进程调用。

查的是**合并清单**（内置 + ``data/tools.local.yaml``），不能只看内置的：
用户自己登记的工具同样要受同一套白名单约束。

:meth:`_validate_argv` 逐项过白名单与路径闸门，:meth:`_build_argv` 负责把
"目标主机"这类占位补全。两者分开是为了让"参数不合法"与"参数合法但目标不对"
能被区分开。
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from core.tools.external import ExternalTool, all_external_tools
from core.tools.probe import Probe
from core.tools.runner.base import _classify_arg, _HARD_TIMEOUT, _NUMERIC_RE


class ExternalMixin:
    """见模块说明。"""

    # ── 外部工具 ──────────────────────────────────────────────────

    async def _h_external_tool(self, session, tool: str = "", args: list[str] | None = None,
                               purpose: str = "") -> str:
        # 必须查**合并清单**，不能只查内置的 EXTERNAL_TOOLS：
        # 探测阶段（probe_external）已经能看到自定义工具，若这里还按内置清单查，
        # 就会出现"tools 列表里明明有，Agent 一调就说未知工具"的割裂。
        # 提示清单同理，否则报错信息会误导模型去调用不存在的能力。
        specs, _errs = all_external_tools()
        spec = next((s for s in specs if s.key == tool), None)
        if spec is None:
            keys = ", ".join(s.key for s in specs)
            return f"【未知外部工具】{tool}。可用：{keys}"
        # 网络能力无法被统一 Gateway 证明的工具（curl/wget）在这里再拦一道：
        # 策略闸门是第一道，这里是"handler 被直接调用"时的第二道。
        from policy import gateway

        if gateway.is_unverifiable(spec.key):
            return f"【已拦截】{gateway.unverifiable_reason(spec.key)}"
        probe = self.probes.get(spec.key)
        if probe is None or not probe.found:
            return (
                f"【未安装】本机没有探测到 {spec.key}。"
                f"请改用内置工具（recon_ports / recon_paths / http_request 等）。"
            )
        if blocked := self._blocked(spec):
            return blocked

        # 模型偶尔把参数列表写成单个字符串：按单 token 处理，不要逐字符迭代
        if isinstance(args, str):
            args = [args]
        argv, err = self._build_argv(
            spec, args or [], bound_target=str(getattr(session, "target", "") or ""),
        )
        if err:
            return f"【参数不合法】{err}"

        return await asyncio.to_thread(self._run_external, spec, probe, argv, purpose)

    def _validate_argv(
        self, spec: ExternalTool, args: list[str], bound_target: str = "",
    ) -> tuple[list[str], str]:
        """校验参数并返回 (argv, 错误信息)。空错误串表示通过。

        取值语义由 :data:`policy.gateway.VALUE_FLAGS` 决定——**不再靠
        "值里有没有斜杠"猜它是不是路径**。这一条是真实踩坑：``-H
        "Content-Type: application/json"`` 曾因为值里有 ``/`` 被判成文件
        引用，正常 Header 直接被拒。

        文件类取值仍然走路径闸门：``-w``（字典）必须在项目目录内且存在，
        ``-t``（模板）路径形式同样受限，``-H @file`` / ``-d @file`` 按
        文件读取授权处理。**没有**为了修 Header 而放宽文件检查。
        """
        from policy import gateway

        argv: list[str] = []
        scoped_targets: list[str] = []
        flag_seen = ""
        for raw in args:
            if not isinstance(raw, str):
                return [], f"参数必须是字符串，收到 {type(raw).__name__}"
            a = raw.strip()
            if not a:
                continue
            if "\n" in a or "\r" in a or "\0" in a:
                return [], "参数含控制字符"

            if a.startswith("-") and len(a) > 1:
                if not self._flag_allowed(a, spec.flags):
                    return [], (
                        f"选项 {a} 不在 {spec.key} 的白名单里。"
                        f"允许的选项：{' '.join(spec.flags) or '（无）'}"
                    )
                argv.append(a)
                flag_seen = a
                continue

            kind = gateway.VALUE_FLAGS.get(flag_seen, "")

            # ── HTTP 头：普通 Header 合法（application/json 不是路径）──
            if kind == "header":
                if a.startswith("@"):
                    ref = a[1:]
                    if gateway.unsafe_file_ref(ref) or not self._path_inside_root(ref):
                        return [], f"Header 文件引用未授权（必须在项目目录内且存在）：{a}"
                elif not gateway.header_value_ok(a):
                    return [], f"Header 取值不合法：{a!r}（应为 'Name: value'，且不含 CR/LF）"
                argv.append(a)
                flag_seen = ""
                continue

            # ── 请求体：@file 才读文件，其余是报文内容 ─────────────
            if kind == "data":
                if a.startswith("@"):
                    ref = a[1:]
                    if gateway.unsafe_file_ref(ref) or not self._path_inside_root(ref):
                        return [], f"请求体文件引用未授权（必须在项目目录内且存在）：{a}"
                argv.append(a)
                flag_seen = ""
                continue

            # ── 字典：必须是项目目录内真实文件 ─────────────────────
            if kind == "wordlist":
                if not self._path_inside_root(a):
                    return [], f"字典文件必须位于项目目录内且必须存在：{a}"
                argv.append(a)
                flag_seen = ""
                continue

            # ── 模板：路径或模板 id（nuclei 的 -t 两种都收）─────────
            if kind == "template":
                if _classify_arg(a) == "path" and not self._path_inside_root(a):
                    return [], f"模板路径必须位于项目目录内且必须存在：{a}"
                argv.append(a)
                flag_seen = ""
                continue

            # ── 显式目标：收集起来做主机级授权 ─────────────────────
            if kind == "target":
                scoped_targets.append(a)
                argv.append(a)
                flag_seen = ""
                continue

            # ── 普通字符串（方法名/UA/Cookie/状态码/模板标签）───────
            if kind == "raw":
                argv.append(a)
                flag_seen = ""
                continue

            # ── 未登记语义的取值：退回结构判定（fail-closed）────────
            if a.startswith("FUZZ") and spec.key == "ffuf":
                argv.append(a)
                flag_seen = ""
                continue

            # 端口号 / 端口范围 / 网段长度这类纯数字取值，不做主机解析
            if _NUMERIC_RE.match(a) and ":" not in a:
                argv.append(a)
                flag_seen = ""
                continue

            arg_kind = _classify_arg(a)
            if arg_kind == "target":
                scoped_targets.append(a)
            elif arg_kind == "path" and not self._path_inside_root(a):
                # 无 shell 也不代表可以随便读文件：绝对路径（/etc/passwd、C:\...）
                # 一律拒绝，避免被当成"某个选项忘了加白名单"的漏口。
                return [], f"不允许引用项目目录之外的文件：{a}"
            argv.append(a)
            flag_seen = ""

        # ── 目标范围：外部工具不得自带第二个目标 ─────────────────────
        if bound_target:
            for t in scoped_targets:
                if not gateway.target_allowed(spec.key, t, bound_target):
                    return [], (
                        f"外部工具不得访问未绑定目标：{t}"
                        f"（绑定目标 {bound_target}）"
                    )
        if spec.needs_target and not scoped_targets:
            return [], (
                f"{spec.key} 需要一个扫描目标，但参数里没有可识别的 URL/主机"
            )
        return argv, ""

    def _path_inside_root(self, a: str) -> bool:
        """判断一个值是否是"项目目录内的真实文件"。"""
        p = Path(a)
        if not p.is_absolute():
            p = self.root / p
        try:
            inside = str(p.resolve()).startswith(str(self.root))
        except OSError:
            return False
        return inside and p.is_file()

    def _build_argv(
        self, spec: ExternalTool, args: list[str], bound_target: str = "",
    ) -> tuple[list[str], str]:
        return self._validate_argv(spec, args, bound_target=bound_target)

    @staticmethod
    def _flag_allowed(arg: str, allowed: tuple[str, ...]) -> bool:
        """选项白名单判定，兼容三种写法：``-T4``、``-p80``、``--top-ports=100``。"""
        if arg in allowed:
            return True
        for a in allowed:
            if a.startswith("--") and arg.startswith(a + "="):
                return True
            # 短选项带粘连值：-p80 匹配 -p；-T4 不会被 -T 误放行（-T 不在白名单里）
            if (
                a.startswith("-")
                and not a.startswith("--")
                and len(a) == 2
                and arg.startswith(a)
                and len(arg) > 2
                and not arg.startswith("--")
            ):
                return True
        return False

    def _run_external(self, spec: ExternalTool, probe: Probe, argv: list[str], purpose: str) -> str:
        """真正启动外部进程。参数已校验，``shell=False`` 直传 argv。"""
        cmd = [probe.path, *argv]
        kw: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": min(int(os.environ.get("POCS_EXT_TIMEOUT", spec.timeout)), _HARD_TIMEOUT),
            "cwd": str(self.root),
        }
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        started = time.perf_counter()
        try:
            r = subprocess.run(cmd, **kw)  # noqa: S603 - argv 直传、无 shell、参数已过白名单
        except subprocess.TimeoutExpired:
            return f"【超时】{spec.key} 超过 {kw['timeout']}s 未返回，已终止。（命令：{' '.join(argv)}）"
        except Exception as exc:  # noqa: BLE001
            return f"【启动失败】{spec.key}: {type(exc).__name__}: {exc}"

        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        body = out or err or "（无输出）"
        header = (
            f"$ {spec.key} {' '.join(argv)}\n"
            f"[{spec.key} {probe.version}] 退出码 {r.returncode}，"
            f"耗时 {time.perf_counter()-started:.1f}s"
            + (f"，意图：{purpose}" if purpose else "")
        )
        parts = [header, "--- 输出 ---", body]
        if out and err:
            parts += ["--- stderr ---", err[:800]]
        parts.append(
            "提示：以上是外部工具的原始文本，不是本工具的判读结果——"
            "需要结合响应判断是否真的命中，不要直接当成漏洞结论。"
        )
        return "\n".join(parts)
