"""执行器骨架：常量、类初始化、调用入口、大输出落盘、编排与会话合并。

这里是**唯一的安全边界**。模型可以要求执行任何东西，所以所有约束都落在
:meth:`ToolRunner.execute` 这条路径上，不能指望提示词里那句"请勿越权"。
三条闸门：

1. **只读模式**：``readonly=true`` 时 ``intrusive`` 类外部工具直接拒绝执行，
   不是提示，是拒执行。
2. **参数白名单**：外部工具只接受声明过的选项，写文件类选项全部不在白名单里。
3. **不用 shell**：``subprocess`` 一律传 argv 数组、``shell=False``。没有 shell
   就没有重定向、管道、命令替换——参数里的 ``&`` ``|`` 只是普通字符。

为什么不用 shell=True + 黑名单：黑名单永远漏。argv 直传是结构性免疫。

其余职责按出处拆在同级模块里，由 :class:`ToolRunner` 多继承组装；
本模块提供骨架与跨模块共用的基础设施（``_target_of``、
``_normalize_target``、``_blocked``）。
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.state import Asset, Finding, Severity
from core.tools.args import normalize_args
from core.tools.external import ExternalTool
from core.tools.probe import Probe


MAX_TOOL_OUTPUT = 6000      # 回灌给模型的单个工具结果上限（字符）
_HARD_TIMEOUT = 600         # 外部进程硬上限（秒）

# 同一端点（http_request 的 url path）连续多少次返回**完全相同**的响应
# 信号，就判定这条路已榨干。与 agent.py 的指纹检测分工：那边拦
# "请求长得一样"（阈值 3 次，提示换参数），这边拦"响应毫无变化"
# （阈值 5 次，提示换端点）——两边互补，不会重复拦截。
ENDPOINT_SIGNAL_LIMIT = 5
# 主机级兜底：同一 netloc 连续多少次拿到**逐字节相同**的响应信号。
# 端点级按 path 计，模型每 5 次换一个 path 就能清零绕开；主机级把
# "换 path 绕检测"也圈进来。阈值放到 15：同一主机 15 次响应完全一致
# 不可能是正常渗透（真实扫描响应千差万别），只可能是无进展打转。
HOST_SIGNAL_LIMIT = 15

# http_request 工具结果里正文预览的字符上限。
# 与 core/rawmsg.py 的 _RESULT_BODY_PREVIEW 是同一件事的两端：
# 这里决定"切多少"，那里决定"怎么读回截断标记"，改了要同步。
_BODY_PREVIEW = 1500

# 这些选项的取值是"文件路径"，需要限制在项目目录内
_FILE_FLAGS = {"-w", "--wordlist", "-t"}
# 端口/数字类取值，不做 host 解析尝试
_NUMERIC_RE = re.compile(r"^[\d,\-./]+$")
_PATH_EXT_RE = re.compile(r"\.(txt|list|lst|dic|wordlist|json|ya?ml|conf|cfg|csv)$", re.I)

# 返回值前缀 → 调用状态。用于把"安全拦截"从"执行成功"里区分出来。
_STATUS_MARKERS: dict[str, str] = {
    "【已拦截】": "blocked",
    "【参数不合法】": "badargs",
    "【未安装】": "missing",
    "【未知外部工具】": "unknown",
    "【未知工具】": "unknown",
    "【执行失败】": "error",
    "【超时】": "timeout",
    "【启动失败】": "error",
}

_CONTEXT_VAR_RE = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_-]{0,63})\}")


def _classify_arg(a: str) -> str:
    """把一个非选项参数归类为 ``target`` / ``path`` / ``other``。

    以前这里是两个函数（``_looks_like_target`` 在 external.py、
    ``_looks_like_path`` 在这里），判断标准有重叠、答案还不互斥——
    ``http://x/y`` 两个都说是，读者要在两个文件之间跳才能理解
    "这个值到底是什么"。合并成一处分界，调用点按结果分支。

    判定顺序**刻意与旧 ``_validate_argv`` 的分支顺序一致**（先 target
    后 path），所以行为逐字节不变：

    * ``target`` —— 带 scheme 的 URL，或纯 IP/域名（含点、无路径分隔符与空格）；
    * ``path``   —— 其余像文件路径的（路径前缀 / 盘符 / 含分隔符 / 已知扩展名）；
    * ``other``  —— 模板 id、关键词之类的自由文本。
    """
    if not a:
        return "other"
    if "://" in a:
        return "target"
    if "." in a and "/" not in a and "\\" not in a and " " not in a:
        return "target"
    if (
        a.startswith(("/", "\\", "./", "../", "~"))
        or re.match(r"^[A-Za-z]:[\\/]", a)
        or "\\" in a
        or "/" in a
    ):
        return "path"
    if _PATH_EXT_RE.search(a):
        return "path"
    return "other"


class ToolBlocked(Exception):
    """执行被安全闸门拦下——这不是错误，是设计如此。"""


class _ToolRunnerBase:
    """内置工具 + 外部进程的统一执行入口。"""

    def __init__(self, cfg, external_probes: list[Probe] | None = None, root: str | Path = ".") -> None:
        self.cfg = cfg
        self.root = Path(root).resolve()
        self.probes: dict[str, Probe] = {p.spec.key: p for p in (external_probes or [])}
        self.poc_map, self.poc_errors = self._load_pocs()
        self._retriever = None
        # 每个工具调用都会记一条，供报告与 /tools 查看
        self.calls: list[dict[str, Any]] = []
        self._det_cache: dict[str, Any] = {}
        # 写操作（目前只有上传）的人工审核通道。
        # None = 没有审核通道 → 上传会被跳过而不是偷偷执行。
        # 由交互层（core/repl.py）注入；全自动模式下注入"自动放行+打日志"。
        self.approver: Callable[[str], Awaitable[bool]] | None = None
        # 落盘文件的命名序号（防同一秒撞名）
        self._spill_seq = 0
        # 最近几次**真实发出**的请求（http_request 的结果快照）。
        # 存在的意义只有一个：模型先验证、隔几轮才 record_finding 时，
        # 把当时那份响应自动附到发现的 PoC 上——否则手工登记的发现
        # 在报告里只有请求没有响应，交付方无从复现。
        self._recent_http: list[dict[str, Any]] = []
        # 端点响应无变化检测（http_request 专用）：endpoint path →
        # 上一发的响应信号指纹 / 连击次数。信号变了连击就断。
        self._endpoint_signal: dict[str, str] = {}
        self._endpoint_streak: dict[str, int] = {}
        # 主机级兜底（netloc）：拦"每 5 次换一个 path 绕端点检测"。
        self._host_signal: dict[str, str] = {}
        self._host_streak: dict[str, int] = {}
        # 后台任务的 asyncio.Task 强引用（task_id -> Task）。
        # ``create_task`` 只被事件循环**弱引用**，不自己存一份的话任务可能
        # 执行到一半被 GC 掉（官方文档明确要求保留引用）。
        self._bg_handles: dict[str, Any] = {}
        # ── 接口测试生命周期权限控制（policy/，111.md 四模块）─────────
        # api_policy 定义矩阵 / request_guard 请求前检查 /
        # test_transaction 约束测试对象生命周期 / audit_logger 审计留痕。
        from policy.audit_logger import PolicyAudit
        from policy.request_guard import RequestGuard
        from policy.test_transaction import TestLedger

        self.policy_guard = RequestGuard(cfg)
        self.test_ledger = TestLedger()
        self.policy_audit = PolicyAudit(
            getattr(cfg, "data_dir", "./data"),
            enabled=bool(getattr(getattr(cfg, "policy", None), "audit", True)),
        )
        # 待登记台账条目（P0-②）：闸门放行 ≠ 对象存在。放行的写操作先
        # 挂到 pending，handler **执行成功**且能从响应取得对象标识后才
        # 真正进台账——"创建成功并取得对象标识后登记"。
        self._pending_ledger: dict[str, Any] | None = None
        # 账号身份上下文（P1-7）：set_target 初始化为匿名，请求带凭证头时
        # 升级为实名（_observe_identity）。绝不固定为 True——它是决策的
        # 真实入参，也进审计与台账。
        self._identity: str = ""

    def reset_target_scope(self) -> None:
        """清掉**与目标绑定**的运行期缓存（换目标 / 彻底重置时调用）。

        这些缓存都是上一个被测对象的残留：

        * ``_recent_http``：最近几次 HTTP 响应快照。留着的话，换目标后
          登记发现时会把**上一个目标**的响应当成新目标的贴进报告——
          这是报告串线最隐蔽的一条路径（URL 恰好对得上时）。
        * ``_endpoint_signal`` / ``_endpoint_streak``：端点响应无变化
          检测的信号与连击次数。换目标后它们对新手目标毫无意义，
          还会让新目标的第一次探测就撞上"连击 5 次"的误拦。
        * ``_host_signal`` / ``_host_streak``：主机级兜底，同理。
        * ``test_ledger``：测试对象台账。台账里的对象属于上一个目标，
          不清的话新目标的删除操作会误认"对象已知"而放行。

        注意**不动** ``_det_cache``（探测器缓存）：它按工具+参数索引，
        与目标无关，清了只会白白多跑一遍探测。
        """
        self._recent_http.clear()
        self._endpoint_signal.clear()
        self._endpoint_streak.clear()
        self._host_signal.clear()
        self._host_streak.clear()
        self.test_ledger.clear()
        # 身份是上一个目标的：换目标后回到匿名，等新目标的请求重新声明
        self._identity = ""



    # ── 基础设施 ──────────────────────────────────────────────────

    def _load_pocs(self):
        from detectors.poc_loader import load_poc_map

        try:
            return load_poc_map(self.cfg.rag.poc_dir)
        except Exception as exc:  # noqa: BLE001
            return {}, [f"POC 库加载失败：{type(exc).__name__}: {exc}"]

    def _normalize_target(self, target: str) -> str:
        """归一化目标 URL：补协议头、去空白。"""
        raw = (target or "").strip()
        if not raw:
            raise ToolBlocked("缺少目标参数")
        return raw if "://" in raw else f"http://{raw}"

    def _target_of(self, session, explicit: str = "") -> str:
        """确定本次请求的目标：显式参数优先，否则用会话目标。"""
        if explicit:
            return self._normalize_target(explicit)
        if not session.target:
            raise ToolBlocked("尚未设定目标。请先调用 set_target 或在对话里给出目标 URL。")
        return self._normalize_target(session.target)

    def _blocked(self, spec: ExternalTool) -> str | None:
        if spec.intrusive and self.cfg.scan.readonly:
            return (
                f"【已拦截】{spec.key} 属于攻击性工具，当前为只读模式（scan.readonly=true）。\n"
                f"原因：{spec.note or '可能对目标造成数据变更或业务影响。'}\n"
                f"如确需使用，请用户在终端执行 /readonly off 放行"
                f"（或改 config.yaml 的 scan.readonly: false）——目标必须已获书面授权。"
            )
        return None

    def _response_signal(self, status_code: Any, body_size: Any, body_text: str) -> str:
        """响应信号：状态码 + 正文大小 + 正文指纹。

        **刻意不含 elapsed_ms**：耗时每次请求都不同，把它算进信号，
        md5 永远不相同，"响应完全相同"的判定永远不成立（真实教训：
        18 连发每次耗时都在 200~300ms 之间抖动，端点检测一次都没触发）。
        body_text 用正文预览即可——同样的响应预览必然一致。
        """
        digest = hashlib.md5((body_text or "").encode("utf-8")).hexdigest()
        return f"{status_code}|{body_size}|{digest}"

    def _check_endpoint_signal(
        self, url: str, status_code: Any, body_size: Any, body_text: str
    ) -> None:
        """http_request 的「响应无变化」检测。命中直接 raise ToolBlocked。

        两级判定：

        * **端点级**（``urlparse(url).path``）：同端点信号相同则连击 +1，
          到 ``ENDPOINT_SIGNAL_LIMIT`` 拦——"这个路径怎么打都一个样"。
        * **主机级**（``netloc``）：同主机信号相同则连击 +1，到
          ``HOST_SIGNAL_LIMIT`` 拦——拦"每 5 次换一个 path 绕端点检测"。
          阈值放宽到 15：15 次响应逐字节相同不可能是正常扫描。

        拦完即清零：模型换手法回来再打，从 1 重新计。信号里但凡有实质
        变化（状态码/正文大小/正文内容任一不同）连击就断，不误伤正常渗透。
        """
        if "://" not in (url or ""):
            return
        parts = urlparse(url)
        endpoint = parts.path or "/"
        host = parts.netloc or ""
        sig = self._response_signal(status_code, body_size, body_text)

        if self._endpoint_signal.get(endpoint) == sig:
            self._endpoint_streak[endpoint] = self._endpoint_streak.get(endpoint, 1) + 1
        else:
            self._endpoint_signal[endpoint] = sig
            self._endpoint_streak[endpoint] = 1
        if self._endpoint_streak[endpoint] >= ENDPOINT_SIGNAL_LIMIT:
            self._endpoint_signal.pop(endpoint, None)
            self._endpoint_streak.pop(endpoint, None)
            raise ToolBlocked(
                f"端点 {endpoint} 连续 {ENDPOINT_SIGNAL_LIMIT} 次响应信号完全相同"
                "（状态码/正文长度/正文均一致），这条探测路线已经榨干，"
                "继续请求不会带来任何新信息。必须换端点或换探测手法"
                "（改路径、改 HTTP 方法、改 payload 结构），或基于已有证据直接给结论；"
                "确实探不到就明确说「当前证据不足以判定」，不要编造。"
            )

        if host:
            if self._host_signal.get(host) == sig:
                self._host_streak[host] = self._host_streak.get(host, 1) + 1
            else:
                self._host_signal[host] = sig
                self._host_streak[host] = 1
            if self._host_streak[host] >= HOST_SIGNAL_LIMIT:
                self._host_signal.pop(host, None)
                self._host_streak.pop(host, None)
                raise ToolBlocked(
                    f"主机 {host} 连续 {HOST_SIGNAL_LIMIT} 次响应信号完全相同"
                    "（状态码/正文长度/正文均一致）——包括中途更换 path 的请求。"
                    "这说明在该主机上的探测已经没有产出，继续打只是空转。"
                    "必须换主机、换探测手法，或基于已有证据直接给结论。"
                )


    # ── 入口 ──────────────────────────────────────────────────────

    async def execute(self, name: str, args: dict[str, Any], session) -> str:
        """执行一次工具调用。**任何异常都转成文本返回给模型，不向上抛。**"""
        started = time.perf_counter()
        # **按 schema 归一实参类型**，必须在展开之前：模型会把布尔写成字符串
        # （`"false"` 在 Python 里恒为真 → `overwrite="false"` 真的会覆盖、
        # `undo="false"` 真的会撤销），也会把枚举写错大小写（`"MD"` → 判断全落空、
        # 静默什么都不做）。逐个 handler 打补丁治不了根，所以收在这一处。
        args = normalize_args(name, args)
        # 变量展开的豁免清单只有 ``context_get``：它按**名字**查池，参数是
        # 变量名而不是值——展开会把变量值当成名字去查，永远"变量不存在"。
        # ``extract_variable`` 刻意**不豁免**：变量必须能链式组合
        # （extract_variable(value="${token}-derived")）。豁免它的话组合式
        # 会被静默存成字面量，后续请求带着 "${token}" 原文到处飞，
        # 模型还以为链路已经打通——这种静默失效最难排查。
        if name != "context_get":
            args = self._expand_context_vars(args, session.result.context_vars)
        status = "ok"
        try:
            handler = getattr(self, f"_h_{name}", None)
            if handler is None:
                out = f"【未知工具】{name}。可用工具见系统提示中的清单。"
                status = "unknown"
            else:
                # ── 接口测试生命周期权限控制（policy/request_guard）────
                # 面向目标的请求在执行前过权限矩阵：拒绝文本直接回灌模型，
                # 状态记 blocked。检查自身异常也按"拒绝执行"处理（fail-closed）。
                verdict = await self._policy_gate(name, args, session)
                if verdict is not None:
                    out = verdict
                    status = "blocked"
                else:
                    # 一律 **args 展开——按位置整个传进去会把参数字典
                    # 当成第一个形参的值（external_tool 因此收到过 tool={...} 这种
                    # 荒谬输入，报"未知外部工具"），这个 bug 真发生过。
                    out = await handler(session, **args)
        except ToolBlocked as exc:
            out = f"【已拦截】{exc}"
            status = "blocked"
        except TypeError as exc:
            out = f"【参数不合法】{type(exc).__name__}: {exc}"
            status = "badargs"
        except Exception as exc:  # noqa: BLE001
            out = f"【执行失败】{type(exc).__name__}: {exc}"
            status = "error"

        text = str(out or "")
        # 把"被拒绝"和"执行成功"分开统计。拒绝是**正常返回值**而不是异常
        # （要喂回模型让它换方案），所以状态只能从文本标记反推——
        # 否则 /status 里会把一堆拦截记成成功，安全拦截就看不出来了。
        if status == "ok":
            for marker, st in _STATUS_MARKERS.items():
                if text.startswith(marker):
                    status = st
                    break
        # P0-②：台账登记只发生在**执行成功**之后。取走 pending（无论
        # 成败都清掉，防止陈旧条目泄漏进下一次调用），成功且能取得
        # 对象标识才真正落台账。
        pend = self._pending_ledger
        self._pending_ledger = None
        if pend and status == "ok":
            self._commit_pending_ledger(pend, text)
        if len(text) > MAX_TOOL_OUTPUT:
            if name == "external_tool":
                # 外部工具的输出长度不可控（curl 拉一个 100KB 的库文件很正常），
                # 只截断不给出路，模型就会去试各种输出选项碰运气（真发生过：
                # 连打十几次 curl -w %{...}，换取值就是新指纹，死循环检测拦不住）。
                text = self._spill(text, name)
            else:
                # 内置工具的输出是**自己设计的**（read_file 分页、http_request 自带截断），
                # 超长说明调用方该换参数（调小 max_lines / 用 start_line 翻页），
                # 不落盘——否则 read_file 读 spill 文件又被截断再 spill，无限派生垃圾文件。
                text = text[:MAX_TOOL_OUTPUT] + (
                    f"\n…（结果过长已截断，共 {len(text)} 字符。"
                    f"如是 read_file：用 grep=\"关键字\" 定位，或 start_line 翻页、max_lines 调小；"
                    f"其他工具：缩小范围重试。）"
                )
        # 键名同时给 "tool" 与 "name"：前者是记录里本来的叫法，后者是
        # repl/统计侧一直在读的叫法。两处不一致曾让**每跑完一轮 Agent 就
        # KeyError: 'name' 崩掉**（`repl._run_agent` 读 `c["name"]`）。
        # 与其只改一边、留下一个未来还会写错的坑，不如让记录对两种读法都成立。
        self.calls.append(
            {
                "tool": name,
                "name": name,
                "status": status,
                "ms": int((time.perf_counter() - started) * 1000),
                "chars": len(text),
                # 三层隔离：工具调用也归属当前目标与扫描轮次。报告与审计
                # 按 run 过滤时，调用记录与发现必须能对得上。
                "target_id": getattr(session, "target", "") or "",
                "run_id": getattr(
                    getattr(session, "result", None), "current_run_id", ""
                )
                or "",
            }
        )
        return text

    @classmethod
    def _expand_context_vars(cls, value: Any, pool: dict[str, Any]) -> Any:
        """递归展开工具参数中的 ``${name}``，未找到的变量保持原样。"""
        if isinstance(value, str):
            def replace(match: re.Match[str]) -> str:
                item = pool.get(match.group(1))
                if isinstance(item, dict) and "value" in item:
                    item = item["value"]
                return str(item) if item is not None else match.group(0)

            return _CONTEXT_VAR_RE.sub(replace, value)
        if isinstance(value, list):
            return [cls._expand_context_vars(item, pool) for item in value]
        if isinstance(value, dict):
            return {key: cls._expand_context_vars(item, pool) for key, item in value.items()}
        return value


    # ── 大输出落盘 ────────────────────────────────────────────────

    _SPILL_DIR = "tool-output"
    _SPILL_WRAP = 2000  # 落盘时单行折到这么长：read_file 按行分页，单行 100KB 没法读
    # 记住最近几次真实请求（record_finding 自动附响应时按 URL 精确匹配）
    _RECENT_HTTP_KEEP = 30

    def _spill(self, text: str, tool: str) -> str:
        """结果过长时把**完整内容**落盘到产物目录，只把开头回灌给模型。

        为什么必须落盘而不是只截断：只截断等于告诉模型"还有几万字符你看不到"，
        却不给任何看到的手段——它为了拿到剩余部分会去试 curl ``-w`` 的各种
        变量（``%{json}`` / ``%{stdout}`` / ``%{http_code}``……），每次换
        取值就是一个新指纹，死循环检测拦不住，一轮轮空转。落盘之后它有现成
        的出路：``read_file`` 本来就支持 ``start_line`` 分页。

        落盘时把超长的单行**折行**：拉回来的库文件/JSON 常常一整行几万字符，
        不折的话 ``read_file`` 一页 400 行其实还是那一行，等于没分页。
        """
        head = text[:MAX_TOOL_OUTPUT]
        total = len(text)
        try:
            outdir = Path(self.cfg.output_dir) / self._SPILL_DIR
            outdir.mkdir(parents=True, exist_ok=True)
            self._spill_seq += 1
            path = outdir / f"{int(time.time())}_{self._spill_seq}_{tool}.txt"
            lines: list[str] = []
            for ln in text.splitlines() or [text]:
                if len(ln) <= self._SPILL_WRAP:
                    lines.append(ln)
                else:
                    lines.extend(
                        ln[i : i + self._SPILL_WRAP]
                        for i in range(0, len(ln), self._SPILL_WRAP)
                    )
            path.write_text("\n".join(lines), encoding="utf-8")
        except OSError:
            # 落盘失败不阻断：退回到原来的纯截断行为
            return head + f"\n…（结果过长已截断，共 {total} 字符；完整输出落盘失败）"
        rel = f"{self._SPILL_DIR}/{path.name}"
        return (
            f"{head}\n…（结果过长已截断，共 {total} 字符。"
            f"**完整输出已保存到 {rel}**。\n"
            f"⚠ **不要从头逐页通读**——先用 read_file(path=\"{rel}\", grep=\"你要找的函数名/关键字\") "
            f"一次定位目标，再读命中行附近即可。例如分析 JS 时直接 "
            f"read_file(path=\"{rel}\", grep=\"postData\")。\n"
            f"确实需要通读时（极少）才用 start_line + max_lines 分段翻页。"
            f"不要用命令行输出选项（如 curl -w）碰运气，文件里什么都有。）"
        )


    # ── 编排类 ────────────────────────────────────────────────────

    # 受权限矩阵管辖的面向目标工具。本地产物读写（files/fsops）、
    # 会话管理、报告导出不在"接口测试生命周期"范围内，不过闸门。
    _POLICY_TOOLS = frozenset({"http_request", "external_tool", "exploit_probe"})

    _LEDGER_ACTIONS = {
        "创建测试数据": "create",
        "修改测试数据": "update",
        "上传测试文件": "upload",
        "删除测试数据": "delete",
    }

    def _current_identity(self, session) -> str:
        """当前会话的**真实账号身份上下文**（P1-7，不固定 True）。

        * 请求声明过凭证（Authorization/Cookie/X-API-Key）→ 实名身份；
        * 否则随目标绑定显式声明为 ``anonymous@<host>``——匿名也是被
          记录、可审计的身份（未认证请求的执行主体就是它），不是
          "随便放行"的占位：它会进决策入参、审计与台账。
        * 会话没有目标 → 没有身份（identity_bound=False，全量拒绝）。
        """
        if self._identity:
            return self._identity
        t = str(getattr(session, "target", "") or "")
        if not t:
            return ""
        try:
            host = urlparse(t).hostname or t
        except ValueError:
            host = t
        return f"anonymous@{host}"

    def _policy_ctx(self, session, url: str):
        """决策上下文：目标、环境、账号身份三要素的绑定。

        ``bound_target`` = 会话绑定的目标 URL。**范围比对在 guard 里做**：
        请求 URL 必须与 bound_target 同主机才算 target_bound（P0-3）——
        只知道"会话有目标"不算绑定，跨主机请求一律按未绑定拒绝。
        ``identity_bound`` / ``identity`` = 真实账号身份上下文（P1-7）：
        凭证头升级实名、无凭证显式匿名，绝不固定为 True。
        真正的牙齿在 L1/L2 的**环境门**上：判不出环境就是 unknown，
        一律按条件不满足拒绝执行。
        """
        from policy.request_guard import GuardContext

        r = getattr(session, "result", None)
        ident = self._current_identity(session)
        return GuardContext(
            target_id=(getattr(r, "target_id", "") or getattr(session, "target", "")),
            run_id=getattr(r, "current_run_id", "") or "",
            environment=self.policy_guard.environment_for(url),
            identity_bound=bool(ident),
            identity=ident,
            bound_target=str(getattr(session, "target", "") or ""),
        )

    def _policy_scope(self, session) -> tuple[str, str]:
        r = getattr(session, "result", None)
        return (
            getattr(r, "target_id", "") or getattr(session, "target", ""),
            getattr(r, "current_run_id", "") or "",
        )

    async def _policy_gate(self, name: str, args: dict[str, Any], session) -> str | None:
        """执行前的权限检查。返回拒绝文本（含【已拦截】前缀）或 None 放行。

        fail-closed：检查自身抛异常时按"条件不满足→拒绝执行"处理——
        权限控制坏了不能变成全放行。
        """
        if name not in self._POLICY_TOOLS:
            return None
        guard = self.policy_guard
        try:
            if name == "http_request":
                url = self._normalize_target(str(args.get("url") or session.target or ""))
                method = str(args.get("method") or "GET")
                body = str(args.get("body") or "")
                self._observe_identity(dict(args.get("headers") or {}) if isinstance(
                    args.get("headers"), dict
                ) else {}, url, body, session=session)
                d = guard.check_request(
                    url, method=method, body=body,
                    params=args.get("params") if isinstance(args.get("params"), dict) else None,
                    poc_hint=str(args.get("poc_id") or args.get("poc") or ""),
                    history_hint=self._history_hint(url),
                    ctx=self._policy_ctx(session, url),
                )
                if d.allowed:
                    # P1-⑤：写操作的放行以审计可持久化为先决条件
                    audit_block = self._audit_gate_for(d, session, url)
                    if audit_block is not None:
                        return audit_block
                    ledger_deny = await self._ledger_check(session, d, url)
                    if ledger_deny is not None:
                        return ledger_deny
                    self._policy_allow(session, d, url=url)
                    return None
                if d.decision == "REVIEW":
                    # P1-⑤：审批事件本身必须能持久化——审计不可持久化时
                    # 审批通道整体关闭，拒绝执行（不用内存记录替代）。
                    if not self.policy_audit.writable:
                        return self._audit_deny_text(d, session, url)
                    # P0-②：审批走运行期逐请求通道（绑定本次 URL）。
                    if await self._policy_review(d, session, url):
                        # 审批通过 = 本次请求的单独审批已绑定；台账未知对象
                        # 因此放行。参数变化 → URL 变化 → 决策重来 → 重新审批。
                        ledger_deny = await self._ledger_check(session, d, url, approved=True)
                        if ledger_deny is not None:
                            return ledger_deny
                        self._policy_allow(session, d, url=url)
                        return None
                return self._policy_deny(session, d, url)

            if name == "exploit_probe":
                kinds = str(args.get("kinds") or "rce,fileread")
                url = self._normalize_target(str(args.get("url") or session.target or ""))
                # P0-4：探针类别 → 矩阵命令，取风险最高的一条判定。
                # **sqli 必须映射到 SQL 注入验证（L3）**，不得落 L0；
                # 未知类别按 UNKNOWN 拒绝（不猜）。
                commands = [
                    self._PROBE_KIND_COMMAND.get(k.strip().lower(), "")
                    for k in kinds.split(",")
                ]
                if not commands or any(not c for c in commands):
                    return (
                        "【已拦截】（策略）exploit_probe 含未识别的探针类别，"
                        "按「条件不满足 → 拒绝执行」处理。"
                        f"已知类别：{'、'.join(sorted(self._PROBE_KIND_COMMAND))}。"
                    )
                from policy.api_policy import (
                    PermissionLevel,
                    rule_for_command,
                    decide as _decide,
                )

                worst = max(commands, key=lambda c: (
                    PermissionLevel.rank(rule_for_command(c).level) if rule_for_command(c) else -1
                ))
                _rule = rule_for_command(worst)
                # P0-①：**不得自行构造简化决策上下文**——与 http_request /
                # external_tool 同一份 _policy_ctx，目标范围校验走 guard 的
                # 统一入口 in_scope（scheme+host+port+路径前缀）。
                ctx = self._policy_ctx(session, url)
                d = _decide(
                    worst,
                    environment=ctx.environment,
                    identity_bound=ctx.identity_bound,
                    target_bound=guard.in_scope(url, ctx.bound_target),
                    approved=False,  # L3 无审批出路；上传的逐请求审批在 REVIEW 通道
                )
                d.category = {
                    "命令执行": "EXECUTE", "SQL 注入验证": "EXECUTE",
                    "上传测试文件": "UPLOAD", "删除测试数据": "DELETE",
                }.get(worst, "READ")
                d.signals = [f"探针类别：{kinds}（最高风险 → {worst}，{_rule.level if _rule else '?'}）"]
                if d.allowed:
                    audit_block = self._audit_gate_for(d, session, url)
                    if audit_block is not None:
                        return audit_block
                    self._policy_allow(session, d, url=url)
                    return None
                if d.decision == "REVIEW":
                    if not self.policy_audit.writable:
                        return self._audit_deny_text(d, session, url)
                    if await self._policy_review(d, session, url):
                        audit_block = self._audit_gate_for(d, session, url)
                        if audit_block is not None:
                            return audit_block
                        self._policy_allow(session, d, url=url)
                        return None
                return self._policy_deny(session, d, url)

            if name == "external_tool":
                tool = str(args.get("tool") or "")
                url = str(args.get("target") or args.get("url") or session.target or "")
                d = guard.check_tool(tool, dict(args), ctx=self._policy_ctx(session, url))
                if d.allowed:
                    audit_block = self._audit_gate_for(d, session, url)
                    if audit_block is not None:
                        return audit_block
                    self._policy_allow(session, d, url=url)
                    return None
                if d.decision == "REVIEW":
                    if not self.policy_audit.writable:
                        return self._audit_deny_text(d, session, url)
                    if await self._policy_review(d, session, url):
                        audit_block = self._audit_gate_for(d, session, url)
                        if audit_block is not None:
                            return audit_block
                        self._policy_allow(session, d, url=url)
                        return None
                return self._policy_deny(session, d, url)
            return None
        except Exception as exc:  # noqa: BLE001
            tid, rid = self._policy_scope(session)
            self.policy_audit.log(
                "error", command=name, target_id=tid, run_id=rid,
                reason=f"权限检查异常：{type(exc).__name__}: {exc}",
            )
            return (
                "【已拦截】（策略）权限检查异常，按「条件不满足 → 拒绝执行」处理：\n"
                f"  {type(exc).__name__}: {exc}\n"
                "  修复 policy 配置或用 /readonly 查看当前状态后重试。"
            )

    # 探针类别 → 权限矩阵命令（P0-4：sqli 必须落 L3，不得落 L0）
    _PROBE_KIND_COMMAND = {
        "rce": "命令执行",              # L3
        "sqli": "SQL 注入验证",          # L3（此前落入查询详情 L0——整改点）
        "upload": "上传测试文件",        # L2
        "fileread": "查询详情",          # L0
        "fileupload": "上传测试文件",    # L2
    }

    def _observe_identity(self, headers: dict, url: str, body: str = "", session=None) -> None:
        """从真实请求观察账号身份（P1-④：**真实账号绑定**，非凭证类型标记）。

        旧实现的 ``cred:authorization`` 只记了"用了哪类凭证"，同一头名下
        的管理员 token 和普通用户 token 身份完全混同。整改后：

        * 凭证值指纹：``cred:<头名>:<sha256 前 10 位>`` —— 不同 token /
          会话 = 不同身份，可区分同一头名下的多个账号；
        * 角色以**显式声明**为准（不猜）：``session.credentials["role"]``
          （登录流程或用户配置写入，如 admin / user）→ ``@<角色>`` 后缀；
          其次认目标自定义角色头（X-User-Role / X-Role / X-Admin）的值；
        * 无凭证 → ``anonymous@<host>``（由 _current_identity 现算）。
        凭证值本身永不进身份标签（只进指纹）。
        """
        for h, v in (headers or {}).items():
            if str(h).lower() in ("authorization", "cookie", "x-api-key", "x-auth-token", "x-token"):
                fp = hashlib.sha256(str(v or "").encode("utf-8")).hexdigest()[:10]
                ident = f"cred:{str(h).lower()}:{fp}"
                role = ""
                if session is not None:
                    role = str((getattr(session, "credentials", None) or {}).get("role") or "")
                if not role:
                    for rh in ("x-user-role", "x-role", "x-admin"):
                        rv = (headers or {}).get(rh)
                        if rv:
                            role = str(rv)[:32]
                            break
                self._identity = f"{ident}@{role}" if role else ident
                return

    def _history_hint(self, url: str) -> str:
        """历史行为提示（P1-6）：台账里同主机出现过的写操作，喂给分类器。"""
        try:
            host = (urlparse(url or "").hostname or "").lower()
        except ValueError:
            return ""
        if not host:
            return ""
        hits: list[str] = []
        for o in self.test_ledger.objects_of():
            try:
                oh = (urlparse(o.url or "").hostname or "").lower()
            except ValueError:
                continue
            if oh == host and o.action in ("delete", "create", "update", "upload"):
                hits.append(o.action)
        return ",".join(sorted(set(hits)))

    async def _ledger_check(
        self, session, d, url: str, *, approved: bool = False,
    ) -> str | None:
        """删除类操作的真实请求前置台账检查（P0-5）。

        返回拒绝文本（含【已拦截】前缀）或 None 放行。检查发生在
        gate 内、handler 执行之前——台账判不过的删除请求**根本不会
        被发出去**。

        ``approved`` 只能来自**绑定本次请求**的运行期审批（P0-②）：
        配置级审批已移除，参数变化 → URL 变化 → 决策重来 → 审批重来，
        不存在"命令审批一次、所有对象复用"的放行。
        """
        if d.command != "删除测试数据":
            return None
        tid, rid = self._policy_scope(session)
        ok, reason = self.test_ledger.delete_verdict(
            url,
            run_id=rid,
            target_id=tid,
            identity=self._current_identity(session),
            environment=self.policy_guard.environment_for(url),
            approved=approved,
        )
        if ok:
            return None
        self.policy_audit.log(
            "deny", command=d.command, level=d.level, decision="DENY",
            category=d.category, url=url, target_id=tid, run_id=rid,
            reason=f"对象台账前置检查拒绝：{reason}",
        )
        lines = [
            "【已拦截】（策略）删除操作未通过测试对象台账检查，请求未发出。",
            f"  理由：{reason}",
            "  台账按目标 + 轮次 + 账号身份 + 对象标识四元组匹配：",
            "  只放行本次测试**执行成功并取得对象标识**后登记的对象；",
            "  删除预置测试数据需对**本次请求**逐次审批（运行期审批通道，",
            "  参数变化后不会复用）。",
        ]
        return "\n".join(lines)

    def _audit_gate_for(self, d, session, url: str) -> str | None:
        """审计持久化前置（P1-⑤）。返回拒绝文本或 None。

        * 写操作（创建/修改/上传/删除）→ 审计不可持久化 = 拒绝执行：
          不能用内存记录替代持久化审计（内存随进程死，复盘无从谈起）；
        * 只读操作 → 放行但必须告警（warn 事件 + 状态行可见）。
        ``audit.enabled=false`` 同样视为不可持久化——要执行写操作，
        持久化审计必须在工作。
        """
        if self.policy_audit.writable:
            return None
        tid, rid = self._policy_scope(session)
        if self._LEDGER_ACTIONS.get(d.command):
            self.policy_audit.warn(
                "审计不可持久化，写操作拒绝执行（P1-⑤）",
                command=d.command, url=url, target_id=tid, run_id=rid,
            )
            return (
                "【已拦截】（策略）审计日志当前无法持久化（磁盘不可写或 audit 已关闭），"
                f"写操作「{d.command}」按 P1-⑤ 拒绝执行。\n"
                "  审计是写操作的先决条件，不是旁路——不能用内存记录替代持久化审计。\n"
                "  修复 data 目录可写性（或恢复 policy.audit: true）后重试。"
            )
        # 只读：放行 + 告警
        self.policy_audit.warn(
            "审计不可持久化，只读操作放行（告警不拦截）",
            command=d.command, url=url, target_id=tid, run_id=rid,
        )
        return None

    def _audit_deny_text(self, d, session, url: str) -> str:
        """审批前置失败（审计不可持久化）的拒绝文本。审批必须留痕。"""
        tid, rid = self._policy_scope(session)
        self.policy_audit.warn(
            "审计不可持久化，审批通道关闭，拒绝执行（P1-⑤）",
            command=d.command, url=url, target_id=tid, run_id=rid,
        )
        return (
            "【已拦截】（策略）审批事件无法持久化审计，按 P1-⑤ 拒绝执行"
            f"（{d.command or '未知操作'}）。\n"
            "  未留痕的审批等于没审批——先恢复审计落盘（data 目录可写、"
            "policy.audit: true）再发起需要审批的操作。"
        )

    def _commit_pending_ledger(self, pend: dict[str, Any], response_text: str) -> None:
        """执行成功后把 pending 台账条目真正落账（P0-②）。

        对象标识提取：创建/上传打在集合端点（URL 尾段是集合名）→
        响应优先；修改/资源型端点 → URL 尾段优先。
        **创建/上传取不到标识就不登记**——之后删除按未知对象走
        逐请求审批，宁可误拦不盲放。
        """
        from policy.test_transaction import extract_object_id

        # 取走 pending（幂等：无论登记与否都消费掉，防陈旧条目泄漏）
        self._pending_ledger = None
        action = pend.get("action") or ""
        url = pend.get("url") or ""
        obj_id = extract_object_id(url, response_text, url_first=action == "update")
        self.test_ledger.record(
            url, action,
            run_id=pend.get("run_id") or "",
            target_id=pend.get("target_id") or "",
            identity=pend.get("identity") or "",
            object_id=obj_id,
        )

    async def _policy_review(self, d, session, url: str) -> bool:
        """REVIEW 决策的运行期审批：有审核通道就问人，没有就拒绝。"""
        tid, rid = self._policy_scope(session)
        if self.approver is None:
            self.policy_audit.log(
                "deny", command=d.command, level=d.level, decision=d.decision,
                category=d.category, url=url, target_id=tid, run_id=rid,
                reason=d.reason + "；无审批通道，拒绝执行",
            )
            return False
        ok = bool(
            await self.approver(
                f"策略审批：{d.command}（{d.level}）针对 {url[:80]}\n  {d.reason}"
            )
        )
        self.policy_audit.log(
            "approval" if ok else "deny",
            command=d.command, level=d.level,
            decision="ALLOW" if ok else "DENY",
            category=d.category, url=url, target_id=tid, run_id=rid,
            reason=("运行期审批通过：" + d.reason) if ok else ("运行期审批拒绝：" + d.reason),
        )
        return ok

    def _policy_allow(self, session, d, url: str = "") -> None:
        """放行留痕 + 写操作挂 pending 台账（P0-②：**放行 ≠ 登记**）。

        台账登记延迟到 handler 执行成功之后（execute →
        _commit_pending_ledger）：闸门放行的创建可能执行失败，"执行
        成功并取得对象标识"才登记。删除不登记（删除不产生对象）。
        """
        tid, rid = self._policy_scope(session)
        self.policy_audit.log(
            "allow", command=d.command, level=d.level, decision=d.decision,
            category=d.category, url=url, target_id=tid, run_id=rid,
            reason=d.reason, extra={"signals": list(d.signals)[:6]} if d.signals else None,
        )
        action = self._LEDGER_ACTIONS.get(d.command)
        if action and url and action != "delete":
            # 台账统一隔离口径（P1-8）：target_id / run_id / identity 一起挂，
            # 执行成功后落账时三个维度都要对得上才认"已知"。
            self._pending_ledger = {
                "url": url,
                "action": action,
                "run_id": rid,
                "target_id": tid,
                "identity": self._current_identity(session),
            }

    def _policy_deny(self, session, d, url: str = "") -> str:
        """DENY/UNKNOWN 决策的留痕 + 拒绝文本。拒绝也必须能对账。"""
        tid, rid = self._policy_scope(session)
        self.policy_audit.log(
            "deny", command=d.command, level=d.level, decision=d.decision,
            category=d.category, url=url, target_id=tid, run_id=rid,
            reason=d.reason, extra={"signals": list(d.signals)[:6]} if d.signals else None,
        )
        return self._policy_deny_text(d, url)

    def _policy_deny_text(self, d, url: str = "") -> str:
        lines = [f"【已拦截】（策略）{d.command or '未知接口'} 被权限控制拒绝执行。"]
        lines.append(f"  判定：{d.decision}（等级 {d.level or '-'} / 分类 {d.category or '-'}）")
        lines.append(f"  理由：{d.reason}")
        if d.signals:
            lines.append("  识别信号：" + "；".join(d.signals[:5]))
        lines.append(
            "  条件不满足统一拒绝执行。如确属已授权的测试环境，请在 config.yaml 的"
            " policy 段绑定环境（environments: {\"<host 通配>\": \"isolated_test\"}"
            " 或 dedicated_test）。L3 命令一律拒绝，无任何审批出路。"
        )
        return "\n".join(lines)

    async def _h_set_target(self, session, url: str = "") -> str:
        norm = self._normalize_target(url).rstrip("/")
        changed = session.target != norm
        session.target = norm
        # 必须同步 result.target：报告命名（report_<日期>_<主域名>）读的是
        # result.target。只改 session.target 的话，导出报告时它还是空串，
        # 文件名就退化成 report_<日期>_target——和 repl 的 /target 命令
        # （repl.py _set_target，两处都改）行为不一致。
        session.result.target = session.target
        if changed:
            # 三层隔离：换目标必须开新的扫描轮次，与 repl /target 保持一致。
            # 目标没变就不开——重复 set_target 不该把正在跑的一轮扫描腰斩。
            session.result.target_id = session.target
            session.result.new_run(f"目标 {session.target}")
            # 身份随目标走（P1-④）：新目标回到匿名（由 _current_identity
            # 现算 anonymous@<host>），凭证由该目标的请求重新声明，避免把
            # 上一个目标的会话凭证算到新目标头上。
            self._identity = ""
        return f"目标已设定：{session.target}"

    async def _h_session_state(self, session, **_: Any) -> str:
        return self.state_text(session)

    def state_text(self, session) -> str:
        """当前会话状态摘要。**纯读**，供系统提示词与 session_state 工具共用。

        单独抽出来是因为它每轮开头都会被塞进 system 消息——走
        :meth:`execute` 会把它记成一次"工具调用"，把调用统计搞脏。
        """
        r = session.result
        kinds: dict[str, int] = {}
        for a in r.assets:
            kinds[a.kind] = kinds.get(a.kind, 0) + 1
        c = r.counts()
        lines = [
            f"目标：{session.target or '（未设定）'}",
            f"阶段：{session.phase.label} | 轮次：{session.turn_no}",
            f"资产：{len(r.assets)} 项 " + ("、".join(f"{k} {v}" for k, v in kinds.items()) or "（无）"),
            f"发现：{len(r.findings)} 项 "
            + ("、".join(f"{Severity(k).label} {v}" for k, v in c.items() if v) or "（无）"),
            f"凭证：{'已取得 Token' if session.credentials.get('token') else '未取得'}",
            f"业务模型：{session.model.summary() if session.model.resources else '尚未建模'}",
        ]
        if r.fingerprints:
            lines.insert(2, f"指纹：{r.fingerprints[0].summary()}")
        # 权限控制状态：Agent 必须知道当前环境判定与策略口径，
        # 否则它发起的写操作被拦时完全摸不着头脑（拦截文本只到单次调用）。
        # 策略恒生效（P0-2），不再有 enabled 开关可看。
        if getattr(self, "policy_guard", None) is not None:
            env = self.policy_guard.environment_for(session.target or "")
            lines.append(
                f"策略：强制生效 | 目标环境 {env or '未知'} | 身份 {self._current_identity(session)}"
                "（L1 仅隔离测试环境、L2 需专门测试环境/审批、L3 一律拒绝）"
            )
        api = [a for a in r.assets if a.kind == "api"]
        if api:
            no_auth = sum(1 for a in api if not a.meta.get("auth"))
            lines.append(f"接口清单：{len(api)} 个操作（其中免鉴权声明 {no_auth}）")
        if r.context_vars:
            lines.append("上下文变量：" + "、".join(sorted(r.context_vars)))
        if r.attack_chains:
            lines.append(f"攻击链：{len(r.attack_chains)} 条（已记录步骤）")
        # 后台任务：每轮开头必须让模型看见，否则它会忘了自己启动过什么、
        # 或者一直干等一个早就完成的任务。列运行中的 id 是给它查询的抓手。
        if session.tasks:
            lines.append(session.tasks.summary_line())
            running = session.tasks.running()
            if running:
                lines.append(
                    "后台运行中：" + "、".join(
                        f"{t.task_id}（{t.label}）" for t in running[:5]
                    ) + "  → 完成后用 list_tasks 取结果，不要原地等"
                )
        # 收尾必须返回拼好的文本：这个函数曾经漏了这一行，导致
        # ``session_state`` 工具永远回空串、系统提示里的"当前会话状态"
        # 永远渲染成"（空白，还没有任何资产与发现）"——模型整场测试都没
        # 看见过真实资产/发现，误以为每次都是从零开始。
        return "\n".join(lines)


    # ── 会话合并 ──────────────────────────────────────────────────

    _last_merged = 0

    def _merge_assets(self, session, assets: list[Asset]) -> int:
        seen = {(a.kind, a.value) for a in session.result.assets}
        added = 0
        for a in assets:
            k = (a.kind, a.value)
            if k in seen:
                continue
            seen.add(k)
            session.result.assets.append(a)
            added += 1
        return added

    def _merge_findings(self, session, findings: list[Finding]) -> int:
        """并入发现。去重、误报排除、重排都在 ``ScanResult.add_findings`` 里做。

        这里刻意不再自己实现一遍——以前去重逻辑散在 toolrun 与 planner 两处，
        一改就漏一处（误报排除就是被这个坑到的第一个策略）。
        """
        added = session.result.add_findings(list(findings))
        self._last_merged = added
        return added
