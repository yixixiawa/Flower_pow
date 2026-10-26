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

        注意**不动** ``_det_cache``（探测器缓存）：它按工具+参数索引，
        与目标无关，清了只会白白多跑一遍探测。
        """
        self._recent_http.clear()
        self._endpoint_signal.clear()
        self._endpoint_streak.clear()
        self._host_signal.clear()
        self._host_streak.clear()



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
                f"如确需使用，让用户改 config.yaml 的 scan.readonly: false 或设 POCS_READONLY=false 后重启。"
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
        if name not in {"extract_variable", "context_get"}:
            args = self._expand_context_vars(args, session.result.context_vars)
        status = "ok"
        try:
            handler = getattr(self, f"_h_{name}", None)
            if handler is None:
                out = f"【未知工具】{name}。可用工具见系统提示中的清单。"
                status = "unknown"
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

    async def _h_set_target(self, session, url: str = "") -> str:
        norm = self._normalize_target(url)
        session.target = norm.rstrip("/")
        # 必须同步 result.target：报告命名（report_<日期>_<主域名>）读的是
        # result.target。只改 session.target 的话，导出报告时它还是空串，
        # 文件名就退化成 report_<日期>_target——和 repl 的 /target 命令
        # （repl.py _set_target，两处都改）行为不一致。
        session.result.target = session.target
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
        api = [a for a in r.assets if a.kind == "api"]
        if api:
            no_auth = sum(1 for a in api if not a.meta.get("auth"))
            lines.append(f"接口清单：{len(api)} 个操作（其中免鉴权声明 {no_auth}）")
        if r.context_vars:
            lines.append("上下文变量：" + "、".join(sorted(r.context_vars)))
        if r.attack_chains:
            lines.append(f"攻击链：{len(r.attack_chains)} 条（已记录步骤）")


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
