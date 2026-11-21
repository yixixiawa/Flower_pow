"""流式 AI Agent 循环——把"对话"变成"边聊边动手"。

它到底做什么
------------
用户说一句人话 → 交给模型 → 模型决定**先说什么、调哪个工具** →
本地执行工具 → 把结果回灌 → 模型基于真实结果继续判断……
直到模型认为这一轮做完了，把控制权交回用户。

和 ``core/planner.py`` 的区别
----------------------------
* ``Planner`` 是**固定剧本**：第 1 轮一定做信息收集，第 3 轮一定做鉴权探测。
  好处是稳定可复现，坏处是它不会因为"这个站点根本没有登录接口"就改变打法。
* ``Agent`` 是**模型驱动**：这一轮做什么由模型看着当前状态决定。
  代价是需要模型靠谱，所以提示词里写了硬约束、执行层还加了四道闸门。

两者都保留：``chat --classic`` 走剧本，默认走 Agent。

循环的安全阀
------------
早先用 ``max_steps`` 做硬截断，单轮到顶就交还控制权；后来又改成
``HARD_STEP_CAP = 200`` 兜底。**两者都已移除**——现在单轮工具调用**没有次数上限**。

理由：这类保守上限会**打断真实的多轮任务**。渗透测试动辄几十上百次调用
（信息收集 → 建业务模型 → 逐接口验证 → 换角度复测），
200 步砍掉的是「模型正在推进中的任务」，用户拿到的仍是半截结论，
既没跑完、又要重新交代一遍。额度消耗是**用户自己的账**，
不该由代码替他做「什么时候算够了」的判断。

唯一保留的是死循环检测（拦的**不是次数而是无进展**），共三道：

* ``LOOP_REPEAT_LIMIT``：同一工具 + 同一参数连续重复 3 次。
* ``LOOP_SKELETON_LIMIT``：同一外部工具 + 同一套选项（忽略取值）连续
  重复 4 次。精确指纹拦不住"换选项取值碰运气"——``curl -w %{json}`` /
  ``-w %{stdout}`` / ``-w %{http_code}`` 每次指纹都不同，本质却是同
  一个无进展死循环（真实事故：模型连打十几次 ``-w`` 想看被截断的输出）。
  骨架把取值抹掉，这类循环 4 次现形。阈值比精确重复宽一档，
  且只对 ``external_tool`` 启用——``http_request`` 换 payload、
  ``sqli_probe`` 换参数都是正常渗透动作，骨架化会误伤真实工作。
* ``http_request`` **语义指纹**（``_FILLER_KEY`` / ``_FILLER_VAL`` +
  ``_normalize_http_args``）：query 里 1~3 个纯字母参数名、值恒为 1 的
  ``xx=1`` 填充参数，在指纹计算前剔除。真实事故：JSONP 探测每轮追加
  一个假参数（jt=1 → ju=1 → jv=1……连打二十几发，响应全是 200/2B/{}），
  每次都是"新指纹"，精确重复拦不住——归一化后这类排列组合在指纹层面
  就是同一次调用，照样走上面的软纠偏 + 硬拒绝链路。

两者触发后先**注入收尾指令**让模型给结论（软纠偏）：确有进展时模型交代一句仍可继续。

**但软纠偏对固执的模型无效**（真实事故：`ca.deppon.com` 返回 418 + 0 字节——WAF 拦截，
模型看着空响应以为"再试一次说不定就通了"，收尾指令被无视，同样的 GET 连打十几轮，
烧的都是用户自己的额度）。所以警告过一次之后还有第二道闸：

* **硬拒绝**：已被警告的调用，模型若**原样再调**（指纹相同），执行层直接拒绝——
  请求根本不发出，工具结果里返回拒绝说明。这不是次数上限（换参数、换路径、
  换工具随时可以继续），只拦"一字不差的原样重试"——同一个请求打同一个目标，
  连响应字节数都相同，重试第十一次和第一次不会有任何区别。

跨轮重复与"看不出进展"
----------------------
上面三道都是**轮内**检测（一次 ``send`` 里连续重复）。真实问题还有两个：

* **跨轮重复**：上一轮已经 ``dirsearch -w big.txt`` 失败过，这一轮模型又提一次
  同样的命令。轮内的指纹列表在每轮开头清空，拦不到。
* **整体无进展**：每一步都在换着花样调工具（``A,B,A,B``），单个动作看不出重复，
  但实际上一步没往前走，发现数/资产数/任务状态全都没变。

对应两层：

* :class:`core.session.explore.ExplorationLedger`（探索台账）——记录 objective、
  每次调用的**参数指纹**与状态、失败方法、已确认事实。每轮开始先看台账，
  已成功/已失败过的同参数动作**不再执行**，回给模型一句"这个动作第 N 轮做过，
  结果是这样；要重做请说明新证据或参数差异"。
  判重键是「工具 + 规范化参数」，**不是工具名**——换个路径、换个字典就是新动作。
* :class:`core.session.explore.NoProgressGuard`（无进展守卫）——按**每步签名**
  （动作指纹集合 + 结果摘要 + 发现/资产/任务状态计数）判断，连续 3 步签名完全
  相同即判定无进展：注入收尾指令、停止继续执行工具、把已知事实与未决问题摊开。
  换自然语言描述同一个操作没用——签名里没有自然语言。

后台任务状态推送
----------------
``TaskManager`` 每进入一个终态就产生一条 :class:`TaskEvent`；本模块每一步
``events_since(cursor)`` 只取"还没见过的"注入一次，游标推进后**同一状态不会
重复注入**。所以模型不需要 ``list_tasks`` 轮询——轮询反而会被反轮询闸门拒绝。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.session.explore import (
    ST_OK,
    ExplorationLedger,
    NoProgressGuard,
    classify_result,
    result_digest,
)
from core.tools import ToolRunner
from llm import prompt as P

MAX_HISTORY_MSGS = 40       # 超过就从头裁，防止上下文无限膨胀
MAX_HISTORY_CHARS = 120_000

# 同一「工具名+参数」连续重复多少次就判定为死循环（不是次数上限，是死循环检测）
LOOP_REPEAT_LIMIT = 3
# 同一「外部工具+选项集」（忽略取值）连续重复多少次判定为换壳死循环。
# 比精确重复宽一档：连打 4 次同骨架的外部命令，基本可以确定是在
# 排列组合碰运气，而不是在推进任务。
LOOP_SKELETON_LIMIT = 4

# http_request 的「填充参数」形态：1~3 个纯字母的参数名 + 值恒为 1。
# 模型往 URL 里堆这种参数（jt=1、ju=1……）想碰运气——每次追加一个
# 都是"新指纹"，精确重复检测拦不住。归一化剔除后，同一端点的排列
# 组合在指纹层面坍缩成同一次调用，走既有的软纠偏 + 硬拒绝链路。
_FILLER_KEY = re.compile(r"^[a-z]{1,3}$")
_FILLER_VAL = re.compile(r"^1$")

# 台账判重的豁免名单：这类工具是**观察**而不是**动作**，同一参数反复调
# 不会"重复劳动"（list_tasks 的反轮询由 runner 侧的闸门管）。
_LEDGER_EXEMPT = frozenset({"list_tasks", "session_state"})


def _refusal_text(name: str, args: dict[str, Any]) -> str:
    """硬拒绝时回给模型的工具结果。

    措辞必须交代三件事：**为什么拒**（同样的请求同样的失败，重试不会有新信息）、
    **什么仍然允许**（换参数/换路径/换方法/换工具随便来）、
    **    退路是什么**（基于已有证据给结论）。只说"拒绝"不说出路，
    模型多半会换个说法再试一次，等于没拦。
    """
    text = (
        "[执行被拒绝] 这个调用（"
        + _describe(name, args)
        + "）刚刚已经**原样**执行过多次，每次返回的结果完全相同，已被判定为无进展死循环，"
        "本次不再发出请求。同一个请求打同一个目标，失败原因（如 WAF 拦截 418/403、"
        "目标无响应、路径不存在）不会因为重试第 N 次而改变——再试只会浪费额度，"
        "不会带来新信息。\n"
        "你可以：① 换参数 / 换路径 / 换 HTTP 方法（这些都会正常执行）；"
        "② 换一个工具换角度验证；③ 若已无新角度，基于已有信息直接给出结论，"
        "探不到就明确说「当前证据不足以判定」，不要编造。"
    )
    if name == "http_request":
        text += (
            "\n补充说明：本次请求在剔除 xx=1 之类无意义填充参数"
            "（1~3 个纯字母的参数名、值恒为 1）之后，与之前已被拒绝的请求完全相同——"
            "填充参数不构成新的探测手法，堆再多也不会改变服务端行为。"
        )
    return text


class Agent:
    """流式工具调用 Agent。"""

    def __init__(
        self,
        cfg,
        session,
        runner: ToolRunner,
        tools: list[dict[str, Any]],
        llm,
        probes: list | None = None,
        on_text: Callable[[str], None] | None = None,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self.cfg = cfg
        self.session = session
        self.runner = runner
        self.tools = tools
        self.llm = llm
        self.probes = probes or []
        # 单轮工具调用次数**无上限**（文档与代码一致，不再有半死的
        # max_steps 形参——"文档说已移除、代码里还留着"比没有更糟）。
        self.on_text = on_text or (lambda s: print(s, end="", flush=True))
        self.on_event = on_event or (lambda s: print(s))
        self.history: list[dict[str, Any]] = []
        # 最近若干次工具调用的指纹，用于识别无进展重复
        self._call_fingerprints: list[str] = []
        # 最近若干次 external_tool 调用的骨架指纹（工具+选项集，忽略取值）
        self._skeletons: list[str] = []
        # 已警告过、再原样重调就拒绝执行的指纹（精确 / 骨架各一份）。
        # **只在本轮 send() 内生效**——下一轮用户输入是新指令，
        # 用户明确要求重试同一请求是合法的，不能带着上一轮的拒绝状态。
        self._refused: set[str] = set()
        self._refused_skel: set[str] = set()
        # ── 探索台账 / 无进展守卫 / 后台事件游标 ──────────────────
        # 台账解决"跨轮重复探索"（轮内的三道检测拦不到上一轮做过的事）
        self.ledger = ExplorationLedger()
        # 守卫看每步的整体签名，连续多步一致 = 一步没往前走
        self.noprog = NoProgressGuard()
        # 只消费新增的后台状态变更：游标之前的都已经注入过了
        tasks = getattr(session, "tasks", None)
        self._task_cursor = int(getattr(tasks, "cursor", 0) or 0)
        # 判定无进展后：工具调用一律不执行，给模型最后一次机会给结论
        self._halted = False
        self._halt_steps = 0
        # 连续"整步都没执行任何工具"的次数（被跳过/被拒绝），兜底防死循环
        self._noop_steps = 0
        # 本轮内同一动作被"跳过"的次数（防止模型换个说法反复提同一件事）
        self._skip_counts: dict[str, int] = {}
        # 统计：每轮一条，累计一份。token 数没有 usage 可读，按字符估算并标注
        self.turn_stats: list[dict[str, Any]] = []
        self.stats: dict[str, int] = {
            "rounds": 0, "steps": 0, "tool_calls": 0, "dup_blocked": 0,
            "refused": 0, "repeats": 0, "prompt_chars": 0, "completion_chars": 0,
        }
        self._turn: dict[str, int] = {}

    # ── 提示词 ────────────────────────────────────────────────────

    def tool_names(self) -> list[str]:
        out = [t["function"]["name"] for t in self.tools if t["function"]["name"] != "external_tool"]
        avail = [p.spec.key for p in self.probes if p.found]
        if any(t["function"]["name"] == "external_tool" for t in self.tools):
            out.append("external_tool" + (f"（{', '.join(avail)}）" if avail else "（本机无可用外部工具）"))
        return out

    def _system(self) -> dict[str, str]:
        extra = self.llm.tool_note if getattr(self.llm, "tool_note", "") else ""
        # 已授权本地文件：只把**清单**（名字 + file_id）放进 system 提示。
        # 正文一律走 read_local_file 的「工具结果」通道——system 里的文字
        # 有指令效力，而文件内容是不可信数据，两者绝不能混。
        files = getattr(self.session, "files", None)
        if files is not None and files.records():
            note = files.prompt_note()
            extra = f"{extra}\n{note}" if extra else note
        # 探索台账也进 extra：模型规划下一步前先看到"哪些动作已经做过、
        # 结果如何"。正文仍然是数据/事实，不是指令，所以放 extra 而不是
        # 拼进 AGENT_SYSTEM 的硬约束段。
        ledger_note = self.ledger.prompt_note()
        if ledger_note:
            extra = f"{extra}\n{ledger_note}" if extra else ledger_note
        return {
            "role": "system",
            "content": P.AGENT_SYSTEM
            + "\n"
            + P.render_agent(
                session_line=self.session.status_line(),
                target=self.session.target,
                state_text=self.runner.state_text(self.session),
                tool_names=self.tool_names(),
                readonly=self.cfg.scan.readonly,
                extra=extra,
            ),
        }

    # ── 主循环 ────────────────────────────────────────────────────

    def _fingerprint(self, name: str, args: dict[str, Any]) -> str:
        """工具调用指纹：工具名 + 规范化后的参数。

        规范化在**Python 对象层面**做，不在 JSON 字符串层面：
        先把 ``"http://t/"`` 折成 ``"http://t"`` 再 dumps，
        否则 JSON 编码会把引号转义成 ``\\"``，字符串级的正则匹配不到。
        """
        if name == "http_request":
            # 传**副本**：归一化只影响指纹，真正发出去的请求保持模型
            # 原样——检测层无权替模型改写请求内容。
            args = self._normalize_http_args(name, dict(args))

        def _norm(v: Any) -> Any:
            if isinstance(v, str):
                # 去掉 URL 末尾斜杠：`http://a/` 与 `http://a` 对目标是同一次请求
                if v.startswith(("http://", "https://")) and v.endswith("/"):
                    return v.rstrip("/")
                return v
            if isinstance(v, dict):
                return {_norm(k): _norm(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_norm(x) for x in v]
            return v

        try:
            norm = json.dumps(_norm(args), sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            norm = str(args)
        return f"{name}|{norm}"

    def _normalize_http_args(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """http_request 专用：剔除 query 里「短参数名 + 值恒为 1」的填充参数。

        只对 http_request 生效——其他工具的参数名有语义（``sqli_probe`` 的
        ``point``、``read_file`` 的 ``start_line``），削了就变味，不得改动。
        url 非法或不含 scheme（``://``）时原样返回，不做任何修改。

        解析用 ``urlparse`` / ``parse_qsl``，剔除后剩余参数**排序**再
        ``urlencode`` / ``urlunparse`` 重组回 ``args["url"]``——排序是让
        参数顺序不同、语义相同的两次调用也命中同一指纹。
        """
        if name != "http_request":
            return args
        url = args.get("url")
        if not isinstance(url, str) or "://" not in url:
            return args
        try:
            parts = urlparse(url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            kept = [
                (k, v)
                for k, v in pairs
                if not (_FILLER_KEY.match(k) and _FILLER_VAL.match(v))
            ]
            kept.sort()
            if kept == pairs:
                return args
            args["url"] = urlunparse(parts._replace(query=urlencode(kept)))
        except ValueError:
            return args
        return args

    def _looping(self, fingerprint: str) -> bool:
        """记录指纹并判断是否陷入无进展重复。"""
        self._call_fingerprints.append(fingerprint)
        if len(self._call_fingerprints) > LOOP_REPEAT_LIMIT:
            self._call_fingerprints.pop(0)
        return (
            len(self._call_fingerprints) >= LOOP_REPEAT_LIMIT
            and len(set(self._call_fingerprints)) == 1
        )

    @staticmethod
    def _skeleton(name: str, args: dict[str, Any]) -> str:
        """外部工具的「骨架指纹」：工具名 + 排序后的选项集合，**忽略取值**。

        只对 ``external_tool`` 返回非空串。其他工具换参数值是正常探索
        （http_request 换 payload、sqli_probe 换参数点），骨架化会误伤。
        """
        if name != "external_tool":
            return ""
        tool = str(args.get("tool") or "?")
        argv = args.get("args") or []
        if not isinstance(argv, list):
            argv = [argv]
        flags = sorted({a for a in (str(x) for x in argv) if a.startswith("-")})
        return f"{tool}|{' '.join(flags)}"

    def _skeleton_looping(self, skeleton: str) -> bool:
        """记录骨架指纹并判断是否陷入「换壳重复」。**只在骨架非空时调用。**"""
        self._skeletons.append(skeleton)
        if len(self._skeletons) > LOOP_SKELETON_LIMIT:
            self._skeletons.pop(0)
        return (
            len(self._skeletons) >= LOOP_SKELETON_LIMIT
            and len(set(self._skeletons)) == 1
        )

    async def send(self, user_text: str, echo: bool = True) -> str:
        """处理一次用户输入，返回模型最后的完整文本。

        循环**不设硬上界**：模型连续调工具时不会被中途切断，
        正常退出条件是「模型不再要求调用工具」。
        仅在检测到同一工具 + 同一参数被连续重复（无进展死循环）时，
        才注入收尾指令让模型收敛输出。
        """
        self.history.append({"role": "user", "content": user_text})
        self._trim()
        self._call_fingerprints.clear()
        self._skeletons.clear()
        self._refused.clear()
        self._refused_skel.clear()
        self._round_start(user_text)
        final = ""
        step = 0

        while True:
            # 后台任务状态变更：只注入"还没见过"的那几条，游标推进后不重复
            self._inject_task_events()
            messages = [self._system(), *self.history]
            text_parts: list[str] = []
            tool_calls: list[dict[str, str]] = []
            error = ""

            if echo and step > 0:
                self.on_event("")

            for ev in self.llm.stream_chat(messages, tools=self.tools or None):
                if ev["type"] == "text":
                    text_parts.append(ev["text"])
                    self.on_text(ev["text"])
                elif ev["type"] == "tool_calls":
                    tool_calls = ev["calls"]
                elif ev["type"] == "error":
                    error = ev["message"]

            content = "".join(text_parts)
            # Token 统计：流式接口不返回 usage，按"消息字符数"记账（估算见 _turn_end）
            prompt_chars = sum(
                len(json.dumps(m, ensure_ascii=False, default=str)) for m in messages
            )
            self._turn["prompt_chars"] = self._turn.get("prompt_chars", 0) + prompt_chars
            self._turn["completion_chars"] = (
                self._turn.get("completion_chars", 0) + len(content)
            )
            self.stats["prompt_chars"] += prompt_chars
            self.stats["completion_chars"] += len(content)

            if error and not content and not tool_calls:
                self.on_event(f"\n[!] 模型调用失败：{error}")
                self.history.append({"role": "assistant", "content": f"（调用失败：{error}）"})
                self._turn_end()
                return f"（调用失败：{error}）"

            if not tool_calls:
                if content:
                    self.on_event("")
                self.history.append({"role": "assistant", "content": content})
                self._turn_end()
                return content

            # ── 有工具调用：先把这个 assistant 轮次按协议格式补全 ──
            norm_calls = []
            for i, c in enumerate(tool_calls): 
                cid = c.get("id") or f"call_{step}_{i}"
                name = c.get("name") or ""
                norm_calls.append({"id": cid, "name": name, "arguments": c.get("arguments") or "{}"})
            self.history.append(
                {
                    "role": "assistant",
                    "content": content or None,
                    "tool_calls": [
                        {
                            "id": c["id"],
                            "type": "function",
                            "function": {"name": c["name"], "arguments": c["arguments"]},
                        }
                        for c in norm_calls
                    ],
                }
            )

            # 循环检测：精确指纹（工具+参数完全相同）与骨架指纹
            # （外部工具换选项取值碰运气）各算各的，任一命中即判无进展
            looped = False
            skeleton_looped = False
            looped_fp = ""
            looped_skel = ""
            step_pairs: list[str] = []
            executed = False
            for c in norm_calls:
                args, parse_note = _parse_args(c["arguments"], self.tools, c["name"])
                fp = self._fingerprint(c["name"], args)
                skel = self._skeleton(c["name"], args)
                # ── 已判定无进展：工具调用一律不执行 ──────────────
                if self._halted:
                    self.history.append(
                        {
                            "role": "tool",
                            "tool_call_id": c["id"],
                            "content": _halted_text(c["name"], args),
                        }
                    )
                    continue
                # ── 硬拒绝：警告过之后仍原样重调 → 请求根本不发出 ──
                # 协议要求每个 tool_call 必须有结果，所以拒绝说明以 tool
                # 消息回灌，模型能读到"为什么拒、接下来能干什么"。
                if fp in self._refused or (skel and skel in self._refused_skel):
                    self.on_event(f"\n  ⛔ 已拒绝重复执行（无进展死循环）")
                    self.stats["refused"] += 1
                    self._turn["refused"] += 1
                    self.history.append(
                        {
                            "role": "tool",
                            "tool_call_id": c["id"],
                            "content": _refusal_text(c["name"], args),
                        }
                    )
                    step_pairs.append(f"{fp}#refused")
                    continue
                # ── 跨轮判重：台账里已执行过同参数动作 → 不执行，先要理由 ──
                dup = (
                    None
                    if c["name"] in _LEDGER_EXEMPT
                    else self.ledger.duplicate_of(c["name"], fp)
                )
                if dup is not None:
                    key = f"{c['name']}|{fp}"
                    self._skip_counts[key] = self._skip_counts.get(key, 0) + 1
                    self.stats["dup_blocked"] += 1
                    self._turn["dup_blocked"] += 1
                    self.on_event(
                        f"\n  ⏸ 跳过重复动作（第 {dup.round} 轮已执行：{dup.status}）"
                    )
                    self.history.append(
                        {
                            "role": "tool",
                            "tool_call_id": c["id"],
                            "content": _duplicate_text(c["name"], args, dup,
                                                       self._skip_counts[key]),
                        }
                    )
                    step_pairs.append(f"{fp}#dup")
                    continue
                if self._looping(fp):
                    looped = True
                    looped_fp = fp
                if skel:
                    if self._skeleton_looping(skel):
                        skeleton_looped = True
                        looped_skel = skel
                else:
                    # 骨架只认**连续**：中间插了别的工具调用，连击断开
                    self._skeletons.clear()
                self.on_event(f"\n  ⚙ {_describe(c['name'], args)}{parse_note}")
                before = self._evidence_snapshot()
                try:
                    result = await self.runner.execute(c["name"], args, self.session)
                except asyncio.CancelledError:
                    result = "【工具中断】该工具调用被用户中断，未取得结果。"
                    self.history.append(
                        {"role": "tool", "tool_call_id": c["id"], "content": result}
                    )
                    raise
                except KeyboardInterrupt:
                    result = "【工具中断】该工具调用被用户中断，未取得结果。"
                    self.history.append(
                        {"role": "tool", "tool_call_id": c["id"], "content": result}
                    )
                    raise
                except Exception as exc:  # noqa: BLE001
                    result = f"【工具失败】{type(exc).__name__}: {exc}"
                self.stats["tool_calls"] += 1
                self._turn["calls"] += 1
                executed = True
                status = classify_result(result)
                self.ledger.record(c["name"], fp, status, result)
                after = self._evidence_snapshot()
                if after != before:
                    # 有新发现/新资产/新线索 → 这是"真的往前走了"的一步
                    self.ledger.note_evidence()
                    self.ledger.note_fact(
                        f"{c['name']} 带来新证据（发现 +{after[0] - before[0]}、"
                        f"资产 +{after[1] - before[1]}、线索 +{after[2] - before[2]}）"
                    )
                step_pairs.append(f"{fp}#{status}:{result_digest(result)}")
                self.on_event(_indent(result))
                self.history.append(
                    {"role": "tool", "tool_call_id": c["id"], "content": result}
                )

            final = content
            step += 1
            self.stats["steps"] += 1
            self._turn["steps"] += 1

            if looped or skeleton_looped:
                self.stats["repeats"] += 1
                self._turn["repeats"] = self._turn.get("repeats", 0) + 1
                # 记下触发循环的指纹：模型若无视下面的收尾指令、
                # 原样再调同一个，就进入硬拒绝（不再发出请求）。
                if looped_fp:
                    self._refused.add(looped_fp)
                if looped_skel:
                    self._refused_skel.add(looped_skel)
                if skeleton_looped:
                    self.on_event(
                        f"\n[!] 检测到连续 {LOOP_SKELETON_LIMIT} 次调用同一外部工具"
                        f"且只是更换选项取值，判定为无进展，停止排列组合并要求模型给出结论。"
                    )
                    hint = (
                        "[系统提示] 你刚刚连续多次调用同一个外部工具，"
                        "只是更换选项取值（比如反复试 curl -w 的不同变量），"
                        "结果没有实质差异。不要再排列选项碰运气——"
                        "再原样重调会被直接拒绝执行。"
                        "如果目的是查看被截断的输出：完整内容已保存到 "
                        "tool-output/ 下的文件，用 read_file 的 start_line "
                        "分段读取即可。"
                        "请基于已有信息直接给出最终结论：已确认的问题、"
                        "未能验证的部分、下一步建议；确实探不到就明确说"
                        "「当前证据不足以判定」，不要编造。"
                    )
                else:
                    self.on_event(
                        f"\n[!] 检测到重复调用同一工具 {LOOP_REPEAT_LIMIT} 次，判定为无进展，"
                        f"停止尝试并要求模型给出结论。"
                    )
                    hint = (
                        "[系统提示] 你刚刚对同一工具重复调用了多次且结果没有变化。"
                        "同一个请求重复发，失败原因不会变（常见的有：WAF/反爬拦截"
                        "如 418/403、目标无响应、路径不存在）——重试第 N 次和第 1 次"
                        "拿到的是同一个结果，只是在烧额度。"
                        "**再原样重调将被直接拒绝执行，请求不会发出。**"
                        "要继续就换方法：改路径、改 HTTP 方法、改请求头（如 User-Agent）、"
                        "换参数、或换一个工具换角度验证。"
                        "如果确实什么都探不到，请基于已有信息直接给出最终结论"
                        "（已确认的问题、未能验证的部分、下一步建议），"
                        "明确说明「当前证据不足以判定」，不要编造。"
                    )
                self.history.append({"role": "user", "content": hint})
                # 不直接 return：给模型最后一次机会输出结论，
                # 它要么给文本（正常结束），要么不再调工具。
                # 清零必须留在本块内：挪到块外等于每轮都重置计数，
                # 精确重复检测永远凑不满 LOOP_REPEAT_LIMIT（真事故：
                # 删 max_steps 时重排缩进，把这两行挪出了 if，守卫整体失效）。
                self._call_fingerprints.clear()
                self._skeletons.clear()
                continue

            # ── 已判定无进展：再给两步机会，仍不收敛就由代码收尾 ──
            # 必须放在最前面：否则每步都会重新 _halt（把计数器清零），
            # 模型一直硬调工具就会无限循环。
            if self._halted:
                self._halt_steps += 1
                if self._halt_steps >= 2:
                    text = self._halt_summary()
                    self.history.append({"role": "assistant", "content": text})
                    self._turn_end()
                    return text
                continue
            # ── 无进展守卫：不看到单个动作，看这一步整体有没有推进 ──
            # 签名 = 动作指纹/结果摘要 + 发现/资产/线索计数 + 后台任务状态。
            # 连续 NO_PROGRESS_LIMIT 步完全一致 → 判定原地打转。
            if norm_calls and not executed:
                # 整步都是"被跳过/被拒绝"：一步没往前走，连续两次即收口。
                # 这条兜底专门防"模型无视拒绝、反复提同一动作"的无限规划循环。
                self._noop_steps += 1
                if self._noop_steps >= 2:
                    self._halt(step_pairs)
                    continue
            else:
                self._noop_steps = 0
            if self.noprog.observe(self._step_signature(step_pairs)):
                self._halt(step_pairs)
                continue

    # ── 轮次台账 / 事件 / 统计 ────────────────────────────────────

    def _round_start(self, user_text: str) -> None:
        """一轮开始：推进台账轮次、清空轮内守卫、开新一轮统计。"""
        self.stats["rounds"] += 1
        self.ledger.begin(user_text)
        self.noprog.reset()
        self._halted = False
        self._halt_steps = 0
        self._noop_steps = 0
        self._skip_counts.clear()
        self._turn = {
            "steps": 0, "calls": 0, "dup_blocked": 0, "refused": 0,
            "repeats": 0, "prompt_chars": 0, "completion_chars": 0,
        }

    def _turn_end(self) -> None:
        """收尾统计：工具调用数、字符数、重复次数、估算 token。"""
        if not self._turn:
            return
        rec = dict(self._turn)
        rec["round"] = self.stats["rounds"]
        rec["objective"] = self.ledger.objective
        # 没有 usage 可读（流式接口不返回），按字符估算并在文档里说明：
        # 中文约 1.5~2 字符/token，英文约 4 字符/token，这里取 2 作折中。
        rec["est_tokens"] = int(
            (rec.get("prompt_chars", 0) + rec.get("completion_chars", 0)) / 2
        )
        self.turn_stats.append(rec)
        if len(self.turn_stats) > 50:
            del self.turn_stats[: len(self.turn_stats) - 50]

    def stats_line(self) -> str:
        """一行统计（/status 与调试用）：调用数 / 重复被拦 / 估算 token。"""
        s = self.stats
        return (
            f"Agent：{s['rounds']} 轮 / {s['steps']} 步 / 工具 {s['tool_calls']} 次"
            f"｜跳过重复 {s['dup_blocked']} 次、硬拒绝 {s['refused']} 次、"
            f"死循环告警 {s['repeats']} 次"
            f"｜字符 {s['prompt_chars'] + s['completion_chars']}"
            f"（估算 {int((s['prompt_chars'] + s['completion_chars']) / 2)} tokens）"
        )

    def _inject_task_events(self) -> bool:
        """把"还没见过"的后台任务状态变更注入上下文，返回是否注入。

        游标之前的都在更早的步骤里注入过了——**同一状态不会被反复注入**
        （任务书 一.5）。没有新事件时什么也不做（不产生空消息）。
        """
        mgr = getattr(self.session, "tasks", None)
        if mgr is None:
            return False
        try:
            mgr.sweep()                       # 超时收割：卡死的任务也要进终态
            events, cursor = mgr.events_since(self._task_cursor)
        except Exception:  # noqa: BLE001 — 台账异常不能把主循环带崩
            return False
        self._task_cursor = cursor
        if not events:
            return False
        lines = [
            "[后台任务状态变更]（系统推送，**不需要**再调用 list_tasks 查询）",
        ]
        lines += [f"- {e.text()}" for e in events]
        lines.append(
            "只处理这些变化：把已完成的结果并入判断；失败/超时的任务不要自动重跑"
            "（改参数或明确 retry 才行）。其余工作照常继续。"
        )
        self.history.append({"role": "user", "content": "\n".join(lines)})
        self.on_event(f"\n  ⤵ 后台任务状态变更 {len(events)} 条（已注入上下文）")
        return True

    def _evidence_snapshot(self) -> tuple[int, int, int]:
        """(发现数, 资产数, 待验证线索数)——判断"这一步有没有带来新证据"。"""
        res = getattr(self.session, "result", None)
        if res is None:
            return (0, 0, 0)
        findings = len(getattr(res, "findings", []) or [])
        assets = len(getattr(res, "assets", []) or [])
        clues = 0
        if hasattr(res, "active_clues"):
            try:
                clues = len(res.active_clues() or [])
            except Exception:  # noqa: BLE001
                clues = 0
        return (findings, assets, clues)

    def _step_signature(self, step_pairs: list[str]) -> str:
        """一步的整体签名：动作+结果 + 会话进展计数 + 后台任务状态。"""
        mgr = getattr(self.session, "tasks", None)
        tasks_sig: list[str] = []
        if mgr is not None:
            try:
                tasks_sig = sorted(f"{t.task_id}:{t.status}" for t in mgr.all())
            except Exception:  # noqa: BLE001
                tasks_sig = []
        payload = json.dumps(
            [sorted(step_pairs), self._evidence_snapshot(), tasks_sig],
            ensure_ascii=False,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _halt(self, step_pairs: list[str]) -> None:
        """判定无进展：停止继续执行工具，要求模型摊开已知事实并收口。"""
        self._halted = True
        self._halt_steps = 0
        # 把这一步还没被硬拒绝的指纹也拉进拒绝集：再来就是"原样重提"
        for p in step_pairs:
            fp = p.split("#", 1)[0]
            if fp:
                self._refused.add(fp)
        self.on_event(
            f"\n[!] 连续 {self.noprog.limit} 步动作与结果完全相同、没有新增发现，"
            f"判定为原地打转，已停止继续执行工具。"
        )
        known = "；".join(self.ledger.facts[-5:]) or "（台账里没有新增事实）"
        self.history.append(
            {
                "role": "user",
                "content": (
                    "[系统提示] 本轮已连续多步**没有任何推进**：动作相同、结果相同、"
                    "发现/资产/任务状态都没变。工具调用已被停止执行。\n"
                    f"已知事实：{known}\n"
                    "现在只能做两件事之一：① 给出**真正不同**的下一步——"
                    "必须说清它和上面已失败动作的差别（不同入口/不同认证态/"
                    "不同参数维度），否则不要提；② 直接给结论：已确认的问题、"
                    "未能验证的部分、建议人工跟进的方向。不再需要调用任何工具。"
                ),
            }
        )

    def _halt_summary(self) -> str:
        """模型在被停止后仍硬调工具时，由代码直接给出一份收口结论。"""
        s = self.ledger.stats()
        facts = "；".join(self.ledger.facts[-5:]) or "（本轮没有取得新的确认事实）"
        failed = "；".join(
            f"{k.split('|', 1)[0]}（{v}）" for k, v in list(self.ledger.failed.items())[-5:]
        ) or "（无）"
        self.on_event("\n[!] 停止后仍在调用工具，直接收尾。")
        return (
            "【已停止重复探索】连续多步动作与结果完全相同，没有新增发现，"
            "继续调用只会在原地打转。\n"
            f"- 已执行 {s['calls']} 次工具调用，其中失败/被拦 {s['failed']} 个方法\n"
            f"- 已确认事实：{facts}\n"
            f"- 已失败方法：{failed}\n"
            "- 未解决：上述失败方法覆盖的入口尚未拿到有效证据；"
            "需要换一个真正不同的角度（不同认证态/不同参数维度/人工介入）\n"
            "- 建议：先用 artifact_query / list_tasks 复核已有结果，"
            "再决定是否换目标面或交人工跟进。"
        )

    # ── 上下文管理 ────────────────────────────────────────────────

    def _trim(self) -> None:
        """裁剪历史。

        不能简单地"从头扔 N 条"：``role=tool`` 的消息必须紧跟发出它的
        那条带 ``tool_calls`` 的 assistant，否则协议上不合法，服务端会 400。
        所以切割点必须落在一个非 tool 消息上。
        """
        self.history = self._repair_tool_history(self.history)
        chars = sum(len(json.dumps(m, ensure_ascii=False)) for m in self.history)
        while len(self.history) > MAX_HISTORY_MSGS or chars > MAX_HISTORY_CHARS:
            if len(self.history) < 4:
                break
            cut = 1
            while cut < len(self.history) and self.history[cut].get("role") == "tool":
                cut += 1
            dropped = self.history[:cut]
            if not dropped:
                break
            self.history = self.history[cut:]
            chars -= sum(len(json.dumps(m, ensure_ascii=False)) for m in dropped)

    @staticmethod
    def _repair_tool_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """补齐恢复/中断后缺失的 tool 消息，保证 OpenAI 消息协议完整。"""
        repaired: list[dict[str, Any]] = []
        pending: dict[str, None] = {}

        def flush() -> None:
            for call_id in pending:
                repaired.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": "【工具结果缺失】该调用在上次会话中未完成。",
                    }
                )
            pending.clear()

        for raw in history or []:
            if not isinstance(raw, dict):
                continue
            msg = dict(raw)
            role = msg.get("role")
            if role == "assistant" and msg.get("tool_calls"):
                flush()
                repaired.append(msg)
                for call in msg.get("tool_calls") or []:
                    if isinstance(call, dict) and call.get("id"):
                        pending[str(call["id"])] = None
                continue
            if role == "tool" and pending:
                call_id = str(msg.get("tool_call_id") or "")
                if call_id in pending:
                    repaired.append(msg)
                    pending.pop(call_id, None)
                continue
            if pending:
                flush()
            repaired.append(msg)
        flush()
        return repaired

    def reset(self) -> None:
        self.history.clear()
        self._call_fingerprints.clear()
        self._skeletons.clear()
        self._refused.clear()
        self._refused_skel.clear()
        self.ledger.reset()
        self.noprog.reset()
        self._halted = False
        self._halt_steps = 0
        self._skip_counts.clear()
        tasks = getattr(self.session, "tasks", None)
        self._task_cursor = int(getattr(tasks, "cursor", 0) or 0)

    def restore(self, history: list[dict[str, Any]]) -> int:
        """回填历史对话，返回实际载入的消息数。

        用于会话恢复：模型得记得上次聊过什么，否则「恢复」只是恢复了资产，
        它会对已经排除过的方向重新试探。
        """
        self.history = self._repair_tool_history(
            [dict(m) for m in (history or []) if isinstance(m, dict)]
        )
        self._trim()
        self._call_fingerprints.clear()
        self._skeletons.clear()
        self._refused.clear()
        self._refused_skel.clear()
        # 恢复后不要重放历史事件：游标对齐到当前水位，之后只消费新变化。
        # 探索台账同理——旧会话的动作记录没有恢复（历史消息里仍在），
        # 从头开始记，避免把"昨天失败过"当成"这一轮已经试过"。
        self.ledger.reset()
        self.noprog.reset()
        self._halted = False
        self._halt_steps = 0
        self._skip_counts.clear()
        tasks = getattr(self.session, "tasks", None)
        self._task_cursor = int(getattr(tasks, "cursor", 0) or 0)
        return len(self.history)

    def history_len(self) -> int:
        return len(self.history)


def _duplicate_text(name: str, args: dict[str, Any], dup, attempt: int) -> str:
    """跨轮重复动作的回灌说明：**没有执行**，先要一个理由。

    措辞必须回答"为什么没执行、上次结果是什么、要怎样才能重做"——
    只说"重复"模型会换个说法再提一次（换说法不改参数，指纹不变）。
    """
    text = (
        f"[未执行：重复动作] {_describe(name, args)} 在第 {dup.round} 轮已经执行过，"
        f"状态「{dup.status}」"
        + (f"，摘要：{dup.summary}" if dup.summary else "")
        + "。相同工具 + 相同参数再执行一次，拿到的是同一个结果，不会带来新信息。\n"
        "要继续请二选一：① 说明**新证据或参数差异**（换路径/换方法/换认证态/"
        "换字典/换端口段），换了参数就是新动作，会正常执行；"
        "② 若已无新角度，基于已有结果直接给结论。"
    )
    if attempt >= 2:
        text += (
            f"\n注意：这是本轮第 {attempt} 次提出同一个动作。"
            "再次提出相同参数会被判定为原地打转，本轮工具调用将被停止。"
        )
    return text


def _halted_text(name: str, args: dict[str, Any]) -> str:
    """已判定无进展后，工具调用一律不执行的说明。"""
    return (
        "[已停止执行] 本轮已判定无进展（连续多步动作与结果完全相同、没有新增发现），"
        f"{_describe(name, args)} 不会再执行。\n"
        "现在只需要给结论：已确认的问题、未能验证的部分、建议人工跟进的方向。"
        "如果确有**真正不同**的下一步（不同入口/认证态/参数维度），"
        "请在文本里说明它和其它尝试的差别，由用户决定是否开始新一轮。"
    )


def _parse_args(raw: str, tools: list[dict[str, Any]], name: str) -> tuple[dict[str, Any], str]:
    """解析工具参数。

    模型偶尔会给出半截 JSON（尤其在被截断时）。这时**不要**直接放弃，
    尝试补全；实在不行就退化成空参数并把情况说明放进返回值，
    让模型看到"我传错了"而不是莫名其妙地失败。
    """
    s = (raw or "").strip()
    if not s:
        return {}, ""
    try:
        d = json.loads(s)
        return (d if isinstance(d, dict) else {}), ""
    except json.JSONDecodeError:
        pass

    # 常见两种可救的情况：代码块包裹、被截断缺少右花括号
    if s.startswith("```"):
        s = s.strip("`")
        s = s[4:] if s[:4].lower() == "json" else s
        s = s.strip()
        try:
            d = json.loads(s)
            return (d if isinstance(d, dict) else {}), ""
        except json.JSONDecodeError:
            pass
    if s.startswith("{"):
        for tail in ("}", "}}", '"}', '""}'):
            try:
                d = json.loads(s + tail)
                return (d if isinstance(d, dict) else {}), "（参数被截断，已尝试补全）"
            except json.JSONDecodeError:
                continue
    return {}, "（参数 JSON 解析失败，已按空参数执行）"


def _describe(name: str, args: dict[str, Any]) -> str:
    """把一次工具调用渲染成一行终端提示。"""
    if name == "external_tool":
        tool = args.get("tool", "?")
        rest = args.get("args") or []
        arr = " ".join(str(x) for x in rest) if isinstance(rest, list) else str(rest)
        return f"{tool} {arr}".strip()
    if not args:
        return name
    bits = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > 60:
            sv = sv[:57] + "…"
        bits.append(f"{k}={sv}")
    return f"{name}({', '.join(bits)})"


def _indent(text: str, prefix: str = "     ") -> str:
    lines = (text or "").rstrip().splitlines() or [""]
    return "\n".join(prefix + ln for ln in lines[:40]) + (
        f"\n{prefix}…（后续 {len(lines)-40} 行省略）" if len(lines) > 40 else ""
    )


__all__ = ["Agent"]
