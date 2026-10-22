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
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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

    # ── 提示词 ────────────────────────────────────────────────────

    def tool_names(self) -> list[str]:
        out = [t["function"]["name"] for t in self.tools if t["function"]["name"] != "external_tool"]
        avail = [p.spec.key for p in self.probes if p.found]
        if any(t["function"]["name"] == "external_tool" for t in self.tools):
            out.append("external_tool" + (f"（{', '.join(avail)}）" if avail else "（本机无可用外部工具）"))
        return out

    def _system(self) -> dict[str, str]:
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
                extra=self.llm.tool_note if getattr(self.llm, "tool_note", "") else "",
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
        final = ""
        step = 0

        while True:
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

            if error and not content and not tool_calls:
                self.on_event(f"\n[!] 模型调用失败：{error}")
                self.history.append({"role": "assistant", "content": f"（调用失败：{error}）"})
                return f"（调用失败：{error}）"

            if not tool_calls:
                if content:
                    self.on_event("")
                self.history.append({"role": "assistant", "content": content})
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
            for c in norm_calls:
                args, parse_note = _parse_args(c["arguments"], self.tools, c["name"])
                fp = self._fingerprint(c["name"], args)
                skel = self._skeleton(c["name"], args)
                # ── 硬拒绝：警告过之后仍原样重调 → 请求根本不发出 ──
                # 协议要求每个 tool_call 必须有结果，所以拒绝说明以 tool
                # 消息回灌，模型能读到"为什么拒、接下来能干什么"。
                if fp in self._refused or (skel and skel in self._refused_skel):
                    self.on_event(f"\n  ⛔ 已拒绝重复执行（无进展死循环）")
                    self.history.append(
                        {
                            "role": "tool",
                            "tool_call_id": c["id"],
                            "content": _refusal_text(c["name"], args),
                        }
                    )
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
                result = await self.runner.execute(c["name"], args, self.session)
                self.on_event(_indent(result))
                self.history.append(
                    {"role": "tool", "tool_call_id": c["id"], "content": result}
                )

            final = content
            step += 1

            if looped or skeleton_looped:
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

    # ── 上下文管理 ────────────────────────────────────────────────

    def _trim(self) -> None:
        """裁剪历史。

        不能简单地"从头扔 N 条"：``role=tool`` 的消息必须紧跟发出它的
        那条带 ``tool_calls`` 的 assistant，否则协议上不合法，服务端会 400。
        所以切割点必须落在一个非 tool 消息上。
        """
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

    def reset(self) -> None:
        self.history.clear()
        self._call_fingerprints.clear()
        self._skeletons.clear()
        self._refused.clear()
        self._refused_skel.clear()

    def restore(self, history: list[dict[str, Any]]) -> int:
        """回填历史对话，返回实际载入的消息数。

        用于会话恢复：模型得记得上次聊过什么，否则「恢复」只是恢复了资产，
        它会对已经排除过的方向重新试探。
        """
        self.history = [dict(m) for m in (history or []) if isinstance(m, dict)]
        self._trim()
        self._call_fingerprints.clear()
        self._skeletons.clear()
        self._refused.clear()
        self._refused_skel.clear()
        return len(self.history)

    def history_len(self) -> int:
        return len(self.history)


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
