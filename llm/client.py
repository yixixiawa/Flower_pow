"""第三方 LLM 接入层（OpenAI 兼容协议）。

覆盖 DeepSeek / OpenAI / vLLM / Ollama 等所有兼容 ``/v1/chat/completions``
的服务——换厂商只需改 ``base_url`` 与 ``model``。

三个任务
--------
1. :meth:`LLMClient.rerank_pocs` —— RAG 召回后的LLM 重排。
2. :meth:`LLMClient.triage` —— 拿真实 HTTP 证据降误报。
3. :meth:`LLMClient.write_report` —— 生成中文交付报告。

可靠性约定
----------
**任何失败都必须静默降级**，绝不让 LLM 挂掉整个扫描：
所有方法在异常时返回空结果 /空字符串，由上层走"无AI 路径"。
JSON 解析用三级兜底（直接解析 → 抠代码块 → 截取花括号区间）。
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from typing import Any

from core.config_loader import LLMConfig
from core.state import Finding, ScanResult
from llm import prompt as P
from llm.models import ROLE_DEEP, ROLE_FAST, ModelSpec, for_role, resolve
from kb.retriever import Retrieval

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

# 流式对话的 max_tokens 下限。cfg.max_tokens（默认 2048）是给短问答准备的，
# Agent 轮次经常要列十几条发现，实测 2048 会在中途被静默截断。
STREAM_MIN_TOKENS = 8192

# 判定"服务端不支持 tools 参数"的关键词。各网关报错文案不统一，
# 只能靠关键字兜底；宁可多认几个，也不要让对话直接卡死。
_TOOL_UNSUPPORTED_HINTS = (
    "tools", "tool_choice", "function", "not supported", "unsupported",
    "unknown parameter", "unrecognized", "invalid_request",
)


def _is_tools_unsupported(exc: Exception) -> bool:
    """判断异常是否属于"这个服务端不吃 tools 参数"。"""
    blob = f"{type(exc).__name__}: {exc}".lower()
    code = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if code not in (None, 400, 422):
        # 401/403/429/5xx 是别的问题，摘掉 tools 重试也不会好
        return False
    return any(h in blob for h in _TOOL_UNSUPPORTED_HINTS)


def extract_json(text: str) -> dict[str, Any] | None:
    """从模型输出里稳健地抠出 JSON——三级兜底。"""
    if not text:
        return None
    raw = text.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    if m := _JSON_FENCE.search(raw):
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


class LLMClient:
    """OpenAI 兼容客户端，按任务角色选模型。"""

    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self._client: Any = None
        self.available = bool(cfg.enabled and cfg.api_key)
        # 统计调用次数与 token 消耗，报告里可见
        self.calls = 0
        self.errors: list[str] = []
        self.total_ms = 0
        # 服务端是否支持 function calling。**不能假设**——不同网关（自建
        # vLLM、老版本代理）对 tools 参数的处理不一致，有的直接 400。
        # 第一次失败后置 False，后续自动退回"纯文本"模式，让对话不至于中断。
        self.supports_tools = True
        self.tool_note = ""
        # 模型解析：旧名会在配置层被换成官方名，这里再解析一次是防御性的
        # ——client 也可能被直接构造（测试、脚本），不经过 load_config。
        self.spec, self._model_warn = resolve(cfg.model)
        self.deep_spec: ModelSpec | None = None
        if cfg.deep_model:
            self.deep_spec, _ = resolve(cfg.deep_model)

    @property
    def client(self) -> Any:
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(
                api_key=self.cfg.api_key,
                base_url=self.cfg.base_url,
                timeout=self.cfg.timeout,
                max_retries=self.cfg.max_retries,
            )
        return self._client

    def model_for(self, role: str) -> str:
        """按任务角色给出实际要发的 model 名。"""
        return for_role(self.cfg.model, self.cfg.deep_model, role)

    def _extra(self, role: str) -> dict[str, Any]:
        """构造厂商扩展参数。

        ``thinking`` 与 ``reasoning_effort`` 不是 OpenAI 标准字段，属于
        **厂商扩展**——发给不支持它的网关（vLLM、部分代理）可能导致 400。
        所以这里按模型能力画像决定发不发，而不是无条件带上。
        """
        model = self.model_for(role)
        spec, _ = resolve(model)
        if not spec.supports_thinking:
            return {}
        if self.cfg.disable_thinking:
            return {"thinking": {"type": "disabled"}}
        return {
            "thinking": {"type": "enabled"},
            "reasoning_effort": self.cfg.reasoning_effort,
        }

    def ask(
        self,
        system: str,
        user: str,
        max_tokens: int | None = None,
        role: str = ROLE_FAST,
    ) -> str:
        """发起一次对话。异常向上抛给调用方做降级。

        ``role`` 决定用主模型还是深度模型（见 :mod:`llm.models` 的角色说明）。
        """
        started = time.perf_counter()
        self.calls += 1
        try:
            resp = self.client.chat.completions.create(
                model=self.model_for(role),
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=self.cfg.temperature,
                max_tokens=max_tokens or self.cfg.max_tokens,
                extra_body=self._extra(role),
            )
            # **必须检查 finish_reason。** 达到 max_tokens 时 OpenAI 兼容
            # 接口不报错，只是把 finish_reason 置为 "length" 并返回**被截断的**
            # 半截内容。报告这种长输出最容易命中——静默返回半份报告，
            # 交付出去才发现「结论章没了」，比直接失败更难发现。
            finish = getattr(resp.choices[0], "finish_reason", "") or ""
            text = resp.choices[0].message.content or ""
            if finish == "length":
                self.errors.append(
                    f"输出被 max_tokens={max_tokens or self.cfg.max_tokens} 截断"
                    f"（得到 {len(text)} 字符）"
                )
                raise RuntimeError(
                    f"LLM 输出被截断（finish_reason=length，"
                    f"max_tokens={max_tokens or self.cfg.max_tokens}）"
                )
            return text
        finally:
            self.total_ms += int((time.perf_counter() - started) * 1000)

    def _safe_ask(
        self, system: str, user: str, max_tokens: int | None = None,
        role: str = ROLE_FAST,
    ) -> dict[str, Any] | None:
        """带错误记录的调用。失败返回 None，不抛。"""
        if not self.available:
            return None
        try:
            return extract_json(self.ask(system, user, max_tokens, role))
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            self.errors.append(msg)
            return None

    # ── 0. 流式对话（Agent 用）─────────────────────────────────────
    def stream_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        role: str = ROLE_FAST,
        max_tokens: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """流式对话，逐块吐出文本与工具调用。

        产出的事件（``dict``，靠 ``type`` 区分）::

            {"type": "text",       "text": "增量文本"}
            {"type": "tool_calls", "calls": [{id, name, arguments}]}
            {"type": "done",       "content": "完整文本", "tool_calls": [...]}
            {"type": "error",      "message": "..."}

        为什么要自己累积 tool_calls
        ---------------------------
        OpenAI 协议把一次工具调用**拆成多个 chunk** 下发：第一块给 ``id`` 和
        函数名，后续块只追加 ``arguments`` 的字符串片段。不按 ``index`` 拼装，
        拿到的就是一地碎片——参数永远是半截 JSON，解析必然失败。

        ``max_tokens`` 默认放大
        ---------------------
        不传时用 ``max(cfg.max_tokens, STREAM_MIN_TOKENS)``。
        ``cfg.max_tokens`` 是给短问答准备的（默认 2048），而Agent 的输出
        经常是「列20 条发现 + 每条含URL/证据/修复建议」这种长文本——
        用 2048 会在中途被**静默**截断（接口只把 finish_reason 置 length），
        实测表现为报告写到一半开始重复「## 四、未测项」这类标题。
        """
        if not self.available:
            yield {"type": "error", "message": "LLM 未配置（缺少 API Key）"}
            return

        if max_tokens is None:
            max_tokens = max(self.cfg.max_tokens, STREAM_MIN_TOKENS)

        use_tools = bool(tools) and self.supports_tools
        started = time.perf_counter()
        self.calls += 1

        stream = None
        try:
            stream = self._open_stream(messages, tools if use_tools else None, role, max_tokens)
        except Exception as exc:  # noqa: BLE001
            if use_tools and _is_tools_unsupported(exc):
                # 服务端不吃 tools 参数 → 摘掉工具重试一次，并把原因记下来
                self.supports_tools = False
                self.tool_note = (
                    f"服务端不接受 tools 参数（{type(exc).__name__}），"
                    f"已退回纯文本对话模式。工具调用能力由模型自身决定。"
                )
                try:
                    stream = self._open_stream(messages, None, role, max_tokens)
                    self.errors.append(f"tools 不被支持：{type(exc).__name__}: {exc}")
                except Exception as exc2:  # noqa: BLE001
                    self.errors.append(f"{type(exc2).__name__}: {exc2}")
                    yield {"type": "error", "message": f"{type(exc2).__name__}: {exc2}"}
                    return
            else:
                self.errors.append(f"{type(exc).__name__}: {exc}")
                yield {"type": "error", "message": f"{type(exc).__name__}: {exc}"}
                return

        parts: list[str] = []
        acc: dict[int, dict[str, str]] = {}
        truncated = False
        try:
            for chunk in stream:
                if not getattr(chunk, "choices", None):
                    continue
                choice = chunk.choices[0]
                # 流式下也要检查 finish_reason：达到 max_tokens 时不报错，
                # 只是把最后一块的 finish_reason 置为 length。不检查的话，
                # 模型会拿到半截内容，而上层还以为它是完整的。
                if getattr(choice, "finish_reason", None) == "length":
                    truncated = True
                delta = choice.delta
                text = getattr(delta, "content", None)
                if text:
                    parts.append(text)
                    yield {"type": "text", "text": text}
                for tc in getattr(delta, "tool_calls", None) or []:
                    slot = acc.setdefault(
                        int(getattr(tc, "index", 0) or 0),
                        {"id": "", "name": "", "arguments": ""},
                    )
                    if getattr(tc, "id", None):
                        slot["id"] = tc.id
                    fn = getattr(tc, "function", None)
                    if fn is not None:
                        if getattr(fn, "name", None):
                            slot["name"] += fn.name
                        if getattr(fn, "arguments", None):
                            slot["arguments"] += fn.arguments
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"流式中断：{type(exc).__name__}: {exc}")
            yield {"type": "error", "message": f"流式中断：{type(exc).__name__}: {exc}"}
        finally:
            self.total_ms += int((time.perf_counter() - started) * 1000)

        if truncated:
            # 不静默——写进 errors 让用户/上层看到「这轮输出不全」
            self.errors.append(
                f"流式输出被 max_tokens={max_tokens} 截断"
                f"（得到 {sum(len(p) for p in parts)} 字符）"
            )
            yield {
                "type": "error",
                "message": (
                    f"输出达到 max_tokens={max_tokens} 上限被截断，内容不完整。"
                    f"请分批处理（例如一次只分析 3-5 个目标），"
                    f"或调大 config.yaml 的 max_tokens。"
                ),
            }
            return

        calls = [acc[i] for i in sorted(acc)]
        if calls:
            yield {"type": "tool_calls", "calls": calls}
        yield {"type": "done", "content": "".join(parts), "tool_calls": calls}

    def _open_stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        role: str,
        max_tokens: int | None,
    ) -> Any:
        kw: dict[str, Any] = {
            "model": self.model_for(role),
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": max_tokens or self.cfg.max_tokens,
            "stream": True,
            "extra_body": self._extra(role),
        }
        if tools:
            kw["tools"] = tools
            kw["tool_choice"] = "auto"
        return self.client.chat.completions.create(**kw)

    # ── 1. RAG 重排 ──────────────────────────────────────────────
    def rerank_pocs(
        self, target: str, query: str, retrievals: list[Retrieval]
    ) -> dict[str, float]:
        """返回 ``{poc_id: score}``。失败返回空 dict（上层保留向量排序）。"""
        if not self.available or not retrievals:
            return {}
        profile = P.render_profile(
            [],
            [{"kind": "query", "value": query[:400]}] if query else [],
        )
        user = P.render_rerank(target, query, retrievals)
        data = self._safe_ask(P.RERANK_SYSTEM, user, max_tokens=2000)
        scores = (data or {}).get("scores")
        if not isinstance(scores, list):
            return {}

        valid = {r.poc.id for r in retrievals}
        out: dict[str, float] = {}
        for row in scores:
            if not isinstance(row, dict):
                continue
            pid = str(row.get("id") or "")
            if pid not in valid:      # 模型幻觉出不存在��� id → 丢弃
                continue
            try:
                out[pid] = max(0.0, min(1.0, float(row.get("score", 0.0))))
            except (TypeError, ValueError):
                continue
        return out

    # ── 2. 降误报研判 ────────────────────────────────────────────
    def triage(self, findings: list[Finding]) -> dict[str, dict[str, Any]]:
        """返回 ``{f"{poc_id}#{idx}": {verdict, confidence, rationale}}``。"""
        if not self.available or not findings:
            return {}
        data = self._safe_ask(
            P.TRIAGE_SYSTEM, P.render_triage(findings), max_tokens=4000,
            role=ROLE_FAST,
        )
        rows = (data or {}).get("results")
        if not isinstance(rows, list):
            return {}

        out: dict[str, dict[str, Any]] = {}
        for r in rows:
            if not isinstance(r, dict) or not r.get("key"):
                continue
            verdict = str(r.get("verdict", "needs_manual"))
            if verdict not in {"true_positive", "false_positive", "needs_manual"}:
                verdict = "needs_manual"
            try:
                conf = max(0.0, min(1.0, float(r.get("confidence", 0.0))))
            except (TypeError, ValueError):
                conf = 0.0
            out[str(r["key"])] = {
                "verdict": verdict,
                "confidence": conf,
                "rationale": str(r.get("rationale", ""))[:400],
            }
        return out

    @staticmethod
    def apply_triage(
        findings: list[Finding], verdicts: dict[str, dict[str, Any]]
    ) -> tuple[list[Finding], list[Finding]]:
        """把研判结果写回 findings。返回 ``(确认列表, 被过滤列表)``。"""
        confirmed: list[Finding] = []
        rejected: list[Finding] = []
        for idx, f in enumerate(findings):
            v = verdicts.get(f"{f.poc_id}#{idx}")
            if not v:
                confirmed.append(f)
                continue
            f.verdict = v["verdict"]
            f.confidence = v["confidence"]
            f.rationale = v["rationale"]
            if v["verdict"] == "true_positive":
                f.confirmed = True
                confirmed.append(f)
            elif v["verdict"] == "false_positive":
                f.confirmed = False
                rejected.append(f)
            else:
                f.confirmed = True
                f.tags = list({*f.tags, "needs-manual"})
                confirmed.append(f)
        return confirmed, rejected

    # ── 3. 报告生成 ──────────────────────────────────────────────
    # 报告正文里的「占位/评述」特征。它们出现过就说明模型把任务理解成
    #「审稿」而不是「写稿」——这类输出必须丢弃，走模板报告。
    _META_PATTERNS = re.compile(
        r"(证据已充分|无需补充|以上内容|详见上文|从略|"
        r"希望这份报告|请查收|如需.{0,6}随时|"
        r"^#{0,2}\s*(好的|以下是|我将|我已经))",
        re.MULTILINE,
    )

    def _report_ok(self, text: str, result: ScanResult) -> bool:
        """校验报告正文是否可用。

        三道检查，任一不过就返回 False 让上层走模板报告：
        1. 够长——太短说明模型没写开；
        2. 无占位语——出现「证据已充分」这类评述说明它把任务当成审稿；
        3. 章节齐——五个必需章节至少要出现三个，否则说明截断或跑题。
        """
        body = (text or "").strip()
        if len(body) < 200:
            return False
        if self._META_PATTERNS.search(body):
            return False
        required = ("测试目标", "风险概览", "发现详情")
        hit = sum(1 for k in required if k in body)
        if hit < 2:
            return False
        # 发现数与正文章节数的关系：3 条以上发现至少要有对应数量的三级标题，
        # 否则说明模型把发现「从略」了
        if len(result.findings) >= 3 and body.count("###") < 3:
            return False
        return True

    def write_report(self, result: ScanResult) -> str:
        """生成中文报告正文（Markdown）。失败返回空串→ 走模板报告。

        走 ``ROLE_DEEP``——报告需要归纳与文笔，是链路里最值得用强模型的一步。

        ``max_tokens`` 按发现数动态放大：固定 4000 在发现多时会被截断，
        而截断是**静默**的（接口只把 finish_reason 置为 length），
        交付出去才发现「结论章没了」。
        """
        if not self.available or not result.findings:
            return ""
        # 每条发现约 400 token + 固定框架 1500，留足余量
        budget = min(16000, 1500 + 400 * len(result.findings))
        try:
            text = self.ask(
                P.REPORT_SYSTEM, P.render_report(result),
                max_tokens=budget, role=ROLE_DEEP,
            )
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"{type(exc).__name__}: {exc}")
            return ""
        if not self._report_ok(text, result):
            self.errors.append(
                "报告正文校验未通过（疑似占位/截断/跑题），回退模板报告"
            )
            return ""
        return text

    # ── 4. 单条修复建议（可选增强）────────────────────────────────
    def suggest_fix(self, finding: Finding) -> str:
        if not self.available:
            return finding.remediation
        data = self._safe_ask(
            P.FIX_SUGGEST_SYSTEM, P.render_fix_suggest(finding), max_tokens=300,
            role=ROLE_FAST,
        )
        return str((data or {}).get("fix") or finding.remediation)

    def stats(self) -> dict[str, Any]:
        # 报告里要能看出"实际用了哪些模型"——配了 pro 但没生效时，
        # 这个字段是唯一的线索。
        #
        # 注意 ``served_by`` 是**每个模型各自的**服务方。只报一个会让
        # 多模型场景产生误读：主模型是 flash、深度模型是 pro 时，
        # 写死 "DeepSeek-V4.1-Flash" 会让人以为报告也是 flash 写的。
        detail = [{"name": self.spec.name, "served_by": self.spec.served_by}]
        if self.deep_spec is not None:
            detail.append(
                {"name": self.deep_spec.name, "served_by": self.deep_spec.served_by}
            )
        return {
            "model": self.cfg.model,
            "models": [d["name"] for d in detail],
            "detail": detail,
            # 单模型场景的便捷字段，保持向后兼容
            "served_by": self.spec.served_by,
            "calls": self.calls,
            "total_ms": self.total_ms,
            "errors": len(self.errors),
        }


def rerank_by_vector(retrievals: list[Retrieval]) -> list[Retrieval]:
    """LLM 不可用时的降级：直接按向量分排序。"""
    return sorted(retrievals, key=lambda r: r.score, reverse=True)