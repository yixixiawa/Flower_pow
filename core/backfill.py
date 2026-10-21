"""从会话历史里把**真实报文**回填到发现上。

解决什么问题
------------
``record_finding`` 早期版本把说明文字截到 500/400/800 字符，还把它同时
当成 ``body_excerpt``——报告里于是出现「说明被截断」+「分析文字摆在
``<<< 响应:`` 位置」两种毛病。那些数据的**源头已经丢了**（快照里存的
就是截断版），但当时的真实请求/响应往往还在会话历史的工具结果里：

* 模型用 ``http_request`` 验证漏洞 → 工具结果里带着请求行、状态码、
  响应头、正文预览（``ToolRunner._h_http_request`` 的输出格式）；
* 这些结果随对话历史一起落盘，恢复会话时能重新读到。

所以"恢复会话 → 回填 → 重新导出"能把老报告补成有真实报文的版本，
而不是只能重跑一遍扫描。

两条纪律
--------
1. **只补不覆盖**：发现上已有的字段一律不动（那是原始记录），只填空的。
   唯一的例外是「说明文字冒充响应体」——那份 ``body_excerpt`` 不是响应，
   留着只会让报告的 PoC 段伪造证据，必须让位给历史里的真报文。
2. **不做模糊匹配**：URL 必须精确相等（主机 + 路径 + **排序后的 query**）。
   匹配不上就不填——把别的接口的响应挂到这条漏洞上，比没有响应更糟。
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.rawmsg import looks_like_analysis, parse_tool_result

# 工具结果里正文预览的长度上限（_h_http_request 里是 1500 字符），
# 回填后按发现正文上限截断即可
_BODY_CAP = 8000
_FULL_BODY_CAP = 65536

# 只有这些工具的结果里带**完整响应语义**（状态码 + 头 + 正文）
_RESPONSE_TOOLS = ("http_request",)


def _tool_results(history: list[dict]) -> list[tuple[str, str, str]]:
    """把历史里成对的 ``tool_call`` 与 ``tool`` 结果配对，返回 (工具名, 入参 JSON, 结果)。

    历史里函数调用与结果分属两条消息，靠 ``tool_call_id`` 关联；
    关联不上的结果直接跳过（宁缺勿错）。
    """
    calls: dict[str, dict] = {}
    out: list[tuple[str, str, str]] = []
    for msg in history or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role == "assistant":
            for tc in msg.get("tool_calls") or []:
                if isinstance(tc, dict):
                    calls[str(tc.get("id"))] = tc.get("function") or {}
        elif role == "tool":
            fn = calls.get(str(msg.get("tool_call_id"))) or {}
            out.append((
                str(fn.get("name") or ""),
                str(fn.get("arguments") or ""),
                str(msg.get("content") or ""),
            ))
    return out


def collect_exchanges(history: list[dict]) -> list[dict]:
    """按**发生顺序**收集历史里所有可识别的真实请求/响应。"""
    found: list[dict] = []
    for name, _args, content in _tool_results(history):
        if name not in _RESPONSE_TOOLS:
            continue
        parsed = parse_tool_result(content)
        if parsed:
            found.append(parsed)
    return found


def _keys(url: str) -> tuple[str, str]:
    """给一个 URL 算两级匹配键：完整 URL（含 query）/ 主机+路径+同序 query。

    **刻意不做"忽略 query 的同路径匹配"**：实测踩到了——``/download``
    的响应取决于 ``?file=`` 的值，``proc/self/environ`` 那条发现会被挂上
    ``etc/passwd`` 的响应。把 A 接口的响应挂到 B 漏洞上比没有响应更糟：
    报告里的 PoC 就成了伪造证据。

    query 参数按名字排序后比较，避免 ``?a=1&b=2`` 与 ``?b=2&a=1`` 被当成两条。
    """
    raw = (url or "").strip()
    if not raw:
        return "", ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlparse(raw)
    except ValueError:
        return raw.lower().rstrip("/"), ""
    query = "&".join(sorted(p for p in (u.query or "").split("&") if p))
    base = f"{(u.hostname or '').lower()}{(u.path or '/').rstrip('/') or '/'}"
    return f"{base}?{query}" if query else base, f"{base}#{query}"


def _needs_fill(ev, description: str = "") -> bool:
    """这条证据缺不缺**真实**响应。已有真实响应的发现一个字段都不动。

    三种算缺：
    * 根本没有状态码；
    * 一条响应痕迹都没有（无头、无体、无落盘文件）；
    * **响应体是旧版塞进来的说明文字**——老 ``record_finding`` 把模型写的
      研判同时存进了 ``body_excerpt``。那种"响应"比留空更糟：报告的
      ``<<< 响应:`` 位置会出现一段中文分析，读起来像服务端真的返回了它。
      既然历史里有真响应，就该把它换掉（渲染端的 ``_looks_like_analysis``
      只能把假体清空，清完这条就成了"有请求没响应"——白白浪费了证据）。
    """
    if ev is None:
        return False
    if ev.status_code is None:
        return True
    if _bogus_body(ev, description):
        return True
    return not (ev.response_headers or ev.body_excerpt or ev.artifact)


def _bogus_body(ev, description: str) -> bool:
    """``body_excerpt`` 是不是说明文字冒充的响应体。"""
    body = str(getattr(ev, "body_excerpt", "") or "")
    return bool(body) and looks_like_analysis(body, description or "")


def backfill_findings(session, evidence_dir: str = "") -> dict:
    """把会话历史里的真实报文补进发现，返回统计。

    返回 ``{"exchanges": n, "candidates": n, "filled": n, "items": [...]}``：
    * ``exchanges`` —— 历史里识别出的真实请求数（能否回填的上限）
    * ``candidates`` —— 缺响应、看起来可回填的发现数
    * ``filled`` —— 实际补上的条数
    """
    from detectors.base import persist_evidence

    result = getattr(session, "result", None)
    if result is None:
        return {"exchanges": 0, "candidates": 0, "filled": 0, "items": []}

    exchanges = collect_exchanges(getattr(session, "history", []) or [])
    index: dict[str, dict] = {}
    for ex in exchanges:
        full, _alt = _keys(str(ex.get("url") or ""))
        if full:
            index[full] = ex          # 后出现的覆盖先出现的：取最近一次

    filled: list[dict] = []
    candidates = 0
    for f in result.findings:
        ev = getattr(f, "evidence", None)
        desc = str(getattr(f, "description", "") or "")
        if not _needs_fill(ev, desc):
            continue
        candidates += 1
        full, _alt = _keys(getattr(f, "matched_at", "") or ev.url)
        ex = index.get(full)
        if not ex:
            continue

        # 只填空字段：已有的（哪怕是截断版）都是当时的原始记录。
        # 例外是"说明冒充响应体"——那份体不是响应，必须让位给真报文。
        if _bogus_body(ev, desc):
            ev.body_excerpt = ""
            ev.full_body = ""
        if ev.status_code is None:
            ev.status_code = ex.get("status_code")
        if not ev.response_headers:
            ev.response_headers = dict(ex.get("headers") or {})
        body = str(ex.get("body") or "")
        if not ev.body_excerpt and body:
            ev.body_excerpt = body[:_BODY_CAP]
        if not ev.body_size:
            ev.body_size = int(ex.get("body_size") or len(body))
        if not ev.elapsed_ms:
            ev.elapsed_ms = int(ex.get("elapsed_ms") or 0)
        if not ev.request_line:
            ev.request_line = (
                f"{ex.get('method') or 'GET'} {ex.get('url')} HTTP/1.1"
            )
        if not ev.full_body and body:
            ev.full_body = body[:_FULL_BODY_CAP]
        persist_evidence(evidence_dir, ev, require_status=False)
        filled.append({
            "poc_id": f.poc_id,
            "url": f.matched_at,
            "status": ev.status_code,
            "truncated": bool(ex.get("body_truncated")),
            "artifact": ev.artifact,
        })

    if filled:
        n_cut = sum(1 for it in filled if it.get("truncated"))
        tail = (
            f"，其中 {n_cut} 条正文是当时的预览截断版（已如实标注）"
            if n_cut else "，正文为完整响应"
        )
        result.notes.append(
            f"原始报文回填：从会话历史补入 {len(filled)} 条发现的请求/响应"
            f"（来源：当轮的 http_request 结果{tail}）"
        )
    return {
        "exchanges": len(exchanges),
        "candidates": candidates,
        "filled": len(filled),
        "items": filled,
    }


__all__ = ["collect_exchanges", "backfill_findings"]
