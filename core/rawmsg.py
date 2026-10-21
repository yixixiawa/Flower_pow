"""原始 HTTP 报文的解析与清洗。

为什么不把这些小函数散在调用点
--------------------------------
「模型把一坨 Burp 风格文本粘进来」这件事有三个地方要处理：

1. ``record_finding`` —— 手工登记时要把它拆成
   ``request_line / request_headers / status_code / response_headers / body``，
   否则报告里只能原样堆一段文本；
2. ``core/backfill.py`` —— 从会话历史里把 ``http_request`` 的工具结果
   还原成同样的结构（那是另一种文本格式）；
3. ``output/report.py`` —— 渲染前要清掉模型顺手带进来的 Markdown 转义
   （从 Markdown 里复制粘贴，``\\``` 、``\\*`` 会一起带过来）。

一旦解析规则分散，三处就会各自漂移——报告里同一条发现换个入口就换个样子。

约定（宽松解析，宁可少认也不能把内容吞掉）
------------------------------------------
* 认不出来时返回 ``ok=False``，**原文照样保留**，由调用方决定怎么用；
* 绝不因为"格式不标准"丢字段：状态行缺失就只少状态码，正文永远留着；
* 不伪造：解析不到状态码就留 ``None``，不假设 200。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Markdown 里带反斜杠的转义：\` \* \_ \{ \} \[ \] \( \) \# \+ \- \. \! \|
_MD_ESCAPE = re.compile(r"\\([`*_{}\[\]()#+\-.!|>~])")

_REQ_LINE = re.compile(r"^(?P<m>[A-Za-z]{3,10})\s+(?P<t>\S+)\s+HTTP/(?P<v>\d(?:\.\d)?)\s*$")
_STATUS_LINE = re.compile(r"^HTTP/(?P<v>\d(?:\.\d)?)\s+(?P<code>\d{3})\b(?P<reason>.*)$")
_HEADER_LINE = re.compile(r"^(?P<k>[!#$%&'*+\-.^_`|~0-9A-Za-z]+)\s*:\s*(?P<v>.*)$")


def unescape_md(text: str) -> str:
    """清掉模型从 Markdown 复制粘贴时带进来的反斜杠转义。

    实测事故：模型把 payload 写成 ``\\`GET /x HTTP/1.1\\```，
    报告里就原样出现 ``\\``` ——交付物读起来像坏了。
    只处理 Markdown 的转义字符集，不动 ``C:\\Windows`` 这类路径
    （反斜杠后面是字母，不在集合里）。

    另外统一剥掉行尾多余空格：报告里那些行尾双空格是 Markdown 硬换行，
    但在代码块里毫无意义，只会在 diff 里制造噪音。
    """
    if not text:
        return text or ""
    t = _MD_ESCAPE.sub(r"\1", text)
    return "\n".join(ln.rstrip() for ln in t.splitlines())


def looks_like_analysis(text: str, description: str) -> bool:
    """判断 ``text`` 是不是**说明文字**而不是真实响应体。

    为什么要这个判断：老版本的 ``record_finding`` 把模型写的说明同时塞进了
    ``body_excerpt``（见该工具的历史实现）。渲染时若直接信任 ``body_excerpt``，
    报告就会出现「``<<< 响应:`` 下面是一段中文分析」——读者会以为那是服务端
    真实返回，实际是模型的话。**把分析文字摆在响应位置比留空更糟**：
    它看起来像证据。

    放在这里而不是 ``output/report.py``：回填（``core/backfill.py``）也要用
    同一个判据来决定"这条记录的响应体是不是假的、要不要重新找"，
    两处各写一份必然漂移。
    """
    a = re.sub(r"\s+", "", text or "")
    b = re.sub(r"\s+", "", description or "")
    if not a or not b:
        return False
    if a == b:
        return True
    head = min(len(a), len(b), 200)
    return head >= 40 and a[:head] == b[:head]


@dataclass
class RawRequest:
    """解析出来的请求。``ok=False`` 表示这不像一条原始报文。"""

    ok: bool = False
    line: str = ""
    method: str = ""
    target: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def as_text(self) -> str:
        parts = [self.line or f"{self.method or 'GET'} {self.target or '/'} HTTP/1.1"]
        parts += [f"{k}: {v}" for k, v in self.headers.items()]
        if self.body:
            parts += ["", self.body]
        return "\n".join(parts)


@dataclass
class RawResponse:
    """解析出来的响应。``ok=False`` 时 ``body`` 可能是有价值的原文。"""

    ok: bool = False
    status_code: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


def split_exchange(text: str) -> tuple[str, str]:
    """把「请求 + 响应」混在一起的文本切成两半。

    支持三种常见分隔（模型从 Burp/终端里粘贴的形态不定）：
    本项目的 ``[RESPONSE]``、Burp 风格的 ``>>> 请求:`` / ``<<< 响应:``、
    以及最朴素的——第一个 ``HTTP/1.1 200`` 状态行。
    切不开时返回 ``(text, "")``：**宁可整段当请求，也不能丢**。
    """
    t = unescape_md(text or "")
    if not t.strip():
        return "", ""
    if "[RESPONSE]" in t:
        a, b = t.split("[RESPONSE]", 1)
        return a.strip("\n"), b.strip("\n")
    m = re.search(r"^[ \t]*(?:<<<|>>>)[^\n]*响应[^\n]*$", t, flags=re.MULTILINE)
    if m:
        return t[: m.start()].strip("\n"), t[m.end():].strip("\n")
    lines = t.splitlines()
    # 首行就是状态行 → 整段是一份纯响应（模型只贴了响应，最常见的情形）
    if _STATUS_LINE.match(lines[0].strip()):
        return "", t
    for i, ln in enumerate(lines):
        if i and _STATUS_LINE.match(ln.strip()):
            return "\n".join(lines[:i]).strip("\n"), "\n".join(lines[i:]).strip("\n")
    return t, ""


def _split_head_body(lines: list[str]) -> tuple[list[str], str]:
    """按第一个空行切出头部与正文。没有空行时**全部当头部**。"""
    for i, ln in enumerate(lines):
        if not ln.strip():
            return lines[:i], "\n".join(lines[i + 1:])
    return lines, ""


def parse_raw_request(text: str) -> RawRequest:
    """解析一条原始请求（Burp 式：请求行 + 头 + 空行 + 体）。"""
    t = unescape_md(text or "")
    if not t.strip():
        return RawRequest()
    lines = t.splitlines()
    m = _REQ_LINE.match(lines[0].strip())
    if not m:
        return RawRequest()
    head, body = _split_head_body(lines[1:])
    headers: dict[str, str] = {}
    for ln in head:
        hm = _HEADER_LINE.match(ln.strip())
        if hm:
            # 同名头保留首次：Cookie 之类的重复头在报告里合并展示即可
            headers.setdefault(hm.group("k").lower(), hm.group("v").strip())
    return RawRequest(
        ok=True,
        line=lines[0].strip(),
        method=m.group("m").upper(),
        target=m.group("t"),
        headers=headers,
        body=body,
    )


def parse_raw_response(text: str) -> RawResponse:
    """解析一条原始响应（状态行 + 头 + 空行 + 体）。

    状态行缺失时 ``ok=False`` 但 ``body`` 仍是**整段原文**——
    模型常常只贴响应体，那是有效证据，不能因为没抄状态行就丢掉。
    """
    t = unescape_md(text or "")
    if not t.strip():
        return RawResponse()
    lines = t.splitlines()
    sm = _STATUS_LINE.match(lines[0].strip())
    if not sm:
        return RawResponse(ok=False, body=t.strip("\n"))
    head, body = _split_head_body(lines[1:])
    headers: dict[str, str] = {}
    for ln in head:
        hm = _HEADER_LINE.match(ln.strip())
        if hm:
            headers[hm.group("k").lower()] = hm.group("v").strip()
    return RawResponse(
        ok=True,
        status_code=int(sm.group("code")),
        reason=sm.group("reason").strip(),
        headers=headers,
        body=body,
    )


# ── 会话历史里的工具结果（回填用） ────────────────────────────────
# 格式由 ToolRunner._h_http_request 生成，形如：
#   GET https://host/path
#   状态码：200  耗时：93ms  正文大小：259B
#   关键响应头：
#     server: nginx/1.29.0
#   正文（截断 1500 字符）：          ← 只有预览真被切了才写「截断」
#   <body>
_RESULT_URL = re.compile(r"^(?P<m>[A-Za-z]{3,10})\s+(?P<u>\S+)\s*$")
_RESULT_META = re.compile(
    r"状态码[：:]\s*(?P<code>\d+).*?耗时[：:]\s*(?P<ms>\d+)\s*ms.*?"
    r"正文大小[：:]\s*(?P<size>\d+)\s*B",
    re.DOTALL,
)
_RESULT_BODY_MARK = re.compile(r"^正文[^\n]*$", flags=re.MULTILINE)
# 标记行里的数字：正文（截断 1500 字符） / 正文（188 字符）
_RESULT_BODY_SAID = re.compile(r"截断\s*(\d+)\s*字符")
# 正文预览的长度上限，与 ToolRunner._h_http_request 里的切片保持一致
_RESULT_BODY_PREVIEW = 1500


def parse_tool_result(text: str) -> dict:
    """解析 ``http_request`` 的工具结果，返回可回填到 ``Evidence`` 的字段。

    返回 ``{}`` 表示这不是一条可识别的请求结果——调用方据此跳过，
    而不是猜。``body_truncated`` 为真时说明我们手上的正文**不是完整的**，
    报告需要如实标注（不能拿残页冒充证据）。
    """
    t = (text or "").strip()
    if not t:
        return {}
    lines = t.splitlines()
    m = _RESULT_URL.match(lines[0].strip())
    if not m:
        return {}
    meta = _RESULT_META.search(t)
    if not meta:
        return {}
    url = m.group("u")
    if not url.lower().startswith(("http://", "https://")):
        # 只认绝对 URL：相对的路径片段没法定位是哪台主机
        return {}
    headers: dict[str, str] = {}
    body = ""
    bm = _RESULT_BODY_MARK.search(t)
    if bm:
        head_part = t[: bm.start()]
        body = t[bm.end():].strip("\n")
        for ln in head_part.splitlines():
            hm = _HEADER_LINE.match(ln.strip())
            if hm:
                headers[hm.group("k").lower()] = hm.group("v").strip()
    declared = int(meta.group("size"))
    present_bytes = len(body.encode("utf-8", "replace"))
    present_chars = len(body)
    marker = bm.group(0) if bm else ""
    # 「不完整」有两条来路，任一成立都要标：
    #
    # 1. 预览被工具切过。**不能只看「截断」两个字**——早期实现无论切没切
    #    都写「正文（截断 N 字符）」，照字面判会把完整响应全标成残缺版
    #    （真实会话里 15 条完整响应全中招）。要看那个 N 是什么：
    #      * 旧格式 N = **切片前**的全长 → N > 实际手数 才说明真被切；
    #      * 新格式只在真被切时才写，N = 切片后的长度（恒等于上限）。
    # 2. 服务端声明的字节数 > 我们拿到的字节数 → 上游（探针 4KB 上限）
    #    就只存了前一段。
    #
    # 两处都留 16 的余量：正文做过 strip，行尾空白不计数。
    preview_cut = False
    cm = _RESULT_BODY_SAID.search(marker)
    if cm:
        said = int(cm.group(1))
        preview_cut = said > present_chars + 16 or (
            said >= _RESULT_BODY_PREVIEW and present_chars >= _RESULT_BODY_PREVIEW
        )
    body_truncated = bool(bm) and (
        preview_cut or declared > present_bytes + 16
    )
    return {
        "method": m.group("m").upper(),
        "url": url,
        "status_code": int(meta.group("code")),
        "elapsed_ms": int(meta.group("ms")),
        "headers": headers,
        "body": body,
        "body_size": declared,
        "body_truncated": body_truncated,
    }


__all__ = [
    "RawRequest", "RawResponse",
    "unescape_md", "split_exchange", "looks_like_analysis",
    "parse_raw_request", "parse_raw_response", "parse_tool_result",
]
