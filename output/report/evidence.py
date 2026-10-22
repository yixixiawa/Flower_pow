"""Burp 式报文转写：把一条证据还原成**可复现的请求** + 响应概要。

原 ``report.py`` 的证据段。markdown 产物的 PoC 段要用，所以抽出来共享。

**请求与响应的待遇不一样，这是有意的**：

* **请求包完整展示**。复现靠的是请求——少一个 Cookie、少一个路径参数，
  粘贴到 Burp Repeater 就是另一个请求，等于没给出可复现的东西。
* **响应只给大概内容**。完整响应可能几百 KB（文件下载 / JSON 导出），
  全贴进来报告就没法看了；判断漏洞成立看的是「请求 + 命中了什么特征」，
  不是响应全文。完整响应永远在证据文件里，报告只需要指路。
"""

from __future__ import annotations

from pathlib import Path
from core.rawmsg import looks_like_analysis


# 响应在报告内的展示上限——「大概内容」够用即可
_TRANSCRIPT_CAP = 6000
# 请求包的防爆上限。请求是我们自己构造的，字节数可控（唯一例外是 multipart
# 上传），正常远小于 64KB；留这个上限只是防止异常大的请求把报告撑爆。
_REQ_CAP = 65536

def _artifact_path(ev, outdir: Path) -> Path | None:
    """把 ``ev.artifact`` 解析成可读路径。相对路径相对 output_dir。

    自定义证据目录落在 output_dir 之外时 artifact 会是绝对路径，
    那也是我们自己写出的文件，允许读。其他形态（``..`` 穿行等）
    一律不读——快照文件可能被人手改过。
    """
    art = (getattr(ev, "artifact", "") or "").strip()
    if not art:
        return None
    p = Path(art)
    if p.is_absolute():
        return p if p.suffix in (".http", ".body", ".txt") else None
    if ".." in p.parts:
        return None
    return outdir / p


def _looks_like_analysis(text: str, description: str) -> bool:
    """见 :func:`core.rawmsg.looks_like_analysis`。

    保留这个名字是因为 report 内部两处调用读起来更顺；判据只有一份，
    回填（core/backfill.py）用的是同一个函数。
    """
    return looks_like_analysis(text, description)


def _burp_transcript(
    ev, outdir: Path, description: str = ""
) -> tuple[str, str, str]:
    """构造 Burp Suite 式的请求 + 响应对。返回 (请求, 响应, 备注)。

    **请求完整、响应概要**——理由见模块 docstring：复现依赖请求的每一个字节，
    而响应只需要看出「命中了什么特征」。

    数据源优先级：**artifact 落盘文件 > Evidence 字段重建**。
    落盘文件里是命中那一刻的完整报文（见 detectors/base.py 的
    persist_evidence）；手工登记或旧快照没有 artifact 时，用
    request_line / response_headers / full_body / body_excerpt
    重建，响应体是截断版时如实标注——交付物里"完整"二字不能靠省略达成。

    ``description`` 是这条发现的说明文字，只用于一件事：识别旧快照里
    「说明被误存进 body_excerpt」的情况，避免伪造出一段假响应。
    """
    req = (ev.request_line or "").strip("\n")
    if not req:
        lines = [f"{ev.method or 'GET'} {ev.url} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in ev.request_headers.items()]
        req = "\n".join(lines)

    resp, note = "", ""
    art = _artifact_path(ev, outdir)
    if art is not None and art.is_file():
        try:
            raw = art.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        if raw:
            if "[RESPONSE]" in raw:
                req_file, resp = raw.split("[RESPONSE]", 1)
                req = req_file.strip("\n") or req
                resp = resp.strip("\n")
            else:
                resp = raw.strip("\n")
            note = f"完整原始报文：`{ev.artifact}`"

    if not resp:
        lines: list[str] = []
        if ev.status_code is not None:
            lines.append(f"HTTP/1.1 {ev.status_code}")
        lines += [f"{k}: {v}" for k, v in ev.response_headers.items()]
        body = ev.full_body or ev.body_excerpt or ""
        if body and description and _looks_like_analysis(body, description):
            # 这是"说明冒充响应体"的旧数据：宁可响应体留空并说明，
            # 也不能让分析文字看起来像服务端返回。
            body = ""
            note = "（旧版登记格式把说明文字存成了响应体，已剔除——那不是真实响应）"
        if body:
            lines += ["", body]
        resp = "\n".join(lines)
        kept = len(body.encode("utf-8", "replace"))
        # 只有**确实少了内容**才提示：回填的正文与声明字节数常差几个字节
        # （行尾换行、预览截断点），差 1 字节就写一句"截断版"是噪音。
        if body and ev.body_size > kept + 16:
            note = (
                f"响应体为截断版（原始 {ev.body_size} 字节，仅前 {kept} 字节）；"
                f"未落盘完整报文——要完整响应需重新请求一次"
            )

    def _cap_request(text: str) -> str:
        """请求包在报告内**完整展示**，只在超过防爆上限时才截。

        刻意不给请求套那个 6000 字符的展示上限——那个上限是给响应的。
        请求被砍掉尾部，等于交付了一份「粘进 Repeater 也复现不出同样结果」
        的东西，那比明确写"这里被截了"更糟。
        """
        if len(text) <= _REQ_CAP:
            return text
        return (
            text[:_REQ_CAP]
            + f"\n…（请求包超过 {_REQ_CAP} 字符，仅展示前段；完整内容见上方报文文件）"
        )

    def _cap_response(text: str) -> str:
        """响应只展示**大概内容**——够看出命中了什么特征即可。"""
        if len(text) <= _TRANSCRIPT_CAP:
            return text
        return (
            text[:_TRANSCRIPT_CAP]
            + f"\n…（响应体较长，报告内仅展示前 {_TRANSCRIPT_CAP} 字符；"
            f"完整内容见上方报文文件）"
        )

    return _cap_request(req), _cap_response(resp), note

