"""本地文件解析——把用户授权的文件变成**带位置信息**的文本。

设计原则（每条都对应需求里的一条硬要求）：

* **解析失败就说失败**。``ParsedFile.error`` 非空即"没解析成功"，
  调用方不得把它当读数成功——坏 JSON / 坏编码 / 缺 PDF 库 / 压缩炸弹 /
  超时，全部落在 ``error`` 上，且**保留原文**让人自己看。
* **位置可引用**。正文一律保留换行结构，:meth:`ParsedFile.numbered`
  出行号；docx 标段落、xlsx 标工作表与行、pdf 标页码。
* **不引新依赖**。docx/xlsx 本质是 zip + XML，直接读容器里的
  ``word/document.xml`` 与 ``xl/*``；PDF 需要解压流与字体映射，
  没有 ``pypdf`` 就明确说"解析器不可用"，而不是吐出乱码当正文。
* **压缩包先量体积再解压**。docx/xlsx 都是 zip：先看中央目录里的
  ``file_size`` 总和与单条压缩比，超限直接拒——不能"解压到内存里
  再发现太大"（那时进程可能已经被打爆）。
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# 单次解析进上下文的字符上限（超出截断并标注，不是静默丢）
DEFAULT_MAX_CHARS = 200_000
# zip 容器（docx/xlsx）解压后的总体积上限
MAX_ZIP_TOTAL = 32 * 1024 * 1024
# 条目数上限（防"一万个小文件"型炸弹）
MAX_ZIP_ENTRIES = 512
# 单条压缩比上限（1 MB 压成 1 KB 是 1000:1，正常文档远达不到）
MAX_ZIP_RATIO = 1000

# 纯文本类（按行读，行号有意义）
TEXT_KINDS: dict[str, str] = {
    ".txt": "text", ".log": "text", ".rst": "text",
    ".md": "markdown", ".markdown": "markdown",
    ".json": "json", ".jsonl": "json",
    ".yaml": "yaml", ".yml": "yaml",
    ".py": "code", ".js": "code", ".mjs": "code", ".cjs": "code",
    ".ts": "code", ".tsx": "code", ".jsx": "code",
    ".java": "code", ".go": "code", ".rs": "code", ".sh": "code",
    ".sql": "code", ".html": "code", ".htm": "code", ".css": "code",
    ".xml": "code", ".toml": "code", ".ini": "code", ".conf": "code",
    ".csv": "csv", ".tsv": "csv",
}
# 容器类（zip + XML）
ZIP_KINDS: dict[str, str] = {".docx": "docx", ".xlsx": "xlsx"}
# 需要外部解析器的
OPTIONAL_KINDS: dict[str, str] = {".pdf": "pdf"}

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


@dataclass(slots=True)
class ParsedFile:
    """一次解析的结果。``error`` 非空 = 没解析成功（读数失败）。"""

    file_id: str
    kind: str
    text: str = ""
    lines: int = 0
    pages: int = 0
    truncated: bool = False
    sha256: str = ""
    notes: list[str] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.error

    def numbered(self, *, start: int = 1, limit: int = 0) -> str:
        """带行号的正文。``limit`` > 0 时只出前 N 行（预览用）。"""
        if not self.text:
            return ""
        out: list[str] = []
        for i, line in enumerate(self.text.splitlines(), start):
            if limit and i - start >= limit:
                out.append(f"    …（共 {self.lines} 行，已省略）")
                break
            out.append(f"{i:>5}| {line}")
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id, "kind": self.kind, "lines": self.lines,
            "pages": self.pages, "truncated": self.truncated,
            "sha256": self.sha256, "notes": list(self.notes), "error": self.error,
        }


def detect_kind(name: str) -> str:
    """按扩展名判定解析器。未知扩展名按纯文本尝试（读不了会报编码错误）。"""
    ext = Path(name or "").suffix.lower()
    return (
        TEXT_KINDS.get(ext)
        or ZIP_KINDS.get(ext)
        or OPTIONAL_KINDS.get(ext)
        or "text"
    )


# ── 文本解码 ────────────────────────────────────────────────────────


def decode_text(data: bytes) -> tuple[str, str, str]:
    """返回 (文本, 使用的编码, 错误)。三种编码都失败才算失败。"""
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(enc), enc, ""
        except (UnicodeDecodeError, LookupError):
            continue
    return "", "", (
        "无法解码为文本（尝试 utf-8-sig / utf-8 / gb18030 均失败）："
        "可能是二进制文件，或使用了其它编码"
    )


# ── zip 容器安全 ────────────────────────────────────────────────────


def check_zip_safe(zf: zipfile.ZipFile) -> str:
    """返回错误描述，空串表示安全。**在解压任何条目之前**调用。"""
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        return f"压缩包条目过多（{len(infos)} > {MAX_ZIP_ENTRIES}），拒绝解压"
    total = 0
    for info in infos:
        if info.file_size > MAX_ZIP_TOTAL:
            return (
                f"压缩包内单个条目解压后过大（{info.file_size} 字节 > "
                f"{MAX_ZIP_TOTAL}），疑似压缩炸弹"
            )
        total += info.file_size
        if total > MAX_ZIP_TOTAL:
            return f"压缩包解压后总体积过大（> {MAX_ZIP_TOTAL} 字节），疑似压缩炸弹"
        if info.compress_size and info.file_size / max(1, info.compress_size) > MAX_ZIP_RATIO:
            return (
                f"压缩包压缩比异常（{info.filename}："
                f"{info.file_size}/{info.compress_size}），疑似压缩炸弹"
            )
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            return f"压缩包内含越界路径条目（{info.filename}），拒绝解压"
    return ""


def _xml_text(xml: str, *, para_tag: str = "</w:p>") -> str:
    """XML → 纯文本：段落转换行，其余标签去掉，实体反转义。"""
    s = xml.replace(para_tag, "\n")
    s = s.replace("<w:tab/>", "\t").replace("<w:br/>", "\n")
    s = _TAG_RE.sub("", s)
    s = (
        s.replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&")
    )
    return _WS_RE.sub(" ", s)


# ── 各格式解析 ──────────────────────────────────────────────────────


def _parse_docx(data: bytes, out: ParsedFile) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        bad = check_zip_safe(zf)
        if bad:
            out.error = bad
            return
        try:
            xml = zf.read("word/document.xml").decode("utf-8", "replace")
        except KeyError:
            out.error = "不是有效的 docx：缺少 word/document.xml"
            return
    text = _xml_text(xml)
    paras = [p.strip() for p in text.splitlines() if p.strip()]
    out.text = "\n".join(paras)
    out.lines = len(paras)
    out.notes.append(f"共 {len(paras)} 段（按段落编号引用）")


def _parse_xlsx(data: bytes, out: ParsedFile) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        bad = check_zip_safe(zf)
        if bad:
            out.error = bad
            return
        names = zf.namelist()
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            sst = zf.read("xl/sharedStrings.xml").decode("utf-8", "replace")
            shared = [
                _xml_text(m.group(1))
                for m in re.finditer(r"<si>(.*?)</si>", sst, re.S)
            ]
        sheets = sorted(n for n in names if n.startswith("xl/worksheets/sheet"))
        if not sheets:
            out.error = "不是有效的 xlsx：缺少 xl/worksheets/sheet*.xml"
            return
        blocks: list[str] = []
        for sheet in sheets:
            xml = zf.read(sheet).decode("utf-8", "replace")
            rows = re.finditer(r'<row[^>]*r="(\d+)"[^>]*>(.*?)</row>', xml, re.S)
            lines: list[str] = []
            for rm in rows:
                rno = rm.group(1)
                cells: list[str] = []
                for cm in re.finditer(r"<c([^>]*)>(.*?)</c>", rm.group(2), re.S):
                    attrs, body = cm.group(1), cm.group(2)
                    vm = re.search(r"<v>(.*?)</v>", body, re.S)
                    if not vm:
                        continue
                    val = _xml_text(vm.group(1))
                    if 't="s"' in attrs:  # 共享字符串索引
                        try:
                            val = shared[int(val)]
                        except (ValueError, IndexError):
                            pass
                    cells.append(val)
                if cells:
                    lines.append(f"  行{rno}: " + " | ".join(cells))
            if lines:
                blocks.append(f"## {Path(sheet).stem}\n" + "\n".join(lines))
        out.text = "\n\n".join(blocks)
        out.lines = out.text.count("\n") + 1 if out.text else 0
        out.notes.append(f"共 {len(sheets)} 个工作表（按 工作表/行号 引用）")


def _parse_pdf(data: bytes, out: ParsedFile) -> None:
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError:
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except ImportError:
            out.error = (
                "缺少 PDF 解析器：未安装 pypdf（可 pip install pypdf 后重试）。"
                "本工具不会用乱码冒充 PDF 正文"
            )
            return
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = list(reader.pages)
    except Exception as exc:  # noqa: BLE001 - 第三方库的异常类型不稳定
        out.error = f"PDF 解析失败：{type(exc).__name__}: {exc}"
        return
    chunks: list[str] = []
    for i, page in enumerate(pages, 1):
        try:
            chunks.append(f"=== 第 {i} 页 ===\n{page.extract_text() or ''}")
        except Exception as exc:  # noqa: BLE001
            chunks.append(f"=== 第 {i} 页 ===\n（本页提取失败：{type(exc).__name__}）")
    out.text = "\n\n".join(chunks)
    out.pages = len(pages)
    out.lines = out.text.count("\n") + 1 if out.text else 0
    out.notes.append(f"共 {len(pages)} 页（按页码引用）")


def _parse_json(text: str, out: ParsedFile) -> None:
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        out.error = f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
        return
    out.notes.append("JSON 合法")


def _parse_yaml(text: str, out: ParsedFile) -> None:
    try:
        import yaml  # type: ignore
    except ImportError:
        out.notes.append("未安装 PyYAML：按纯文本处理，未做语法校验")
        return
    try:
        yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - yaml 的异常层级不稳定
        out.error = f"YAML 解析失败：{type(exc).__name__}: {exc}"
        return
    out.notes.append("YAML 合法（safe_load）")


def _parse_csv(text: str, out: ParsedFile) -> None:
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        out.error = f"CSV 解析失败：{exc}"
        return
    cols = max((len(r) for r in rows), default=0)
    out.notes.append(f"{len(rows)} 行 × 最多 {cols} 列（按行号引用）")


# ── 入口 ────────────────────────────────────────────────────────────


def parse_bytes(
    record,  # FileRecord（只用 name/file_id/sha256/size）
    data: bytes,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    deadline: float | None = None,
) -> ParsedFile:
    """把字节解析成 :class:`ParsedFile`。**任何失败都落在 ``error`` 上。**"""
    started = time.monotonic()
    kind = detect_kind(getattr(record, "name", "") or "")
    out = ParsedFile(
        file_id=getattr(record, "file_id", ""),
        kind=kind,
        sha256=getattr(record, "sha256", ""),
    )

    def timed_out() -> bool:
        return deadline is not None and time.monotonic() > deadline

    try:
        if timed_out():
            out.error = f"解析超时（超过 {1} 个时间片，已放弃）"
            return out
        if not data:
            out.notes.append("空文件（0 字节）：读取成功，但没有内容可解析")
            return out

        if kind in ("docx", "xlsx", "pdf"):
            if kind == "docx":
                _parse_docx(data, out)
            elif kind == "xlsx":
                _parse_xlsx(data, out)
            else:
                _parse_pdf(data, out)
            if timed_out() and out.ok:
                out.error = "解析超时：已停止并丢弃本次结果"
                out.text = ""
                return out
        else:
            text, enc, err = decode_text(data)
            if err:
                out.error = err
                return out
            out.notes.append(f"编码 {enc}")
            out.text = text
            if kind == "json":
                _parse_json(text, out)
            elif kind == "yaml":
                _parse_yaml(text, out)
            elif kind == "csv":
                _parse_csv(text, out)

        # 截断（结构解析完再截，保证摘要/合法性判断基于全文）
        if max_chars and len(out.text) > max_chars:
            out.text = out.text[:max_chars]
            out.truncated = True
            out.notes.append(
                f"内容超过 {max_chars} 字符，已截断（引用位置以截断前的行号为准）"
            )
        if not out.lines and out.text:
            out.lines = out.text.count("\n") + 1
        if out.ok and kind not in ("docx", "xlsx", "pdf") and not out.text.strip():
            out.notes.append("文件只有空白字符")
    except zipfile.BadZipFile:
        out.error = "不是有效的 zip 容器（docx/xlsx 本质是 zip）"
    except Exception as exc:  # noqa: BLE001 - 解析器的边界就是"不向上抛"
        out.error = f"解析失败：{type(exc).__name__}: {exc}"
    finally:
        out.elapsed = round(time.monotonic() - started, 4)
        if out.error:
            # 失败时保留原文（能解码的话），但把 text 标记为"仅供参考"
            if not out.text and kind not in ("docx", "xlsx", "pdf"):
                text, _enc, _err = decode_text(data)
                out.text = text
        out.lines = out.lines or (out.text.count("\n") + 1 if out.text else 0)
    return out
