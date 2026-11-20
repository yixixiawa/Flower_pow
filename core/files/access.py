"""本地文件访问——**唯一的入口是用户显式给出的路径**。

这条链上刻意没有的东西，比有的东西更重要：

* 没有 ``scan()`` / ``walk()`` / ``glob()`` —— 不存在"遍历用户磁盘"的代码
  路径。第一阶段只做"用户点名一个文件，我读它"。能做目录得靠第二阶段
  的显式白名单（``roots``），且必须由用户先授权目录。
* 没有"按内容发现更多文件"的能力 —— 文件内容里出现的路径不会被自动
  打开（否则一份 README 里写满 ``../../.ssh/id_rsa`` 就等于把钥匙递出去）。
* 不落副本 —— 只记路径 + SHA256 + 元数据。把用户文件复制进项目 data
  目录等于把密钥复制一份到可能被分享的目录里；读的时候按 SHA256 复检，
  变了就报"内容已变化"，让用户重新授权/重新分析。

授权判据（顺序固定，先拒绝后允许）：

1. 非空、无 NUL、不是 UNC、不含 ``..`` 段；
2. 逐段检查符号链接/目录联接（Windows 的 junction 也拦——``is_symlink``
   对它返回 False，只靠它就等于没检查）；
3. 必须是**已存在的普通文件**（目录留给第二阶段的目录白名单）；
4. 不超过单文件字节上限；不超过本会话文件数量上限；
5. 解析期再卡时间（见 :mod:`core.files.parser`）。
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from core.files.parser import DEFAULT_MAX_CHARS, ParsedFile, parse_bytes
from core.fsops import is_reparse_point

# 单文件上限：接口文档/源码远用不到 8 MB；再大多半是数据导出或打包文件，
# 塞进对话上下文只会撑爆模型，且解析也慢。
MAX_FILE_BYTES = 8 * 1024 * 1024
# 单会话文件数上限：防止"一次拖 200 个文件"把上下文和内存一起打满
MAX_FILES_PER_SESSION = 32
# 单文件解析时间上限（秒）
MAX_PARSE_SECONDS = 5.0

_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# 系统目录：即使被显式点名也不读。
# 理由不是"怕用户看自己的文件"，而是这些目录里的内容与"分析用户文档/源码"
# 的用途无关，却包含大量与本机其他用户/服务相关的信息（SAM、hosts、
# 服务配置、驱动）。第一阶段不做全盘访问，边界画在这里最省事也最难绕。
_DENY_ROOTS: tuple[str, ...] = tuple(
    str(Path(p).resolve())
    for p in (
        os.environ.get("SystemRoot", r"C:\Windows"),
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        "/etc", "/proc", "/sys", "/dev", "/boot", "/private/etc",
    )
    if p and Path(p).exists()
)
# 认证类头/键的值（脱敏用）
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|private[_-]?key)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
    re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
)


class FileAccessDenied(Exception):
    """文件访问被结构性闸门拒绝。**这是正常返回值，不是异常路径。**"""


def redact_secrets(text: str) -> str:
    """把疑似凭证的**值**替换成 ``***``，键名保留（便于定位问题）。

    用途：摘要、审计、错误信息、终端预览。文件正文进模型上下文时不做
    改动（用户自己有责任），但任何"会被留存/展示给别人看"的派生文本都
    必须先过这一层。
    """
    out = text or ""
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}***", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}***", out)
    for pat in _SECRET_PATTERNS[2:]:
        out = pat.sub("***", out)
    return out


@dataclass(slots=True)
class Limits:
    """资源上限。测试里会调小它们来验证"超限被拒"。"""

    max_bytes: int = MAX_FILE_BYTES
    max_files: int = MAX_FILES_PER_SESSION
    parse_seconds: float = MAX_PARSE_SECONDS
    max_chars: int = DEFAULT_MAX_CHARS


@dataclass(slots=True)
class FileRecord:
    """一个被授权文件的事实记录（**不含内容**，内容按需重读）。"""

    file_id: str
    session_id: str
    name: str
    path: str
    size: int
    mime: str
    sha256: str
    added_at: float = field(default_factory=time.time)
    source: str = "user"

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id, "session_id": self.session_id,
            "name": self.name, "path": self.path, "size": self.size,
            "mime": self.mime, "sha256": self.sha256,
            "added_at": self.added_at, "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileRecord | None":
        try:
            return cls(
                file_id=str(d.get("file_id") or ""),
                session_id=str(d.get("session_id") or ""),
                name=str(d.get("name") or ""),
                path=str(d.get("path") or ""),
                size=int(d.get("size") or 0),
                mime=str(d.get("mime") or ""),
                sha256=str(d.get("sha256") or ""),
                added_at=float(d.get("added_at") or time.time()),
                source=str(d.get("source") or "user"),
            )
        except (TypeError, ValueError):
            return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FileAccess:
    """一个会话的文件授权台账 + 按需读取。

    ``session_id`` 是隔离维度：另一个会话拿这个 ``file_id`` 来读，会被
    明确拒绝（不是"查不到就返回空"）。并发场景下每个会话各持一个实例，
    上下文用 :func:`core.files.context.use_files` 绑定，互不污染。
    """

    def __init__(
        self,
        session_id: str,
        *,
        limits: Limits | None = None,
        records: list[FileRecord] | None = None,
    ) -> None:
        self.session_id = session_id or ""
        self.limits = limits or Limits()
        self._records: dict[str, FileRecord] = {}
        self._cache: dict[tuple[str, str], ParsedFile] = {}
        for rec in records or []:
            if rec.session_id != self.session_id:
                # 跨会话的记录一律丢弃：快照被手改/串用时不能顺着读过去
                continue
            self._records[rec.file_id] = rec

    # ── 查询 ──────────────────────────────────────────────────────
    def records(self) -> list[FileRecord]:
        return list(self._records.values())

    def get(self, file_id: str) -> FileRecord | None:
        return self._records.get(file_id or "")

    def __len__(self) -> int:
        return len(self._records)

    def to_dict(self) -> dict:
        return {"records": [r.to_dict() for r in self._records.values()]}

    # ── 授权 ──────────────────────────────────────────────────────
    def authorize(self, path: str | Path) -> FileRecord:
        """用户点名的文件 → 登记记录。**这是进入本会话的唯一入口。**"""
        raw = str(path or "").strip().strip('"').strip("'")
        if not raw:
            raise FileAccessDenied("路径不能为空：请给出具体文件路径（如 ./doc/api.md）")
        if "\x00" in raw:
            raise FileAccessDenied("路径含 NUL 字节，拒绝")
        if raw.startswith("//") or raw.startswith("\\\\"):
            raise FileAccessDenied(f"拒绝 UNC / 网络路径（不在本机授权范围内）：{raw}")
        norm = raw.replace("\\", "/")
        if any(seg == ".." for seg in norm.split("/")):
            raise FileAccessDenied(
                f"路径含 ..（不允许相对跳转，请给出规范的绝对路径或当前目录下的相对路径）：{raw}"
            )
        if unquote(norm) != norm and any(
            seg == ".." for seg in unquote(norm).split("/")
        ):
            # %2e%2e 之类：解码后才看得出是穿越
            raise FileAccessDenied(f"路径编码后含 ..（编码穿越）：{raw}")

        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path(os.getcwd()) / p
        self._assert_no_links(p)

        if not p.exists():
            raise FileAccessDenied(f"文件不存在：{raw}")
        if p.is_dir():
            raise FileAccessDenied(
                f"这是目录，不是文件：{raw}（第一阶段只接受用户点名的单个文件）"
            )
        if not p.is_file():
            raise FileAccessDenied(f"不是普通文件（设备/管道等不支持）：{raw}")

        real = p.resolve()
        denied = self._deny_reason(real)
        if denied:
            raise FileAccessDenied(
                f"{denied}：{raw}（本工具不做系统目录访问，请指向用户自己的文档或源码）"
            )
        try:
            size = real.stat().st_size
        except OSError as exc:
            raise FileAccessDenied(f"无法读取文件状态：{raw}（{exc}）") from exc
        if size > self.limits.max_bytes:
            raise FileAccessDenied(
                f"文件超过大小上限（{size} 字节 > {self.limits.max_bytes} 字节）：{raw}"
            )

        data = self._read_bytes(real)
        digest = _sha256(data)

        # 幂等：同一路径同一内容重复授权不占额度、file_id 不变
        for rec in self._records.values():
            if rec.path == str(real) and rec.sha256 == digest:
                return rec

        if len(self._records) >= self.limits.max_files:
            raise FileAccessDenied(
                f"本会话文件数量已达上限（{self.limits.max_files} 个）："
                f"先用 /files --drop <id> 移除不再需要的文件"
            )

        rec = FileRecord(
            file_id=self._new_file_id(digest),
            session_id=self.session_id,
            name=real.name,
            path=str(real),
            size=size,
            mime=self._mime(real.name),
            sha256=digest,
        )
        self._records[rec.file_id] = rec
        return rec

    # ── 读取 ──────────────────────────────────────────────────────
    def read(self, file_id: str) -> ParsedFile:
        """按 file_id 读取并解析。**内容变化 / 越权 / 解析失败都明确报错。**"""
        rec = self._records.get(file_id or "")
        if rec is None:
            if file_id and any(r.file_id == file_id for r in self._records.values()):
                raise FileAccessDenied(f"file_id {file_id} 不属于本会话（跨会话读取被拒绝）")
            raise FileAccessDenied(
                f"file_id {file_id!r} 未授权：请先用 /read <路径> 授权该文件"
            )
        cached = self._cache.get((rec.file_id, rec.sha256))
        if cached is not None:
            return cached

        p = Path(rec.path)
        self._assert_no_links(p)
        if not p.is_file():
            raise FileAccessDenied(f"授权时的文件已不存在或已不是文件：{rec.name}")
        data = self._read_bytes(p)
        digest = _sha256(data)
        if digest != rec.sha256:
            raise FileAccessDenied(
                f"文件内容已变化（sha256 {rec.sha256[:12]}… → {digest[:12]}…）："
                f"请重新 /read 授权后再分析（旧计划随之失效）"
            )
        parsed = parse_bytes(
            rec, data,
            max_chars=self.limits.max_chars,
            deadline=time.monotonic() + max(0.05, self.limits.parse_seconds),
        )
        self._cache[(rec.file_id, rec.sha256)] = parsed
        return parsed

    def verify(self, file_id: str) -> tuple[bool, str]:
        """按磁盘现状复算 SHA256。返回 (是否与授权时一致, 现状摘要)。

        删除判定、计划执行前都要用它——**计划绑定的是内容，不是路径**。
        """
        rec = self._records.get(file_id or "")
        if rec is None:
            return False, f"file_id {file_id!r} 未授权"
        p = Path(rec.path)
        try:
            if is_reparse_point(p) or not p.is_file():
                return False, f"{rec.name} 已不存在或已变成链接"
            data = self._read_bytes(p)
        except OSError as exc:
            return False, f"{rec.name} 无法读取：{exc}"
        digest = _sha256(data)
        if digest != rec.sha256:
            return False, f"{rec.name} 内容已变化（{rec.sha256[:12]}… → {digest[:12]}…）"
        return True, f"{rec.name} 未变化（{digest[:12]}…）"

    # ── 清理 ──────────────────────────────────────────────────────
    def forget(self, file_id: str) -> bool:
        rec = self._records.pop(file_id or "", None)
        if rec is None:
            return False
        self._cache = {k: v for k, v in self._cache.items() if k[0] != rec.file_id}
        return True

    def clear(self) -> int:
        n = len(self._records)
        self._records.clear()
        self._cache.clear()
        return n

    # ── 内部 ──────────────────────────────────────────────────────
    def _read_bytes(self, p: Path) -> bytes:
        try:
            size = p.stat().st_size
        except OSError as exc:
            raise FileAccessDenied(f"无法读取文件状态：{exc}") from exc
        if size > self.limits.max_bytes:
            raise FileAccessDenied(
                f"文件超过大小上限（{size} 字节 > {self.limits.max_bytes} 字节）"
            )
        try:
            with open(p, "rb") as fh:
                # 多读 1 字节：读的过程中被追加也能发现
                data = fh.read(self.limits.max_bytes + 1)
        except OSError as exc:
            raise FileAccessDenied(f"读取失败：{type(exc).__name__}: {exc}") from exc
        if len(data) > self.limits.max_bytes:
            raise FileAccessDenied(
                f"文件超过大小上限（读取时已超过 {self.limits.max_bytes} 字节）"
            )
        return data

    @staticmethod
    def _deny_reason(real: Path) -> str:
        """系统目录一律拒绝（显式点名也不行）。返回拒绝理由或空串。"""
        try:
            text = str(real)
        except (OSError, ValueError):
            return "路径无法规范化"
        for root in _DENY_ROOTS:
            if text == root or text.startswith(root.rstrip("\\/") + os.sep):
                return f"系统目录不在授权范围内（{root}）"
        return ""

    @staticmethod
    def _assert_no_links(p: Path) -> None:
        """逐段检查符号链接/目录联接（``Path.is_symlink`` 挡不住 junction）。"""
        try:
            anchor = Path(p.anchor) if p.anchor else Path("")
        except (OSError, ValueError):
            raise FileAccessDenied(f"路径无法解析：{p}") from None
        cur = anchor
        parts = list(p.parts)
        for part in parts[1:]:
            cur = cur / part
            if is_reparse_point(cur):
                raise FileAccessDenied(
                    f"路径包含符号链接/目录联接（{part}）："
                    f"请给出真实文件路径，不接受链接跳转"
                )

    def _new_file_id(self, digest: str) -> str:
        base = digest[:8]
        if base not in self._records:
            return base
        for i in range(1, 99):
            cand = f"{digest[:8]}-{i}"
            if cand not in self._records:
                return cand
        return f"{digest[:8]}-{int(time.time())}"

    @staticmethod
    def _mime(name: str) -> str:
        ext = Path(name).suffix.lower()
        mapped = {
            ".md": "text/markdown", ".markdown": "text/markdown",
            ".json": "application/json", ".yaml": "application/yaml",
            ".yml": "application/yaml", ".csv": "text/csv",
            ".ts": "text/plain", ".tsx": "text/plain", ".py": "text/x-python",
            ".js": "text/javascript", ".docx":
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".pdf": "application/pdf",
        }
        return mapped.get(ext) or (mimetypes.guess_type(name)[0] or "application/octet-stream")
