"""沙箱化的本地文件操作——给智能体「新建 / 修改 / 删除文件」的手，但关在产物目录里。

要解决什么
----------
报告导出过去每次都在生成**新文件**（``report_x_2026-10-12.md`` →
``_2.md`` → ``_3.md``）。改一轮、导一次，很快就堆出一串近似重复的报告，
用户还得猜哪份是最新的；智能体也没法"接着上一份改"，只能整篇重写。

所以补两件事：一是本模块（新建/读取/修改/删除），二是报告导出改成
**就地覆盖同一个文件**。

安全边界（这一层是唯一边界）
-----------------------------
模型可以要求写任意路径，所以约束必须落在代码里，不能指望提示词。
所有操作共用同一个 :meth:`FileSandbox.resolve`，五道结构性闸门：

1. **只能在 ``output_dir`` 内**。绝对路径、盘符、UNC、``..`` 一律拒绝，
   最后再用 ``resolve()`` 的结果做一次"必须在根之内"的校验（这一步同时挡住
   符号链接/junction 逃逸——链接会被解析成真实路径，落在根外就出不去）。
2. **只认白名单扩展名**。这里是**白名单不是黑名单**——黑名单永远漏
   （``.phtml``、``.xhtml``、``.shtml``、``.ps1xml``…）。而且这个沙箱的用途
   就是"写报告产物"，不是通用文件系统，白名单是能用结构说清楚的。
3. **不写目录、不删目录**，只对文件生效。删目录一条命令就能毁掉整个产物区，
   而工具本身没有任何场景需要它。
4. **原子写**（临时文件 + ``os.replace``），中途崩溃不会留下半个报告。
5. **精确编辑**（:meth:`FileSandbox.edit`）：要替换的片段出现次数与 ``count``
   不符就拒绝。含糊的替换比不改更糟——它可能悄悄改掉别处的同一段文字。

为什么读取也要关在里面
----------------------
读不关就等于钥匙漏了：``read_file("../../.env")`` 拿到 API Key，
再接一发 ``http_request`` 就出去了。所以读写删共用同一套路径校验。

和 ``readonly`` 的关系
----------------------
``scan.readonly`` 管的是**对目标**的写操作（上传、篡改），本模块管的是
**本地产物**。导报告本来就要写本地文件，在只读模式下也照跑，
所以这里不看 ``readonly``。想整体关掉用 ``scan.fs_ops_enabled``。
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# 允许写入的产物扩展名。**白名单**——黑名单永远漏（可执行/脚本的变体数不清），
# 而这个沙箱的用途是"写报告产物"，用白名单能一句话说清边界。
ALLOWED_EXTS: frozenset[str] = frozenset(
    {
        ".md", ".markdown", ".txt", ".rst",
        ".json", ".jsonl", ".csv", ".tsv", ".xml", ".yaml", ".yml",
        ".html", ".htm", ".svg",
        ".log", ".diff", ".patch", ".sarif", ".sql", ".mmd", ".puml",
    }
)

# Windows 保留设备名——写 ``con.md`` 之类会打到设备上而不是文件
_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# 单次写入上限：报告是给人读的，2 MB 足够；不设上限会被"写入一万条日志"拖死
MAX_WRITE_BYTES = 2 * 1024 * 1024
# 单次读取上限
MAX_READ_BYTES = 1 * 1024 * 1024
# 列目录上限
MAX_LIST = 200


class FileOpDenied(Exception):
    """文件操作被结构性闸门拒绝。**不是异常路径，是正常返回值**。"""


def is_reparse_point(p: Path) -> bool:
    """是不是符号链接**或目录联接**（Windows junction）。

    为什么不能用 ``Path.is_symlink()``：它在 Windows 上对**目录联接返回 False**
    ——而联接同样能把路径引到根外。实测：``Path.symlink_to(dir)`` 创建出来的东西
    ``is_symlink()`` 就是 False，只靠它检查等于没检查。

    改用 ``lstat`` + 重解析点属性：两种都算。
    """
    try:
        st = p.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and (attrs & flag))


@dataclass
class FileOp:
    """一次文件操作的审计记录。"""

    action: str          # write | edit | delete
    path: str            # 相对 output_dir 的路径
    bytes: int = 0
    detail: str = ""

    def line(self) -> str:
        size = f"，{self.bytes} 字节" if self.bytes else ""
        extra = f"，{self.detail}" if self.detail else ""
        return f"{self.action} {self.path}{size}{extra}"


@dataclass
class FileSandbox:
    """把文件操作关在 ``root`` 里。"""

    root: Path
    log: list[FileOp] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    # ── 路径校验（五道闸门全在这一处）────────────────────────────
    def resolve(self, rel: str, *, must_exist: bool = False) -> Path:
        """把相对路径解析成绝对路径，越界一律拒绝。"""
        raw = (rel or "").strip()
        if not raw:
            raise FileOpDenied("路径不能为空")
        if "\x00" in raw:
            raise FileOpDenied("路径含 NUL 字节")

        norm = raw.replace("\\", "/")
        if norm.startswith("//"):
            raise FileOpDenied(f"拒绝 UNC 路径（网络路径不属于产物目录）：{rel}")
        if norm.startswith("/") or _DRIVE_RE.match(norm):
            raise FileOpDenied(
                f"只接受**相对 output 目录**的路径，收到绝对路径：{rel}"
            )

        parts = [p for p in norm.split("/") if p not in ("", ".")]
        if not parts:
            raise FileOpDenied("路径不能指向 output 目录本身")
        for part in parts:
            if part == "..":
                raise FileOpDenied(f"路径不能包含 ..（不允许越出产物目录）：{rel}")
            if ":" in part:
                raise FileOpDenied(f"路径片段含 ':'（Windows 数据流 / 非法名）：{part}")
            if part != part.rstrip(" ."):
                # Windows 会把 "a.md." 静默归一成 "a.md"，绕过扩展名白名单
                raise FileOpDenied(f"路径片段不能以点或空格结尾：{part!r}")
            if part.split(".")[0].lower() in _RESERVED:
                raise FileOpDenied(f"Windows 保留设备名：{part}")

        target = self.root
        for part in parts:
            target = target / part
            if is_reparse_point(target):
                # 符号链接/目录联接会把读写引到根外，必须在**解引用之前**拦住：
                # 等 resolve() 之后再比对就晚了（那时路径已经指到外面）。
                raise FileOpDenied(f"路径中包含符号链接/联接，已拒绝：{part}")

        resolved = target.resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise FileOpDenied(
                f"路径越出产物目录（{self.root}）：{rel}"
            )

        if must_exist:
            if not resolved.exists():
                raise FileOpDenied(f"文件不存在：{rel}")
            if not resolved.is_file():
                raise FileOpDenied(f"不是文件（本工具不操作目录）：{rel}")
        return resolved

    @staticmethod
    def check_ext(path: Path) -> None:
        ext = path.suffix.lower()
        if ext not in ALLOWED_EXTS:
            allow = " ".join(sorted(ALLOWED_EXTS))
            raise FileOpDenied(
                f"不允许写 {ext or '（无扩展名）'} 文件。"
                f"产物目录只接受这些格式：{allow}"
            )

    def rel(self, path: Path) -> str:
        try:
            return str(Path(path).resolve().relative_to(self.root))
        except ValueError:
            return str(path)

    # ── 列目录 ────────────────────────────────────────────────────
    def list_dir(self, rel: str = "") -> list[dict]:
        """列出产物目录下的文件与子目录（一层）。"""
        target = self.root if not (rel or "").strip() else self.resolve(rel)
        if not target.exists():
            raise FileOpDenied(f"路径不存在：{rel}")
        if not target.is_dir():
            raise FileOpDenied(f"不是目录：{rel}")
        out: list[dict] = []
        for p in sorted(target.iterdir()):
            if is_reparse_point(p):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            out.append(
                {
                    "name": p.name,
                    "path": self.rel(p),
                    "dir": p.is_dir(),
                    "size": st.st_size if p.is_file() else 0,
                    "mtime": st.st_mtime,
                }
            )
            if len(out) >= MAX_LIST:
                break
        return out

    # ── 读 ────────────────────────────────────────────────────────
    def read(self, rel: str, *, max_bytes: int = MAX_READ_BYTES) -> str:
        path = self.resolve(rel, must_exist=True)
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes]
            text = data.decode("utf-8", errors="replace")
            return text + f"\n\n…（已截断，文件共 {path.stat().st_size} 字节）"
        return data.decode("utf-8", errors="replace")

    # ── 写（新建 / 覆盖）──────────────────────────────────────────
    def write(self, rel: str, text: str, *, overwrite: bool = True) -> Path:
        path = self.resolve(rel)
        self.check_ext(path)
        raw = (text or "").encode("utf-8")
        if len(raw) > MAX_WRITE_BYTES:
            raise FileOpDenied(
                f"内容 {len(raw)} 字节超过上限 {MAX_WRITE_BYTES}；"
                "报告请分批写，或改用 export_report 生成"
            )
        existed = path.exists()
        if existed and not path.is_file():
            raise FileOpDenied(f"目标已存在且不是文件：{rel}")
        if existed and not overwrite:
            raise FileOpDenied(
                f"文件已存在：{rel}。确认要覆盖请显式传 overwrite=true"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, raw)
        self.log.append(
            FileOp(
                action="write",
                path=self.rel(path),
                bytes=len(raw),
                detail="覆盖" if existed else "新建",
            )
        )
        return path

    # ── 改（精确替换）────────────────────────────────────────────
    def edit(
        self,
        rel: str,
        old: str,
        new: str,
        *,
        count: int = 1,
    ) -> tuple[Path, int]:
        """把 ``old`` 替换成 ``new``。

        ``count=1``（默认）要求**恰好出现一次**；``count=0`` 表示全部替换。
        出现次数不符一律拒绝：含糊的替换比不改更糟——它可能悄悄改掉别处的
        同一段文字，而报告里这种"看起来改过了"最危险。
        """
        path = self.resolve(rel, must_exist=True)
        self.check_ext(path)
        if not old:
            raise FileOpDenied("old_text 不能为空")
        if old == new:
            raise FileOpDenied("old_text 与 new_text 相同，没有需要修改的内容")
        text = path.read_text(encoding="utf-8", errors="replace")
        found = text.count(old)
        if found == 0:
            raise FileOpDenied(
                f"在 {rel} 里没找到要替换的内容。请先 read_file 确认原文"
                f"（要替换的片段通常含空白/换行，逐字符照抄）"
            )
        if count and count > 0:
            if found != count:
                raise FileOpDenied(
                    f"要替换的片段在 {rel} 里出现了 {found} 次，"
                    f"与 count={count} 不符。"
                    f"请把 old_text 写得更长以唯一确定，或传 count=0 表示全部替换"
                )
            new_text = text.replace(old, new, count)
            done = count
        else:
            new_text = text.replace(old, new)
            done = found
        if len(new_text.encode("utf-8")) > MAX_WRITE_BYTES:
            raise FileOpDenied(f"修改后超过上限 {MAX_WRITE_BYTES} 字节，已放弃")
        _atomic_write(path, new_text.encode("utf-8"))
        self.log.append(
            FileOp(action="edit", path=self.rel(path), detail=f"替换 {done} 处")
        )
        return path, done

    # ── 删 ────────────────────────────────────────────────────────
    def delete(self, rel: str) -> tuple[Path, int]:
        """删除单个文件，返回 ``(路径, 原大小)``。**目录一律不删**。"""
        path = self.resolve(rel)
        if not path.exists():
            raise FileOpDenied(f"文件不存在：{rel}")
        if path.is_dir():
            raise FileOpDenied(
                f"拒绝删除目录（{rel}）：本工具只删单个文件。"
                "清理整批产物请用文件管理器，别交给模型"
            )
        if is_reparse_point(path):
            raise FileOpDenied(f"拒绝删除符号链接/联接：{rel}")
        size = path.stat().st_size
        path.unlink()
        self.log.append(FileOp(action="delete", path=self.rel(path), bytes=size))
        return path, size


def _atomic_write(path: Path, raw: bytes) -> None:
    """临时文件 + ``os.replace``：崩在中途也不会留下半个报告。"""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".fs-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def sandbox_for(cfg) -> FileSandbox:
    """按配置建沙箱。``fs_ops_enabled=false`` 时抛 :class:`FileOpDenied`。

    关掉的语义是"这些工具不可用"，而不是"抛异常崩掉"——调用方把它当正常
    返回值喂回模型即可。
    """
    if not getattr(getattr(cfg, "scan", cfg), "fs_ops_enabled", True):
        raise FileOpDenied(
            "文件操作已关闭（scan.fs_ops_enabled=false / POCS_FS_OPS=false）。"
            "需要让模型改报告文件时把它打开。"
        )
    root = getattr(cfg, "output_dir", "./output")
    return FileSandbox(root=Path(root))


__all__ = [
    "FileSandbox",
    "FileOpDenied",
    "FileOp",
    "ALLOWED_EXTS",
    "MAX_WRITE_BYTES",
    "MAX_READ_BYTES",
    "is_reparse_point",
    "sandbox_for",
]
