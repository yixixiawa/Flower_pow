"""PATH 发现：回答"我装的东西到底有没有被认出来"。

为什么不做自动识别："扫 PATH 猜哪些是安全工具"这条路实测走不通。
本机 PATH 有 **2660** 个可执行文件，按名字里的 scan/sql/crack 之类筛，
出来的绝大多数是同名噪音——``doskey`` / ``charmap`` / ``secpol``（系统组件）、
``psql`` / ``sqlite3``（数据库客户端）、``ffprobe``（视频工具）。
把这些塞给模型不是"扩展能力"，是往上下文里灌垃圾。

真正有价值的不是猜，而是**让人看清现状**：列出 PATH 下非系统目录的可执行
文件，与已登记清单做差集，让人自己确认"这个 exe 要不要登记"。
判断"是不是安全工具"必须由人来做，不能靠猜。
"""


from __future__ import annotations

import os
import re
from pathlib import Path

from core.tools.external import all_external_tools


# ── PATH 发现（回答"我装的东西到底有没有被认出来"）───────────────────

# 为什么不做自动识别
# ------------------
# "扫 PATH 猜哪些是安全工具"这条路实测走不通：本机 PATH 有 **2660** 个可执行
# 文件，按名字里的 scan/sql/crack 之类的词筛，出来的绝大多数是同名噪音——
#   doskey / charmap / secpol / fixmapi   ← Windows 系统组件
#   psql / sqlite3 / sqldiff               ← 数据库客户端
#   ffprobe                                 ← 视频工具
#   nettle-hash / ssh-keyscan              ← 开发库附带
# 把这些塞给模型不是"扩展能力"，是往上下文里灌垃圾。
#
# 真正有价值的不是猜，而是**让人看清现状**。所以这里做的是：
# 列出 PATH 下非系统目录的可执行文件，并与已登记清单做差集，
# 让人自己一眼确认"这个 exe 是不是我要的工具、要不要登记"。
# 判断"是不是安全工具"必须由人（或明确的名字提示）来做，不能靠猜。

# 扫描时跳过的目录片段。系统与开发工具链的目录只会产生噪音。
_PATH_SKIP_HINTS = (
    "windows", "python3", "nodejs", "git/", "java", "gradle",
    "flutter", "dart", "go/bin", "mingw", "/bin/", "system32",
    # Git/MSYS 运行时（Git Bash 自带 coreutils 等几百个 .exe）。
    # 注意 "/bin/" 那条已能命中一部分，这里补的是 \usr\bin 与便携版目录。
    "\\usr\\bin", "/usr/bin", "portablegit", "miniconda", "anaconda",
)

# 逐个跳过目录成本高且不准（用户可能把工具装在 python/Scripts 下），
# 改为**逐条文件**过滤。这些是明确的噪音模式：conda/accelerate 家族、
# GNU coreutils 的变体、Git usr/bin 里的 Unix 工具。
_NOISE_PATTERNS = re.compile(
    r"^(accelerate|aistudio|automat|jupyter|ipython|pip|python|"
    r"[a-z0-9]+-config|[a-z0-9]+-estimate)",
    re.I,
)
_NOISE_EXACT = {
    # coreutils / gnu / git 附带，与安全测试无关
    "awk", "gawk", "mawk", "sed", "grep", "egrep", "fgrep", "arch", "basename",
    "cat", "chmod", "chown", "cksum", "comm", "csplit", "cut", "date", "dd",
    "df", "dirname", "du", "echo", "env", "expr", "factor", "false", "find",
    "fmt", "fold", "head", "hostid", "id", "install", "join", "ln", "ls",
    "md5sum", "mkdir", "mkfifo", "mktemp", "mv", "ninja", "nl", "nohup",
    "nproc", "od", "paste", "patch", "pathchk", "pidof", "printenv", "printf",
    "pwd", "readlink", "realpath", "rm", "rmdir", "sha1sum", "sha224sum",
    "sha256sum", "sha384sum", "sha512sum", "shred", "shuf", "sleep", "split",
    "stat", "stdbuf", "stty", "sum", "sync", "tac", "tail", "tee", "test",
    "touch", "tr", "truncate", "tsort", "uname", "unexpand", "uniq", "unlink",
    "unset", "wc", "which", "whoami", "xargs", "yes", "base32", "base64",
    "b2sum", "cksum", "sha256sum", "zstd", "lz4", "xz", "bzip2", "gzip",
    "git", "git-*", "less", "more", "nano", "vim", "vi", "diff", "cmp",
    "hexdump", "xxd", "od", "strings", "objdump", "readelf", "nm",
    "bzip2recover", "lzfse", "lzop", "zstdcat",
}


def _looks_like_noise(stem: str) -> bool:
    """判断一个可执行文件名是否明显属于开发工具链噪音。

    只拦**有把握**的（GNU 工具、conda 家族、git 附带）。判断不确定的一律放过——
    宁可多显示几条让人自己排除，也不要把真工具悄悄藏起来。
    """
    low = stem.lower()
    if low in _NOISE_EXACT or low.startswith("git-"):
        return True
    return bool(_NOISE_PATTERNS.match(low))


def scan_path_executables(limit: int | None = None) -> list[tuple[str, str]]:
    """扫描 PATH 下所有可执行文件，返回 ``[(名字, 路径), ...]``。

    **只列出来给人看，不会自动登记成工具**——见上面"为什么不做自动识别"。

    识别 Windows 可执行文件靠 ``PATHEXT`` 而不是写死 ``.exe``：
    同一台机器上 ``sqlmap.py``、``wcurl.bat`` 都能直接在终端敲起来，
    漏掉它们就漏掉了真实的工具。
    """
    raw = os.environ.get("PATH", "")
    dirs = [d.strip().strip('"') for d in raw.split(os.pathsep) if d.strip()]
    exts = [e.lower() for e in os.environ.get("PATHEXT", "").split(";") if e]
    if not exts:
        exts = [".exe", ".cmd", ".bat", ".py"]

    out: dict[str, tuple[str, str]] = {}
    for d in dirs:
        p = Path(d)
        low = d.lower()
        if any(s in low for s in _PATH_SKIP_HINTS):
            continue
        if not p.is_dir():
            continue
        try:
            for it in p.iterdir():
                if it.suffix.lower() not in exts:
                    continue
                if not it.is_file():
                    continue
                stem = it.stem.lower()
                # Git for Windows 的 MSYS 符号链接会以 "[.exe" 这种怪名字出现
                if not stem or stem.startswith("["):
                    continue
                if _looks_like_noise(stem):
                    continue
                out.setdefault(stem, (it.name, str(it)))
        except OSError:
            continue
    items = sorted(out.values(), key=lambda x: x[0].lower())
    return items[:limit] if limit else items


def unregistered_executables(limit: int | None = None) -> list[tuple[str, str]]:
    """PATH 里存在、但**没有登记进任何清单**的可执行文件。

    这就是"我明明装了却不被认"的那部分。返回结果供``discover`` 命令展示。
    """
    specs, _errs = all_external_tools()
    known: set[str] = set()
    for s in specs:
        for b in s.bins:
            known.add(Path(b).stem.lower())
    return [(n, f) for n, f in scan_path_executables() if Path(n).stem.lower() not in known][:limit]
