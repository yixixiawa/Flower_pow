"""凭据泄漏自检——提交前跑一次，确认仓库里没有能直接用的令牌。

为什么需要这个
--------------
渗透测试项目天然会踩到「凭据落盘」：调试时把登录拿到的 JWT 存成
``data/recon/token.txt``、验证码截成 png、请求响应写进 ``.log``。
这些文件**都不在** ``.gitignore`` 里等着被 ``git add .`` 带进仓库——
``data/reacon/`` 正是这么漏出去过一次（2026-10-06 留下的 ftitle.studio
有效 JWT，直到 10-13 才过期）。

``.gitignore`` 是被动防线（规则写漏了就失效），这个脚本是主动的：
直接扫内容，命中就退出码非 0。

用法::

    python scripts/secret_scan.py              # 扫当前目录
    python scripts/secret_scan.py --path .     # 指定目录
    python scripts/secret_scan.py --quiet      # 只在发现问题时输出

退出码：0 =干净，1 =发现疑似凭据。

**刻意不做的事**：不上传任何内容、不修改文件。命中后只报文件路径与
命中规则，不回显凭据本体——扫描日志本身也可能被转发。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# 规则表：(名称, 正则, 说明)
# 顺序有意义：更具体的规则排前面，避免被宽松规则抢先匹配。
RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "deepseek-key",
        re.compile(r"\bsk-[A-Za-z0-9]{24,}\b"),
        "DeepSeek / OpenAI 风格 API Key",
    ),
    (
        "aliyun-ak",
        re.compile(r"\bLTAI[A-Za-z0-9]{12,}\b"),
        "阿里云 AccessKey ID",
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "JWT（三段 base64）",
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "私钥文件内容",
    ),
    (
        "aws-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS AccessKey ID",
    ),
    (
        "bearer",
        re.compile(r"(?i)\bauthorization\s*[:=]\s*[\"']?bearer\s+[A-Za-z0-9._-]{20,}"),
        "硬编码的 Authorization: Bearer",
    ),
]

# 官方文档里的经典示例值，出现在测试数据/扫描结果中是**正常的**。
# 不排除会让每次扫描都报一堆假阳性，久了就没人看结果了——这是安全扫描器
# 最常见的失效方式。
KNOWN_EXAMPLES = {
    # AWS 官方文档通用示例
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/b",
    "AKIAI44QH8DHBEXAMPLE",
    # JWT 官方文档示例（jwt.io）
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abc123def456",
    # DeepSeek 文档示例
    "sk-your-key-here",
}

# 目录/文件白名单：这些位置的 token 形态是**正常业务内容**（POC 规则、
# 检测器规则里就是要写这些字符串），不是泄漏。
# output/ 与 data/sessions/ 也在列：两者都已在 .gitignore 中（不提交），
# 且天然含真实目标的漏洞证据与 JWT——扫它们既没用，又会淹掉该看的告警。
WHITELIST_DIRS = {
    ".venv", "__pycache__", ".git", ".workbuddy", ".backup",
    "node_modules", ".pytest_cache", ".ruff_cache", "data/intel",
    "output", "data/sessions",
}
# 白名单文件：模板与示例，允许出现占位形式的 key
WHITELIST_FILES = {".env.example"}

# 二进制/大文件跳过（验证码 png、索引 json 之类）
MAX_BYTES = 2 * 1024 * 1024
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg",
    ".ini", ".env", ".http", ".body", ".html", ".js", ".sh", ".ps1", "",
}


def _norm(path: Path, root: Path) -> str:
    """归一化为相对 posix 路径，便于与白名单比对。"""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_whitelisted(rel: str, name: str) -> bool:
    """判断文件是否在白名单内。

    白名单条目分两种形态：单段名（``output``）与多段路径（``data/sessions``）。
    **必须用前缀匹配而不是分段集合求交**——后者拿 ``data``/``sessions``
    去比对 ``data/sessions`` 永远匹配不上，白名单形同虚设。
    """
    if name in WHITELIST_FILES:
        return True
    parts = Path(rel).parts
    for entry in WHITELIST_DIRS:
        seg = entry.split("/")
        if parts[: len(seg)] == tuple(seg):
            return True
    return False


def scan(root: Path, quiet: bool = False) -> int:
    """扫描 ``root``，返回命中文件数量。"""
    if not root.exists():
        print(f"路径不存在：{root}", file=sys.stderr)
        return 0

    hits: list[tuple[str, str, str]] = []  # (相对路径, 规则名, 说明)
    scanned = 0
    skipped = 0

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = _norm(p, root)
        if _is_whitelisted(rel, p.name):
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            skipped += 1
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                skipped += 1
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        # 按行扫，只记录行号不回显内容
        for lineno, line in enumerate(text.splitlines(), 1):
            # 命中示例值的行整体跳过：同一行里若有真凭据，
            # 通常会落在别的行上（配置与示例不会写在一起）
            if any(ex in line for ex in KNOWN_EXAMPLES):
                continue
            for name, pat, desc in RULES:
                if pat.search(line):
                    hits.append((f"{rel}:{lineno}", name, desc))

    if not quiet or hits:
        print(f"扫描 {scanned} 个文本文件（跳过 {skipped} 个二进制/超大文件）")
    if not hits:
        print("✅ 未发现疑似凭据")
        return 0

    print(f"\n❌ 发现 {len(hits)} 处疑似凭据：\n")
    by_file: dict[str, list[str]] = {}
    for loc, name, desc in hits:
        by_file.setdefault(loc.split(":")[0], []).append(f"L{loc.split(':')[1]} [{name}] {desc}")
    for f in sorted(by_file):
        print(f"  {f}")
        for detail in by_file[f]:
            print(f"      {detail}")
    print(
        "\n处理建议：\n"
        "  1. 确认是否为真实有效凭据（是则**立即吊销**，别只删文件）\n"
        "  2. 移到项目目录外或加入 .gitignore\n"
        "  3. 若已 commit 过，改用 git filter-repo 清理历史（单纯删文件无效）"
    )
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="扫描仓库内的凭据残留")
    ap.add_argument("--path", default=".", help="扫描根目录（默认当前目录）")
    ap.add_argument("--quiet", action="store_true", help="只在发现问题时输出")
    args = ap.parse_args()
    return scan(Path(args.path).resolve(), quiet=args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
