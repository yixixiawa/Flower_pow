"""极小 ``.env`` 读写——不引入 python-dotenv 依赖。

为什么自己写
------------
配置优先级是「环境变量 > config.yaml > 默认值」。首次运行时用户输入的
API Key 需要一个**持久化落点**，最自然的位置就是 ``.env``（已在
``.gitignore`` 里，不会误提交）。

只用两个能力，所以不必要为一个 300 行的依赖多装一个包：

* :func:`load_env_file` —— 把 ``.env`` 读进 ``os.environ``，**不覆盖**已存在的
  环境变量。这一条很关键：CI 里用 ``export DEEPSEEK_API_KEY=...`` 注入的密钥
  必须优先于本地文件，否则本地一个过期 Key 会静默盖掉流水线的正确配置。
* :func:`set_env_value` —— 按 key 就地改写一行，**保留注释、空行和其它键**。
  直接整体重写会让用户手写的注释消失，下次他就不敢用这个功能了。

刻意不支持的语法：多行值、变量插值、``${VAR}`` 展开。用到了就说明该换
正经的密钥管理方案，而不是继续往 .env 里塞。
"""

from __future__ import annotations

import os
import re
from pathlib import Path

DEFAULT_ENV_PATH = ".env"

_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _unquote(raw: str) -> str:
    """去掉包裹引号并处理常见转义。"""
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
        if raw.strip()[0] == '"':
            v = v.replace("\\n", "\n").replace('\\"', '"')
    # 行尾注释：只在没有引号包裹时才安全剥离
    return v


def parse_env(text: str) -> dict[str, str]:
    """解析 .env 文本为字典。忽略注释与非法行。"""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        val = _unquote(raw)
        # 未加引号时按 # 截断行尾注释
        if raw.strip() and raw.strip()[0] not in ("'", '"') and " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        out[key] = val
    return out


def load_env_file(path: str | Path = DEFAULT_ENV_PATH, override: bool = False) -> dict[str, str]:
    """把 ``.env`` 里的键值注入 ``os.environ``。

    ``override=False``（默认）时**不覆盖**已存在的环境变量——真实环境变量
    优先级永远高于本地文件。返回本次实际注入的键值对。
    """
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {}
    pairs = parse_env(text)
    applied: dict[str, str] = {}
    for k, v in pairs.items():
        if override or k not in os.environ:
            os.environ[k] = v
            applied[k] = v
    return applied


def set_env_value(
    key: str,
    value: str,
    path: str | Path = DEFAULT_ENV_PATH,
    comment: str = "",
) -> Path:
    """就地写入 / 更新一个键，保留文件里其它内容。

    文件不存在时创建，并带上 ``comment`` 作为文件头注释。
    值一律用双引号包裹，避免 Key 里的特殊字符（``#``、空格）被误解析。
    """
    p = Path(path)
    lines: list[str] = []
    if p.is_file():
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
    if not lines:
        lines = [f"# {comment}"] if comment else []

    quoted = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    new_line = f"{key}={quoted}"
    hit = False
    for i, line in enumerate(lines):
        m = _LINE_RE.match(line)
        if m and m.group(1) == key:
            lines[i] = new_line
            hit = True
            break
    if not hit:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(new_line)

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def mask(secret: str, keep: int = 4) -> str:
    """脱敏展示，用于终端回显——不要把 Key 原样打到屏幕上。"""
    s = (secret or "").strip()
    if not s:
        return "(空)"
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * 8}{s[-keep:]}"


__all__ = ["DEFAULT_ENV_PATH", "parse_env", "load_env_file", "set_env_value", "mask"]
