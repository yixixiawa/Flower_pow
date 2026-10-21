"""内置字典的落盘导出。

gobuster / ffuf 这类工具"必须给 -w"，而字典只在代码里。不做导出的话，
它们在初始化报告里显示"可用"，模型一调用却因为缺字典失败——
**探测结果和实际可用性对不上，比不探测更误导人。**
"""


from __future__ import annotations

from pathlib import Path


def wordlist_path(root: str | Path = ".") -> Path:
    """内置字典的落盘位置——外部工具（gobuster/ffuf）需要文件形式的字典。"""
    return Path(root) / "data" / "wordlists" / "builtin.txt"


def write_wordlist(root: str | Path = ".") -> Path | None:
    """把内置高价值字典导出成文件，供外部工具使用。

    不做的话 gobuster / ffuf 这类"必须给 -w"的工具在初始化报告里显示为
    "可用"，模型一调用却因为缺字典失败——探测结果和实际可用性对不上，
    比不探测更误导人。
    """
    try:
        from collectors.path_scan import DEFAULT_WORDS
    except Exception:  # noqa: BLE001
        return None
    p = wordlist_path(root)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(DEFAULT_WORDS) + "\n", encoding="utf-8")
    except OSError:
        return None
    return p
