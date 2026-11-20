"""验收用例的公共小工具（不属于任何一条需求）。"""

from __future__ import annotations

from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]


def read_yaml_cfg(ctx, env: str) -> Path:
    """写一份最小配置：把 mock A 绑定到指定环境。

    CLI / MCP 用例通过 ``--config`` 读它——这样测的是**真实入口**，
    不是"在测试里直接调 active_scan_check"（后者只能证明函数返回值）。
    """
    import yaml

    path = Path(ctx.tmp) / f"policy_{env}.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "policy": {
                    "default_environment": "unknown",
                    "environments": {ctx.net.a.binding: env},
                },
                "scan": {"proxy": None, "timeout": 3.0},
                "llm": {"enabled": False},
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path


__all__ = ["PROJECT", "read_yaml_cfg"]
