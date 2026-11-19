"""动态规则库：把 POC 从静态 YAML 升级为 Git 驱动的可增量更新规则中心。

模块结构（刻意收敛为小模块，不做重型情报平台）::

    intel/
    └── updater/
        ├── __init__.py
        ├── git_sync.py       # Git 仓库同步（fetch / SHA 比较 / 增量 diff）
        ├── yaml_validator.py # YAML 规则验证（语法 + Schema + ID 去重）
        ├── registry.py       # 本地规则管理（版本清单 / 发布 / 下架）
        └── scheduler.py      # 定时更新入口（check / update / status / rollback）

配套状态目录::

    data/updater/
    ├── state.json         # 同步状态（各仓库上次同步的 Commit SHA / 按天门控）
    ├── history.json       # 更新历史
    └── repositories.json  # 仓库配置
"""

from intel.updater.git_sync import GitSync, RepoConfig
from intel.updater.registry import RuleRegistry
from intel.updater.scheduler import Updater, auto_update_if_due, load_repositories

__all__ = [
    "GitSync",
    "RepoConfig",
    "RuleRegistry",
    "Updater",
    "auto_update_if_due",
    "load_repositories",
]
