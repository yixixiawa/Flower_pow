"""更新器子包：Git 同步 → YAML 验证 → 本地注册的窄管道。"""

from intel.updater.git_sync import GitSync, RepoConfig, RuleChange
from intel.updater.registry import RuleRegistry
from intel.updater.scheduler import Updater, auto_update_if_due, load_repositories

__all__ = [
    "GitSync",
    "RepoConfig",
    "RuleChange",
    "RuleRegistry",
    "Updater",
    "auto_update_if_due",
    "load_repositories",
]
