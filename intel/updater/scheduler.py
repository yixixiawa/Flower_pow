"""定时更新入口 —— check / update / status / rollback 的编排层。

增量更新协议（用户明确要求的机制，刻意保持简单）::

    第一次更新：  Remote AAAAAAA · 本地记录 None   → 全量下载/注册
    第二次更新：  Remote BBBBBBB · 本地记录 AAAAAAA → 只处理 A→B 之间变化的 YAML
    第三次更新：  Remote BBBBBBB · 本地记录 BBBBBBB → 无变化，不做任何操作

本地记录（上个 Commit SHA）存 ``data/updater/state.json``；每次更新事件追加
到 ``history.json``；仓库配置在 ``repositories.json``。

按天自动更新：``auto_update_if_due()`` 在**每次启动**时被调用，state 里记着
上次自动检查的日期——同一天内不重复触发（不管上次成败），跨天才真正执行。
自动更新**绝不抛异常、绝不阻塞启动**：规则是增强项，网络挂了照常扫描。
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

from intel.updater.git_sync import GitSync, GitSyncError, RepoConfig, RuleChange
from intel.updater.registry import RuleRegistry, STATUS_APPROVED, sha256_bytes, today
from intel.updater.yaml_validator import IdDeduper, validate_rule_bytes

# ── 默认仓库配置（repositories.json 不存在时写入的种子）───────────────
DEFAULT_REPOSITORIES: dict = {
    "repositories": [
        {
            "name": "nuclei",
            "url": "https://github.com/projectdiscovery/nuclei-templates.git",
            "branch": "main",
            "enabled": True,
            "rule_path": "",
            "auto_update": True,
        },
        {
            "name": "flower",
            "url": "",  # 自建社区规则仓库，填上 URL 并 enabled=true 后生效
            "branch": "main",
            "enabled": False,
            "rule_path": "community/",
            "auto_update": True,
        },
    ]
}

HISTORY_CAP = 500  # history.json 最多保留多少条事件
COMMITS_CAP = 50  # state 里每个仓库记住多少个历史 Commit（供回滚）


# ── 仓库配置装载 ─────────────────────────────────────────────────────


def load_repositories(data_dir: str | Path) -> tuple[list[RepoConfig], list[str]]:
    """读 ``data/updater/repositories.json``，不存在则写种子。返回 (仓库, 警告)。"""
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "repositories.json"
    warnings: list[str] = []
    if not p.is_file():
        try:
            p.write_text(
                json.dumps(DEFAULT_REPOSITORIES, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            warnings.append(f"repositories.json 写入失败: {exc}")
            return [], warnings
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(f"repositories.json 解析失败: {exc}")
        return [], warnings
    repos: list[RepoConfig] = []
    for row in raw.get("repositories") or []:
        if not isinstance(row, dict):
            continue
        try:
            repos.append(RepoConfig.from_dict(row))
        except ValueError as exc:
            warnings.append(f"仓库配置非法（已跳过）: {exc}")
    return repos, warnings


# ── 状态与历史 ───────────────────────────────────────────────────────


class StateStore:
    """``data/updater/state.json`` 与 ``history.json`` 的读写。"""

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state: dict = {"version": 1, "last_auto_check": "", "repos": {}, "commits": {}}
        self.load()

    def _state_path(self) -> Path:
        return self.data_dir / "state.json"

    def _history_path(self) -> Path:
        return self.data_dir / "history.json"

    def load(self) -> None:
        p = self._state_path()
        if p.is_file():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.state = raw
            except (json.JSONDecodeError, OSError):
                pass  # 状态坏了按首装处理：损失一次增量（退化为全量），可接受
        self.state.setdefault("version", 1)
        self.state.setdefault("last_auto_check", "")
        self.state.setdefault("repos", {})
        self.state.setdefault("commits", {})

    def save(self) -> None:
        try:
            self._state_path().write_text(
                json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass  # 落盘失败下次退化为全量同步，不值得中断流程

    def repo_state(self, name: str) -> dict:
        return self.state["repos"].setdefault(name, {})

    def last_commit(self, name: str) -> str | None:
        v = self.repo_state(name).get("last_commit")
        return str(v) if v else None

    def record_commit(self, name: str, sha: str) -> None:
        rs = self.repo_state(name)
        rs["last_commit"] = sha
        rs["last_sync"] = time.time()
        hist = self.state["commits"].setdefault(name, [])
        if sha not in hist:
            hist.append(sha)
        # 只留最近 N 个，state.json 不无限膨胀（回滚只支持回退到记录过的点）
        del hist[:-COMMITS_CAP]

    def truncate_commits_to(self, name: str, sha: str) -> None:
        hist = self.state["commits"].setdefault(name, [])
        if sha in hist:
            idx = hist.index(sha)
            self.state["commits"][name] = hist[: idx + 1]
        else:
            self.state["commits"][name] = [sha]

    def append_history(self, event: dict) -> None:
        try:
            p = self._history_path()
            hist: list = []
            if p.is_file():
                try:
                    raw = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(raw, list):
                        hist = raw
                except (json.JSONDecodeError, OSError):
                    hist = []
            hist.append(event)
            del hist[:-HISTORY_CAP]
            p.write_text(
                json.dumps(hist, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass  # 历史写不进去不影响同步本身


# ── 更新器 ───────────────────────────────────────────────────────────


class Updater:
    """四个动作的编排：check / update / status / rollback。"""

    def __init__(
        self,
        data_dir: str | Path,
        remote_dir: str | Path,
        publish_dir: str | Path,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.remote_dir = Path(remote_dir)
        self.publish_dir = Path(publish_dir)
        self.state = StateStore(self.data_dir)
        self.repos, self.warnings = load_repositories(self.data_dir)

    def _sync(self, cfg: RepoConfig) -> GitSync:
        return GitSync(cfg, self.remote_dir)

    def _registry(self, cfg: RepoConfig, sync: GitSync) -> RuleRegistry:
        reg = RuleRegistry(cfg, sync, self.publish_dir)
        reg.load()
        return reg

    # ── check：只看不改 ───────────────────────────────────────────
    def check(self, repo: str | None = None) -> list[dict]:
        """检查远程是否有新版本。返回每个仓库的待更新摘要，不改任何状态。

        raises GitSyncError —— 网络问题由 CLI 层展示，这里不吞。
        """
        out: list[dict] = []
        for cfg in self._enabled(repo):
            sync = self._sync(cfg)
            sync.ensure_cloned()
            sync.fetch()
            remote = sync.remote_sha()
            local_recorded = self.state.last_commit(cfg.name)
            pending: list[RuleChange] = []
            if remote and remote != local_recorded:
                if local_recorded:
                    pending = sync.diff_files(local_recorded, remote)
                else:
                    pending = [
                        RuleChange("A", p) for p in sync.list_yaml_files()
                    ]
            out.append(
                {
                    "repo": cfg.name,
                    "url": cfg.url,
                    "remote_sha": (remote or "")[:12],
                    "local_sha": (local_recorded or "")[:12],
                    "up_to_date": bool(remote and remote == local_recorded),
                    "pending_yaml": sum(1 for c in pending if c.is_yaml),
                    "pending_total": len(pending),
                }
            )
        return out

    # ── update：增量落地 ──────────────────────────────────────────
    def update(self, repo: str | None = None, force: bool = False) -> list[dict]:
        """执行增量更新。返回每个仓库的更新摘要。

        单仓库失败（网络 / git 异常）只影响该仓库，其余继续——
        外部依赖失败自动降级、不崩流水线。
        """
        results: list[dict] = []
        for cfg in self._enabled(repo):
            summary: dict = {
                "repo": cfg.name,
                "status": "skipped",
                "added": 0,
                "updated": 0,
                "removed": 0,
                "invalid": 0,
                "published": 0,
                "errors": [],
            }
            try:
                self._update_one(cfg, summary, force)
            except GitSyncError as exc:
                summary["status"] = "error"
                summary["errors"].append(str(exc))
            except Exception as exc:  # noqa: BLE001 —— 单仓库崩不影响其他仓库
                summary["status"] = "error"
                summary["errors"].append(f"{type(exc).__name__}: {exc}")
            results.append(summary)
            self.state.append_history(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "update",
                    **{k: v for k, v in summary.items() if k != "repo"},
                    "repo": cfg.name,
                }
            )
        self.state.save()
        return results

    def _update_one(self, cfg: RepoConfig, summary: dict, force: bool) -> None:
        sync = self._sync(cfg)
        if not cfg.url:
            summary["status"] = "no-url"
            return
        sync.ensure_cloned()
        sync.fetch()
        remote = sync.remote_sha()
        if not remote:
            raise GitSyncError(f"无法解析远程分支 {cfg.branch} 的 SHA")
        local_recorded = self.state.last_commit(cfg.name)

        if local_recorded == remote and not force:
            summary["status"] = "up-to-date"
            return

        reg = self._registry(cfg, sync)
        # 先 checkout 到目标 Commit（工作区即目标状态），再处理变更
        sync.checkout(remote)

        if local_recorded and not force:
            changes = sync.diff_files(local_recorded, remote)
        else:
            # 首次同步 / 强制刷新：全量
            changes = [RuleChange("A", p) for p in sync.list_yaml_files()]

        deduper = IdDeduper()
        for ch in changes:
            if not ch.is_yaml:
                continue
            if ch.is_delete:
                # 删除的文件读不到内容：按路径反查 manifest 里登记的 rule_id
                rid = self._rid_by_path(reg, ch.path)
                if rid and reg.mark_removed(rid, remote):
                    summary["removed"] += 1
                continue
            try:
                data = sync.read_file(ch.path)
            except (OSError, GitSyncError) as exc:
                summary["invalid"] += 1
                summary["errors"].append(f"{ch.path}: 读取失败: {exc}")
                continue
            res = validate_rule_bytes(data, source_name=ch.path)
            if not res.ok:
                summary["invalid"] += 1
                summary["errors"].append(res.error)
                continue
            conflict = deduper.check(res.rule_id, ch.path)
            if conflict:
                summary["invalid"] += 1
                summary["errors"].append(conflict)
                continue
            # 计数依据"登记前是否存在"，而不是 version——已存在但内容未变的
            # 规则 version 可能停在 1，按 version 判断会把刷新误计成新增
            existed = res.rule_id in reg.rules
            reg.register(
                res.rule_id,
                remote,
                sha256_bytes(data),
                kind=res.kind,
                repo_path=ch.path,
            )
            if existed:
                summary["updated"] += 1
            else:
                summary["added"] += 1

        published, pub_errors = reg.publish_all(remote)
        summary["published"] = published
        summary["errors"].extend(pub_errors)
        reg.save()

        self.state.record_commit(cfg.name, remote)
        summary["status"] = "updated"
        summary["to_sha"] = remote[:12]

    @staticmethod
    def _rid_by_path(reg: RuleRegistry, path: str) -> str | None:
        for rid, entry in reg.rules.items():
            if entry.get("file") == path:
                return rid
        return None

    # ── status：本地规则状态 ──────────────────────────────────────
    def status(self) -> list[dict]:
        out: list[dict] = []
        for cfg in self.repos:
            sync = self._sync(cfg)
            reg = self._registry(cfg, sync)
            stats = reg.stats()
            published_dir = self.publish_dir / cfg.name
            published = (
                sum(1 for _ in published_dir.rglob("*.yaml"))
                if published_dir.is_dir()
                else 0
            )
            out.append(
                {
                    "repo": cfg.name,
                    "url": cfg.url or "-",
                    "branch": cfg.branch,
                    "enabled": cfg.enabled,
                    "auto_update": cfg.auto_update,
                    "cloned": sync.is_cloned,
                    "last_commit": (self.state.last_commit(cfg.name) or "-")[:12],
                    "last_sync": self.repo_sync_time(cfg.name),
                    **stats,
                    "published": published,
                }
            )
        return out

    def repo_sync_time(self, name: str) -> str:
        ts = self.state.repo_state(name).get("last_sync")
        if not ts:
            return "-"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))

    # ── rollback：回滚规则版本 ────────────────────────────────────
    def rollback(self, repo: str, to: str | None = None) -> dict:
        """回滚到上一个（或指定）Commit 并全量重注册。

        只允许回退到 state 里记录过的 Commit——盲回滚到没拉过的 SHA
        意味着重放完整历史，既慢又不可控。
        """
        hist = self.state.state["commits"].get(repo) or []
        if to:
            target = next(
                (h for h in hist if h.startswith(to)), None
            )
            if not target:
                raise GitSyncError(f"未记录过 Commit {to[:12]}（只可回退到已同步过的版本）")
        else:
            if len(hist) < 2:
                raise GitSyncError("没有可回滚的历史版本（只同步过一次）")
            target = hist[-2]

        cfg = next((r for r in self.repos if r.name == repo), None)
        if cfg is None:
            raise GitSyncError(f"未配置仓库: {repo}")
        sync = self._sync(cfg)
        if not sync.is_cloned:
            raise GitSyncError(f"仓库 {repo} 尚未克隆，无需回滚")

        sync.reset_to(target)
        reg = self._registry(cfg, sync)
        deduper = IdDeduper()
        present_paths = set(sync.list_yaml_files())
        for path in present_paths:
            data = sync.read_file(path)
            res = validate_rule_bytes(data, source_name=path)
            if not res.ok:
                continue  # 回滚目标上的坏文件：登记不了就跳过，历史里留痕
            if deduper.check(res.rule_id, path):
                continue
            reg.register(res.rule_id, target, sha256_bytes(data), kind=res.kind, repo_path=path)
        # 现在不在目标 Commit 里的规则 → 下架
        for rid, entry in list(reg.rules.items()):
            if entry.get("file") not in present_paths:
                reg.mark_removed(rid, target)
        published, pub_errors = reg.publish_all(target)
        reg.save()

        self.state.record_commit(repo, target)
        self.state.truncate_commits_to(repo, target)
        self.state.save()
        self.state.append_history(
            {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "action": "rollback",
                "repo": repo,
                "to_commit": target[:12],
                "published": published,
                "errors": pub_errors,
                "status": "ok",
            }
        )
        return {
            "repo": repo,
            "to_commit": target[:12],
            "published": published,
            "errors": pub_errors,
        }

    # ── 内部 ──────────────────────────────────────────────────────
    def _enabled(self, repo: str | None) -> list[RepoConfig]:
        out = [
            c
            for c in self.repos
            if c.enabled and c.url and (repo is None or c.name == repo)
        ]
        return out


# ── 按天自动更新门控 ─────────────────────────────────────────────────


def auto_update_if_due(cfg) -> dict | None:
    """启动时调用：跨天首次启动才触发规则更新，同一天不重复。

    - 判定基准是 ``state.json`` 的 ``last_auto_check``（当天日期串）；
    - 当天已触发过（无论成败）→ 返回 None，什么都不做；
    - 触发后**无条件**写入今天日期——失败的更新第二天才有机会重试，
      避免网络不可用时每次启动都干等 git 超时；
    - **只对已克隆的仓库做增量 fetch**——首次克隆（nuclei-templates 全量
      数百 MB）太重，不能塞进启动路径，留给显式 ``intel update``；
    - 任何异常都在这里消化，调用方（boot）不需要 try。
    """
    if not getattr(cfg, "intel", None) or not cfg.intel.auto_update:
        return None
    try:
        updater = _updater_from_config(cfg)
        state = updater.state
        if state.state.get("last_auto_check") == today():
            return None
        state.state["last_auto_check"] = today()
        state.save()

        results: list[dict] = []
        for c in updater.repos:
            # 仓库级 auto_update 开关 + 已克隆门槛（见 docstring）
            if not (c.enabled and c.auto_update and c.url):
                continue
            if not updater._sync(c).is_cloned:
                continue
            results.extend(updater.update(repo=c.name))
        touched = [r for r in results if r.get("status") == "updated"]
        if not touched:
            return None
        return {
            "repos": [
                {
                    "repo": r["repo"],
                    "added": r["added"],
                    "updated": r["updated"],
                    "removed": r["removed"],
                    "invalid": r["invalid"],
                }
                for r in touched
            ]
        }
    except Exception:  # noqa: BLE001 —— 自动更新绝不阻塞启动
        return None


def _updater_from_config(cfg) -> Updater:
    """从 Config 实例构造 Updater（相对路径锚定到 data_dir 的父目录=项目根）。

    为什么不直接用 CWD：mcp_server.main() 会 chdir 到项目根，但用户手工
    从别的目录启动时 CWD 不确定；config_loader 已把 data_dir 锚定到配置
    文件所在目录，拿它的父目录当基准最稳。
    """
    base = Path(cfg.data_dir).resolve().parent

    def _resolve(p: str) -> Path:
        pp = Path(p)
        return pp if pp.is_absolute() else base / pp

    return Updater(
        data_dir=_resolve(cfg.intel.data_dir),
        remote_dir=_resolve(cfg.intel.remote_dir),
        publish_dir=_resolve(cfg.intel.publish_dir),
    )
