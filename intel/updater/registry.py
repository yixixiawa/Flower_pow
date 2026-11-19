"""本地规则注册表 —— 规则版本管理机制。

每条规则的版本元数据**严格按以下格式落盘**（``remote_rules/<name>/manifest.json``）::

    {
      "rule_id": "http/example-detection",
      "source": "nuclei-templates",
      "source_url": "https://github.com/projectdiscovery/nuclei-templates",
      "commit": "abcdef123456",
      "sha256": "xxxx",
      "version": 3,
      "status": "approved",
      "first_seen": "2026-11-19",
      "last_updated": "2026-11-19"
    }

字段语义：

================= ====================================================
字段               含义
================= ====================================================
``rule_id``        规则唯一 ID（flower 取 YAML ``id``；nuclei 取模板 id）
``source``         来源仓库名（repositories.json 里的 name）
``source_url``     来源仓库 URL
``commit``         该内容版本对应的远程 Commit SHA
``sha256``         规则文件内容的哈希——内容是否真变的**唯一判据**
``version``        递增版本号：内容每变一次 +1，回滚重注册不变号
``status``         approved（在用）/ removed（下架）/ pending（未审）
``first_seen``     首次入库日期
``last_updated``   最近一次状态/内容变化日期
================= ====================================================

status 生命周期::

    新规则        → approved
    内容变化      → approved（version +1）
    远程删除      → removed（**记录保留**，回滚与审计需要历史）
    回滚后再出现  → approved（version 不变，内容以回滚目标 Commit 为准）

发布（publish）：flower 形态的规则复制到 ``poc/community/<repo>/``，
让现有 ``detectors.poc_loader``（rglob 递归）与 RAG 索引**零改动**感知新规则。
nuclei 形态只登记不发布（引擎暂不能执行 nuclei 语法）。
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import date
from pathlib import Path

from intel.updater.git_sync import GitSync, GitSyncError, RepoConfig
from intel.updater.yaml_validator import ValidationResult

STATUS_APPROVED = "approved"
STATUS_REMOVED = "removed"
STATUS_PENDING = "pending"


def today() -> str:
    return date.today().isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RuleRegistry:
    """一个仓库的本地规则清单（manifest.json 读写 + 版本演进 + 发布）。"""

    def __init__(self, cfg: RepoConfig, sync: GitSync, publish_dir: str | Path) -> None:
        self.cfg = cfg
        self.sync = sync
        self.publish_dir = Path(publish_dir)
        self.rules: dict[str, dict] = {}

    # ── 清单读写 ──────────────────────────────────────────────────
    def load(self) -> None:
        p = self.sync.manifest_path
        if not p.is_file():
            self.rules = {}
            return
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # 清单坏了不能拖垮更新：按空清单重建，丢失的版本号以 first_seen 修复
            self.rules = {}
            return
        rules = raw.get("rules") if isinstance(raw, dict) else None
        self.rules = dict(rules) if isinstance(rules, dict) else {}

    def save(self) -> Path:
        payload = {
            "repo": self.cfg.name,
            "source_url": self.cfg.url,
            "updated_at": today(),
            "rule_count": len(self.rules),
            "rules": self.rules,
        }
        p = self.sync.manifest_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return p

    # ── 版本演进 ──────────────────────────────────────────────────
    def register(
        self,
        rule_id: str,
        commit: str,
        sha256: str,
        *,
        kind: str,
        repo_path: str,
        initial_version: int = 1,
    ) -> dict:
        """登记/更新一条规则。返回这条规则的元数据。

        内容没变（sha256 相同）→ 只刷新 commit，version 不动，last_updated 不动
        （mtime 变化不代表内容变化，避免天天"假更新"刷版本号）。
        内容变了 → version +1、last_updated 刷新、status 拉回 approved。
        新规则 → version 取 initial_version，first_seen 记今天。
        """
        entry = self.rules.get(rule_id)
        now = today()
        if entry is None:
            entry = {
                "rule_id": rule_id,
                "source": self.cfg.name,
                "source_url": self.cfg.url,
                "commit": commit,
                "sha256": sha256,
                "version": max(1, int(initial_version)),
                "status": STATUS_APPROVED,
                "first_seen": now,
                "last_updated": now,
            }
            self.rules[rule_id] = entry
        elif entry.get("sha256") != sha256:
            entry["version"] = int(entry.get("version") or 0) + 1
            entry["sha256"] = sha256
            entry["last_updated"] = now
            entry["status"] = STATUS_APPROVED  # 下架过的规则回来了
        # 共同字段每次刷新
        entry["commit"] = commit
        entry["source"] = self.cfg.name
        entry["source_url"] = self.cfg.url
        entry["kind"] = kind  # 附加字段：flower 可发布 / nuclei 仅登记
        entry["file"] = repo_path  # 附加字段：仓库内相对路径（回滚重注册要用）
        # 内容未变但之前被下架（远程删除后回滚回来）：注册即视为在用
        if entry.get("status") == STATUS_REMOVED:
            entry["status"] = STATUS_APPROVED
            entry["last_updated"] = now
        return entry

    def mark_removed(self, rule_id: str, commit: str) -> dict | None:
        """远程删除 → 下架。记录保留（审计与回滚需要），返回元数据或 None。"""
        entry = self.rules.get(rule_id)
        if entry is None:
            return None
        if entry.get("status") != STATUS_REMOVED:
            entry["status"] = STATUS_REMOVED
            entry["last_updated"] = today()
        entry["commit"] = commit
        return entry

    # ── 发布 ──────────────────────────────────────────────────────
    def _publish_path(self, rule_id: str) -> Path:
        """发布目标：poc/community/<repo>/<rule_id>.yaml。

        flower 的 rule_id 不含 '/'（验证器挡掉了），直接当文件名；
        保留字符做最小转义，防 Windows 非法文件名。
        """
        safe = rule_id.replace("\\", "_").replace(":", "_").replace("*", "_")
        safe = safe.replace("?", "_").replace('"', "_").replace("<", "_")
        safe = safe.replace(">", "_").replace("|", "_").strip() or "_unnamed"
        return self.publish_dir / self.cfg.name / f"{safe}.yaml"

    def publish_all(self, commit: str, dest: Path | None = None) -> tuple[int, list[str]]:
        """按当前清单全量重发布 flower 规则。返回 (数量, 错误列表)。

        先清目标目录再逐条写：保证"清单与磁盘一致"，
        删掉的规则不会在目标目录里留尸体。

        ``dest`` 为空发布到正式执行目录（``poc/community/<repo>/``）；
        给定路径则发布到该目录——**隔离暂存区**（P2-12：外部更新先入
        暂存区，审核通过后才进执行目录）就靠这个参数落地。
        """
        errors: list[str] = []
        target = Path(dest) if dest is not None else self.publish_dir / self.cfg.name
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        n = 0
        for rid, entry in self.rules.items():
            if entry.get("status") != STATUS_APPROVED or entry.get("kind") != "flower":
                continue
            try:
                data = self.sync.read_file(entry.get("file") or "")
                # 文件名 = _publish_path 的文件名部分；目录以 target 为准
                dest_file = target / (self._publish_path(rid).name)
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                dest_file.write_bytes(data)
                n += 1
            except (OSError, GitSyncError) as exc:
                errors.append(f"发布 {rid} 失败: {exc}")
        return n, errors

    def unpublish(self) -> None:
        """整仓下架（回滚失败 / 仓库禁用时调用）。"""
        target = self.publish_dir / self.cfg.name
        if target.exists():
            shutil.rmtree(target)

    # ── 统计 ──────────────────────────────────────────────────────
    def stats(self) -> dict:
        out: dict[str, int] = {"approved": 0, "removed": 0, "pending": 0, "flower": 0, "nuclei": 0}
        for e in self.rules.values():
            st = str(e.get("status") or "pending")
            out[st] = out.get(st, 0) + 1
            kind = str(e.get("kind") or "")
            if kind in ("flower", "nuclei"):
                out[kind] += 1
        return out
