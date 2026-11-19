"""Git 仓库同步引擎 —— 规则更新的唯一拉取通道。

设计原则：**直接利用 Git，不造第二套下载器。**

机制刻意保持简单（用户明确要求不做复杂同步器）：

1. 本地保存远程仓库上次同步的 Commit SHA（``data/updater/state.json``）；
2. 每次更新 ``git fetch`` 后取远程分支最新 SHA，与本地记录比较；
3. SHA 相同 → 跳过，不做任何操作；
4. SHA 不同 → ``git diff --name-status <old> <new>`` 拿到**变化文件清单**，
   只处理旧 SHA → 新 SHA 之间发生变化的 YAML，不整仓下载、不整仓重扫。

为什么用 subprocess 调 git 而不是 GitPython / dulwich
----------------------------------------------------
git 本身就在渗透机上必装（本工具自己的更新也依赖它），subprocess 调用
零依赖、行为与手工操作完全一致；GitPython 已停止维护且拖一整棵依赖树，
dulwich 则要自己处理 pack 协议。增量 diff 场景下 git 命令行是最短路径。
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

# git 输出按字节拿、统一按 utf-8 解（Windows 中文机器默认 GBK 会把
# 仓库里偶发的非 ASCII 文件名解坏；git 在这类场景输出的是转义字节序）
GIT_TIMEOUT = 180.0


@dataclass(slots=True)
class RepoConfig:
    """一个远程规则仓库的配置，与 ``data/updater/repositories.json`` 一一对应。"""

    name: str
    url: str
    branch: str = "main"
    enabled: bool = True
    # 仓库内规则所在的子目录（相对仓库根，"" = 整仓）。只处理该目录下的 YAML。
    rule_path: str = ""
    auto_update: bool = True

    @classmethod
    def from_dict(cls, raw: dict) -> "RepoConfig":
        name = str(raw.get("name") or "").strip()
        if not name:
            raise ValueError("仓库配置缺少 name")
        return cls(
            name=name,
            url=str(raw.get("url") or "").strip(),
            branch=str(raw.get("branch") or "main").strip() or "main",
            enabled=bool(raw.get("enabled", True)),
            rule_path=str(raw.get("rule_path") or "").strip().strip("/"),
            auto_update=bool(raw.get("auto_update", True)),
        )


@dataclass(slots=True)
class RuleChange:
    """diff 里的一条文件级变更。status 是 git 的 A / M / D / R…"""

    status: str
    path: str  # 仓库内相对路径（posix 风格）

    @property
    def is_delete(self) -> bool:
        return self.status.startswith("D")

    @property
    def is_yaml(self) -> bool:
        return self.path.lower().endswith((".yaml", ".yml"))


class GitSyncError(RuntimeError):
    """git 操作失败。上层捕获后降级（打警告、不崩流水线）。"""


class GitSync:
    """单个远程规则仓库的本地克隆与增量同步。

    克隆位置：``<remote_dir>/<repo.name>/``（目录即仓库工作区），版本清单
    ``manifest.json`` 按规划放在 ``<remote_dir>/<name>/manifest.json``。

    manifest 在克隆目录**内部**是刻意的（与规划图一致），靠两道机制保证它
    不被 git 操作误伤：

    * ``git clean -fd``（不带 ``-x``）只清 untracked、不清 ignored 文件；
      克隆后立即把 ``manifest.json`` 写进该克隆的 ``.git/info/exclude``
      （本地 exclude，不污染上游 .gitignore），它就变成 ignored，clean 无视它；
    * checkout/reset 都走 ``--force`` + clean，ignored 文件同样幸免。

    若上游哪天也在根目录放 ``manifest.json``，本地读取会覆盖它但内容仍以
    我们的注册表为准——此冲突暂不处理，出现时把 manifest 挪出克隆目录即可。
    """

    def __init__(self, cfg: RepoConfig, remote_dir: str | Path) -> None:
        self.cfg = cfg
        self.remote_dir = Path(remote_dir)
        self.worktree = self.remote_dir / cfg.name
        self.manifest_path = self.worktree / "manifest.json"

    # ── 底层 git 调用 ─────────────────────────────────────────────
    def _run(self, *args: str, cwd: Path | None = None) -> str:
        """跑一条 git 命令，返回 stdout。失败抛 :class:`GitSyncError`。"""
        cmd = ["git", *args]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                timeout=GIT_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise GitSyncError("git 未安装或不在 PATH 中") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitSyncError(f"git {' '.join(args[:2])} 超时（{GIT_TIMEOUT:.0f}s）") from exc
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            detail = tail[-1] if tail else f"exit code {proc.returncode}"
            raise GitSyncError(f"git {' '.join(args[:2])} 失败: {detail}")
        return proc.stdout.decode("utf-8", "replace")

    # ── 克隆与抓取 ────────────────────────────────────────────────
    @property
    def is_cloned(self) -> bool:
        return (self.worktree / ".git").exists()

    def ensure_cloned(self) -> None:
        """没有本地克隆就克隆一份。**必须完整历史**：增量 diff 要比较任意两个
        SHA，浅克隆（--depth 1）拿不到旧对象，diff 会直接失败。"""
        if self.is_cloned:
            return
        if not self.cfg.url:
            raise GitSyncError(f"仓库 {self.cfg.name} 未配置 url")
        self.remote_dir.mkdir(parents=True, exist_ok=True)
        self._run("clone", "--branch", self.cfg.branch, self.cfg.url, str(self.worktree))
        self._protect_manifest()

    def _protect_manifest(self) -> None:
        """把 manifest.json 加进克隆的本地 exclude，使其成为 ignored 文件。

        ``git clean -fd`` 不带 -x 时只清 untracked、保留 ignored——这一行就是
        manifest 能安全住在克隆目录内的全部原因（详见类 docstring）。
        """
        exclude = self.worktree / ".git" / "info" / "exclude"
        try:
            existing = exclude.read_text(encoding="utf-8") if exclude.is_file() else ""
            if "manifest.json" not in existing:
                with exclude.open("a", encoding="utf-8") as fh:
                    if existing and not existing.endswith("\n"):
                        fh.write("\n")
                    fh.write("# flower_pow 规则版本清单（本地注册表，勿删）\nmanifest.json\n")
        except OSError:
            pass  # 保护失败不阻塞同步；clean 真删了 manifest 顶多重注册一遍

    def fetch(self) -> None:
        """只抓不合并——合并动作由上层 diff 后显式 checkout，可控且可回滚。"""
        self._run("fetch", "origin", self.cfg.branch, cwd=self.worktree)

    # ── SHA 比较 ─────────────────────────────────────────────────
    def local_sha(self) -> str | None:
        """工作区当前 HEAD 的完整 SHA。未克隆返回 None（首次全量场景）。"""
        if not self.is_cloned:
            return None
        out = self._run("rev-parse", "HEAD", cwd=self.worktree)
        return out.strip() or None

    def remote_sha(self) -> str | None:
        """``git fetch`` 之后远程分支的最新 SHA（取自 FETCH_HEAD）。"""
        out = self._run("rev-parse", "FETCH_HEAD^{commit}", cwd=self.worktree)
        return out.strip() or None

    # ── 增量 diff ─────────────────────────────────────────────────
    def diff_files(self, old_sha: str, new_sha: str) -> list[RuleChange]:
        """两个 Commit 之间的文件级变更，限定在本仓库 rule_path 内。

        返回值保持 git 输出顺序（增/改在前、删在后由 git 决定），上层只看
        status 与路径。非 YAML 文件这里**不过滤**——上层验证器会按内容判型，
        这里过滤会漏掉 `.YAML` 大写扩展名之类的边角。
        """
        if old_sha == new_sha:
            return []
        prefix = f"{self.cfg.rule_path}/" if self.cfg.rule_path else ""
        out = self._run(
            "diff", "--name-status", "--no-renames", old_sha, new_sha,
            cwd=self.worktree,
        )
        changes: list[RuleChange] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            status, path = parts[0].strip(), parts[1].strip()
            if prefix and not path.replace("\\", "/").startswith(prefix):
                continue
            changes.append(RuleChange(status=status, path=path.replace("\\", "/")))
        return changes

    # ── 工作区操作 ────────────────────────────────────────────────
    def checkout(self, sha: str) -> None:
        """把工作区切到指定 Commit（更新落地 = checkout 新 SHA）。"""
        self._run("checkout", "--force", sha, cwd=self.worktree)
        self._run("clean", "-fd", cwd=self.worktree)

    def reset_to(self, sha: str) -> None:
        """回滚：硬重置到指定 Commit。只允许回退到 state 里记录过的 SHA。"""
        self._run("reset", "--hard", sha, cwd=self.worktree)
        self._run("clean", "-fd", cwd=self.worktree)

    def list_yaml_files(self) -> list[str]:
        """当前工作区内（限定 rule_path）的全部 YAML，posix 相对路径，排序稳定。

        首次同步（无旧 SHA）与回滚后的重注册都从这里拿全量清单。
        """
        prefix = f"{self.cfg.rule_path}/" if self.cfg.rule_path else ""
        files: list[str] = []
        for pat in ("*.yaml", "*.yml"):
            files.extend(
                f.relative_to(self.worktree).as_posix()
                for f in self.worktree.rglob(pat)
            )
        out = sorted(set(files))
        if prefix:
            out = [p for p in out if p.startswith(prefix)]
        return out

    def read_file(self, repo_path: str) -> bytes:
        """读工作区内某个规则文件的原始字节（sha256 计算用）。"""
        p = (self.worktree / repo_path).resolve()
        # 防路径穿越：解析后必须仍在工作区内
        if not p.is_relative_to(self.worktree.resolve()):
            raise GitSyncError(f"非法路径: {repo_path}")
        return p.read_bytes()
