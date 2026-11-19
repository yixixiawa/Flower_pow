"""动态规则库（intel/updater）回归测试（不触网）。

用本地文件协议 git 仓库（file:// …）模拟远程，覆盖完整同步管道：

  1. 首次同步：无本地 SHA → 全量注册与发布（flower 规则进 poc/community）
  2. 增量同步：新 SHA 与本地记录相同 → up-to-date，不做任何操作
  3. 增量同步：远程新增/修改/删除 → 只处理变化的 YAML
  4. 版本演进：内容变化 version+1；未变内容重刷不涨版本号
  5. 元数据格式：rule_id/source/source_url/commit/sha256/version/status/
     first_seen/last_updated 逐字段校验
  6. 非法 YAML：被挡在门外（invalid 计数），不混进规则库
  7. 删除规则：status → removed，发布目录同步清除
  8. 回滚：回退到上一 Commit，规则内容随之还原，重发布正确
  9. 按天门控：同一天第二次 auto_update_if_due 返回 None；跨天触发
 10. CLI 装配：intel 子命令组注册成功（check/update/status/rollback/cve）
 11. index_is_stale：.yml 变化也能触发索引过期（kb/indexer 修复项）

运行：.venv/Scripts/python.exe scripts/intel_updater_test.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from intel.updater.git_sync import GitSync, GitSyncError, RepoConfig  # noqa: E402
from intel.updater.scheduler import Updater, auto_update_if_due, load_repositories  # noqa: E402
from kb.indexer import index_is_stale  # noqa: E402

FLOWER_V1 = """\
id: community-demo-rule
name: 社区规则演示
category: content_match
severity: low
description: 测试用社区规则
request:
  method: GET
  paths: ['/demo']
match:
  - patterns: ['demo-marker']
"""

FLOWER_V2 = FLOWER_V1.replace("demo-marker", "demo-marker-v2")

FLOWER_EXTRA = """\
id: community-extra-rule
name: 社区规则新增
category: content_match
severity: medium
description: 第二条规则
request:
  method: GET
  paths: ['/extra']
match:
  - patterns: ['extra-marker']
"""

BROKEN_YAML = "id: [broken\n  name: {{{"

NUCLEI_TPL = """\
id: http/cves/2021/cve-2021-demo
info:
  name: Demo Nuclei Template
  severity: high
http:
  - path: /demo
"""


def _git(*args: str, cwd: str) -> str:
    p = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True,
        stdin=subprocess.DEVNULL,
    )
    if p.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {p.stderr.strip()}")
    return p.stdout.strip()


def _init_remote(root: Path) -> tuple[Path, str]:
    """建一个本地 bare 仓库当远程，塞入第一版规则。返回 (bare路径, 首SHA)。"""
    bare = root / "remote.git"
    _git("init", "--bare", "-b", "main", "remote.git", cwd=str(root))
    work = root / "seed"
    work.mkdir()
    _git("init", "-b", "main", cwd=str(work))
    _git("config", "user.email", "test@test", cwd=str(work))
    _git("config", "user.name", "test", cwd=str(work))
    rules = work / "rules"
    rules.mkdir()
    (rules / "demo.yaml").write_text(FLOWER_V1, encoding="utf-8")
    (rules / "broken.yaml").write_text(BROKEN_YAML, encoding="utf-8")
    (rules / "nuclei-demo.yaml").write_text(NUCLEI_TPL, encoding="utf-8")
    _git("add", "-A", cwd=str(work))
    _git("commit", "-m", "v1", cwd=str(work))
    _git("remote", "add", "origin", bare.as_uri(), cwd=str(work))
    _git("push", "-u", "origin", "main", cwd=str(work))
    return bare, _git("rev-parse", "HEAD", cwd=str(work))


def _commit_remote(work: Path, message: str) -> str:
    _git("add", "-A", cwd=str(work))
    _git("commit", "-m", message, cwd=str(work))
    _git("push", "origin", "main", cwd=str(work))
    return _git("rev-parse", "HEAD", cwd=str(work))


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    with tempfile.TemporaryDirectory(prefix="intel_test_") as tmp:
        root = Path(tmp)
        bare, sha1 = _init_remote(root)

        data_dir = root / "data" / "updater"
        remote_dir = root / "remote_rules"
        publish_dir = root / "poc" / "community"

        # 仓库配置：指向本地 bare 仓库
        (data_dir).mkdir(parents=True)
        (data_dir / "repositories.json").write_text(
            json.dumps(
                {
                    "repositories": [
                        {
                            "name": "community-poc",
                            "url": bare.as_uri(),
                            "branch": "main",
                            "enabled": True,
                            "rule_path": "rules/",
                            "auto_update": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        upd = Updater(data_dir, remote_dir, publish_dir)
        check(len(upd.repos) == 1, "repositories.json 装载", str(upd.repos))

        # ── 1. 首次同步：全量 ──
        r1 = upd.update()[0]
        check(r1["status"] == "updated", "首次同步状态 updated", r1)
        check(r1["added"] == 2, "首次新增 2 条（flower+nuclei）", r1)
        check(r1["invalid"] == 1, "坏 YAML 被挡在门外", r1)
        reg = upd._registry(upd.repos[0], GitSync(upd.repos[0], remote_dir))
        check(reg.rules.get("community-demo-rule", {}).get("version") == 1, "新规则 version=1")
        check(
            reg.rules.get("http/cves/2021/cve-2021-demo", {}).get("kind") == "nuclei",
            "nuclei 模板登记且不发布",
        )
        demo = publish_dir / "community-poc" / "community-demo-rule.yaml"
        check(demo.is_file(), "flower 规则发布到 poc/community")
        check(
            not (publish_dir / "community-poc" / "nuclei-demo.yaml").exists(),
            "nuclei 模板不发布",
        )
        manifest = json.loads(
            (remote_dir / "community-poc" / "manifest.json").read_text(encoding="utf-8")
        )
        e1 = manifest["rules"]["community-demo-rule"]
        # ── 5. 元数据格式逐字段校验 ──
        required_keys = [
            "rule_id", "source", "source_url", "commit", "sha256",
            "version", "status", "first_seen", "last_updated",
        ]
        check(all(k in e1 for k in required_keys), "版本元数据字段齐全", list(e1))
        check(e1["source"] == "community-poc", "source = 仓库名")
        check(e1["commit"] == sha1, "commit 记录远程 SHA")
        check(e1["status"] == "approved", "status 初始 approved")
        check(len(e1["sha256"]) == 64, "sha256 长度合法")
        check(e1["version"] == 1, "version 初始 1")

        # state.json 已记录 SHA
        state = json.loads((data_dir / "state.json").read_text(encoding="utf-8"))
        check(state["repos"]["community-poc"]["last_commit"] == sha1, "state 记录 Commit SHA")
        hist = json.loads((data_dir / "history.json").read_text(encoding="utf-8"))
        check(len(hist) == 1 and hist[0]["action"] == "update", "history 记录更新事件")

        # ── 2. 无变化：跳过 ──
        r2 = upd.update()[0]
        check(r2["status"] == "up-to-date", "SHA 相同则跳过", r2)
        check(r2["added"] == 0 and r2["updated"] == 0, "跳过时不做任何操作")

        # ── 3. 增量：新增 + 修改 ──
        work = root / "seed"
        rules = work / "rules"
        (rules / "extra.yaml").write_text(FLOWER_EXTRA, encoding="utf-8")
        (rules / "demo.yaml").write_text(FLOWER_V2, encoding="utf-8")
        sha2 = _commit_remote(work, "v2: add extra, change demo")

        # check 先行（只看不改）
        pend = upd.check()[0]
        check(not pend["up_to_date"], "check 发现远程有更新")
        check(pend["pending_yaml"] == 2, "check 报告待处理 YAML 数", pend)

        r3 = upd.update()[0]
        check(r3["status"] == "updated", "增量同步执行", r3)
        check(r3["added"] == 1 and r3["updated"] == 1, "只处理变化的 2 个文件", r3)
        reg.load()
        e2 = reg.rules["community-demo-rule"]
        check(e2["version"] == 2, "内容变化 version+1", e2)
        check(e2["commit"] == sha2, "元数据 commit 刷新")
        check(e2["sha256"] != e1["sha256"], "sha256 随内容变化")
        check(e2["first_seen"] == e1["first_seen"], "first_seen 保持不变")
        published = (publish_dir / "community-poc" / "community-demo-rule.yaml").read_text(
            encoding="utf-8"
        )
        check("demo-marker-v2" in published, "发布内容同步为新版本")

        # ── 4. 未变内容重刷不涨版本号（force 全量重注册同一份内容）──
        (rules / "untouched.yaml").write_text(
            FLOWER_V1.replace("community-demo-rule", "community-untouched-rule"),
            encoding="utf-8",
        )
        _commit_remote(work, "v3: add untouched")
        upd.update()
        reg.load()
        check(
            reg.rules["community-untouched-rule"]["version"] == 1,
            "新规则独立 version=1",
        )
        upd.update(force=True)
        reg.load()
        check(reg.rules["community-demo-rule"]["version"] == 2, "同内容重注册 version 不涨")

        # ── 7. 远程删除 → removed ──
        sha3 = _git("rev-parse", "HEAD", cwd=str(work))  # v3 的 SHA（回滚目标）
        (rules / "extra.yaml").unlink()
        _commit_remote(work, "v4: remove extra")
        r4 = upd.update()[0]
        check(r4["removed"] == 1, "远程删除计入 removed", r4)
        reg.load()
        check(reg.rules["community-extra-rule"]["status"] == "removed", "下架状态落盘")
        check(
            not (publish_dir / "community-poc" / "community-extra-rule.yaml").exists(),
            "下架规则从发布目录清除",
        )

        # ── 8. 回滚（无 --to → 回退到上一已同步 Commit，即 v3）──
        rb = upd.rollback("community-poc")
        check(rb["to_commit"] == sha3[:12], "回滚到上一个已同步 Commit", rb)
        reg.load()
        check(reg.rules["community-extra-rule"]["status"] == "approved", "回滚后规则复活")
        published = (publish_dir / "community-poc" / "community-demo-rule.yaml").read_text(
            encoding="utf-8"
        )
        check("demo-marker-v2" in published, "回滚后内容还原到目标版本")
        state = json.loads((data_dir / "state.json").read_text(encoding="utf-8"))
        check(state["repos"]["community-poc"]["last_commit"] == sha3, "state 记录回滚目标")

        # 回滚目标必须是记录过的 Commit
        try:
            upd.rollback("community-poc", to="deadbeef" * 2)
            check(False, "盲回滚被拒绝")
        except GitSyncError:
            check(True, "盲回滚被拒绝")

        # ── 9. 按天门控 ──
        class FakeIntel:
            pass

        FakeIntel.auto_update = True
        FakeIntel.data_dir = str(data_dir)
        FakeIntel.remote_dir = str(remote_dir)
        FakeIntel.publish_dir = str(publish_dir)

        class FakeCfg:
            pass

        FakeCfg.data_dir = str(root / "data")
        FakeCfg.intel = FakeIntel

        # 回滚停在 v3：先同步到 v4（把删除落完），再测门控
        upd.update()
        state = json.loads((data_dir / "state.json").read_text(encoding="utf-8"))
        sha4 = state["repos"]["community-poc"]["last_commit"]

        # 已是最新 → 无 touched → 返回 None，但 last_auto_check 已写
        r = auto_update_if_due(FakeCfg())
        check(r is None, "无更新时返回 None")
        state = json.loads((data_dir / "state.json").read_text(encoding="utf-8"))
        check(bool(state.get("last_auto_check")), "触发后记录当天日期")
        # 同一天第二次：直接跳过（模拟远程有更新也绝不执行）
        (rules / "demo.yaml").write_text(FLOWER_V1, encoding="utf-8")
        _commit_remote(work, "v5: should not sync today")
        r = auto_update_if_due(FakeCfg())
        check(r is None, "同一天不重复触发")
        state = json.loads((data_dir / "state.json").read_text(encoding="utf-8"))
        check(state["repos"]["community-poc"]["last_commit"] == sha4, "同天内 SHA 未变")
        # 跨天：把 last_auto_check 改成昨天
        state["last_auto_check"] = "2000-01-01"
        (data_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        r = auto_update_if_due(FakeCfg())
        check(r is not None, "跨天后触发更新")
        reg.load()
        # 未克隆的仓库不参与自动更新：清掉克隆验证门槛
        upd2 = Updater(data_dir, remote_dir, publish_dir)
        check(all(s["repo"] == "community-poc" for s in upd2.status()), "status 覆盖全部仓库")

        # ── 10. CLI 装配 ──
        from cli.app import app as typer_app  # noqa: E402
        import typer  # noqa: E402

        names = set()
        for grp in typer_app.registered_groups:
            names.add(grp.name)
        check("intel" in names, "intel 子命令组已注册", names)
        intel_grp = next(g for g in typer_app.registered_groups if g.name == "intel")
        sub_names = {c.name for c in intel_grp.typer_instance.registered_commands}
        check(
            {"check", "update", "status", "rollback", "cve"} <= sub_names,
            "intel 子命令齐全",
            sub_names,
        )
        # 旧 intel 单命令不再注册（避免撞名）
        check(not ({"intel"} & {c.name for c in typer_app.registered_commands}), "旧 intel 单命令已移除")

        # ── 11. index_is_stale 支持 .yml ──
        with tempfile.TemporaryDirectory(prefix="stale_") as t2:
            pdir = Path(t2)
            db = pdir / "index.json"
            db.write_text("{}", encoding="utf-8")
            (pdir / "a.yml").write_text("id: yml-only\nname: y", encoding="utf-8")
            time.sleep(0.05)
            (pdir / "a.yml").write_text("id: yml-only2\nname: y", encoding="utf-8")
            check(index_is_stale(pdir, db), ".yml mtime 变化触发索引过期")
            db.write_text("{}", encoding="utf-8")
            import os

            os.utime(pdir / "a.yml", (1, 1))
            check(not index_is_stale(pdir, db), "无更新时不触发过期")

    # load_repositories 种子写入
    with tempfile.TemporaryDirectory(prefix="intel_seed_") as t3:
        repos, warns = load_repositories(Path(t3))
        check(len(repos) == 2 and not warns, "缺省 repositories.json 自动生成种子", warns)

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
