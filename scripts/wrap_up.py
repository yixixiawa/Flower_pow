"""收尾提交：一轮改动的 ``git add .`` + ``git commit``，标题写清这轮改了什么。

为什么要有这个脚本（而不是手敲 git 命令）——本仓库真实发生过两次
"提交了却没提交到"的事故：

1. **源码被 .gitignore 误伤，从未入库**：``output/report/*.py``（报告
   写入器）曾被 ``output/`` 整目录规则排除，手敲 ``git add .`` 看起来
   "全收了"，其实源码一个都没进——新克隆直接 ImportError，历轮对
   paths/markdown/json/html 的修改只存在于本地磁盘。
2. **带着挂起的测试提交**：``agent_loop_test`` 场景 2 曾因一次缩进
   改动（循环守卫的 clear+continue 被挪出 if 块）无限循环，当时
   ``git add . && git commit`` 照常执行——回归是红的，提交是绿的。

所以收尾必须是**带门禁的例行仪式**，不是随手两条命令：

    .venv/Scripts/python.exe scripts/wrap_up.py "这轮改了哪些功能点" \\
        -m "怎么改的、为什么（第一点）" -m "第二点"

流程：
  1. 确认在 git 仓库内、工作区有改动（干净则直接退出，不算失败）
  2. ``git status --short`` + ``git diff --stat``：**先看清这轮改了什么**，
     标题要对着这份清单写，不许凭印象
  3. 门禁（默认全开；任一失败即中止，**不做 add 也不 commit**）：
       - compileall：编译 git 已知 + 未跟踪的全部 .py（新文件不漏）
       - secret_scan.py：凭据泄漏自检
       - run_tests.py：全量回归（``--quick`` 跳过）
  4. ``git add .``（.gitignore 已保证产物/凭据/记忆日志不会混入）
  5. 安全网：add 之后仍未跟踪的 .py（被 .gitignore 误伤的源码）与被
     忽略的 .py 一律列出来警告——不让"看似全收了其实漏了源码"再次
     静默发生
  6. ``git commit -m 标题 [-m 正文...]``
  7. ``git show --stat HEAD`` 汇报这轮实际收了哪些文件

选项：
  -m/--body   追加一段正文（可重复）。标题说"改了哪些功能点与方法"，
              正文展开每点的根因/做法/验证
  --quick     只跑编译 + 密钥扫描，跳过全量回归——仅限纯文档/纯注释
              改动；动了代码就别用
  --force     跳过全部门禁（**仅限你已手工跑过回归并确认绿了**）
  --dry-run   只展示状态与将执行的命令，不 add 不 commit 不跑门禁
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
# 这些目录里的 .py 是归档/第三方运行环境，不是本项目源码：
# 被 .gitignore 误伤的审计要把它们排除掉，否则每次收尾都刷一堆噪音
_NOT_SOURCE = ("__pycache__", ".venv", ".backup", "site-packages")


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """在仓库根目录执行 git，失败时打印 stderr 并以退出码 1 中止。"""
    try:
        p = subprocess.run(
            ["git", *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        print("找不到 git 可执行文件——先装 Git for Windows 并确保在 PATH 里。")
        raise SystemExit(1) from None
    if check and p.returncode != 0:
        print(f"git {' '.join(args)} 失败：\n{p.stderr.strip()}")
        raise SystemExit(1)
    return p


def _py_files() -> list[str]:
    """git 已知的 + 未跟踪且未被忽略的全部 .py（新文件也要过编译门禁）。"""
    tracked = _git("ls-files", "-z", "--", "*.py").stdout.split("\0")
    fresh = _git(
        "ls-files", "--others", "--exclude-standard", "-z", "--", "*.py"
    ).stdout.split("\0")
    return sorted({p for p in tracked + fresh if p})


def _run_gate(name: str, argv: list[str]) -> bool:
    """跑一道门禁，打印尾部输出；通过返回 True，失败返回 False。"""
    print(f"\n▸ 门禁：{name}")
    p = subprocess.run(
        [PY, *argv],
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,   # 补全类测试会等 stdin，必须堵死
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for ln in (p.stdout or "").strip().splitlines()[-8:]:
        print(f"  {ln}")
    if p.returncode != 0:
        for ln in (p.stderr or "").strip().splitlines()[-4:]:
            print(f"  {ln}")
        print(f"  ✗ {name} 未通过 —— 中止提交（未做 git add，工作区原样）")
        return False
    print(f"  ✓ {name} 通过")
    return True


def _gates(quick: bool) -> bool:
    """默认三门禁：编译 + 密钥扫描 + 全量回归。任一不过即中止。"""
    if not _run_gate("编译检查", ["-m", "compileall", "-q", *_py_files()]):
        return False
    if not _run_gate("密钥扫描", ["scripts/secret_scan.py"]):
        return False
    if quick:
        print("  （--quick：跳过全量回归）")
        return True
    return _run_gate("全量回归", ["scripts/run_tests.py"])


def _audit_orphan_py() -> None:
    """add 之后仍游离在版本控制之外的 .py，列出来明确警告。

    两种漏法都要防：
    - ``??``：未跟踪且未被忽略（add . 没收到的边缘情况）
    - 被 .gitignore 忽略的 .py（output/report/*.py 事故的形态：
      曾经整目录 output/ 被排除，源码从未入库也无人察觉）
    """
    leftover = _git("status", "--porcelain").stdout.splitlines()
    orphans = [
        ln for ln in leftover
        if ln.startswith("??") and ln[3:].strip().endswith(".py")
    ]
    if orphans:
        print("\n⚠ add 之后仍有未跟踪的 .py：")
        for ln in orphans:
            print(f"    {ln}")
        print("  确认是否该入库（git add -f），别让源码静默漏掉。")

    ignored = (
        _git(
            "ls-files", "--others", "--ignored", "--exclude-standard",
            "-z", "--", "*.py",
        ).stdout.split("\0")
    )
    suspicious = [
        p for p in ignored
        if p and not any(bad in p for bad in _NOT_SOURCE)
    ]
    if suspicious:
        print("\n⚠ 有 .py 被 .gitignore 忽略（若是源码，属于误伤，要修 .gitignore）：")
        for p in suspicious:
            print(f"    {p}")
        print("  参考事故：output/report/*.py 曾被 output/ 整目录规则排除，从未入库。")


def _usage() -> None:
    print(__doc__)
    raise SystemExit(2)


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    title = ""
    bodies: list[str] = []
    quick = force = dry = False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-m", "--body"):
            if i + 1 >= len(args):
                print(f"{a} 缺参数")
                return 2
            bodies.append(args[i + 1])
            i += 2
        elif a == "--quick":
            quick = True
            i += 1
        elif a == "--force":
            force = True
            i += 1
        elif a == "--dry-run":
            dry = True
            i += 1
        elif a in ("-h", "--help"):
            _usage()
        elif a.startswith("-"):
            print(f"不认识的选项：{a}")
            return 2
        elif not title:
            title = a
            i += 1
        else:
            print(f"只能有一个标题参数（已收到 {title!r}，又来了 {a!r}）")
            return 2

    if not title.strip():
        print("缺少提交标题。标题要写清这轮改了哪些功能点与方法，例如：")
        print('  "修复循环守卫缩进失效；新增 wrap_up.py 收尾提交脚本"')
        return 2

    if _git("rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        print("当前目录不在 git 工作区内")
        return 1

    dirty = _git("status", "--porcelain").stdout.strip()
    if not dirty:
        print("工作区干净，没有可提交的改动。")
        return 0

    print("这轮的改动（标题对着这份清单写）：")
    print(_git("status", "--short").stdout.rstrip())
    stat = _git("diff", "--stat", "HEAD").stdout.strip()
    if stat:
        print()
        print(stat)

    if dry:
        print("\n--dry-run：将执行 git add . 后 git commit -m "
              f"{title!r}" + (f" + {len(bodies)} 段正文" if bodies else ""))
        print("（未跑门禁、未 add、未 commit）")
        return 0

    if not force and not _gates(quick):
        return 1

    _git("add", ".")
    staged = _git("diff", "--cached", "--stat").stdout.strip()
    if not staged:
        print("\nadd 之后暂存区是空的——改动全被 .gitignore 排除了？")
        print("检查 .gitignore 是否误伤源码（output/report/*.py 事故的形态）。")
        return 1
    print("\n即将提交：")
    print(staged)

    _audit_orphan_py()

    cmd = ["commit", "-m", title.strip()]
    for b in bodies:
        cmd += ["-m", b]
    p = _git(*cmd)
    print(p.stdout.rstrip())

    print("\n提交结果：")
    print(_git("log", "-1", "--stat", "--format=%h %s").stdout.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
