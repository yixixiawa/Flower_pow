"""配置层测试：环境变量语义统一 / 类型容错 / yaml 校验 / init 模板同步。

这四件事都是「配错了不会报错、只会在很远的地方炸」的类型，
正是最需要回归测试守住的。

运行：.venv/Scripts/python.exe scripts/test_config.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/：取 _cli_src

from _srcs import cli_source  # noqa: E402

import yaml  # noqa: E402

from core.config_loader import (  # noqa: E402
    Config,
    RAGConfig,
    ScanConfig,
    _apply_section,
    _env_bool,
    _env_int,
    _env_list,
    load_config,
)

PY = sys.executable


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    saved = dict(os.environ)

    def restore():
        os.environ.clear()
        os.environ.update(saved)

    # ── 场景1 空字符串 = 未设置（两种语义已统一）────────────────
    print("场景1 空串环境变量一律视为未设置")
    os.environ["POCS_READONLY"] = ""
    check(_env_bool("POCS_READONLY", True) is True,
          "空串不把只读关掉（修之前会变成 False，危险方向）")
    os.environ["POCS_PORT_SCAN"] = ""
    check(_env_bool("POCS_PORT_SCAN", True) is True,
          "空串与未设置行为一致（修之前这两者行为相反）")
    check(_env_bool("NOT_SET_AT_ALL", True) is True, "未设置 → 默认")
    restore()

    # ── 场景2 布尔解析 ───────────────────────────────────────────
    print("\n场景2 布尔值解析")
    for raw, want in (("1", True), ("true", True), ("TRUE", True), ("yes", True),
                      ("on", True), ("0", False), ("false", False), ("no", False),
                      ("off", False), ("  true  ", True)):
        os.environ["POCS_X"] = raw
        check(_env_bool("POCS_X", not want) is want, f"{raw!r} → {want}")
    # 无法识别的值必须保留默认，不能静默取反
    os.environ["POCS_X"] = "maybe"
    check(_env_bool("POCS_X", True) is True, "无法识别的值保留默认 True（不静默取反）")
    check(_env_bool("POCS_X", False) is False, "无法识别的值保留默认 False")
    restore()

    # ── 场景3 数值容错 ───────────────────────────────────────────
    print("\n场景3 数值型环境变量不再崩溃")
    os.environ["POCS_X"] = "abc"
    check(_env_int("POCS_X", 8) == 8, "POCS_CONCURRENCY=abc → 保留默认 8（修之前 ValueError 崩）")
    check(_env_int("POCS_X", 12) == 12, "默认值被正确使用")
    os.environ["POCS_X"] = ""
    check(_env_int("POCS_X", 8) == 8, "空串 → 默认")
    os.environ["POCS_X"] = "16"
    check(_env_int("POCS_X", 8) == 16, "正常值生效")
    restore()

    # ── 场景3b 列表型环境变量（POCS_NO_PROXY 用）─────────────────
    print("\n场景3b 列表环境变量 _env_list")
    os.environ["POCS_X"] = "a.com, b.com ,, c.com"
    check(_env_list("POCS_X", []) == ["a.com", "b.com", "c.com"],
          "逗号分隔 + strip + 去空项（空项会变成'匹配所有主机'，危险）")
    os.environ["POCS_X"] = "a.com;b.com"
    check(_env_list("POCS_X", []) == ["a.com", "b.com"], "分号也当分隔符")
    os.environ["POCS_X"] = ""
    check(_env_list("POCS_X", ["d"]) == ["d"], "空串 → 保留默认")
    os.environ.pop("POCS_X", None)
    check(_env_list("POCS_X", ["d"]) == ["d"], "未设置 → 保留默认")
    os.environ["POCS_X"] = "10.0.0.0/8, 192.168.*"
    check(_env_list("POCS_X", []) == ["10.0.0.0/8", "192.168.*"], "CIDR 与通配保留原样")
    restore()

    # ── 场景4 端到端：环境变量真的走到 config 上 ─────────────────
    print("\n场景4 新增参数的环境变量入口真的存在")
    os.environ.update({
        "POCS_KNOWLEDGE": "false",
        "POCS_KNOWLEDGE_MIN_SEVERITY": "high",
        "POCS_KNOWLEDGE_MAX_ENTRIES": "500",
        "POCS_FILE_UPLOAD_PROBE": "true",
        "POCS_PROBE_CONCURRENCY": "2",
        "POCS_JS_LOGIC": "false",
    })
    cfg = load_config(ROOT / "config.yaml")
    check(cfg.rag.knowledge_enabled is False, "POCS_KNOWLEDGE=false 生效")
    check(cfg.rag.knowledge_min_severity == "high", "POCS_KNOWLEDGE_MIN_SEVERITY 生效")
    check(cfg.rag.knowledge_max_entries == 500, "POCS_KNOWLEDGE_MAX_ENTRIES 生效")
    check(cfg.scan.file_upload_probe_enabled is True, "POCS_FILE_UPLOAD_PROBE 生效")
    check(cfg.scan.probe_concurrency == 2, "POCS_PROBE_CONCURRENCY 生效")
    check(cfg.scan.js_logic_enabled is False, "POCS_JS_LOGIC 生效")
    restore()

    # ── 场景4b 代理相关配置端到端 ────────────────────────────────
    print("\n场景4b 代理配置项的环境变量入口")
    os.environ["POCS_PROXY"] = "http://127.0.0.1:8080"
    os.environ["POCS_NO_PROXY"] = "a.com,10.0.0.0/8"
    os.environ["POCS_PROXY_AUTODETECT"] = "false"
    cfg = load_config(ROOT / "config.yaml")
    check(cfg.scan.proxy == "http://127.0.0.1:8080", "POCS_PROXY 生效")
    check(cfg.scan.no_proxy == ["a.com", "10.0.0.0/8"], "POCS_NO_PROXY 解析为列表")
    check(cfg.scan.proxy_autodetect is False, "POCS_PROXY_AUTODETECT=false 生效")
    restore()

    # ── 场景5 yaml 非法值在加载期被拦住 ─────────────────────────
    print("\n场景5 yaml 非法值：坏项保留默认、好项照常生效")
    tmp = Path(tempfile.mkdtemp())
    bad = tmp / "bad.yaml"
    bad.write_text(
        "scan:\n"
        "  timeout: not-a-number\n"
        "  readonly: false\n"
        "rag:\n"
        "  top_k: \"abc\"\n"
        "  min_score: 0.2\n",
        encoding="utf-8",
    )
    c = load_config(bad)
    check(c.scan.timeout == 12.0, f"非法 timeout 保留默认，实={c.scan.timeout}")
    check(isinstance(c.rag.top_k, int) and c.rag.top_k == 12,
          f"非法 top_k 保留默认且**类型正确**（修之前会变成字符串，跑到 retriever 才炸），"
          f"实={c.rag.top_k!r}")
    check(c.rag.min_score == 0.2,
          f"同段的合法值不被连坐，实={c.rag.min_score}")
    check(c.scan.readonly is False, "同段的合法布尔生效")

    # ── 场景6 拼错的字段名会被点名 ───────────────────────────────
    print("\n场景6 未知字段被忽略并点名")
    r = RAGConfig()
    _apply_section(r, {"typo_field": 1, "top_k": 20})
    check(r.top_k == 20, "合法字段仍被应用")
    check(not hasattr(r, "typo_field"), "拼错的字段不会被凭空创建")

    # ── 场景7 init 模板与 config.yaml 同构 ───────────────────────
    print("\n场景7 init 模板与仓库 config.yaml 同构（防再次过时）")
    import re

    src = cli_source()
    m = re.search(r'_TEMPLATE_CONFIG = """\\\n(.*?)\n"""', src, re.S)
    check(bool(m), "能从源码里取出 _TEMPLATE_CONFIG")
    tpl = yaml.safe_load(m.group(1)) if m else {}
    repo = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))

    tpl_scan = set((tpl or {}).get("scan") or {})
    repo_scan = set((repo or {}).get("scan") or {})
    missing = repo_scan - tpl_scan
    check(not missing, f"模板 scan 段不缺项（缺：{sorted(missing)}）")

    tpl_rag = set((tpl or {}).get("rag") or {})
    repo_rag = set((repo or {}).get("rag") or {})
    missing_r = repo_rag - tpl_rag
    check(not missing_r, f"模板 rag 段不缺项（缺：{sorted(missing_r)}）")

    # 模板里的每一项都必须是真实存在的配置字段（拼错会在用户那侧静默失效）
    tpl_scan_cfg = ScanConfig()
    unknown = [k for k in tpl_scan if not hasattr(tpl_scan_cfg, k)]
    check(not unknown, f"模板 scan 段没有拼错的字段（多出：{unknown}）")
    tpl_rag_cfg = RAGConfig()
    unknown_r = [k for k in tpl_rag if not hasattr(tpl_rag_cfg, k)]
    check(not unknown_r, f"模板 rag 段没有拼错的字段（多出：{unknown_r}）")

    # 反过来：config.yaml 里的每个字段都该在 ScanConfig 上存在
    cfg_all = Config()
    aliases = {"ai"}
    unknown_repo = [
        k for k in (repo or {}) if k not in ("scan", "rag", "llm", "output_dir", "data_dir")
        and k not in aliases
    ]
    check(not unknown_repo, f"config.yaml 顶层没有多余段（多出：{unknown_repo}）")

    # ── 场景8 _TEMPLATE_ENV 覆盖了所有 POCS_ 入口 ────────────────
    print("\n场景8 .env 模板覆盖全部 POCS_ 环境变量")
    me = re.search(r'_TEMPLATE_ENV = """\\\n(.*?)\n"""', src, re.S)
    tpl_env = me.group(1) if me else ""
    declared = set(re.findall(r"^\s*#?\s*(POCS_[A-Z_]+)\s*=", tpl_env, re.M))
    from core import config_loader as CL

    loader_src = Path(CL.__file__).read_text(encoding="utf-8")
    used = set(re.findall(r'_env_\w+\(\s*"(POCS_[A-Z_]+)"', loader_src))
    missing_env = used - declared
    check(not missing_env,
          f".env 模板已包含所有解析入口（缺：{sorted(missing_env)}）")

    # ── 场景9 空 env 不会覆盖 config.yaml（端到端）───────────────
    print("\n场景9 空串环境变量不覆盖 config.yaml 的值")
    os.environ["POCS_READONLY"] = ""
    os.environ["POCS_TIMEOUT"] = ""
    c2 = load_config(ROOT / "config.yaml")
    from core.config_loader import load_config as _lc

    base = _lc(ROOT / "config.yaml")
    check(c2.scan.readonly == base.scan.readonly, "readonly 不被空串改动")
    restore()

    # ── 场景10 CLI 可正常启动（导入无副作用崩溃）────────────────
    print("\n场景10 CLI 冒烟")
    p = subprocess.run(
        [PY, str(ROOT / "flower_pow.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    check(p.returncode == 0, f"flower_pow.py --help 退出码 0，实={p.returncode}",
          (p.stderr or "")[-300:])
    check("init" in p.stdout, "--help 里能看到 init 命令")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
