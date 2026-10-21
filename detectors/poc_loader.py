"""POC YAML 加载器：把 ``poc/*.yaml`` 编译成可执行的 :class:`POC` 对象。

YAML 结构
---------
.. code-block:: yaml

    id: path-env                       # 唯一ID，报告与去重靠它
    name: 环境配置文件泄露 (.env)
    category: path_probe# 决定用哪个 detector
    severity: critical                 # info|low|medium|high|critical
    description: ...
    remediation: ...
    applies_to: [php, nodejs]          # 技术栈命中时优先
    tags: [disclosure, secret]
    cve: [CVE-2021-44228]
    intrusive: false                   # true = 只读模式下跳过
    request:                # 请求模板
      method: GET
      paths: ['.env', '.env.local']
      headers: {Cookie: 'rememberMe=1'}
      params: {}
      expect_status: [200, 401, 403]
    match:# 匹配规则（全部满足才算命中）
      - patterns: ['=', 'secret']
        match_all: false
        soft_404: ['404 not found']    # 命中即视为软 404 → 抑制

    # 响应头专用（category: header_check），op 语义见 MatchOp
    match:
      - op: missing                    # 该响应头不存在即命中
        target: header
        header: content-security-policy
      - op: absent                     # 头存在但缺少 value_regex 内容
        target: header
        header: set-cookie
        value_regex: httponly
      - op: contains                # 头存在且匹配 value_regex
        target: header
        header: server
        value_regex: "[0-9]+\\.[0-9]+"   # 注意 YAML 里反斜杠要转义

加载策略：**静默跳过坏文件并收集错误**，不让一个 YAML 语法错误让整次扫描失败。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.state import Category, POC

_REQUIRED = ("id", "name")


def parse_poc_file(path: str | Path) -> POC:
    """解析单个 YAML 文件为 POC。失败抛异常由上层收集。"""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("顶层不是映射（YAML 应为 key: value 结构）")
    for k in _REQUIRED:
        if not raw.get(k):
            raise ValueError(f"缺少必填字段: {k}")
    raw.setdefault("category", "content_match")
    raw.setdefault("severity", "info")
    try:
        return POC.from_dict(raw, source=str(p))
    except ValueError as exc:
        raise ValueError(f"字段非法: {exc}") from exc


def load_poc_dir(poc_dir: str | Path) -> tuple[list[POC], list[str]]:
    """加载目录下所有 POC。

    返回 ``(pocs, errors)``。同名 ID 后加载的会覆盖先加载的并在 errors 里提示——
    这比静默覆盖安全。
    """
    d = Path(poc_dir)
    errors: list[str] = []
    if not d.is_dir():
        return [], [f"POC 目录不存在: {d}"]

    by_id: dict[str, POC] = {}
    files = sorted([*d.rglob("*.yaml"), *d.rglob("*.yml")])
    for f in files:
        if f.name.startswith("_"):  # _ 开头的当模板/笔记，不加载
            continue
        try:
            poc = parse_poc_file(f)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[poc] 跳过 {f.name}: {type(exc).__name__}: {exc}")
            continue
        if poc.id in by_id:
            errors.append(f"[poc] ID 重复 '{poc.id}'：{f.name} 覆盖了 {by_id[poc.id].source}")
        by_id[poc.id] = poc

    return list(by_id.values()), errors


def load_poc_map(poc_dir: str | Path) -> tuple[dict[str, POC], list[str]]:
    """同:func:`load_poc_dir`，但返回 ``{id: POC}``。"""
    pocs, errors = load_poc_dir(poc_dir)
    return {p.id: p for p in pocs}, errors


# 由专用探测器执行的类别：它们需要"按接口填参数、命中即停"的动态逻辑，
# HttpDetector 只会做静态路径探测，跑了也毫无意义（还会产生假阴性）。
_DEDICATED_CATEGORIES = frozenset(
    {Category.INJECTION, Category.RCE, Category.FILE_OP, Category.JS_LOGIC}
)


def filter_executable(
    pocs: list[POC], readonly: bool = True, min_severity_rank: int = 0
) -> tuple[list[POC], list[str]]:
    """按只读模式与最低危险等级过滤出可执行的 POC。

    返回 ``(pocs, skip_reasons)``——后者会写进报告，让"没跑什么"也可追溯。
    """
    from core.state import Severity

    reasons: list[str] = []
    out: list[POC] = []
    for p in pocs:
        if p.category is Category.FINGERPRINT:
            reasons.append(f"{p.id}: 指纹类，不作为验证项")
            continue
        if p.category in _DEDICATED_CATEGORIES:
            reasons.append(f"{p.id}: 由专用探测器执行（{p.category.value}），不参与静态路径探测")
            continue
        if readonly and p.intrusive:
            reasons.append(f"{p.id}: 需写操作，只读模式跳过")
            continue
        if p.severity.rank < min_severity_rank:
            reasons.append(f"{p.id}: 低于最低等级门槛")
            continue
        if p.intrusive:
            reasons.append(f"{p.id}: 写操作模式（已明确启用）")
        out.append(p)
    return out, reasons