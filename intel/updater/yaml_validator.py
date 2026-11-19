"""YAML 规则验证器 —— 同步管道的第二道闸门。

从远程仓库拉下来的 YAML **不能直接信**：语法坏、字段缺、ID 撞车都会把
扫描链路拖垮（``detectors.poc_loader`` 的哲学是"坏文件静默跳过并收集错误"，
但更新器应该把坏规则**挡在门外**并明确报告，而不是让它们混进本地规则库
之后才在扫描时报错）。

验证分三步（与规划图一致）：

1. **语法检查** —— ``yaml.safe_load`` 能不能过；
2. **Schema 检查** —— 按规则形态校验必需字段；
3. **ID 去重** —— 同一仓库内 rule_id 撞车视为无效（后到的报错）。

规则形态自动判型
----------------
外部仓库可能混着两种 YAML：

* **flower 形态**（本项目 POC Schema，``id``/``name``/``request``/``match``…）
  —— 验证通过后会被**发布**到 ``poc/community/`` 参与扫描与 RAG 索引；
* **nuclei 形态**（``id`` + ``info.name``/``info.severity`` + ``http.steps``…）
  —— 引擎暂不能直接执行，登记进版本清单留作情报/RAG 参考，不发布。

判型规则：有 ``info`` 映射 → nuclei；否则按 flower Schema 验证。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

# flower 形态的必填字段（与 detectors.poc_loader._REQUIRED 对齐，name 必须有）
_FLOWER_REQUIRED = ("id", "name")
# nuclei 形态的必填字段
_NUCLEI_REQUIRED = ("id", "info")


@dataclass(slots=True)
class ValidationResult:
    """单文件验证结果。kind = flower / nuclei / invalid。"""

    ok: bool
    kind: str  # flower | nuclei | invalid
    rule_id: str  # 验证通过时非空
    error: str = ""  # 失败原因（给 history 与 CLI 展示）


def _parse_yaml(text: bytes | str) -> dict:
    """safe_load 并要求顶层是映射。失败抛异常由调用方收集。"""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("顶层不是映射（YAML 应为 key: value 结构）")
    return raw


def _validate_nuclei(raw: dict) -> str:
    """nuclei 模板校验：id + info.name。返回 rule_id。"""
    for k in _NUCLEI_REQUIRED:
        if not raw.get(k):
            raise ValueError(f"nuclei 模板缺少必填字段: {k}")
    info = raw["info"]
    if not isinstance(info, dict) or not info.get("name"):
        raise ValueError("nuclei 模板 info.name 缺失")
    rid = str(raw["id"]).strip()
    # nuclei 官方模板 id 形如 http/cves/2023/CVE-2023-xxxx —— 保持原样，
    # 与用户规划的 rule_id 示例 "http/example-detection" 形态一致
    return rid


def _validate_flower(raw: dict) -> str:
    """flower POC Schema 校验：走正式加载器，保证发布出去一定能被扫描执行。

    复用 :func:`detectors.poc_loader.parse_poc_file` 的字段语义——验证标准
    与运行时加载标准**必须是同一份**，否则"验证通过、扫描报错"。
    """
    from detectors.poc_loader import parse_poc_file  # 延迟导入避免循环

    for k in _FLOWER_REQUIRED:
        if not raw.get(k):
            raise ValueError(f"缺少必填字段: {k}")
    rid = str(raw["id"]).strip()
    if "/" in rid:
        # flower POC 的 id 约定不带路径分隔（nuclei 才带），
        # 带了会和发布目录结构冲突，提前挡掉
        raise ValueError("flower POC 的 id 不应包含 '/'")
    # 借加载器做一次完整字段合法性检查（Category/Severity 枚举、match 结构）
    import tempfile

    with tempfile.NamedTemporaryFile(
        suffix=".yaml", delete=False, mode="w", encoding="utf-8"
    ) as tmp:
        yaml.safe_dump(raw, tmp, allow_unicode=True, sort_keys=False)
        tmp_path = tmp.name
    try:
        poc = parse_poc_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if poc.id != rid:
        raise ValueError("id 归一化后不一致（检查空白/大小写）")
    return rid


def validate_rule_bytes(data: bytes, source_name: str = "<bytes>") -> ValidationResult:
    """验证一段 YAML 字节。自动判型（nuclei / flower），失败给人类可读原因。"""
    try:
        raw = _parse_yaml(data)
    except yaml.YAMLError as exc:
        return ValidationResult(False, "invalid", "", f"{source_name}: YAML 语法错误: {exc}")
    except ValueError as exc:
        return ValidationResult(False, "invalid", "", f"{source_name}: {exc}")

    # 判型：nuclei 模板都带 info 映射（flower Schema 没有 info 字段）
    is_nuclei = isinstance(raw.get("info"), dict)
    try:
        if is_nuclei:
            rid = _validate_nuclei(raw)
            return ValidationResult(True, "nuclei", rid)
        rid = _validate_flower(raw)
        return ValidationResult(True, "flower", rid)
    except ValueError as exc:
        return ValidationResult(False, "invalid", "", f"{source_name}: {exc}")
    except Exception as exc:  # noqa: BLE001 —— 单文件坏不能让整次同步崩
        return ValidationResult(
            False, "invalid", "", f"{source_name}: {type(exc).__name__}: {exc}"
        )


def validate_rule_file(path: str | Path) -> ValidationResult:
    """验证工作区里的一个规则文件。"""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return ValidationResult(False, "invalid", "", f"{p.name}: 读取失败: {exc}")
    return validate_rule_bytes(data, source_name=p.name)


class IdDeduper:
    """同一仓库内的 rule_id 去重器。

    规则：同一 rule_id 在一次同步里出现两次（不同文件）→ 后者无效。
    跨同步版本（add vs update）由 registry 处理，这里只管单批内撞车。
    """

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}  # rule_id -> 首次出现的文件

    def check(self, rule_id: str, path: str) -> str | None:
        """返回冲突提示（撞车时），否则记录并返回 None。"""
        first = self._seen.get(rule_id)
        if first is not None and first != path:
            return f"ID 重复 '{rule_id}': {path} 与 {first} 冲突，后者忽略"
        self._seen.setdefault(rule_id, path)
        return None
