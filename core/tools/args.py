"""参数归一化：把模型给的 JSON 收敛成工具真正能吃的形状。

模型给参数的方式有三种不靠谱：类型对不上（``"false"`` 而不是 ``False``）、
数字是字符串、枚举值大小写不一致。这里逐个纠正；**认不出来就丢弃**，
而不是猜一个值塞进去——猜错了会让"工具调用失败"变成"静默改了行为"。

同时负责生成喂给 LLM 的 tool schema（:func:`llm_schemas`）与给人看的
说明文本，保证"模型看到的"和"实际接受的"来自同一份声明。
"""


from __future__ import annotations

from typing import Any

from core.tools.builtins import BUILTINS, BuiltinTool
from core.tools.external import EXTERNAL_TOOLS
from core.tools.probe import Probe


def spec_for(name: str) -> BuiltinTool | None:
    """按名字取内置工具的定义（schema 归一时要用）。"""
    return next((t for t in BUILTINS if t.name == name), None)


_BOOL_TRUE = frozenset({"true", "1", "yes", "y", "on", "t"})
_BOOL_FALSE = frozenset({"false", "0", "no", "n", "off", "f", ""})


def _to_bool(value: Any) -> bool | None:
    """字符串 → 布尔。**认不出来就返回 None（不猜）**。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in _BOOL_TRUE:
            return True
        if s in _BOOL_FALSE:
            return False
    return None


def _to_number(value: Any, want: str) -> int | float | None:
    if isinstance(value, bool):        # bool 是 int 的子类，别让它混进数字分支
        return None
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip()) if want == "integer" else float(value.strip())
        except ValueError:
            return None
    return None


def _match_enum(value: str, enum: list[Any]) -> Any | None:
    """按忽略大小写/首尾空白匹配枚举，**返回枚举里的规范值**（不是用户输入）。

    这样 ``fmt="MD"`` 会变成 ``fmt="md"``，下游的 ``if fmt in (...)`` 才命中。
    """
    v = value.strip().lower()
    for item in enum:
        if isinstance(item, str) and item.strip().lower() == v:
            return item
    return None


def normalize_args(name: str, args: dict[str, Any] | None) -> dict[str, Any]:
    """按工具的 JSON Schema 归一实参类型。**在 execute 里统一调用**。

    这不是"迁就模型写错"，而是把 JSON 的语义补上：模型走 function-calling，
    实参常把布尔写成字符串（``"false"``）、把枚举写错大小写（``"MD"``），
    而它们在 Python 里的默认语义是**错的**：

    * ``"false"`` 是**非空字符串 → 恒为真**。于是 ``overwrite="false"`` 真的去覆盖、
      ``undo="false"`` 真的去撤销 —— 用户明明说了"不要"，工具却做了。
    * ``"MD" != "md"`` → 枚举判断全部落空，静默什么都不做。

    逐个 handler 打补丁治不了根：每加一个参数都要记得手工转一次，迟早漏。
    统一按 schema 转，新工具天然被覆盖。**认不出来的值一律原样传下去**，
    让 handler 自己报错，不在这里瞎猜。
    """
    raw = dict(args or {})
    spec = spec_for(name)
    props: dict[str, Any] = {}
    if spec is not None and isinstance(spec.params, dict):
        props = spec.params.get("properties") or {}

    out: dict[str, Any] = {}
    for key, value in raw.items():
        prop = props.get(key) or {}
        want = prop.get("type")
        enum = prop.get("enum")

        if isinstance(value, str) and isinstance(enum, list):
            hit = _match_enum(value, enum)
            if hit is not None:
                out[key] = hit
                continue

        if want == "boolean" and not isinstance(value, bool):
            b = _to_bool(value)
            if b is not None:
                out[key] = b
                continue

        if want in ("integer", "number"):
            n = _to_number(value, want)
            if n is not None:
                out[key] = n
                continue

        if want == "string" and isinstance(value, int | float | bool):
            out[key] = str(value)
            continue

        out[key] = value
    return out


def llm_schemas(externals: list[Probe] | None = None) -> list[dict[str, Any]]:
    """生成喂给 LLM 的 tool 列表（OpenAI function-calling 格式）。

    只把**探测到**的外部工具写进 ``external_tool`` 的说明里——列一堆没装的
    工具，模型会去调用然后拿到"命令不存在"，白白浪费一轮往返。
    """
    schemas: list[dict[str, Any]] = []
    avail = [p for p in (externals or []) if p.found]
    for t in BUILTINS:
        # external_tool 的 description 必须按"实际装了哪些"动态生成，
        # 所以在下面单独追加，这里跳过，否则会出现两个同名 function。
        if t.name == "external_tool":
            continue
        schemas.append(
            {"type": "function", "function": {"name": t.name, "description": t.desc, "parameters": t.params}}
        )

    lines = []
    for p in avail:
        s = p.spec
        lines.append(f"- {s.key}（{s.category}）：{s.desc}" + (f" 示例：{s.example}" if s.example else ""))
    if not avail:
        lines.append("（本机未探测到任何外部工具，请只用内置工具）")
    ext_desc = (
        "调用本机已安装的外部命令行工具。可选工具：\n" + "\n".join(lines)
        + "\n参数请用 args 数组逐个给出；写文件类选项会被拒绝。"
    )
    schemas.append(
        {
            "type": "function",
            "function": {
                "name": "external_tool",
                "description": ext_desc,
                "parameters": next(t for t in BUILTINS if t.name == "external_tool").params,
            },
        }
    )
    return schemas


def describe_externals(probes: list[Probe]) -> str:
    """给 CLI ``engines`` 用的一行摘要。"""
    ok = [p.spec.key for p in probes if p.found]
    miss = [p.spec.key for p in probes if not p.found]
    bits = []
    if ok:
        bits.append(f"可用 {len(ok)}：{', '.join(ok)}")
    if miss:
        bits.append(f"缺失 {len(miss)}：{', '.join(miss)}")
    return "；".join(bits) or "未探测"


def tool_help_text() -> str:
    """初始化界面用的中文说明，按类别分组。"""
    groups: dict[str, list[str]] = {}
    for s in EXTERNAL_TOOLS:
        groups.setdefault(s.category, []).append(s.key)
    return "、".join(f"{c}：{'/'.join(v)}" for c, v in groups.items())
