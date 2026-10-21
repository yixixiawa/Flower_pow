"""DeepSeek 模型注册表——"当前可用什么模型"的唯一事实来源。

为什么需要这张表
----------------
模型名在代码里散落成一个裸字符串时，有两个具体后果：

1. **改名要全文搜索**：厂商调一次命名，`config.yaml`、`config_loader`
   默认值、`init` 模板、README、`.env` 示例五处都要改，漏一处就是
   线上跑旧名。
2. **能力差异无处表达**：pro 与 flash 在成本/质量上差一个量级，但调用侧
   只认一个 ``model`` 字符串，没法按任务选型。

所以本模块只声明**当前官方模型**及其能力画像，调用侧依赖 :func:`resolve`
与 :func:`for_role`，不自己拼字符串。

不收录已下线的模型名
--------------------
厂商下线某个模型名后，**调用它不会报错**——服务端照常返回 200，只是
换成别的模型提供服务。这类名字最容易在排查时误导人。

但本模块不维护下线名清单：那是历史包袱，且永远补不全（每次改名都要加）。
取而代之的是 :func:`resolve` 的未知分支——凡是注册表里没有的名字，一律
放行但**强制报警告**，并在警告里直接点明"可能是已下线的旧名"。
这样既不背着历史清单走，又不丢掉排查线索。

数据来源
--------
https://api-docs.deepseek.com/zh-cn/ （"首次调用 API"）
官方给出的取值是 ``deepseek-flash`` 与 ``deepseek-v4-pro``。
"""

from __future__ import annotations

from dataclasses import dataclass

# ── 任务角色 ────────────────────────────────────────────────────────
#
# 扫描链路里 LLM 承担四种任务，它们的"贵不贵"差别很大：
#
#   rerank  每次扫描都调，输入是候选 POC 列表，输出是打分 —— 高频机械活
#   triage  每条疑似漏洞调一次，输出是判定 —— 中频，但需要一点推理
#   model   业务建模，一次扫描一两次 —— 低频，需要理解力
#   report  出报告，一次扫描一次 —— 低频，需要文笔与归纳
#
# 前两者量大且答案是"结构化打勾"，用快模型；后两者量小但要理解力，
# 值得用 pro。这是本文件的核心取舍，不是拍脑袋。
ROLE_FAST = "fast"        # 重排、研判：高频、机械
ROLE_DEEP = "deep"        # 建模、报告：低频、需要理解力

ROLE_LABELS: dict[str, str] = {
    ROLE_FAST: "高频机械任务（RAG 重排、误报研判）",
    ROLE_DEEP: "低频理解任务（业务建模、报告撰写）",
}


@dataclass(frozen=True)
class ModelSpec:
    """一个模型的能力与成本画像。"""

    name: str                     # 官方名字，直接作为 API 的 model 参数
    label: str                    # 人读的说明
    served_by: str                # 实际提供服务的模型版本
    tier: str                     # flash | pro
    context_tokens: int
    supports_thinking: bool       # 是否接受 thinking / reasoning_effort 参数
    default_role: str             # 默认派给哪类任务
    note: str = ""

    @property
    def is_pro(self) -> bool:
        return self.tier == "pro"


# ── 官方模型 ────────────────────────────────────────────────────────
_SPECS: tuple[ModelSpec, ...] = (
    ModelSpec(
        name="deepseek-flash",
        label="DeepSeek Flash（快、便宜）",
        served_by="DeepSeek-V4.1-Flash",
        tier="flash",
        context_tokens=128_000,
        supports_thinking=True,
        default_role=ROLE_FAST,
        note="默认模型。扫描链路的高频调用都用它。",
    ),
    ModelSpec(
        name="deepseek-v4-pro",
        label="DeepSeek V4 Pro（强、贵）",
        served_by="DeepSeek-V4-Pro",
        tier="pro",
        context_tokens=128_000,
        supports_thinking=True,
        default_role=ROLE_DEEP,
        note="需要深度理解时用：业务建模、报告撰写、复杂越权推理。",
    ),
)

_BY_NAME: dict[str, ModelSpec] = {s.name: s for s in _SPECS}

# ── 简写 ────────────────────────────────────────────────────────────
#
# 这里**只放项目自己的输入简写**，不放厂商的历史模型名。
#
# 下线模型名不进入本模块：注册表的职责是"声明当前可用什么"，不是
# "记录曾经有什么"。把已下线名字堆在这里，等于让历史包袱跟着代码走，
# 每次厂商改名都要往里加一条。
#
# 代价是：用户填了下线名时会落进 resolve() 的未知分支。所以那个分支的
# 措辞必须自己承担起排查提示（见 resolve 的 docstring）。
_SHORTHAND: dict[str, str] = {
    "flash": "deepseek-flash",
    "pro": "deepseek-v4-pro",
    "deepseek-pro": "deepseek-v4-pro",
}


def specs() -> tuple[ModelSpec, ...]:
    """全部官方模型。"""
    return _SPECS


def names() -> list[str]:
    """官方模型名列表（不含别名）。"""
    return list(_BY_NAME)


def get(name: str) -> ModelSpec | None:
    """按官方名取画像，找不到返回 None。"""
    return _BY_NAME.get((name or "").strip())


def resolve(name: str) -> tuple[ModelSpec, str]:
    """把用户填的模型名解析成官方模型。

    返回 ``(画像, 警告)``，警告为空串表示无需提醒。四种情况：

    * 空串                 → 默认模型，不警告
    * 官方名               → 原样返回，不警告
    * 本项目简写(pro/flash) → 归一化，不警告（只是输入方便，报警只会添乱）
    * 其他名字             → **原样放行并警告**

    关于最后一条
    ------------
    放行而不是拒绝，是因为 ``base_url`` 可指向 OpenAI / vLLM / 自建网关，
    那些模型名本项目无从校验，拒绝会挡掉合法用法。

    但放行有个必须防的坑：**厂商对已下线的模型名不报错**，会静默换成别的
    模型提供服务。所以这里不能用"查不到就静默通过"的写法，必须让上层
    把警告打出来。本项目不再维护下线名清单（那是历史包袱，且永远补不全），
    因此这条警告要把"你可能是填了下线名"这个可能性直接说清楚。
    """
    raw = (name or "").strip()
    if not raw:
        return _SPECS[0], ""

    if spec := _BY_NAME.get(raw):
        return spec, ""

    if target := _SHORTHAND.get(raw.lower()):
        return _BY_NAME[target], ""

    # 未知名字放行——可能是第三方模型，也可能是已下线的 DeepSeek 名字。
    # 造一个临时画像，让它照常工作，但明确标注"未校验"。
    return (
        ModelSpec(
            name=raw,
            label=f"{raw}（未在注册表中）",
            served_by="未知",
            tier="custom",
            context_tokens=0,
            supports_thinking=False,   # 不敢假设，未知网关多不支持该参数
            default_role=ROLE_FAST,
            note="不在注册表中，按第三方 OpenAI 兼容模型处理。",
        ),
        f"模型 '{raw}' 不在注册表中，将原样发给服务端（已关闭 thinking 参数）。"
        f"可用的官方模型：{'、'.join(names())}。"
        f"若这是已下线的旧模型名，服务端不会报错、只会静默换成别的模型提供服务，"
        f"请直接改用官方名。",
    )


def normalize(name: str) -> tuple[str, str]:
    """把用户填的名字归一化成"最终要用的名字"，并给出警告。

    返回 ``(最终名字, 警告)``。与 :func:`resolve` 的区别在于对未知名字的
    处理：``resolve`` 会造一个临时画像（供能力判断用），而这里只回答
    "这个字符串最终该原样保留还是替换"——这是配置层与 CLI 需要的答案。

    之所以单独立一个函数：这段"要不要改写用户填的值"的判断原本在
    `config_loader` 和 CLI 里各写了一遍，两处迟早会不一致。规则只有一条，
    就只该有一个实现：

    * 空串 / 官方名 / 简写 → 换成确定的官方名（简写归一化，官方名不变）
    * 其他名字             → **原样保留**。可能是第三方网关的模型，也可能
      只是用户拼错了。擅自改写成别的名字，等于替用户做决定，
      而且还掩盖了他配错这个事实。只报警告，不改值。
    """
    raw = (name or "").strip()
    if not raw:
        return _SPECS[0].name, ""
    if spec := _BY_NAME.get(raw):
        return spec.name, ""
    if target := _SHORTHAND.get(raw.lower()):
        return target, ""
    _, warn = resolve(raw)
    return raw, warn


def for_role(cfg_model: str, cfg_deep_model: str, role: str) -> str:
    """按任务角色挑模型名。

    ``cfg_deep_model`` 为空时，所有任务都用 ``cfg_model``——这是默认行为，
    保持"配一个模型就能跑"的简单性。显式配了 pro 才分流。
    """
    base, _ = resolve(cfg_model)
    if not cfg_deep_model:
        return base.name
    deep, _ = resolve(cfg_deep_model)
    return deep.name if role == ROLE_DEEP else base.name


def describe_table() -> list[tuple[str, str, str, str]]:
    """给 CLI 渲染用的表格数据：``(模型名, 说明, 由谁提供, 默认用途)``。"""
    rows: list[tuple[str, str, str, str]] = []
    for s in _SPECS:
        role = "高频任务" if s.default_role == ROLE_FAST else "深度任务"
        rows.append((s.name, s.label, s.served_by, role))
    return rows


def describe_shorthand() -> list[tuple[str, str]]:
    """简写对照：``(简写, 解析为)``，供 CLI 展示。"""
    return sorted(_SHORTHAND.items())
