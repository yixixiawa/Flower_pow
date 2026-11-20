"""接口测试生命周期权限控制——权限矩阵与默认决策（111.md 模块职责之一）。

四个模块的分工（**职责即边界，不是额外的执行权限**）：

* :mod:`policy.api_policy` —— 定义命令权限矩阵和默认决策（本模块）；
* :mod:`policy.request_guard` —— 执行请求前的权限检查和拒绝控制；
* :mod:`policy.test_transaction` —— 约束测试对象生命周期；
* :mod:`policy.audit_logger` —— 记录允许、拒绝和审批相关事件。

权限矩阵原文（不得新增或扩大允许范围）::

    查询详情   L0  有条件允许        查询列表   L0  有条件允许
    创建测试数据 L1 仅隔离测试环境     修改测试数据 L1 仅隔离测试环境
    上传测试文件 L2 需要专门测试环境   删除测试数据 L2 需要单独审批
    批量删除   L3  默认禁止          SQL 注入验证 L3 默认禁止
    命令执行   L3  默认禁止          定时任务执行 L3 默认禁止

Hybrid 决策规则：

* ALLOW —— 仅在满足对应矩阵条件时允许；
* REVIEW —— 没有明确审批时拒绝执行；
* DENY —— 直接拒绝执行；
* UNKNOWN —— 默认拒绝执行（不得自动放行未知接口）。

边界（不得自行增加权限例外、执行路径或隐含授权）：

* 所有规则按**目标、环境和账号身份**绑定；
* 测试环境允许删除测试用户，**不得推导为生产环境允许删除**；
* 条件不满足时，统一处理为**拒绝执行**。

EXPORT / AUTH 无矩阵授权（第四轮整改，收紧）::

    矩阵原文恰好十条命令，**没有 EXPORT/AUTH 行**——导出（数据外带）
    与认证操作（提交凭证）都不是矩阵授权过的能力。此前两轮曾为它们
    各造一条规则（「导出数据」L1、「认证操作」L0），本质仍是"为通过
    分类器而新增允许范围"。整改后：

    * ApiCategory.EXPORT / ApiCategory.AUTH 保持**独立分类**与风险信号
      （分类器照常识别、审计照常记录识别信号）；
    * 但 COMMAND_FOR_CATEGORY 映射为空串 → ``decide()`` 判 UNKNOWN →
      **默认拒绝执行**。没有明确授权依据的类别一律 UNKNOWN/DENY，
      不得为通过分类器而映射进任何矩阵命令；
    * 导出/认证需求要合法落地，只能走"人改代码加白名单"（与 L3 同一
      唯一合法途径），不存在配置旁路。
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── 枚举 ──────────────────────────────────────────────────────────


class PermissionLevel:
    """权限等级。字符串枚举风格，便于直接进审计日志与报告。"""

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"

    ALL = (L0, L1, L2, L3)

    _RANK = {L0: 0, L1: 1, L2: 2, L3: 3}

    @classmethod
    def rank(cls, level: str) -> int:
        return cls._RANK.get(level, 99)


class Decision:
    """Hybrid 决策。UNKNOWN 独立于 DENY：它表示"规则根本没覆盖"。"""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class ApiCategory:
    """接口分类。**EXPORT 独立分类，不自动归入 READ**。"""

    READ = "READ"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    UPLOAD = "UPLOAD"
    EXPORT = "EXPORT"
    EXECUTE = "EXECUTE"
    AUTH = "AUTH"
    UNKNOWN = "UNKNOWN"

    ALL = (
        READ, CREATE, UPDATE, DELETE, UPLOAD, EXPORT, EXECUTE, AUTH, UNKNOWN,
    )


class Environment:
    """目标环境。判定语义写在 :mod:`policy.request_guard`，这里只定名。"""

    PRODUCTION = "production"
    DEDICATED_TEST = "dedicated_test"      # 专门测试环境
    ISOLATED_TEST = "isolated_test"        # 隔离测试环境
    UNKNOWN = "unknown"

    # "测试环境"（相对 production 而言）：删除类操作的边界——
    # 测试环境允许删除测试用户，不得推导为生产环境允许删除。
    TEST_ENVS = (DEDICATED_TEST, ISOLATED_TEST)


# ── 权限矩阵：十条规则，每条恰好六个字段 ────────────────────────────


@dataclass(slots=True)
class PolicyRule:
    """一条命令权限规则。字段严格六个，与 111.md 输出要求一一对应。"""

    command: str          # 命令名称
    level: str            # 权限等级（L0-L3）
    allow_when: str       # 允许条件（仅按矩阵原文归纳）
    default_status: str   # 默认状态
    deny_when: str        # 禁止或拒绝执行条件（由允许条件反向推导）
    handling: str = "拒绝执行"  # 条件不满足时的处理（统一为拒绝执行）

    def to_row(self) -> list[str]:
        return [
            self.command,
            self.level,
            self.allow_when,
            self.default_status,
            self.deny_when,
            self.handling,
        ]


RULES: list[PolicyRule] = [
    PolicyRule(
        command="查询详情",
        level=PermissionLevel.L0,
        allow_when="有条件允许：目标、环境与账号身份已完成绑定，操作为只读",
        default_status="允许（条件满足时）",
        deny_when="目标/环境/账号身份未绑定，或操作超出只读范围",
    ),
    PolicyRule(
        command="查询列表",
        level=PermissionLevel.L0,
        allow_when="有条件允许：目标、环境与账号身份已完成绑定，操作为只读",
        default_status="允许（条件满足时）",
        deny_when="目标/环境/账号身份未绑定，或操作超出只读范围",
    ),
    PolicyRule(
        command="创建测试数据",
        level=PermissionLevel.L1,
        allow_when="仅隔离测试环境",
        default_status="非隔离测试环境默认拒绝",
        deny_when="目标环境不是隔离测试环境",
    ),
    PolicyRule(
        command="修改测试数据",
        level=PermissionLevel.L1,
        allow_when="仅隔离测试环境",
        default_status="非隔离测试环境默认拒绝",
        deny_when="目标环境不是隔离测试环境",
    ),
    PolicyRule(
        command="上传测试文件",
        level=PermissionLevel.L2,
        allow_when="需要专门测试环境，且逐请求审批",
        default_status="非专门测试环境默认拒绝",
        deny_when="目标环境不是专门测试环境（隔离测试环境亦不满足），或未获逐请求审批",
    ),
    PolicyRule(
        command="删除测试数据",
        level=PermissionLevel.L2,
        allow_when="需要单独审批，且仅限测试环境",
        default_status="无审批默认拒绝",
        deny_when="无单独审批，或目标环境为生产环境",
    ),
    PolicyRule(
        command="批量删除",
        level=PermissionLevel.L3,
        allow_when="无（默认禁止）",
        default_status="禁止",
        deny_when="任何情形",
    ),
    PolicyRule(
        command="SQL 注入验证",
        level=PermissionLevel.L3,
        allow_when="无（默认禁止）",
        default_status="禁止",
        deny_when="任何情形",
    ),
    PolicyRule(
        command="命令执行",
        level=PermissionLevel.L3,
        allow_when="无（默认禁止）",
        default_status="禁止",
        deny_when="任何情形",
    ),
    PolicyRule(
        command="定时任务执行",
        level=PermissionLevel.L3,
        allow_when="无（默认禁止）",
        default_status="禁止",
        deny_when="任何情形",
    ),
]
# 矩阵**恰好十条命令**（第四轮整改）：不再为 EXPORT/AUTH 新增规则行——
# 矩阵原文没有这两类，为它们造行就是"为通过分类器而扩大允许范围"。
# EXPORT/AUTH 保持独立分类与风险信号（识别层），但命令映射为空串，
# decide() 判 UNKNOWN 默认拒绝（决策层）——授权依据必须来自矩阵本身。

_RULE_BY_COMMAND = {r.command: r for r in RULES}


def rule_for_command(command: str) -> PolicyRule | None:
    return _RULE_BY_COMMAND.get(command)


def rules_table_markdown() -> str:
    """输出六列规则清单表（供报告附录与审计文档使用）。"""
    header = (
        "| 命令名称 | 权限等级 | 允许条件 | 默认状态 | "
        "禁止或拒绝执行条件 | 条件不满足时的处理 |"
    )
    sep = "|---|---|---|---|---|---|"
    rows = ["| " + " | ".join(r.to_row()) + " |" for r in RULES]
    return "\n".join([header, sep, *rows])


# ── 接口分类 → 命令映射 ──────────────────────────────────────────

# 分类本身独立（EXPORT 不是 READ），但落到权限矩阵时需要一条命令。
# **第四轮整改**：EXPORT/AUTH 在矩阵里**没有授权行**——映射为空串，
# ``decide()`` 判 UNKNOWN 默认拒绝。分类器照常识别这两类并保留风险
# 信号（审计可见它识别出了 EXPORT/AUTH），但**没有明确授权依据就
# 不得映射进任何矩阵命令**——不得为通过分类器而把新类别映射到 L0，
# 也不得为它们新增矩阵行（矩阵恰好十条，不扩大允许范围）。
COMMAND_FOR_CATEGORY: dict[str, str] = {
    ApiCategory.READ: "查询详情",
    ApiCategory.EXPORT: "",
    ApiCategory.AUTH: "",
    ApiCategory.CREATE: "创建测试数据",
    ApiCategory.UPDATE: "修改测试数据",
    ApiCategory.UPLOAD: "上传测试文件",
    ApiCategory.DELETE: "删除测试数据",
    ApiCategory.EXECUTE: "命令执行",
    ApiCategory.UNKNOWN: "",
}


# ── 决策引擎 ──────────────────────────────────────────────────────


@dataclass(slots=True)
class PolicyDecision:
    """一次权限判定的完整结论。"""

    decision: str            # ALLOW / REVIEW / DENY / UNKNOWN
    command: str = ""        # 命中的命令（空 = 未识别，UNKNOWN）
    level: str = ""          # 权限等级
    category: str = ""       # 接口分类
    reason: str = ""         # 人可读的判定理由（进审计与拒绝回执）
    rule: PolicyRule | None = None
    signals: list[str] = field(default_factory=list)  # 各维度的识别信号

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision in (Decision.DENY, Decision.UNKNOWN, Decision.REVIEW)


def decide(
    command: str,
    *,
    environment: str = Environment.UNKNOWN,
    identity_bound: bool = False,
    target_bound: bool = False,
    approved: bool = False,
    clearly_read_only: bool = False,
) -> PolicyDecision:
    """按矩阵对一条命令做 Hybrid 决策。

    判定顺序刻意写成"先拒绝后允许"：任何一条禁止条件命中就走拒绝，
    剩下的才检查允许条件——保证不会因为两条都沾边而放行。

    ``clearly_read_only``（第六轮整改 P1-1：L0 加环境绑定）——本次请求
    是否为**无歧义的只读**（方法 GET/HEAD/OPTIONS 且七维度分类没有任何
    更高风险信号）。矩阵 L0 的允许条件写着"目标、环境与账号身份已完成
    绑定，操作为只读"：环境未绑定（unknown）时只放行明确只读操作，
    带任何写语义/注入 payload/批量特征的请求一律拒绝——unknown 不是
    "什么都行"，而是"只放行一眼就能确认无害的请求"。
    """
    rule = rule_for_command(command)
    if rule is None:
        return PolicyDecision(
            decision=Decision.UNKNOWN,
            command="",
            reason="接口未识别出任何已知命令（不得自动放行未知接口）",
        )

    base = PolicyDecision(
        decision=Decision.DENY,
        command=rule.command,
        level=rule.level,
        rule=rule,
        reason="",
    )

    if rule.level == PermissionLevel.L3:
        # L3 默认禁止：**任何情形拒绝，审批不给任何出路**（P0 整改：
        # 原"显式授权后交由 request_guard 复核环境"的分支已删除——
        # 配置文件里的 approvals 一旦写错 host 通配，就是生产环境
        # 执行 SQL 注入验证的直接通路。L3 命令要跑，唯一的合法
        # 途径是人自己改代码加白名单，而不是改配置。）
        base.reason = f"{rule.command}（L3）默认禁止：任何情形一律拒绝执行（审批不设出路）"
        return base

    # 目标 / 账号身份绑定是**所有等级的公共前置**（边界 1）
    if not target_bound or not identity_bound:
        missing = []
        if not target_bound:
            missing.append("目标未绑定")
        if not identity_bound:
            missing.append("账号身份未绑定")
        base.reason = f"{rule.command}（{rule.level}）：{'、'.join(missing)}，按矩阵拒绝执行"
        return base

    if rule.level == PermissionLevel.L0:
        # P1-1（第六轮整改）：L0 的环境绑定是真实条件——unknown 环境
        # 只放行**明确只读**操作（方法只读且七维度分类无更高风险信号）。
        # 带写语义或 payload 特征的请求在 unknown 环境一律拒绝。
        if environment == Environment.UNKNOWN and not clearly_read_only:
            base.reason = (
                f"{rule.command}（L0）目标环境未绑定（unknown），"
                "仅明确只读操作放行；本次请求带非只读语义/特征，拒绝执行"
            )
            return base
        base.decision = Decision.ALLOW
        base.reason = f"{rule.command}（L0）只读且目标/环境/身份已绑定，有条件允许"
        return base

    if rule.command == "删除测试数据":
        # 单独审批 + 仅测试环境（测试环境允许删测试用户，
        # 不得推导为生产环境允许删除）
        if environment == Environment.PRODUCTION:
            base.reason = f"{rule.command}（L2）目标为生产环境：测试环境的删除权限不得推导到生产"
            return base
        if environment not in Environment.TEST_ENVS:
            base.reason = f"{rule.command}（L2）目标环境未知（{environment}），视为不满足测试环境条件"
            return base
        if not approved:
            base.decision = Decision.REVIEW
            base.reason = f"{rule.command}（L2）环境满足，但无单独审批 → 无审批时拒绝执行"
            return base
        base.decision = Decision.ALLOW
        base.reason = f"{rule.command}（L2）测试环境 + 单独审批已记录"
        return base

    if rule.command == "上传测试文件":
        # 需要专门测试环境（P1-③：**仅 dedicated_test**——隔离测试环境
        # 不满足"专门"条件，不得因 TEST_ENVS 包含 isolated_test 而放行）。
        # 且上传必须**逐请求审批**：dedicated_test 也先给 REVIEW，交
        # 运行期审批通道（绑 URL 的逐请求审批），审批通过才放行。
        if environment != Environment.DEDICATED_TEST:
            base.reason = (
                f"{rule.command}（L2）目标环境为 {environment or '未知'}，"
                "上传仅允许专门测试环境（dedicated_test），拒绝执行"
            )
            return base
        if not approved:
            base.decision = Decision.REVIEW
            base.reason = f"{rule.command}（L2）目标为专门测试环境，但上传需逐请求审批"
            return base
        base.decision = Decision.ALLOW
        base.reason = f"{rule.command}（L2）专门测试环境 + 逐请求审批已通过"
        return base

    # L1：仅隔离测试环境
    if environment == Environment.ISOLATED_TEST:
        base.decision = Decision.ALLOW
        base.reason = f"{rule.command}（L1）目标为隔离测试环境"
    else:
        base.reason = (
            f"{rule.command}（L1）目标环境为 {environment or '未知'}，"
            "仅隔离测试环境允许，拒绝执行"
        )
    return base
