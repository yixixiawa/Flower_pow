"""执行请求前的权限检查和拒绝控制（111.md 模块职责之二）。

两步走：

1. **识别**（:func:`classify_request`）——不得仅凭 HTTP Method 判断操作
   类型，必须综合 URL 路径、请求参数、请求体、POC 声明、历史行为、
   认证要求、目标环境七个维度；**任一维度识别出更高风险时，按更高风险
   处理**。EXPORT 必须独立分类，不自动归入 READ。
2. **决策**（:meth:`RequestGuard.check`）——分类映射到权限矩阵命令，
   交 :func:`policy.api_policy.decide` 判 ALLOW / REVIEW / DENY / UNKNOWN。
   REVIEW 没有明确审批时拒绝执行；UNKNOWN 默认拒绝执行。

Guard 自身**绝不放行**：它只产出结论，拒绝文本与审计记录由调用方
（:mod:`core.tools.runner`）落给模型与人。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from policy.api_policy import (
    COMMAND_FOR_CATEGORY,
    ApiCategory,
    Decision,
    Environment,
    PermissionLevel,
    PolicyDecision,
    decide,
)

# ── 识别信号表 ────────────────────────────────────────────────────

# URL 路径关键词 → 分类。**顺序即优先级**：一条路径同时命中多个词表时，
# 取表中更靠前（更高风险）的类别——与"任一维度更高风险为准"同向。
_PATH_SIGNALS: list[tuple[str, ApiCategory]] = [
    (r"/batch[-_]?delete|/bulk[-_]?delete|delete[_-]?all|batch.*remove", ApiCategory.DELETE),
    (r"/export(?:[-_/]|$)|/download|/dump|/backup", ApiCategory.EXPORT),
    (r"/upload(?:[-_/]|$)|/import(?:[-_/]|$)|/attach|/file[-_]?save", ApiCategory.UPLOAD),
    (r"/exec(?:ute)?(?:[-_/]|$)|/cmd(?:[-_/]|$)|/command|/run[-_]?script|/eval(?:[-_/]|$)|/shell|/terminal", ApiCategory.EXECUTE),
    (r"/cron|/schedul|/timer|/job[-_]?run|/task[-_]?run|/delayed", ApiCategory.EXECUTE),
    (r"/delete|/remove|/drop|/destroy", ApiCategory.DELETE),
    (r"/login|/logout|/auth|/token|/sso|/captcha|/session", ApiCategory.AUTH),
    (r"/update|/edit|/modify|/patch|/reset|/set(?:[-_/]|$)", ApiCategory.UPDATE),
    (r"/add(?:[-_/]|$)|/create|/new(?:[-_/]|$)|/save|/submit|/register|/insert", ApiCategory.CREATE),
    (r"/list|/query|/search|/page|/detail|/info|/view|/get(?:[-_/]|$)|/select", ApiCategory.READ),
]

# 请求体 / 参数里的破坏性信号 → 直接按最高风险处理。
# 这些不是"接口是干什么的"，而是"这次请求里带了什么"——
# 破坏性 SQL（改数据/换结构/执行命令）哪怕打在一个查询接口上，
# 风险也得按 SQL 注入验证（L3）算。
_DESTRUCTIVE_SQL = re.compile(
    r"(drop\s+table|drop\s+database|delete\s+from|truncate\s+table|"
    r"insert\s+into|update\s+\w+\s+set|alter\s+table|"
    r"xp_cmdshell|exec\s*\(|sleep\s*\(|benchmark\s*\(|load_file\s*\()",
    re.I,
)
_CMD_INJECTION = re.compile(r"(;\s*(sh|bash|powershell|cmd)|\|\s*(nc|curl|wget)\b|`[^`]+`)", re.I)

_UPLOAD_HINTS = re.compile(r"multipart/form-data|filename\s*=|content-disposition:\s*form-data", re.I)
_BATCH_DELETE_HINTS = re.compile(r'["\']?ids?["\']?\s*[:=]\s*\[|["\']?batch["\']?\s*[:=]\s*(true|1)|["\']?all["\']?\s*[:=]\s*(true|1)', re.I)
_SCHEDULE_HINTS = re.compile(r"(cron|schedule[_d]?|interval|delayed[_-]?run)", re.I)

# 请求体出现写语义动词（POST /search 带 {"action":"delete"} 这种）
_BODY_ACTION = re.compile(r"[\"'](action|op|operation|type)[\"']\s*:\s*[\"'](\w+)[\"']", re.I)

# 各维度的风险排名：数值越大风险越高（"更高风险为准"的实现依据）
_RISK_RANK = {
    ApiCategory.READ: 0,
    ApiCategory.AUTH: 1,
    ApiCategory.EXPORT: 2,
    ApiCategory.CREATE: 3,
    ApiCategory.UPDATE: 3,
    ApiCategory.UPLOAD: 4,
    ApiCategory.DELETE: 4,
    ApiCategory.EXECUTE: 5,
}


def _rank(cat: str) -> int:
    return _RISK_RANK.get(cat, 9)


class Command:
    """权限矩阵命令名（与 policy.api_policy.RULES 一致，避免魔法串）。"""

    QUERY_DETAIL = "查询详情"
    QUERY_LIST = "查询列表"
    CREATE_DATA = "创建测试数据"
    UPDATE_DATA = "修改测试数据"
    UPLOAD_FILE = "上传测试文件"
    DELETE_DATA = "删除测试数据"
    BATCH_DELETE = "批量删除"
    SQLI_VERIFY = "SQL 注入验证"
    EXECUTE_CMD = "命令执行"
    SCHEDULED_TASK = "定时任务执行"


# ── 分类结果 ──────────────────────────────────────────────────────


@dataclass(slots=True)
class ClassifiedRequest:
    """多维度识别的产出：最终分类 + 各维度信号（审计要能还原判定）。"""

    category: str
    command: str            # 映射到权限矩阵的命令
    signals: list[str] = field(default_factory=list)
    risk_level: str = PermissionLevel.L0  # 命中维度的最高风险等级提示

    @property
    def batch(self) -> bool:
        return self.command == Command.BATCH_DELETE


def classify_request(
    url: str,
    method: str = "GET",
    body: str = "",
    params: dict[str, Any] | None = None,
    poc_hint: str = "",
    history_hint: str = "",
) -> ClassifiedRequest:
    """按七维度识别接口操作类型，**任一维度更高风险按更高风险处理**。

    维度覆盖（111.md 第五节）：URL 路径 / 请求参数 / 请求体 / POC 声明 /
    历史行为 / 认证要求 / 目标环境。前三项在这里判定；POC 声明与历史行为
    以字符串提示传入；认证要求与目标环境不改变**分类**（它们是决策阶段的
    条件），但会产生信号记录。
    """
    signals: list[str] = []
    worst = ApiCategory.READ
    worst_rank = -1

    def bump(cat: str, signal: str) -> None:
        nonlocal worst, worst_rank
        signals.append(signal)
        if _rank(cat) > worst_rank:
            worst, worst_rank = cat, _rank(cat)

    path = urlparse(url or "").path or "/"
    low_path = path.lower()

    # ── 维度 1：URL 路径 ─────────────────────────────────────────
    # AUTH 是**用途级**信号：POST /login 是登录（建立测试前状态），
    # 不是"创建资源"——method 维度对 AUTH 端点不参与风险升级，
    # 否则所有登录都会被误判成创建测试数据（L1）而全局被拒。
    auth_endpoint = False
    matched_path = False
    for pat, cat in _PATH_SIGNALS:
        if re.search(pat, low_path):
            bump(cat, f"URL 路径命中 {cat}：{path}")
            matched_path = True
            auth_endpoint = cat is ApiCategory.AUTH
            break
    if not matched_path:
        bump(ApiCategory.READ, f"URL 路径无写语义关键词：{path}")

    # ── 维度 2：HTTP Method（只是维度之一，不作唯一判据）──────────
    m = (method or "GET").upper()
    if m in ("GET", "HEAD", "OPTIONS"):
        bump(ApiCategory.READ, f"Method {m} 只读")
    elif m == "POST" and not auth_endpoint:
        bump(ApiCategory.CREATE, "Method POST 写语义")
    elif m == "POST":
        signals.append("Method POST（AUTH 端点：登录动作，不按创建资源升级）")
    elif m in ("PUT", "PATCH"):
        bump(ApiCategory.UPDATE, f"Method {m} 更新语义")
    elif m == "DELETE":
        bump(ApiCategory.DELETE, "Method DELETE 删除语义")
    else:
        bump(ApiCategory.UNKNOWN, f"Method {m} 未识别")

    # ── 维度 3：请求参数（query/表单名）───────────────────────────
    if params:
        keys = " ".join(str(k) for k in params).lower()
        if re.search(r"batch|bulk|ids", keys):
            bump(ApiCategory.DELETE, f"参数含批量特征：{keys[:60]}")
        if re.search(r"cron|schedule|delay|interval", keys):
            bump(ApiCategory.EXECUTE, f"参数含定时任务特征：{keys[:60]}")

    # ── 维度 4：请求体 ────────────────────────────────────────────
    body_low = (body or "").lower()
    if body_low:
        if _UPLOAD_HINTS.search(body):
            bump(ApiCategory.UPLOAD, "请求体为 multipart/文件上传")
        hit = _DESTRUCTIVE_SQL.search(body)
        if hit:
            bump(ApiCategory.EXECUTE, f"请求体含破坏性 SQL：{hit.group(0)[:50]}")
        if _CMD_INJECTION.search(body):
            bump(ApiCategory.EXECUTE, "请求体含命令注入特征")
        if _BATCH_DELETE_HINTS.search(body) and worst == ApiCategory.DELETE:
            bump(ApiCategory.DELETE, "请求体含批量删除特征（ids 数组 / batch=true）")
        for act in _BODY_ACTION.finditer(body):
            act_low = act.group(2).lower()
            if act_low in ("delete", "remove", "drop"):
                bump(ApiCategory.DELETE, f"请求体 action={act_low}")
            elif act_low in ("exec", "execute", "run", "eval"):
                bump(ApiCategory.EXECUTE, f"请求体 action={act_low}")
            elif act_low in ("export", "download"):
                bump(ApiCategory.EXPORT, f"请求体 action={act_low}")

    # ── 维度 5：POC 声明 ─────────────────────────────────────────
    poc_low = (poc_hint or "").lower()
    if poc_low:
        if re.search(r"batch|bulk", poc_low):
            bump(ApiCategory.DELETE, "POC 声明含批量操作")
        if re.search(r"sqli|sql[-_]?injection|注入", poc_low):
            bump(ApiCategory.EXECUTE, "POC 声明为 SQL 注入类")
        if re.search(r"rce|command|exec|代码执行|命令执行", poc_low):
            bump(ApiCategory.EXECUTE, "POC 声明为命令执行类")
        if re.search(r"upload|上传", poc_low):
            bump(ApiCategory.UPLOAD, "POC 声明为上传类")

    # ── 维度 6：历史行为 ─────────────────────────────────────────
    his_low = (history_hint or "").lower()
    if re.search(r"batch[-_]?delete|批量删除", his_low):
        bump(ApiCategory.DELETE, "历史行为出现过批量删除")

    # 维度 7（认证要求 / 目标环境）不改变分类，仅记信号：
    # 它们是决策条件（api_policy.decide 的入参），混进分类会让
    # "这是什么操作"和"允不允许做"两个问题互相污染。

    # ── 特判：SQL 注入验证 / 批量删除 / 定时任务执行 ──────────────
    command = _map_command(worst, signals)
    return ClassifiedRequest(
        category=worst,
        command=command,
        signals=signals,
    )


def _map_command(category: str, signals: list[str]) -> str:
    """分类 + 信号 → 权限矩阵命令。特判三条不在普通分类里的命令。"""
    joined = " ".join(signals)
    if "破坏性 SQL" in joined or "SQL 注入类" in joined:
        return Command.SQLI_VERIFY
    if "批量" in joined and category == ApiCategory.DELETE:
        return Command.BATCH_DELETE
    if "定时任务特征" in joined:
        return Command.SCHEDULED_TASK
    if category == ApiCategory.EXECUTE:
        return Command.EXECUTE_CMD
    return COMMAND_FOR_CATEGORY.get(category, "")


# ── Guard 本体 ────────────────────────────────────────────────────


@dataclass(slots=True)
class GuardContext:
    """决策的上下文绑定：目标、环境、账号身份（边界 1 的三要素）。

    ``environment`` 留空 = 未指定（guard 会按 URL 的 host 绑定表现算）；
    显式填 unknown / production 等值则**覆盖** URL 判定——调用方已经
    知道答案时不必再猜一遍。
    """

    target_id: str = ""
    run_id: str = ""
    environment: str = ""           # 空 = 按 URL 现算；非空 = 调用方给定
    identity_bound: bool = False    # 账号身份是否已绑定（有凭证/已声明身份）
    target_bound: bool = False      # 目标是否已绑定（会话目标与请求同源）
    approved_commands: set[str] = field(default_factory=set)  # 显式审批过的命令


class RequestGuard:
    """请求前的权限检查入口。所有目标面请求都应过这一道。"""

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        p = getattr(cfg, "policy", None)
        self.enabled = bool(getattr(p, "enabled", True))
        self.default_environment = str(
            getattr(p, "default_environment", Environment.UNKNOWN) or Environment.UNKNOWN
        )
        # host 通配 → 环境的绑定表（目标维度的落地）
        self.environments: dict[str, str] = dict(getattr(p, "environments", None) or {})
        # 显式审批表：{"SQL 注入验证": true} —— 只认配置里明确写的 true
        approvals = getattr(p, "approvals", None) or {}
        self.approved: set[str] = {
            cmd for cmd, v in approvals.items() if v is True
        }

    # ── 目标 → 环境 ──────────────────────────────────────────────
    def environment_for(self, url: str) -> str:
        """按 host 通配绑定表判环境；未命中走 default_environment。

        判不出就是 UNKNOWN——**不猜**。UNKNOWN 在决策里等价于拒绝
        （L1/L2 条件不满足），安全方向不会错。
        """
        try:
            host = (urlparse(url or "").hostname or "").lower()
        except ValueError:
            return self.default_environment
        for pat, env in self.environments.items():
            if self._glob_match(host, pat.lower()):
                return env
        return self.default_environment

    @staticmethod
    def _glob_match(host: str, pattern: str) -> bool:
        if "*" not in pattern:
            return host == pattern
        prefix, _, suffix = pattern.partition("*")
        return host.startswith(prefix) and host.endswith(suffix)

    # ── 主入口 ───────────────────────────────────────────────────
    def check_request(
        self,
        url: str,
        method: str = "GET",
        body: str = "",
        params: dict[str, Any] | None = None,
        poc_hint: str = "",
        ctx: GuardContext | None = None,
    ) -> PolicyDecision:
        """识别 + 决策。enabled=False 时直接给 ALLOW（策略整体关闭）。"""
        if not self.enabled:
            return PolicyDecision(decision=Decision.ALLOW, reason="策略已关闭（policy.enabled=false）")
        ctx = ctx or GuardContext()
        cls = classify_request(url, method=method, body=body, params=params, poc_hint=poc_hint)
        if not cls.command:
            return PolicyDecision(
                decision=Decision.UNKNOWN,
                category=cls.category,
                signals=cls.signals,
                reason="接口未识别出已知命令，默认拒绝执行",
            )
        approved = cls.command in self.approved or cls.command in ctx.approved_commands
        d = decide(
            cls.command,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=ctx.target_bound,
            approved=approved,
        )
        d.category = cls.category
        d.signals = cls.signals
        if d.decision == Decision.REVIEW and d.level == PermissionLevel.L3:
            # L3 即使有显式授权，也要环境兜底：生产环境的危险操作
            # **不得因审批解锁**（Hybrid 规则明文）。
            if (ctx.environment or self.environment_for(url)) not in Environment.TEST_ENVS:
                d.decision = Decision.DENY
                d.reason = f"{d.command}（L3）虽已显式授权，但目标环境非测试环境，不得解锁"
        return d

    def check_tool(self, tool_key: str, args: dict[str, Any], ctx: GuardContext | None = None) -> PolicyDecision:
        """外部工具调用走这里：按工具语义直接映射命令（无需报文识别）。"""
        if not self.enabled:
            return PolicyDecision(decision=Decision.ALLOW, reason="策略已关闭")
        command = _TOOL_COMMAND.get(tool_key, "")
        if not command:
            # 未知外部工具 → UNKNOWN 默认拒绝（不得自动放行未知接口）
            return PolicyDecision(
                decision=Decision.UNKNOWN,
                command="",
                reason=f"外部工具 {tool_key} 不在权限矩阵映射内，默认拒绝执行",
            )
        ctx = ctx or GuardContext()
        url = str(args.get("target") or args.get("url") or "")
        approved = command in self.approved or command in ctx.approved_commands
        d = decide(
            command,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=ctx.target_bound,
            approved=approved,
        )
        d.category = ApiCategory.EXECUTE
        if d.decision == Decision.REVIEW and d.level == PermissionLevel.L3:
            if (ctx.environment or self.environment_for(url)) not in Environment.TEST_ENVS:
                d.decision = Decision.DENY
                d.reason = f"{d.command}（L3）虽已显式授权，但目标环境非测试环境，不得解锁"
        return d


# 外部工具语义映射：这些工具的能力本身就是矩阵里的一条命令。
# 没列进来的外部工具一律 UNKNOWN → 拒绝（不自动放行未知工具）。
# 映射按工具的**主要能力**归类，不是按它"通常拿来干什么"：
# curl 能发任意请求，但本工具链里它承担的是取回事实（L0 语义），
# 写语义请求应走 http_request（那里有逐请求的分类与判定）。
_TOOL_COMMAND: dict[str, str] = {
    "nmap": Command.QUERY_LIST,       # 端口探测 = 只读列举
    "masscan": Command.QUERY_LIST,
    "dirsearch": Command.QUERY_LIST,  # 路径枚举
    "gobuster": Command.QUERY_LIST,
    "ffuf": Command.QUERY_LIST,
    "nikto": Command.QUERY_LIST,      # 已知漏洞指纹比对（只读取证）
    "whatweb": Command.QUERY_LIST,    # 指纹识别
    "wpscan": Command.QUERY_LIST,     # CMS 枚举（默认无 --password 攻击）
    "curl": Command.QUERY_DETAIL,     # 取回事实：JS/接口响应
    "sqlmap": Command.SQLI_VERIFY,    # SQL 注入验证（L3）
    "nuclei": Command.SQLI_VERIFY,    # 模板扫可能带利用 payload（L3）
    "hydra": Command.EXECUTE_CMD,     # 攻击性爆破，按 L3 攻击命令归类
}
