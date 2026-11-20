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
    rule_for_command,
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

    # 路径同样规范化（第四轮整改 #5）：编码变体（%65xport、%2Fexport）
    # 不得逃过分类信号——先摊平再匹配，识别与范围比对同一把尺子。
    path = normalize_url_path(urlparse(url or "").path or "/")
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

# ── 统一目标范围校验（P0-①：全工程唯一的一把尺子）─────────────────
# scheme + hostname + port 规范化比较（默认端口归一：http:80 / https:443
# 与省略端口等价），路径按授权范围处理——绑定目标声明了非根路径前缀时
# （如 http://host:8080/app），请求路径必须落在该前缀内。
# runner 的 exploit_probe 等所有工具一律调这里，不得自行构造简化判定。

_DEFAULT_PORTS = {"http": 80, "https": 443}

# ── URL 路径规范化（第四轮整改 #5：防路径前缀绕过）──────────────────
# 攻击者可以用编码与点段让"前缀比对"看走眼：
#   /app/%2e%2e/other   → 百分号编码的 ..，字面量前缀比对会判"在 /app 内"
#   /app/..%2fother     → 同上变体
#   /app//other         → 双斜杠折叠出与登记不同的路径形态
#   /app/./other        → 点段冗余
#   /app\other          → 反斜杠在部分服务端等价 /
#   /app/sub/           → 尾斜杠不影响同一资源
# 一律先规范化成**真实语义路径**再做前缀比对，绕过形态在比对前就被摊平。

_MAX_UNQUOTE = 3  # 重复解码上限（%252e → %2e → . 的多层编码）


def normalize_url_path(path: str) -> str:
    """URL 路径规范化：多层解码 → 反斜杠归一 → 折叠斜杠 → 解析点段。

    返回以 ``/`` 开头的规范化路径。解析失败按根路径处理（fail-closed：
    与 in_scope 的"解析失败 = 出界"同向，不会因规范化异常而放行）。
    """
    p = path or "/"
    try:
        from urllib.parse import unquote

        for _ in range(_MAX_UNQUOTE):
            dec = unquote(p)
            if dec == p:
                break
            p = dec
    except Exception:  # noqa: BLE001 —— 解码失败按原样继续（后续仍会滤点段）
        pass
    p = p.replace("\\", "/")
    # 折叠连续斜杠
    while "//" in p:
        p = p.replace("//", "/")
    # 解析 . / .. 点段（逐段扫描，.. 弹出上一段；越界弹出按根处理）
    segs: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    return "/" + "/".join(segs)


def over_decode_limit(path: str) -> bool:
    """路径解码达到上限仍有残余编码 → **歧义，不可判**（第六轮整改 P1-5）。

    ``normalize_url_path`` 最多解码 ``_MAX_UNQUOTE`` 层；超出上限的
    多层编码路径（``%252532``×N 层嵌套）真实语义依赖服务端解码层数，
    静态分析无法确知——此时"规范化后的前缀比对"结论不可信。
    调用方（in_scope/_endpoint）对歧义路径一律 fail-closed 拒绝，
    不猜服务端会解几层。
    """
    p = path or ""
    try:
        from urllib.parse import unquote

        for _ in range(_MAX_UNQUOTE):
            dec = unquote(p)
            if dec == p:
                return False
            p = dec
        # 达到上限后仍在变化 → 还有未解码层 → 歧义
        return unquote(p) != p
    except Exception:  # noqa: BLE001
        return False


def _endpoint(url: str) -> tuple[str, str, int, str] | None:
    """URL → (scheme, hostname, port, path)，全部规范化。解析失败返回 None。

    path 经 :func:`normalize_url_path` 规范化（第四轮整改 #5）：编码的 ``..``、
    双斜杠、点段冗余在前缀比对之前摊平，``/app/%2e%2e/other`` 不会再
    被字面量前缀比对误判为"在 /app 内"。
    """
    try:
        p = urlparse(url or "")
        scheme = (p.scheme or "").lower()
        host = (p.hostname or "").lower()
        if not host:
            return None
        port = p.port  # 非法端口会抛 ValueError → 被外层捕获
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(scheme, 0)
    # P1-5（第六轮整改）：解码达上限仍歧义的路径 → 不可判 → fail-closed。
    # 多层编码路径（%2525...嵌套）的真实语义取决于服务端解码层数，
    # 规范化结论不可信——按"解析失败"处理（in_scope 判 False）。
    if over_decode_limit(p.path or "/"):
        return None
    return scheme, host, port, normalize_url_path(p.path or "/")


def in_scope(url: str, bound_target: str) -> bool:
    """请求 URL 是否落在绑定目标的授权范围内（P0-① 统一入口）。

    * scheme 必须一致（绑定 http 就不得打 https 混淆）；
    * hostname 大小写不敏感、**端口参与比较**（默认端口归一）——
      修掉旧实现只比 hostname、``http://host:9999`` 也算同源的洞；
    * 路径：绑定目标带非根路径前缀时，请求路径必须在该前缀内
      （``http://host/app`` 授权范围不含 ``/other``）。
    """
    a = _endpoint(bound_target)
    b = _endpoint(url)
    if a is None or b is None:
        return False
    if a[0] != b[0] or a[1] != b[1] or a[2] != b[2]:
        return False
    base = a[3].rstrip("/")
    if base:  # 绑定目标声明了具体路径前缀 → 授权范围含路径边界
        req = b[3]
        if req != base and req != base + "/" and not req.startswith(base + "/"):
            return False
    return True


# 兼容旧名：项目内已有调用点与测试用 _same_host，语义即 in_scope。
def _same_host(url_a: str, url_b: str) -> bool:
    """统一的范围校验（P0-① 升级：scheme+host+port+路径前缀，详见 in_scope）。"""
    return in_scope(url_a, url_b) or in_scope(url_b, url_a)


# 主机级授权工具：端口扫描/子域枚举的对象本来就是"主机上的任意端口/域"，# noqa: E501
# 严格 port 比对会把工具的本职工作判成出界。这类工具按 scheme+host 授权。
HOST_SCOPED_TOOLS: frozenset[str] = frozenset({
    "recon_ports", "recon_ports_bg", "recon_subdomains",
})


def host_in_scope(url: str, bound_target: str) -> bool:
    """主机级范围比对（scheme + hostname，不比端口）。

    仅限 :data:`HOST_SCOPED_TOOLS` 使用——绑定 ``http://h:8080`` 表示
    授权"主机 h"，端口扫描扫该主机的其他端口是工具的定义而非越界。
    路径类工具仍走严格 :func:`in_scope`（scheme+host+port+路径前缀）。
    """
    a = _endpoint(bound_target)
    b = _endpoint(url)
    if a is None or b is None:
        return False
    return a[0] == b[0] and a[1] == b[1]


# ── 目标 URL 合法性校验（第二轮整改 #1：明确拒绝非法目标/协议/端口）──
# in_scope 管"请求是否落在授权范围内"，validate_target_url 管"这个
# 目标本身是否合法"——两道独立的门：协议混淆（ftp://）、端口越界
# （:70000）、含控制字符的 URL 在**进范围比对之前**就该被明确拒绝，
# 而不是靠范围比对"碰巧"判 False 后给一句含糊的"目标未绑定"。

ALLOWED_SCHEMES: tuple[str, ...] = ("http", "https")


def validate_target_url(url: str) -> str:
    """目标 URL 合法性校验。合法返回原串（已 strip），非法抛 ``ValueError``。

    * 非空、不含空白/控制字符；
    * scheme **必须**是 http/https（调用方先做补头归一化，这里只放行
      明确合法的协议——ftp/file/gopher 等一律拒绝）；
    * 主机名非空；
    * 端口（若显式给出）必须在 1-65535（``urlparse`` 对越界端口抛
      ``ValueError``，同样按非法处理）。

    调用方（runner）把 ``ValueError`` 转成明确的拒绝文本回灌模型。
    """
    raw = (url or "").strip()
    if not raw:
        raise ValueError("目标为空")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        raise ValueError(f"URL 含空白或控制字符：{raw[:60]!r}")
    try:
        p = urlparse(raw)
        scheme = (p.scheme or "").lower()
        host = p.hostname
        port = p.port  # 越界端口（如 :70000）在此抛 ValueError
    except ValueError as exc:
        raise ValueError(f"URL 无法解析或端口越界：{exc}") from exc
    if not scheme:
        raise ValueError(f"URL 缺少协议头（仅允许 {'/'.join(ALLOWED_SCHEMES)}）：{raw[:60]!r}")
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"协议 {scheme!r} 不在允许范围（仅 http/https），拒绝执行")
    if not host:
        raise ValueError(f"URL 缺少主机名：{raw[:60]!r}")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"端口 {port} 越界（合法范围 1-65535）")
    return raw


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
    identity: str = ""              # 账号身份上下文（审计与台账用，P1-7）
    target_bound: bool = False      # 兼容字段：仅表示"会话已有目标"
    bound_target: str = ""          # **绑定的目标 URL**（P0-①：in_scope 全量校验）


class RequestGuard:
    """请求前的权限检查入口。所有目标面请求都应过这一道。"""

    # 统一范围校验挂成方法：runner 的所有分支（含 exploit_probe）都调
    # ``guard.in_scope(url, bound)``——全工程同一把尺子，不许自带简化版。
    in_scope = staticmethod(in_scope)

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        p = getattr(cfg, "policy", None)
        # P0 整改：``policy.enabled`` **不再是旁路开关**——安全策略强制
        # 执行，配置里的 enabled 字段保留只为兼容旧配置文件，guard 不读。
        self.enabled = True
        self.default_environment = str(
            getattr(p, "default_environment", Environment.UNKNOWN) or Environment.UNKNOWN
        )
        # host 通配 → 环境的绑定表（目标维度的落地）
        self.environments: dict[str, str] = dict(getattr(p, "environments", None) or {})
        # P0-② 整改：**配置级命令审批放行已整体移除**。原 config
        # ``policy.approvals`` 是命令级的静态白名单——命令写对了一次，
        # 之后所有对象、所有参数的同类操作全部复用放行，审批根本没绑定
        # 到具体请求上。现在审批**只存在于运行期**：逐请求、绑定对象
        # URL、参数变化即重新审批（core/tools/runner 的 approver 通道）。
        # 守卫层对 decide() 恒传 approved=False。

    # ── 目标 → 环境 ──────────────────────────────────────────────
    def environment_for(self, url: str) -> str:
        """按环境绑定表判环境；未命中走 default_environment。

        绑定模式支持 ``[scheme://]host-glob[:port]``（整改：目标匹配
        不再只看 hostname）：

        * 模式显式声明了 scheme（``http://192.168.*``）→ 请求 scheme
          必须一致——https 请求不会继承 http 绑定的环境分类；
        * 模式显式声明了端口（``192.168.1.10:8080``）→ 请求**有效端口**
          （默认端口归一：http:80 / https:443 与省略等价）必须一致——
          同主机换端口不会继承环境分类；
        * 只写 host 的模式（``192.168.*``）= 宿主显式声明"该主机名的
          所有 scheme/端口同一环境"，这是配置所有者的明确授权面，
          不是推断。

        判不出就是 UNKNOWN——**不猜**。UNKNOWN 在决策里等价于拒绝
        （L1/L2 条件不满足），安全方向不会错。
        """
        try:
            p = urlparse(url or "")
            scheme = (p.scheme or "").lower()
            host = (p.hostname or "").lower()
            port = p.port
        except ValueError:
            return self.default_environment
        for pat, env in self.environments.items():
            if self._binding_match(str(pat), scheme, host, port):
                return env
        return self.default_environment

    @classmethod
    def _binding_match(cls, pattern: str, scheme: str, host: str, port: int | None) -> bool:
        """环境绑定模式匹配：``[scheme://]host-glob[:port]``。"""
        pat = (pattern or "").strip().lower()
        if not pat:
            return False
        want_scheme: str | None = None
        if "://" in pat:
            want_scheme, _, pat = pat.partition("://")
        # 尾段是纯数字 → 端口声明；否则整段是 host 通配
        head, sep, tail = pat.rpartition(":")
        want_port: int | None = None
        if sep and tail.isdigit():
            want_port, pat = int(tail), head
        if want_scheme is not None and want_scheme != scheme:
            return False
        if want_port is not None:
            effective = port if port is not None else _DEFAULT_PORTS.get(scheme, 0)
            if effective != want_port:
                return False
        return cls._glob_match(host, pat)

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
        history_hint: str = "",
        ctx: GuardContext | None = None,
    ) -> PolicyDecision:
        """识别 + 决策。**策略恒生效**（P0-2：enabled 不再是旁路）。"""
        ctx = ctx or GuardContext()
        cls = classify_request(
            url, method=method, body=body, params=params,
            poc_hint=poc_hint, history_hint=history_hint,
        )
        if not cls.command:
            return PolicyDecision(
                decision=Decision.UNKNOWN,
                category=cls.category,
                signals=cls.signals,
                reason="接口未识别出已知命令，默认拒绝执行",
            )
        # P0-①：目标范围校验走**统一入口** in_scope（scheme+host+port+路径前缀）。
        # 只知道"会话有目标"不算绑定，范围外请求视为未绑定 → 拒绝。
        target_bound = bool(ctx.bound_target) and in_scope(url, ctx.bound_target)
        # P1-1（第六轮整改）：L0 的环境绑定需要"明确只读"证据——
        # 方法只读且七维度分类没有任何更高风险信号。破坏性 SQL/上传/
        # 批量特征会把 category 抬高，这里自然为 False。
        clearly_read_only = (
            (method or "GET").upper() in ("GET", "HEAD", "OPTIONS")
            and cls.category == ApiCategory.READ
        )
        # P0-②：审批不在配置层——恒传 False，逐请求审批在运行期通道。
        d = decide(
            cls.command,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=target_bound,
            approved=False,
            clearly_read_only=clearly_read_only,
        )
        d.category = cls.category
        d.signals = cls.signals
        return d

    def check_tool(self, tool_key: str, args: dict[str, Any], ctx: GuardContext | None = None) -> PolicyDecision:
        """外部工具调用走这里：按工具语义直接映射命令（无需报文识别）。"""
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
        # 工具未显式给目标时默认作用于绑定目标本身（与 runner 的回退一致）
        if not url and ctx.bound_target:
            url = ctx.bound_target
        # P0-①：与 check_request 同一统一入口（scheme+host+port+路径前缀）。
        # 显式给了不同目标的工具调用按出界处理；未给目标且会话已绑定 → 视为在范围内。
        target_bound = bool(ctx.bound_target) and (
            not str(args.get("target") or args.get("url") or "")
            or in_scope(url, ctx.bound_target)
        )
        # P1-1（第六轮整改）：映射为只读语义的外部工具（nmap/curl/dirsearch
        # 等枚举与取回事实类）构成"明确只读"——unknown 环境照旧放行；
        # L3 类映射（sqlmap/nuclei/hydra）不受此影响（矩阵一律拒绝）。
        d = decide(
            command,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=target_bound,
            approved=False,  # P0-②：审批只在运行期逐请求发生
            clearly_read_only=command in (Command.QUERY_LIST, Command.QUERY_DETAIL),
        )
        d.category = ApiCategory.EXECUTE
        return d

    def check_builtin(self, tool_key: str, url: str, ctx: GuardContext | None = None) -> PolicyDecision:
        """Runner 内置目标请求工具的统一决策入口（第六轮整改 P0-1）。

        sqli_probe / login / authz_probe / recon_* 全部走这里——与
        check_request / check_tool / check_probe 同一条授权路径：
        范围统一 :func:`in_scope`、环境统一 :meth:`environment_for`、
        审批恒 False（L3 无出路；L2 的逐请求审批在运行期通道）。

        映射表 :data:`_BUILTIN_TOOL_COMMAND`；映射为空串（如 login——
        AUTH 无矩阵授权）或缺席 → UNKNOWN 默认拒绝。
        """
        command = _BUILTIN_TOOL_COMMAND.get(tool_key)
        if not command:
            return PolicyDecision(
                decision=Decision.UNKNOWN,
                command="",
                category=ApiCategory.AUTH if command == "" else ApiCategory.UNKNOWN,
                reason=(
                    f"内置工具 {tool_key} 无权限矩阵授权行"
                    + ("（AUTH 类不映射 L0）" if command == "" else "，不在映射内")
                    + "，默认拒绝执行"
                ),
            )
        ctx = ctx or GuardContext()
        # 范围判定与 check_request 同源：目标为空或出界 → 未绑定 → 拒绝。
        # 端口扫描/子域枚举按主机级授权（扫其他端口是工具本职，不是越界）。
        if tool_key in HOST_SCOPED_TOOLS:
            target_bound = bool(ctx.bound_target) and bool(url) and host_in_scope(url, ctx.bound_target)
        else:
            target_bound = bool(ctx.bound_target) and bool(url) and in_scope(url, ctx.bound_target)
        d = decide(
            command,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=target_bound,
            approved=False,
            # 内置侦察/越权工具只发只读 GET——L0 的 unknown 环境放行条件
            clearly_read_only=True,
        )
        d.category = ApiCategory.READ if command in (Command.QUERY_LIST, Command.QUERY_DETAIL) else _CATEGORY_FOR_COMMAND.get(command, ApiCategory.UNKNOWN)
        d.signals = [f"内置工具 {tool_key} → {command}"]
        return d

    def check_probe(self, url: str, kinds: str, ctx: GuardContext | None = None) -> PolicyDecision:
        """exploit_probe 的统一决策入口（整改：runner **不得**直接调用
        ``api_policy.decide()`` 自行拼决策）。

        与 check_request / check_tool 同一条授权路径：

        * 目标范围 → 统一入口 :func:`in_scope`（scheme+hostname+port
          规范化 + 路径前缀），绑定目标为空或出界即 target_bound=False；
        * 环境 → :meth:`environment_for`（绑定表支持 scheme/port 声明）；
        * 审批 → 恒 False（L3 无审批出路；L2 的逐请求审批在运行期通道）。

        探针类别 → 矩阵命令映射见 :data:`PROBE_KIND_COMMAND`；任一类别
        未识别 → UNKNOWN 默认拒绝（不猜）。
        """
        commands = [PROBE_KIND_COMMAND.get(k.strip().lower(), "") for k in (kinds or "").split(",")]
        if not commands or any(not c for c in commands):
            return PolicyDecision(
                decision=Decision.UNKNOWN,
                command="",
                category=ApiCategory.UNKNOWN,
                reason=(
                    f"exploit_probe 含未识别的探针类别，默认拒绝执行"
                    f"（已知类别：{'、'.join(sorted(PROBE_KIND_COMMAND))}）"
                ),
            )
        worst = max(commands, key=lambda c: (
            PermissionLevel.rank(rule_for_command(c).level)
            if rule_for_command(c) is not None else -1
        ))
        rule = rule_for_command(worst)
        ctx = ctx or GuardContext()
        # 与 check_request 完全同源的范围判定——这是"不可绕过"的保证：
        # runner 只喂 url 与 ctx，范围/环境/身份判定全部在本模块内完成。
        target_bound = bool(ctx.bound_target) and in_scope(url, ctx.bound_target)
        d = decide(
            worst,
            environment=ctx.environment or self.environment_for(url),
            identity_bound=ctx.identity_bound,
            target_bound=target_bound,
            approved=False,
        )
        d.category = _CATEGORY_FOR_COMMAND.get(worst, ApiCategory.READ)
        d.signals = [
            f"探针类别：{kinds}",
            f"最高风险命令：{worst}（{rule.level if rule else '?'}）",
            f"范围判定：{'在授权范围内' if target_bound else '出界或未绑定（拒绝）'}",
        ]
        return d


# 探针类别 → 权限矩阵命令（P0-4：sqli 必须落 L3，不得落 L0）。
# **权威表在本模块**——runner 只引用，不得复制一份自行漂移。
# P0-4（第六轮整改）：**fileread 移出映射**——文件读取探针（路径穿越
# 取 /etc/passwd 类）是主动利用行为，不是"查询详情"这种合法只读；
# 矩阵没有它的授权行 → 映射空串 → UNKNOWN 默认拒绝。
PROBE_KIND_COMMAND: dict[str, str] = {
    "rce": "命令执行",             # L3
    "sqli": "SQL 注入验证",        # L3（此前落入查询详情 L0——整改点）
    "upload": "上传测试文件",      # L2
    "fileupload": "上传测试文件",  # L2
    # "fileread" 刻意不在表内：无矩阵授权 → UNKNOWN/DENY（第六轮整改 P0-4）
}

# 命令 → 分类（check_probe 供审计展示用）
_CATEGORY_FOR_COMMAND: dict[str, str] = {
    "命令执行": ApiCategory.EXECUTE,
    "SQL 注入验证": ApiCategory.EXECUTE,
    "上传测试文件": ApiCategory.UPLOAD,
    "删除测试数据": ApiCategory.DELETE,
    "批量删除": ApiCategory.DELETE,
    "查询详情": ApiCategory.READ,
    "查询列表": ApiCategory.READ,
    "创建测试数据": ApiCategory.CREATE,
    "修改测试数据": ApiCategory.UPDATE,
}


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


# Runner **内置**目标请求工具 → 权限矩阵命令（第六轮整改 P0-1：
# sqli_probe / login / authz_probe / recon_* 全部纳入策略执行）。
# 权威表在本模块，runner 只引用；映射缺席的内置工具一律 UNKNOWN 拒绝。
# * sqli_probe 的唯一能力就是 SQL 注入验证 → L3 一律拒绝；
# * login 提交凭证建立会话——矩阵没有 AUTH 授权行 → 空串 UNKNOWN 拒绝
#   （与 http_request 打 /login 端点的判定同口径，不得映射 L0）；
# * authz_probe / recon_* 只发只读 GET 侦察 → 查询列表（L0，
#   环境绑定条件由 decide() 的 L0 分支把关）。
_BUILTIN_TOOL_COMMAND: dict[str, str] = {
    "sqli_probe": Command.SQLI_VERIFY,      # L3：一律拒绝
    "login": "",                            # AUTH 无矩阵授权 → UNKNOWN
    "authz_probe": Command.QUERY_LIST,      # L0：只读 GET 对比
    "recon_fingerprint": Command.QUERY_LIST,
    "recon_ports": Command.QUERY_LIST,
    "recon_ports_bg": Command.QUERY_LIST,
    "recon_paths": Command.QUERY_LIST,
    "recon_js": Command.QUERY_LIST,
    "js_audit": Command.QUERY_LIST,
    "recon_openapi": Command.QUERY_LIST,
    "recon_subdomains": Command.QUERY_LIST,
}

# 过闸的内置工具名集合（runner 引用；guard 是权威，不得各自漂移）
BUILTIN_POLICY_TOOLS: frozenset[str] = frozenset(_BUILTIN_TOOL_COMMAND)
