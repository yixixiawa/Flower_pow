"""主动扫描的统一策略入口（P1-10）。

Agent 交互路径的工具调用逐次过 ``request_guard``（``core.tools.runner`` 的
``_policy_gate``），但**一次性扫描**有三条绕过 runner 的执行路径：

* CLI：``flower-pow scan`` / ``engines`` / ``ask``（``cli/*.py`` 直起 Scheduler）；
* MCP：``scan_start`` 工具（``mcp_server/jobs.py`` 起线程跑 Scheduler）；
* REPL 后台任务（也经 runner，但 Scheduler 流水线内部的探测器不走
  runner 的逐请求闸门）。

Scheduler 流水线里的探测器（SQLi / RCE / 上传探针）发出的请求不经过
``request_guard`` 的逐请求分类——这是**结构性**的：流水线探测器是批量
打点，逐请求过闸会把它变成逐请求问人。所以这些路径的入口统一收敛到
这里的 ``active_scan_check``：**进门前按环境一次定性**。

定性规则（与权限矩阵同向，保守；第六轮整改 P0-3 收紧）：

* ``production`` —— 拒绝整个主动扫描（返回拒绝文本）；
* ``unknown`` —— 放行但**降级**为被动模式：主动利用类探针
  （SQLi / RCE / 文件读取 / 文件上传）全部关闭，只留只读侦察与指纹；
* 测试环境（isolated / dedicated）—— 依配置执行，但 **L3 探针
  （SQLi 验证 / RCE 命令执行）在所有环境一律关闭**：矩阵对 L3 的
  授权是"无（默认禁止）"，批量流水线没有逐请求审批通道，
  "测试环境"不构成 L3 的授权依据（P0-3：测试环境不得自动放行 L3）。
  L2 上传探针仍需 dedicated 环境 + 逐请求人工审批（由探测器的
  approver 通道承担）。

Agent 路径不受这里影响：它逐请求过闸，矩阵本来就管得住。
"""

from __future__ import annotations

from urllib.parse import urlparse

from policy.api_policy import Environment
from policy.request_guard import RequestGuard

# L3 探针（ScanConfig 字段名）：SQL 注入验证 / 命令执行——矩阵 L3
# 默认禁止且审批无出路，批量流水线**任何环境**都不得自动放行（P0-3）。
_L3_PROBES = (
    "sqli_probe_enabled",
    "rce_probe_enabled",
)

# unknown 环境下**额外**强制关闭的主动利用类探针：文件读取探针
# （GET /etc/passwd 类穿越）与文件上传探针。测试环境按配置执行
# （fileread 请求本身是只读 GET，受 Detector 统一安全入口的
# 逐请求分类约束；upload 需 dedicated 环境 + 逐请求审批）。
_PASSIVE_ONLY_PROBES = (
    "file_read_probe_enabled",
    "file_upload_probe_enabled",
)


def environment_of(cfg, target: str) -> str:
    """统一环境判定：与 request_guard 同一份绑定表与默认值。"""
    return RequestGuard(cfg).environment_for(target or "")


def active_scan_check(cfg, target: str) -> tuple[bool, str]:
    """主动扫描进门检查。返回 (是否放行, 说明/拒绝文本)。

    拒绝文本直接可回给 CLI/MCP 调用方——三个入口共用这一份措辞。
    """
    env = environment_of(cfg, target)
    if env == Environment.PRODUCTION:
        return False, (
            f"【已拦截】（策略）目标 {target} 被绑定为生产环境（policy.environments），"
            "主动扫描拒绝执行。生产环境只允许人工核验过的只读检查；"
            "如目标确属测试环境，请修正 config.yaml 的 policy.environments 绑定。"
        )
    if env not in Environment.TEST_ENVS:
        return True, (
            f"目标环境未绑定（{env}）：主动利用类探针（SQLi/RCE/文件读取/文件上传）"
            "已强制关闭，本次扫描降级为只读侦察。"
        )
    return True, (
        f"目标环境 {env}：按配置执行；L3 探针（SQLi/RCE）在批量流水线中"
        "一律关闭（P0-3：测试环境不构成 L3 的授权依据）。"
    )


def scoped_scan_config(cfg, target: str) -> tuple[object, str]:
    """按环境定性返回扫描用配置。

    * production → 抛 ValueError（调用方应先过 ``active_scan_check``）；
    * unknown → 返回**配置副本**，主动利用探针强制关闭；
    * 测试环境 → 配置副本，**L3 探针（SQLi/RCE）一律关闭**（P0-3：
      批量流水线没有逐请求审批通道，"测试环境"不是 L3 的授权依据）。
    """
    env = environment_of(cfg, target)
    if env == Environment.PRODUCTION:
        raise ValueError("生产环境禁止主动扫描（policy.environments 绑定）")
    scan = _copy_scan(cfg.scan)
    if env in Environment.TEST_ENVS:
        # P0-3：测试环境也不得自动放行 L3——SQLi 验证 / 命令执行探针
        # 在批量流水线里没有逐请求审批通路，矩阵对它们是"无（默认禁止）"。
        for k in _L3_PROBES:
            setattr(scan, k, False)
        return _copy_cfg(cfg, scan), "L3 探针（SQLi/RCE）已按矩阵强制关闭（P0-3）"
    for k in _L3_PROBES:
        setattr(scan, k, False)
    for k in _PASSIVE_ONLY_PROBES:
        setattr(scan, k, False)
    note = "未绑定环境：主动利用类探针已强制关闭（只读侦察）"
    return _copy_cfg(cfg, scan), note


def _copy_scan(scan):
    """浅拷贝 ScanConfig。pydantic 模型走 model_copy；测试用的
    假配置对象（SimpleNamespace / 类属性）退回 copy.copy。"""
    try:
        return scan.model_copy()
    except AttributeError:
        import copy as _copy

        return _copy.copy(scan)


def _copy_cfg(cfg, scan):
    try:
        return cfg.model_copy(update={"scan": scan})
    except AttributeError:
        import copy as _copy

        dup = _copy.copy(cfg)
        dup.scan = scan
        return dup
