"""安全需求目录：需求、用例、结构化预期、基线。

**这里是对抗"造 PASS"的核心**：预期写在本文件里，不写在用例函数里。
用例只采集事实，改测试代码（删断言、放宽判断）改不动这里的预期。

``REQUIRED_REQ_IDS`` 是冻结清单——谁把某条需求连同它的用例一起删掉，
:func:`check_integrity` 会直接报"需求缺失"，整体验收 FAIL。
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

from scripts.acceptance.model import CaseSpec, Requirement

HERE = Path(__file__).resolve().parent
BASELINE_PATH = HERE / "baseline.json"

# ── 需求（与用户验收规则第二节逐条对齐）───────────────────────────

REQUIREMENTS: list[Requirement] = [
    Requirement(
        "REQ-L3-DENY", "L3 命令在任何环境下均拒绝", "P0",
        "L3（批量删除/SQL 注入验证/命令执行/定时任务执行）不得因环境、审批或配置放行",
        ("policy/api_policy.py", "policy/enforcer.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-UNKNOWN-DENY", "UNKNOWN 命令默认拒绝", "P0",
        "未识别的命令/方法/外部工具不得自动放行",
        ("policy/api_policy.py", "policy/request_guard.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-EXPORT-AUTH-DENY", "EXPORT 与 AUTH 没有明确授权时拒绝", "P0",
        "EXPORT/AUTH 保持独立分类但没有矩阵授权行 → UNKNOWN/DENY",
        ("policy/api_policy.py", "policy/request_guard.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-FILEREAD-NOT-L0", "fileread 不得映射为 L0 查询详情", "P0",
        "文件读取探针无矩阵授权 → UNKNOWN 拒绝，不得落 L0",
        ("policy/request_guard.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-GATEWAY", "所有 HTTP 网络请求必须经过统一 Gateway", "P0",
        "每个出网客户端都由 core.proxy.build_client_kwargs 构造；无裸 httpx 客户端",
        ("core/proxy.py", "detectors/base.py", "collectors/", "core/auth.py", "kb/intel.py"),
    ),
    Requirement(
        "REQ-NO-BYPASS", "Runner/Detector/Collector/Scheduler/CLI/MCP/后台任务无策略旁路", "P0",
        "每个入口的目标请求都过同一套 policy 判定；生产环境拒绝主动扫描",
        ("core/tools/runner/base.py", "detectors/base.py", "collectors/path_scan.py",
         "policy/enforcer.py", "cli/scan.py", "mcp_server/jobs.py", "core/planner.py"),
    ),
    Requirement(
        "REQ-SCOPE", "目标范围外请求必须拒绝", "P0",
        "scheme+host+port+路径前缀统一校验；编码/点段/反斜杠绕过在比对前摊平",
        ("policy/request_guard.py", "core/tools/runner/base.py", "detectors/base.py"),
    ),
    Requirement(
        "REQ-REDIRECT", "重定向后的每一跳必须重新检查目标范围", "P0",
        "跨主机/跨端口重定向不得被跟随；同源重定向正常跟随",
        ("detectors/base.py", "core/tools/runner/recon.py", "core/proxy.py"),
    ),
    Requirement(
        "REQ-IDENTITY", "身份必须绑定 session、target 和 credential context", "P0",
        "身份三元组 base|sess|tgt；无凭证显式匿名、不继承前次实名",
        ("core/tools/runner/base.py", "core/session/session.py"),
    ),
    Requirement(
        "REQ-CONCURRENCY", "并发任务不得导致身份或审批状态污染", "P0",
        "pending 台账/身份/审批票据在并发执行下互相隔离",
        ("core/tools/runner/base.py", "policy/test_transaction.py"),
    ),
    Requirement(
        "REQ-LEDGER", "删除必须验证本次创建或上传的具体对象 ID", "P0",
        "只放行本次 create/upload 且取得 object_id 的对象；审批不能替代对象身份验证",
        ("policy/test_transaction.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-APPROVAL", "审批必须绑定具体请求并验证真实审批主体", "P0",
        "一次性票据绑定 URL/命令/方法/指纹/等级/目标/轮次/身份/审批人；L3 不签发",
        ("policy/test_transaction.py", "core/tools/runner/base.py"),
    ),
    Requirement(
        "REQ-AUDIT", "拒绝事件必须写入审计日志", "P0",
        "deny 事件落盘可追溯（run_id/target_id/命令/理由）；审计不可写时写操作拒绝",
        ("policy/audit_logger.py", "core/tools/runner/base.py", "detectors/base.py"),
    ),
    # ── 对话式文件访问 + Plan/Work（本地文件是"用户输入"，不是目标）────
    Requirement(
        "REQ-FILE-AUTH", "本地文件读取必须经过用户显式授权", "P0",
        "只认用户点名的文件；跨会话、路径穿越、链接逃逸、系统目录一律拒绝；"
        "文件内容是不可信数据（注入不改变策略）",
        ("core/files/access.py", "core/files/parser.py", "core/files/context.py"),
    ),
    Requirement(
        "REQ-PLAN-READONLY", "Plan 阶段不得产生任何副作用", "P0",
        "只读已授权文件：不调用工具、不发请求、不写盘；本地写操作与 L3 步骤"
        "在构建期即被拒绝",
        ("core/workflow/plan.py",),
    ),
    Requirement(
        "REQ-WORK-GATE", "Work 只能执行已确认的计划，且每步仍过原有闸门", "P0",
        "未确认/内容变更/文件变化/过期 → 拒绝；执行期 L3、UNKNOWN、生产写操作"
        "照样被拦；每步落审计",
        ("core/workflow/work.py", "core/workflow/approval.py"),
    ),
]

REQUIRED_REQ_IDS = tuple(r.id for r in REQUIREMENTS)


# ── 用例 ──────────────────────────────────────────────────────────

CASES: list[CaseSpec] = [
    # ── 本地文件授权（用户输入侧）─────────────────────────────────
    CaseSpec(
        "SEC-FILE-001", "REQ-FILE-AUTH",
        "未授权/跨会话/穿越/链接/系统目录读取全部拒绝，且零网络请求", "security",
        "scripts.acceptance.cases_workflow:file_auth_required",
        expect={"values.unauth_read_allowed": False,
                "values.cross_session_read_allowed": False,
                "values.traversal_blocked": 3,
                "values.system_dir_allowed": False,
                "network.count": 0},
        negative=True, min_assertions=8,
        sources=("core/files/access.py",),
    ),
    CaseSpec(
        "SEC-FILE-002", "REQ-FILE-AUTH",
        "超大/超量受限；注入内容不改变策略且无法闭合不可信数据容器", "security",
        "scripts.acceptance.cases_workflow:file_limits_and_untrusted",
        expect={"values.oversize_allowed": False,
                "values.over_count_allowed": False,
                "values.truncated": True,
                "values.container_closed_by_content": False,
                "values.l3_after_injection": "DENY",
                "network.count": 0},
        negative=True, min_assertions=9,
        sources=("core/files/parser.py", "core/files/context.py"),
    ),
    # ── Plan 只读 ─────────────────────────────────────────────────
    CaseSpec(
        "SEC-PLAN-001", "REQ-PLAN-READONLY",
        "Plan 阶段零工具调用/零请求；本地写与 L3 步骤被拒绝", "security",
        "scripts.acceptance.cases_workflow:plan_readonly",
        expect={"values.plan_tool_calls": 0,
                "values.network_count": 0,
                "values.write_step_rejected": True,
                "values.l3_step_rejected": True},
        negative=True, min_assertions=8,
        sources=("core/workflow/plan.py",),
    ),
    # ── Work 闸门 ─────────────────────────────────────────────────
    CaseSpec(
        "SEC-WORK-001", "REQ-WORK-GATE",
        "未确认/计划变更/输入文件变化 → 拒绝执行且零请求", "security",
        "scripts.acceptance.cases_workflow:work_requires_approval",
        expect={"values.unauth_allowed": False,
                "values.changed_plan_allowed": False,
                "values.file_changed_allowed": False,
                "network.count": 0},
        negative=True, min_assertions=6,
        sources=("core/workflow/work.py", "core/workflow/approval.py"),
    ),
    CaseSpec(
        "SEC-WORK-002", "REQ-WORK-GATE",
        "执行期 L3 被拦、生产删除被拦、正常只读才发出；每步落审计", "security",
        "scripts.acceptance.cases_workflow:work_steps_still_gated",
        expect={"values.completed": True,
                "values.l3_step_status": "blocked",
                "values.production_step_status": "blocked",
                "network.count": 1},
        negative=True, min_assertions=7,
        sources=("core/workflow/work.py",),
    ),
    # ── L3 ───────────────────────────────────────────────────────
    CaseSpec(
        "SEC-L3-001", "REQ-L3-DENY", "L3 四命令 × 四环境 × 审批开关全部 DENY", "unit",
        "scripts.acceptance.cases_policy:l3_decide_all_envs",
        expect={"values.total": 32, "values.deny_count": 32, "values.allow_count": 0},
        negative=True, min_assertions=33,
    ),
    CaseSpec(
        "SEC-L3-002", "REQ-L3-DENY", "Runner sqli_probe 在隔离环境仍被拒且不触网", "security",
        "scripts.acceptance.cases_runtime:runner_sqli_probe_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0,
                "audit.any": {"event": "deny", "command": "SQL 注入验证"}},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-L3-003", "REQ-L3-DENY", "Runner exploit_probe(kinds=sqli) 被拒且不触网", "security",
        "scripts.acceptance.cases_runtime:runner_exploit_sqli_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=3,
        sources=("core/tools/runner/base.py", "policy/request_guard.py"),
    ),
    CaseSpec(
        "SEC-L3-004", "REQ-L3-DENY", "审批台账拒绝为 L3 签发任何票据", "unit",
        "scripts.acceptance.cases_policy:approval_refuses_l3",
        expect={"values.raised": 4, "values.issued": 0},
        negative=True, min_assertions=5,
        sources=("policy/test_transaction.py",),
    ),
    CaseSpec(
        "SEC-L3-005", "REQ-L3-DENY", "批量流水线在任何环境都关闭 L3 探针", "integration",
        "scripts.acceptance.cases_runtime:enforcer_disables_l3_all_envs",
        expect={"values.all_off": True, "values.original_untouched": True, "http_sent": False},
        negative=True, min_assertions=7,
        sources=("policy/enforcer.py",),
    ),
    # ── UNKNOWN ──────────────────────────────────────────────────
    CaseSpec(
        "SEC-UNK-001", "REQ-UNKNOWN-DENY", "矩阵外命令 → UNKNOWN 且 denied", "unit",
        "scripts.acceptance.cases_policy:unknown_command_denied",
        expect={"values.decision": "UNKNOWN", "values.denied": True},
        negative=True, min_assertions=3, sources=("policy/api_policy.py",),
    ),
    CaseSpec(
        "SEC-UNK-002", "REQ-UNKNOWN-DENY", "未识别 HTTP 方法 → UNKNOWN 命令", "unit",
        "scripts.acceptance.cases_policy:unknown_method_denied",
        expect={"values.decision": "UNKNOWN", "values.command": ""},
        negative=True, min_assertions=4, sources=("policy/request_guard.py",),
    ),
    CaseSpec(
        "SEC-UNK-003", "REQ-UNKNOWN-DENY", "Runner 发 PROPFIND 被拒且不触网", "security",
        "scripts.acceptance.cases_runtime:runner_unknown_method_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0,
                "audit.any": {"event": "deny", "decision": "UNKNOWN"}},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-UNK-004", "REQ-UNKNOWN-DENY", "未知外部工具被拒且不创建进程/不触网", "security",
        "scripts.acceptance.cases_runtime:runner_unknown_tool_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=3,
        sources=("policy/request_guard.py", "core/tools/external.py"),
    ),

    # ── EXPORT / AUTH ────────────────────────────────────────────
    CaseSpec(
        "SEC-EXP-001", "REQ-EXPORT-AUTH-DENY", "EXPORT 独立分类但无命令映射 → UNKNOWN", "unit",
        "scripts.acceptance.cases_policy:export_denied",
        expect={"values.category": "EXPORT", "values.decision": "UNKNOWN", "values.command": ""},
        negative=True, min_assertions=4, sources=("policy/api_policy.py", "policy/request_guard.py"),
    ),
    CaseSpec(
        "SEC-EXP-002", "REQ-EXPORT-AUTH-DENY", "Runner GET /export 被拒且数据未出网", "security",
        "scripts.acceptance.cases_runtime:runner_export_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0,
                "audit.any": {"event": "deny", "category": "EXPORT"}},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-EXP-003", "REQ-EXPORT-AUTH-DENY", "AUTH 独立分类但无命令映射 → UNKNOWN", "unit",
        "scripts.acceptance.cases_policy:auth_denied",
        expect={"values.category": "AUTH", "values.decision": "UNKNOWN", "values.command": ""},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-EXP-004", "REQ-EXPORT-AUTH-DENY", "Runner login 工具被拒且不提交凭证", "security",
        "scripts.acceptance.cases_runtime:runner_login_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0,
                "audit.any": {"event": "deny", "decision": "UNKNOWN"}},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-EXP-005", "REQ-EXPORT-AUTH-DENY", "矩阵无导出/认证授权行（不得为分类器造行）", "unit",
        "scripts.acceptance.cases_policy:no_export_auth_rows",
        expect={"values.rules": 10, "values.export_row": False, "values.auth_row": False},
        negative=True, min_assertions=4, sources=("policy/api_policy.py",),
    ),

    # ── fileread ─────────────────────────────────────────────────
    CaseSpec(
        "SEC-FR-001", "REQ-FILEREAD-NOT-L0", "fileread 不在探针映射表 → UNKNOWN", "unit",
        "scripts.acceptance.cases_policy:fileread_unmapped",
        expect={"values.mapped": False, "values.decision": "UNKNOWN"},
        negative=True, min_assertions=3, sources=("policy/request_guard.py",),
    ),
    CaseSpec(
        "SEC-FR-002", "REQ-FILEREAD-NOT-L0", "Runner exploit_probe(fileread) 被拒且不读文件", "security",
        "scripts.acceptance.cases_runtime:runner_fileread_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-FR-003", "REQ-FILEREAD-NOT-L0", "sqli 映射到 L3 而非 L0（同表不得漂移）", "unit",
        "scripts.acceptance.cases_policy:sqli_maps_l3",
        expect={"values.sqli_command": "SQL 注入验证", "values.sqli_level": "L3",
                "values.read_level": "L0"},
        negative=True, min_assertions=3, sources=("policy/request_guard.py",),
    ),

    # ── Gateway ──────────────────────────────────────────────────
    CaseSpec(
        "SEC-GW-001", "REQ-GATEWAY", "产品代码无裸 httpx 客户端（AST 扫描）", "security",
        "scripts.acceptance.cases_runtime:gateway_static_no_bare_clients",
        expect={"values.constructions_at_least_7": True, "values.ungoverned": 0,
                "http_sent": False},
        negative=True, min_assertions=4,
        sources=("core/proxy.py", "detectors/", "collectors/", "core/auth.py", "kb/intel.py"),
    ),
    CaseSpec(
        "SEC-GW-002", "REQ-GATEWAY", "Detector 请求经由 build_client_kwargs 构造的客户端", "integration",
        "scripts.acceptance.cases_runtime:detector_uses_gateway",
        expect={"values.status": 200, "http_sent": True, "network.count": 1,
                "gateway.all_governed": True},
        min_assertions=4,
    ),
    CaseSpec(
        "SEC-GW-003", "REQ-GATEWAY", "Runner http_request 经由统一 Gateway", "integration",
        "scripts.acceptance.cases_runtime:runner_uses_gateway",
        expect={"values.blocked": False, "http_sent": True, "network.count": 1,
                "gateway.all_governed": True},
        min_assertions=3,
    ),

    # ── 无旁路 ───────────────────────────────────────────────────
    CaseSpec(
        "SEC-BYP-001", "REQ-NO-BYPASS", "Runner：只读放行 / 未绑定环境的写操作拒绝", "security",
        "scripts.acceptance.cases_runtime:runner_read_allow_write_deny",
        expect={"values.read_blocked": False, "values.write_blocked": True,
                "network.count": 1},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-BYP-002", "REQ-NO-BYPASS", "Detector 批量探测逐请求受策略约束", "security",
        "scripts.acceptance.cases_runtime:detector_batch_blocked",
        expect={"values.blocked": 3, "values.allowed": 0, "http_sent": False,
                "network.count": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-BYP-003", "REQ-NO-BYPASS", "Collector（PathScanner）跨主机请求被拒", "security",
        "scripts.acceptance.cases_runtime:collector_cross_host_blocked",
        expect={"values.blocked": True, "network.count": 1, "values.cross_hits": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-BYP-004", "REQ-NO-BYPASS", "Scheduler 入口：生产拒绝 / 未绑定降级", "integration",
        "scripts.acceptance.cases_runtime:scheduler_entry_gate",
        expect={"values.prod_allowed": False, "values.unknown_note": True,
                "values.probes_off_in_unknown": True, "http_sent": False},
        negative=True, min_assertions=5,
        sources=("policy/enforcer.py", "core/scheduler/"),
    ),
    CaseSpec(
        "SEC-BYP-005", "REQ-NO-BYPASS", "CLI scan 生产目标在起任务前退出", "integration",
        "scripts.acceptance.cases_runtime:cli_production_refused",
        expect={"values.exit_code": 2, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=2,
        sources=("cli/scan.py",),
    ),
    CaseSpec(
        "SEC-BYP-006", "REQ-NO-BYPASS", "MCP 扫描任务生产目标被拒", "integration",
        "scripts.acceptance.cases_runtime:mcp_production_refused",
        expect={"values.raised": True, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=2,
        sources=("mcp_server/jobs.py",),
    ),
    CaseSpec(
        "SEC-BYP-007", "REQ-NO-BYPASS", "后台任务（recon_ports_bg）跨主机被拒且不建任务", "security",
        "scripts.acceptance.cases_runtime:background_task_blocked",
        expect={"values.blocked": True, "values.bg_tasks": 0,
                "http_sent": False, "network.count": 0},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-BYP-008", "REQ-NO-BYPASS", "Planner 的 AUTH 登录在无授权时被跳过", "security",
        "scripts.acceptance.cases_runtime:planner_auth_refused",
        expect={"values.allowed": False, "values.calls_before_login": True, "http_sent": False},
        negative=True, min_assertions=3,
        sources=("core/planner.py", "policy/request_guard.py"),
    ),

    # ── 范围 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-SCP-001", "REQ-SCOPE", "in_scope 矩阵：端口/scheme/路径/编码绕过", "unit",
        "scripts.acceptance.cases_policy:scope_matrix",
        expect={"values.failures": 0, "values.checks": 14},
        negative=True, min_assertions=14, sources=("policy/request_guard.py",),
    ),
    CaseSpec(
        "SEC-SCP-002", "REQ-SCOPE", "Runner 打非绑定端口被拒且不触网", "security",
        "scripts.acceptance.cases_runtime:runner_cross_port_blocked",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0,
                "audit.any": {"event": "deny"}},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-SCP-003", "REQ-SCOPE", "Detector 绑定 A 后打 B 被拒", "security",
        "scripts.acceptance.cases_runtime:detector_cross_host_blocked",
        expect={"values.blocked": True, "network.count": 1, "values.cross_hits": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-SCP-004", "REQ-SCOPE", "主机级授权只对端口/子域工具生效", "unit",
        "scripts.acceptance.cases_policy:host_scope_only_for_host_tools",
        expect={"values.host_ok": True, "values.strict_ok": False,
                "values.port_tool_listed": True},
        negative=True, min_assertions=4, sources=("policy/request_guard.py",),
    ),

    # ── 重定向 ───────────────────────────────────────────────────
    CaseSpec(
        "SEC-RED-001", "REQ-REDIRECT", "跨主机重定向被拦截，外部主机 0 请求", "security",
        "scripts.acceptance.cases_runtime:detector_cross_redirect_blocked",
        expect={"values.blocked": True, "network.count": 1, "values.cross_hits": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-RED-002", "REQ-REDIRECT", "同源重定向正常跟随（功能未被误杀）", "integration",
        "scripts.acceptance.cases_runtime:detector_same_redirect_followed",
        expect={"values.status": 200, "network.count": 2, "values.cross_hits": 0},
        min_assertions=3,
    ),
    CaseSpec(
        "SEC-RED-003", "REQ-REDIRECT", "Runner http_request 跟随跨主机重定向时被拦", "security",
        "scripts.acceptance.cases_runtime:runner_cross_redirect_blocked",
        expect={"values.blocked_signal": True, "values.cross_hits": 0, "http_sent": True},
        negative=True, min_assertions=2,
    ),

    # ── 身份 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-ID-001", "REQ-IDENTITY", "身份三元组：base|sess|tgt，凭证值不进标签", "unit",
        "scripts.acceptance.cases_runtime:identity_triplet",
        expect={"values.same_token_diff_session": True, "values.has_sess": True,
                "values.has_tgt": True, "values.leaked_token": False},
        min_assertions=5, sources=("core/tools/runner/base.py",),
    ),
    CaseSpec(
        "SEC-ID-002", "REQ-IDENTITY", "无凭证请求不继承前次实名身份", "security",
        "scripts.acceptance.cases_runtime:identity_no_inherit",
        expect={"values.after_without_cred": "anonymous", "values.before_with_cred": "cred",
                "http_sent": False},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-ID-003", "REQ-IDENTITY", "换目标后身份与台账归属随之变化", "integration",
        "scripts.acceptance.cases_runtime:identity_target_change",
        expect={"values.identity_changed": True, "values.old_object_not_known": True},
        min_assertions=3,
    ),

    # ── 并发 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-CON-001", "REQ-CONCURRENCY", "两会话并发创建：台账身份不串线", "security",
        "scripts.acceptance.cases_runtime:concurrent_ledger_isolated",
        expect={"values.objects": 2, "values.identities_distinct": True,
                "values.pending_left": False, "network.count": 2},
        negative=True, min_assertions=5,
    ),
    CaseSpec(
        "SEC-CON-002", "REQ-CONCURRENCY", "并发审批票据互不消费（精确绑定）", "unit",
        "scripts.acceptance.cases_policy:approval_no_cross_consume",
        expect={"values.a_ok": True, "values.b_ok": True,
                "values.cross_ok": False, "values.reuse_ok": False},
        negative=True, min_assertions=5, sources=("policy/test_transaction.py",),
    ),

    # ── 台账 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-LDG-001", "REQ-LEDGER", "删除判定只认本次创建/上传且带对象 ID 的条目", "unit",
        "scripts.acceptance.cases_policy:ledger_strict_id",
        expect={"values.created_ok": True, "values.other_id_ok": False,
                "values.update_only_ok": False, "values.root_ok": False},
        negative=True, min_assertions=6, sources=("policy/test_transaction.py",),
    ),
    CaseSpec(
        "SEC-LDG-002", "REQ-LEDGER", "Runner：删本次创建的对象放行，删他人 ID 拒绝", "security",
        "scripts.acceptance.cases_runtime:runner_delete_requires_created_id",
        expect={"values.create_ok": True, "values.recorded": True,
                "values.delete_created_ok": True, "values.delete_other_blocked": True,
                "network.count": 2},
        negative=True, min_assertions=7,
    ),
    CaseSpec(
        "SEC-LDG-003", "REQ-LEDGER", "创建返回 500 不登记，之后删除被拒", "security",
        "scripts.acceptance.cases_runtime:failed_create_not_recorded",
        expect={"values.objects": 0, "values.delete_blocked": True,
                "network.count": 1},
        negative=True, min_assertions=4,
    ),
    CaseSpec(
        "SEC-LDG-004", "REQ-LEDGER", "仅有审批、无对象身份验证的删除仍被拒", "security",
        "scripts.acceptance.cases_policy:ledger_approval_cannot_replace_identity",
        expect={"values.known_ok": True, "values.unknown_approved_ok": False,
                "values.unknown_no_approval_ok": False},
        negative=True, min_assertions=3, sources=("policy/test_transaction.py",),
    ),

    # ── 审批 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-APR-001", "REQ-APPROVAL", "票据绑定 URL/方法/指纹/等级/轮次/身份，单次有效", "unit",
        "scripts.acceptance.cases_policy:ticket_binding",
        expect={"values.first_ok": True, "values.wrong_url_ok": False,
                "values.wrong_digest_ok": False, "values.reuse_ok": False,
                "values.expired_ok": False},
        negative=True, min_assertions=7, sources=("policy/test_transaction.py",),
    ),
    CaseSpec(
        "SEC-APR-002", "REQ-APPROVAL", "审批审计记录真实审批主体（字符串身份）", "integration",
        "scripts.acceptance.cases_runtime:approver_identity_recorded",
        expect={"values.allowed": True, "http_sent": True,
                "audit.any": {"event": "approval", "decision": "ALLOW"}},
        min_assertions=5,
    ),
    CaseSpec(
        "SEC-APR-003", "REQ-APPROVAL", "裸 True 审批记为未认证审批人（不得冒充身份）", "security",
        "scripts.acceptance.cases_runtime:bare_true_approver_unauthenticated",
        expect={"values.allowed": True,
                "values.authenticated_approver": False, "http_sent": True},
        negative=True, min_assertions=2,
    ),
    CaseSpec(
        "SEC-APR-004", "REQ-APPROVAL", "请求内容变更后旧审批不再适用（重新审批）", "security",
        "scripts.acceptance.cases_runtime:approval_not_reused_after_change",
        expect={"values.approver_calls": 2, "network.count": 2},
        negative=True, min_assertions=2,
    ),

    # ── 审计 ─────────────────────────────────────────────────────
    CaseSpec(
        "SEC-AUD-001", "REQ-AUDIT", "拒绝事件落盘 JSONL（含命令/理由/run_id）", "integration",
        "scripts.acceptance.cases_runtime:deny_event_persisted",
        expect={"values.file_exists": True, "values.deny_lines": 1, "http_sent": False,
                "audit.any": {"event": "deny", "command": "SQL 注入验证"}},
        negative=True, min_assertions=4, sources=("policy/audit_logger.py",),
    ),
    CaseSpec(
        "SEC-AUD-002", "REQ-AUDIT", "审计不可持久化时写操作拒绝（不能用内存替代）", "security",
        "scripts.acceptance.cases_runtime:audit_disabled_blocks_write",
        expect={"values.blocked": True, "http_sent": False, "network.count": 0},
        negative=True, min_assertions=3,
    ),
    CaseSpec(
        "SEC-AUD-003", "REQ-AUDIT", "Detector 层拦截也写入审计（不只 Runner）", "integration",
        "scripts.acceptance.cases_runtime:detector_block_audited",
        expect={"values.blocked": True, "http_sent": False,
                "audit.any": {"event": "deny"}},
        negative=True, min_assertions=3,
        sources=("detectors/base.py", "policy/audit_logger.py"),
    ),
]


# ── 基线 / 完整性 ────────────────────────────────────────────────

_SKIP_RE = re.compile(
    r"(pytest\.mark\.(?:skip|xfail)|unittest\.skip|@skipIf|\.skipTest\()"
)
_ALLOWED_EXPECT_PREFIX = (
    "values.", "http_sent", "gateway.all_governed", "network.", "audit.", "assertions",
)


def load_baseline() -> tuple[dict[str, int], list[str]]:
    """读断言数基线。文件缺失 → 全部用例都记为"基线缺失"。"""
    if not BASELINE_PATH.exists():
        return {}, [c.id for c in CASES]
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, [c.id for c in CASES]
    cases = data.get("cases") or {}
    missing = [c.id for c in CASES if c.id not in cases]
    return {str(k): int(v) for k, v in cases.items()}, missing


def write_baseline() -> Path:
    data = {
        "note": "安全验收断言数基线。低于基线即 FAIL；不得为了通过而调低。",
        "cases": {c.id: c.min_assertions for c in CASES},
    }
    BASELINE_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    return BASELINE_PATH


def _scan_skip_markers() -> list[str]:
    bad: list[str] = []
    root = HERE.parent
    for path in sorted(root.glob("*_test.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in _SKIP_RE.finditer(text):
            line = text[:m.start()].count("\n") + 1
            bad.append(f"{path.name}:{line} 出现跳过/预期失败标记（{m.group(0)}）")
    return bad


def check_integrity() -> list[str]:
    """目录与测试资产完整性。返回错误清单（空 = 通过）。"""
    errs: list[str] = []

    ids = [c.id for c in CASES]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        errs.append(f"用例 ID 重复：{sorted(dup)}")

    reqs = {r.id: r for r in REQUIREMENTS}
    for rid in REQUIRED_REQ_IDS:
        if rid not in reqs:
            errs.append(f"必需需求缺失：{rid}")

    for req in REQUIREMENTS:
        mine = [c for c in CASES if c.req == req.id]
        if not mine:
            errs.append(f"{req.id} 没有任何用例")
            continue
        if req.must_be_negative and not any(c.negative for c in mine):
            errs.append(f"{req.id} 缺少负向用例")
        if not any(c.kind == "security" for c in mine):
            errs.append(f"{req.id} 缺少 SECURITY 类型用例（不得只用单元测试交差）")

    for c in CASES:
        if c.req not in reqs:
            errs.append(f"{c.id} 的需求 {c.req} 不存在")
        if c.negative and "cases_runtime" in c.fn:
            # 走真实请求路径的负向用例，必须把"有没有发出去"写成预期：
            # http_sent 或 network.count 二者其一，不能只断言返回值。
            if "http_sent" not in c.expect and "network.count" not in c.expect:
                errs.append(
                    f"{c.id} 是负向用例但没有 http_sent / network.count 预期"
                    "（无法证明未触网）"
                )
        for key in c.expect:
            if not key.startswith(_ALLOWED_EXPECT_PREFIX):
                errs.append(f"{c.id} 的预期键 {key} 不受支持")
        mod, _, fn = c.fn.partition(":")
        try:
            m = importlib.import_module(mod)
            if not callable(getattr(m, fn, None)):
                errs.append(f"{c.id} 指向的函数不存在：{c.fn}")
        except Exception as exc:  # noqa: BLE001
            errs.append(f"{c.id} 用例模块导入失败：{type(exc).__name__}: {exc}")

    baseline, missing = load_baseline()
    if missing:
        errs.append("断言数基线缺失（先跑 --init-baseline 并提交）：" + "、".join(missing[:6]))

    errs.extend(_scan_skip_markers())
    return errs


__all__ = [
    "REQUIREMENTS", "CASES", "REQUIRED_REQ_IDS",
    "load_baseline", "write_baseline", "check_integrity", "BASELINE_PATH",
]
