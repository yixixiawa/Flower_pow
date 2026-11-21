"""第二章 请求分类与风险决策 专项测试（guardschedule5）。

逐条对应任务书 §7 的 16 条必测项：

  1. 非标准路径显式登记成功
  2. 非标准路径未登记时拒绝
  3. URL 关键词不匹配不影响显式登记
  4. ``/api/users/delete`` 不得因被登记为 login 获得删除请求放行
  5. 已登记登录请求满足条件时仍能正常通过
  6. AUTH 请求包含批量删除信号时按 L3 拒绝
  7. AUTH 请求包含命令执行信号时按 L3 拒绝
  8. AUTH 请求包含上传信号时不能直接走 AUTH_BOOTSTRAP
  9. EXPORT 仍为独立分类且 UNKNOWN
 10. AUTH 仍为独立分类且没有矩阵授权行
 11. 未知 Method 不得降级为 READ
 12. ``environment=""`` 与 ``environment="unknown"`` 决策一致
 13. 同一请求经过 Runner / Detector / POC 时分类一致
 14. 同一登录请求不能重复消耗两次频率配额
 15. L3 永久拒绝，审批不能解锁
 16. DENY 和 UNKNOWN 不进入 GUARD 审批

测试只用离线单元判定与 ``127.0.0.1`` 的 MockNet，不向任何真实目标发请求。

运行：``.venv/Scripts/python.exe scripts/classify_guard_test.py``（退出码 0 = 全过）。
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import Config
from core.session import Session
from core.state import Asset
from core.tools.runner import ToolRunner
from policy import auth_bootstrap as ab
from policy import auth_registry as ar
from policy.api_policy import (
    COMMAND_FOR_CATEGORY,
    RULES,
    ApiCategory,
    Decision,
    PolicyDecision,
    decide,
    rule_for_command,
)
from policy.request_guard import (
    GuardContext,
    RequestGuard,
    classify_request,
)
from scripts.acceptance.mocknet import MockNet

PROJECT = Path(__file__).resolve().parent.parent
PASS = 0
FAIL: list[str] = []


def check(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


def section(title: str) -> None:
    print(f"\n{title}")


# ── 夹具 ──────────────────────────────────────────────────────────


def make_cfg(tmp: Path, *, env: str = "isolated_test", binding: str = "",
             default_env: str = "unknown") -> Config:
    cfg = Config()
    cfg.scan.timeout = 5.0
    cfg.scan.follow_redirects = True
    cfg.scan.proxy = None
    cfg.scan.no_proxy = []
    cfg.scan.proxy_autodetect = False
    cfg.scan.verify_tls = False
    cfg.llm.enabled = False
    cfg.rag.enabled = False
    cfg.data_dir = str(tmp / "data")
    cfg.output_dir = str(tmp / "out")
    cfg.scan.audit_dir = cfg.data_dir
    cfg.policy.default_environment = default_env
    cfg.policy.audit = True
    cfg.policy.environments = {binding: env} if binding else {}
    return cfg


def auth_assets() -> list[Asset]:
    return [
        Asset(kind="api", value="/api/auth/login",
              meta={"method": "POST", "path": "/api/auth/login",
                    "body_fields": ["username", "password"]}),
        Asset(kind="api", value="/api/auth/captcha",
              meta={"method": "GET", "path": "/api/auth/captcha"}),
    ]


def make_session(net: MockNet) -> Session:
    s = Session(target=net.target)
    s.result.target = s.target
    s.result.target_id = s.target
    s.result.assets.extend(auth_assets())
    return s


def run_login(runner, session, **kw):
    args = {"url": session.target, "username": "tester", "password": "S3cret!pass"}
    args.update(kw)
    return asyncio.run(runner.execute("login", args, session))


def ctx_of(base: str, *, env: str = "isolated_test", entries=(), sid: str = "c1"):
    return GuardContext(
        target_id=base, bound_target=base, environment=env,
        identity_bound=True, identity=f"test|sess={sid}",
        session_id=sid, auth_entries=tuple(entries),
    )


def audit_text(cfg: Config) -> str:
    p = Path(cfg.data_dir) / "policy" / "audit.jsonl"
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


BASE = "http://127.0.0.1:8080"


# ── 1/2/3/5. 非标准路径的显式登记 ─────────────────────────────────


def scenario_register_nonstandard(tmp: Path) -> None:
    section("1-3/5. 非标准认证路径：显式登记成功、未登记拒绝、关键词不参与判定")
    cfg = make_cfg(tmp / "s1")
    g = RequestGuard(cfg)
    # 这个路径不含 login/auth/token/sso/captcha/session 任何关键词
    url = f"{BASE}/api/v2/ticket"
    check(ab.implicit_endpoint(url) is None,
          "前提：该路径不命中任何认证关键词（关键词识别也认不出它）")
    check(not ar.entries_for(cfg, BASE), "未登记时登记表为空")

    def judge(u: str, body: str = '{"username":"u","password":"p"}',
              entries=None, method: str = "POST"):
        return g.check_auth(
            u, method=method, body=body,
            ctx=ctx_of(BASE, entries=(ar.entries_for(cfg, BASE) if entries is None else entries)),
            count_rate=False,
        )

    d = judge(url)
    check(not d.allowed and "ENDPOINT_UNREGISTERED" in " ".join(d.signals),
          f"② 未登记的显式路径必须拒绝：{d.reason[:120]}")
    check("候选识别" not in d.reason,
          "③ 关键词识别不出这条路径——拒绝理由里也不应出现候选提示")
    # ② 未登记时走矩阵：这条路径只会被 "Method POST" 判成创建测试数据（L1），
    #    unknown 环境下按"L1 条件不满足"拒绝——它进不了 AUTH_BOOTSTRAP。
    d = g.check_request(url, method="POST",
                        ctx=ctx_of(BASE, env="unknown", entries=()))
    check(not d.allowed and d.category == ApiCategory.CREATE,
          f"② 未登记的非标准路径按矩阵判（L1 拒绝）：{d.category}/{d.decision}")

    msg = ar.register(
        cfg, target="127.0.0.1", url="/api/v2/ticket", kind="login",
        fields=["username", "password"], note="非标准登录端点（用户确认）",
    )
    check("已登记" in msg and "来源 user" in msg, f"① 显式登记成功：{msg[:120]}")
    eps = ar.entries_for(cfg, BASE)
    hit = [e for e in eps if e.url.endswith("/api/v2/ticket")]
    check(bool(hit), f"① 登记表应包含该入口：{[e.url for e in eps]}")
    check(hit and hit[0].source == "user", "① 登记来源记为 user（可追溯）")
    check(hit and "username" in hit[0].fields, "① 登记字段被保留（参数结构校验用）")
    txt = audit_text(cfg)
    check('"event": "registry"' in txt and '"decision": "REGISTER"' in txt,
          "登记必须产生审计记录（event=registry / decision=REGISTER）")

    d = judge(url)
    check(d.allowed and d.level == "AUTH_BOOTSTRAP",
          f"⑤ 已登记 + 条件满足 → 正常放行：{d.reason[:120]}")
    check(any("来源 user" in s for s in d.signals),
          f"审计信号应标注登记来源：{d.signals}")

    # ③⑤ 登记事实参与"走哪条通道"：同一条 URL 经 http_request（check_request）
    #     也不再被 "Method POST = 创建测试数据（L1）" 判死。
    d = g.check_request(url, method="POST",
                        body='{"username":"u","password":"p"}',
                        ctx=ctx_of(BASE, entries=ar.entries_for(cfg, BASE)))
    check(d.allowed and d.level == "AUTH_BOOTSTRAP",
          f"③ 已登记的非标准路径经统一入口也走 AUTH_BOOTSTRAP："
          f"{d.level}/{d.decision}/{d.reason[:80]}")

    # ⑤ 反向：已登记入口照样受参数结构约束（不是"登记即通行"）
    d = judge(url, body='{"pageNum": 1}')
    check(not d.allowed and "结构" in d.reason,
          f"⑤ 已登记入口仍要求参数符合认证结构：{d.reason[:120]}")


# ── 4/6/7/8. AUTH 不是风险豁免 ────────────────────────────────────


def scenario_auth_not_exemption(tmp: Path) -> None:
    section("4/6/7/8. AUTH 只是用途分类，不屏蔽更高风险信号")
    cfg = make_cfg(tmp / "s2")
    g = RequestGuard(cfg)
    login = f"{BASE}/api/auth/login"
    entry = ab.AuthEndpoint(
        kind="login", url=login, method="POST",
        fields=frozenset({"username", "password"}), source="user",
    )
    ctx = ctx_of(BASE, entries=(entry,))

    # ④ 把删除接口登记成 login：写入前就拒
    try:
        ar.register(cfg, target="127.0.0.1", url="/api/users/delete", kind="login")
        check(False, "④ 删除接口不得被登记成登录入口")
    except ar.AuthRegistryError as exc:
        check("删除测试数据" in str(exc), f"④ 拒登理由指出它属于删除类：{str(exc)[:140]}")
        check("拒绝登记" in str(exc), "④ 拒登文本明确说明拒绝登记")

    # ④ 兜底：就算条目从别的途径混进登记表，执行期也拦得住
    bad = ab.AuthEndpoint(kind="login", url=f"{BASE}/api/users/delete",
                          method="POST", source="user")
    d = g.check_auth(f"{BASE}/api/users/delete", method="POST",
                     body='{"username":"u","password":"p"}',
                     ctx=ctx_of(BASE, entries=(bad,)), count_rate=False)
    check(not d.allowed and "ENDPOINT_RISK_MISMATCH" in " ".join(d.signals),
          f"④ 执行期用途复核必须拦下错误登记：{d.reason[:140]}")
    check("删除测试数据" in d.reason, f"④ 拒绝理由给出应走的矩阵命令：{d.reason[:140]}")

    # ④ http_request 路径：删除语义直接按矩阵判，不进 AUTH 通道
    d = g.check_request(f"{BASE}/api/users/delete", method="POST",
                        body='{"id": 7}', ctx=ctx)
    check(d.command == "删除测试数据" and d.level == "L2",
          f"④ 删除请求按 L2 判（不是 AUTH_BOOTSTRAP）：{d.command}/{d.level}")

    # ⑥ 批量删除信号 → L3
    d = g.check_request(login, method="POST",
                        body='{"username":"u","password":"p","ids":[1,2,3]}', ctx=ctx)
    check(d.command == "批量删除" and d.level == "L3" and d.decision == Decision.DENY,
          f"⑥ 登录端点夹带 ids 数组 → 批量删除 L3 拒绝：{d.command}/{d.level}/{d.decision}")
    d = g.check_auth(login, method="POST",
                     body='{"username":"u","password":"p","ids":[1,2,3]}',
                     ctx=ctx, count_rate=False)
    check(not d.allowed and "ENDPOINT_RISK_MISMATCH" in " ".join(d.signals),
          f"⑥ AUTH 通道自己也拒（不走 AUTH_BOOTSTRAP）：{d.reason[:140]}")

    # ⑦ 命令执行信号 → L3
    d = g.check_request(login, method="POST",
                        body='{"username":"u","password":"p","action":"exec"}', ctx=ctx)
    check(d.command == "命令执行" and d.level == "L3",
          f"⑦ 登录端点夹带命令执行 → L3：{d.command}/{d.level}")
    check(d.decision == Decision.DENY, f"⑦ L3 必须 DENY，实际 {d.decision}")

    # ⑧ 上传信号 → L2，绝不落 AUTH_BOOTSTRAP
    multipart = (
        '--X\r\nContent-Disposition: form-data; name="username"\r\n\r\nu\r\n'
        '--X\r\nContent-Disposition: form-data; name="file"; filename="a.php"\r\n'
        '<?php echo 1; ?>\r\n--X--\r\n'
    )
    d = g.check_request(login, method="POST", body=multipart, ctx=ctx)
    check(d.command == "上传测试文件" and d.level == "L2",
          f"⑧ 上传信号按 L2 判：{d.command}/{d.level}")
    check(d.level != "AUTH_BOOTSTRAP" and not d.allowed,
          f"⑧ 上传请求不得借 AUTH_BOOTSTRAP 放行：{d.level}/{d.decision}")

    # 对照：干净登录仍然是 AUTH_BOOTSTRAP
    d = g.check_request(login, method="POST",
                        body='{"username":"u","password":"p"}', ctx=ctx)
    check(d.allowed and d.level == "AUTH_BOOTSTRAP",
          f"对照：干净登录仍走 AUTH_BOOTSTRAP：{d.level}/{d.decision}")


# ── 9/10/11. 分类与映射不变形 ─────────────────────────────────────


def scenario_classification(tmp: Path) -> None:
    section("9/10/11. EXPORT / AUTH 独立分类、未知 Method 不降级 READ")
    cfg = make_cfg(tmp / "s3")
    g = RequestGuard(cfg)

    c = classify_request(f"{BASE}/api/users/export", method="GET")
    check(c.category == ApiCategory.EXPORT and c.command == "",
          f"⑨ EXPORT 独立分类且不映射命令：{c.category}/{c.command!r}")
    d = g.check_request(f"{BASE}/api/users/export", method="GET",
                        ctx=ctx_of(BASE))
    check(d.decision == Decision.UNKNOWN,
          f"⑨ EXPORT 无矩阵行 → UNKNOWN 默认拒绝：{d.decision}")

    c = classify_request(f"{BASE}/api/auth/login", method="POST")
    check(c.category == ApiCategory.AUTH and c.command == "",
          f"⑩ AUTH 独立分类且不映射命令：{c.category}/{c.command!r}")
    check(len(RULES) == 10, f"⑩ 矩阵仍恰好十条：{len(RULES)}")
    check(COMMAND_FOR_CATEGORY.get(ApiCategory.AUTH) == "",
          "⑩ AUTH 的矩阵映射必须为空串")
    check(rule_for_command("认证初始化") is None,
          "⑩ 矩阵里不得有「认证初始化」授权行")

    c = classify_request(f"{BASE}/api/users/1", method="PROPFIND")
    check(c.category == ApiCategory.UNKNOWN and c.command == "",
          f"⑪ 未知 Method 必须判 UNKNOWN，不得降级 READ：{c.category}/{c.command!r}")
    d = g.check_request(f"{BASE}/api/users/1", method="PROPFIND", ctx=ctx_of(BASE))
    check(d.decision == Decision.UNKNOWN, f"⑪ 未知 Method → UNKNOWN：{d.decision}")

    # 破坏性 SQL 打在一个 GET 查询接口上：分类必须被抬到 L3，不得因 GET 降级
    c = classify_request(f"{BASE}/api/users/list", method="GET",
                         body='{"q":"1; drop table users"}')
    check(c.command == "SQL 注入验证",
          f"⑪ 更高风险信号不得被只读方法降级：{c.command}")


# ── 12. 空环境 = unknown ──────────────────────────────────────────


def scenario_empty_environment(tmp: Path) -> None:
    section('12. environment="" 与 "unknown" 决策完全一致')
    for cmd in ("查询详情", "创建测试数据", "修改测试数据", "删除测试数据",
                "上传测试文件", "批量删除"):
        a = decide(cmd, environment="", identity_bound=True, target_bound=True)
        b = decide(cmd, environment="unknown", identity_bound=True,
                   target_bound=True)
        check(a.decision == b.decision and a.level == b.level,
              f'⑫ {cmd}：空环境与 unknown 结论必须一致（{a.decision}/{b.decision}）')

    d = decide("查询详情", environment="", identity_bound=True, target_bound=True,
               clearly_read_only=False)
    check(d.decision == Decision.DENY,
          f"⑫ 空环境 + 非明确只读 → 拒绝（此前会误放行）：{d.decision}")
    d = decide("查询详情", environment="", identity_bound=True, target_bound=True,
               clearly_read_only=True)
    check(d.decision == Decision.ALLOW,
          f"⑫ 空环境 + 明确只读 → 放行（严格条件保留）：{d.decision}")
    d = decide("创建测试数据", environment="", identity_bound=True, target_bound=True)
    check(d.decision == Decision.DENY and "L1" in d.reason,
          f"⑫ 空环境的 L1 仍按条件不满足拒绝：{d.reason[:80]}")


# ── 13. 多入口分类一致 ────────────────────────────────────────────


def scenario_entry_consistency(tmp: Path) -> None:
    section("13. 同一请求经 Runner / Detector / POC 分类一致")
    cfg = make_cfg(tmp / "s4")
    g = RequestGuard(cfg)
    ctx = ctx_of(BASE)
    url = f"{BASE}/api/user"

    d_req = g.check_request(url, method="POST",
                            body='{"q": "1; drop table users"}', ctx=ctx)
    d_probe = g.check_probe(url, "sqli", ctx=ctx)
    d_builtin = g.check_builtin("sqli_probe", url, ctx=ctx)
    check({d_req.command, d_probe.command, d_builtin.command} == {"SQL 注入验证"},
          f"⑬ 三个入口对 SQL 注入的映射一致：{d_req.command}/{d_probe.command}/{d_builtin.command}")
    check({d_req.level, d_probe.level, d_builtin.level} == {"L3"},
          f"⑬ 等级也必须一致（L3）：{d_req.level}/{d_probe.level}/{d_builtin.level}")
    check({d_req.decision, d_probe.decision, d_builtin.decision} == {Decision.DENY},
          "⑬ 结论一致：全部 DENY")

    multipart = '--X\r\nContent-Disposition: form-data; filename="a.php"\r\n'
    d_req = g.check_request(url, method="POST", body=multipart, ctx=ctx)
    d_probe = g.check_probe(url, "upload", ctx=ctx)
    check(d_req.command == d_probe.command == "上传测试文件",
          f"⑬ 上传语义两个入口一致：{d_req.command}/{d_probe.command}")
    check(d_req.level == d_probe.level == "L2",
          f"⑬ 上传等级一致（L2）：{d_req.level}/{d_probe.level}")

    # 静态：Detector 必须复用 guard.check_request，不得自带一套分类/决策
    src = (PROJECT / "detectors" / "base.py").read_text(encoding="utf-8")
    check("check_request(" in src, "⑬ detectors/base.py 必须复用 RequestGuard.check_request")
    check("classify_request(" not in src,
          "⑬ detectors/base.py 不得自己再分类一份")
    check(".decide(" not in src, "⑬ detectors/base.py 不得直接调用 decide()")
    # 后台任务同样只走 runner.execute（→ _policy_gate），不另建判定
    tasks_src = (PROJECT / "core" / "tools" / "runner" / "tasks.py").read_text(
        encoding="utf-8")
    check("classify_request(" not in tasks_src and ".decide(" not in tasks_src,
          "⑬ 后台任务模块不得自带分类/决策")


# ── 14. 频率只扣一次 ──────────────────────────────────────────────


def scenario_single_quota(tmp: Path, net: MockNet) -> None:
    section("14. 同一登录请求只消耗一次频率配额")
    cfg = make_cfg(tmp / "s5", binding=net.a.binding)
    runner = ToolRunner(cfg, root=tmp)
    s = make_session(net)

    # 单元层：意图判定不计配额
    ab.configure_rate_limit(max_attempts=1, window=60.0, min_interval=0.0)
    ab.reset_rate_limits()
    entries = ab.entries_for(net.target, s.result.assets)
    try:
        i1 = ab.check_intent(kind="login", target_id=s.target, bound_target=s.target,
                             environment="isolated_test", entries=entries,
                             session_id="q1")
        i2 = ab.check_intent(kind="login", target_id=s.target, bound_target=s.target,
                             environment="isolated_test", entries=entries,
                             session_id="q1")
        check(i1.allowed and i2.allowed,
              "⑭ 工具级意图判定连续两次都放行（意图不消耗配额）")

        # 请求层：一次请求一次配额
        first = asyncio.run(runner.execute(
            "login", {"url": s.target, "username": "tester", "password": "S3cret!pass"}, s))
        check("登录成功" in first,
              f"⑭ 配额 1 时单次登录必须成功（若工具级也计数就会被自己挡下）：{first[:160]}")
        second = asyncio.run(runner.execute(
            "login", {"url": s.target, "username": "tester", "password": "S3cret!pass"}, s))
        check("登录未成功" in second and "频率" in second,
              f"⑭ 第二次登录必须被频率限制拦住：{second[:160]}")
    finally:
        ab.configure_rate_limit(max_attempts=5, window=60.0, min_interval=0.5)
        ab.reset_rate_limits()

    # 桶是按 (会话|目标|入口) 分的：Detector 用自己的 session_id 不会吃掉
    # Runner 的配额（guardschedule3/5 的计数责任划分）。
    ab.configure_rate_limit(max_attempts=1, window=60.0, min_interval=0.0)
    ab.reset_rate_limits()
    try:
        g = RequestGuard(cfg)
        login = f"{net.target}/api/auth/login"
        ent = (ab.AuthEndpoint(kind="login", url=login, method="POST",
                               fields=frozenset({"username", "password"})),)
        body = '{"username":"u","password":"p"}'
        for sid in ("detector|h", "sess-1"):
            d = g.check_auth(login, method="POST", body=body,
                             ctx=ctx_of(net.target, entries=ent, sid=sid))
            check(d.allowed, f"⑭ 不同会话各自一份配额（{sid}）：{d.reason[:100]}")
    finally:
        ab.configure_rate_limit(max_attempts=5, window=60.0, min_interval=0.5)
        ab.reset_rate_limits()


# ── 15/16. 审批通道的边界 ─────────────────────────────────────────


def scenario_approval_boundary(tmp: Path) -> None:
    section("15/16. L3 永久拒绝；DENY / UNKNOWN 不进审批")
    cfg = make_cfg(tmp / "s6")
    runner = ToolRunner(cfg, root=tmp)
    s = Session(target=BASE)
    s.result.target = BASE
    s.result.target_id = BASE

    called: list[str] = []

    async def fake_review(d, session, url, *, method="", req_digest=""):
        called.append(url)
        return True

    runner._policy_review = fake_review     # type: ignore[assignment]

    cases = [
        ("REVIEW", "L3", "批量删除"),
        ("DENY", "L3", "批量删除"),
        ("DENY", "L2", "删除测试数据"),
        ("UNKNOWN", "", ""),
    ]
    for decision, level, command in cases:
        d = PolicyDecision(decision=decision, command=command, level=level,
                           category="DELETE", reason="单测构造")
        out = asyncio.run(runner._review_or_allow(d, s, f"{BASE}/x",
                                                  req_ctx={"method": "POST"}))
        check(out is not None and out.startswith("【已拦截】"),
              f"⑮⑯ {decision}/{level or '-'} 必须拒绝：{str(out)[:80]}")
    check(not called, f"⑮⑯ DENY/UNKNOWN/L3 一律不得进入审批通道（实际调用 {called}）")

    # 对照：L2 的 REVIEW 才走审批（且审批通过才放行）
    d = PolicyDecision(decision="REVIEW", command="上传测试文件", level="L2",
                       category="UPLOAD", reason="单测构造")
    out = asyncio.run(runner._review_or_allow(d, s, f"{BASE}/upload",
                                              req_ctx={"method": "POST"}))
    check(called == [f"{BASE}/upload"],
          f"⑮ L2 的 REVIEW 才进审批通道（实际调用 {called}）")
    check(out is None, f"⑮ 审批通过后放行：{str(out)[:80]}")

    # 决策层：L3 给 approved=True 也照样拒绝
    d = decide("批量删除", environment="isolated_test", identity_bound=True,
               target_bound=True, approved=True)
    check(d.decision == Decision.DENY,
          f"⑮ L3 审批也不解锁：{d.decision}")


# ── 主流程 ────────────────────────────────────────────────────────


def main() -> int:
    net = MockNet()
    try:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            scenario_register_nonstandard(tmp)
            scenario_auth_not_exemption(tmp)
            scenario_classification(tmp)
            scenario_empty_environment(tmp)
            scenario_entry_consistency(tmp)
            scenario_single_quota(tmp, net)
            scenario_approval_boundary(tmp)
    finally:
        net.close()

    print()
    if FAIL:
        print(f"失败 {len(FAIL)} 项：")
        for f in FAIL:
            print(f"  - {f}")
    print(f"结果：{PASS}/{PASS + len(FAIL)} 通过")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
