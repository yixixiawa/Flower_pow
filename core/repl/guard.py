"""``/guard`` 分级权限管理命令（REPL 层）。

在既有权限矩阵（``policy/api_policy``）、请求指纹（``request_fingerprint``）、
一次性票据与审计之上，提供**查看 / 管理 / 按具体操作审批**的命令面：

* 等级命令（L0..L3）**只展示规则与状态，不是解锁开关**——矩阵是代码，
  命令改不动它；
* ``approve/deny/revoke`` 操作的是 :class:`~policy.guard_registry.GuardRequest`
  编号，票据只对该具体请求有效，内容/目标/会话任一变化即失效；
* L3 与 UNKNOWN 永远不出现在可审批队列。
"""

from __future__ import annotations

import time

from core.repl.consts import COMMANDS

_LEVEL_RULES = {
    "L0": (
        "L0 只读查询 —— 有条件允许\n"
        "  覆盖：GET / HEAD / OPTIONS 及七维分类无更高风险信号的只读探针\n"
        "  约束：目标范围（in_scope）· 身份三元组 · 环境绑定 三项全部通过\n"
        "  环境判不出（unknown）时仅放行明确只读"
    ),
    "L1": (
        "L1 测试数据操作 —— 仅隔离测试环境允许\n"
        "  覆盖：测试环境内的创建/修改探测数据\n"
        "  约束：仅 isolated_test；生产 / 专门测试 / unknown 环境一律拒绝\n"
        "  同样受 目标范围 · 身份 · 环境绑定 约束"
    ),
    "L2": (
        "L2 高风险操作 —— 逐请求人工审批\n"
        "  覆盖：上传 / 删除 / 写操作\n"
        "  约束：上传需专门/隔离测试环境；删除需单独审批且只认本次创建并\n"
        "        取得对象 ID 的对象（审批不能替代对象身份验证）\n"
        "  票据：一次性、300 秒有效，仅该具体请求可用"
    ),
    "L3": (
        "L3 禁止操作 —— 永久拒绝\n"
        "  覆盖：SQL 注入验证 / 命令执行 / 批量删除 / 定时任务等\n"
        "  约束：任何环境、任何审批、任何配置都不能放行\n"
        "  审批层拒签票据，通道层二次拒绝，enforcer 强制关闭对应探针"
    ),
    "UNKNOWN": (
        "UNKNOWN —— 一律 DENY\n"
        "  覆盖：矩阵/分类判不出的命令、方法、探针类别（fail-closed）\n"
        "  EXPORT / AUTH 没有明确矩阵授权行时按 UNKNOWN 处理\n"
        "  不猜、不映射、不放行"
    ),
}


class _GuardMixin:
    # ── /guard ────────────────────────────────────────────────────
    def _guard(self, arg: str = "") -> None:
        """``/guard [status|L0|L1|L2|L3|pending|approve|deny|revoke|readonly]``。"""
        parts = (arg or "").split()
        sub = parts[0].lower() if parts else ""
        if sub in ("status", "状态"):
            self._guard_status()
        elif sub in ("l0", "l1", "l2", "l3", "unknown"):
            self._guard_level(sub.upper())
        elif sub == "pending":
            self._guard_pending()
        elif sub == "approve":
            self._guard_decision(parts[1] if len(parts) > 1 else "", action="approve")
        elif sub == "deny":
            self._guard_decision(parts[1] if len(parts) > 1 else "", action="deny")
        elif sub == "revoke":
            self._guard_decision(parts[1] if len(parts) > 1 else "", action="revoke")
        elif sub == "readonly":
            # 复用既有 /readonly 实现（运行期切换），语义见 _set_readonly
            self._set_readonly("readonly " + " ".join(parts[1:]))
        else:
            self._guard_overview()

    # ── 视图 ─────────────────────────────────────────────────────
    def _guard_overview(self) -> None:
        ro = bool(getattr(self.cfg.scan, "readonly", True))
        from policy.guard_registry import get_registry

        reg = get_registry(self.cfg.data_dir)
        n = len(reg.pending(self.session.session_id))
        lines = [
            "════════════════════════════════════════════════",
            " GUARD 权限控制",
            "════════════════════════════════════════════════",
            f" 运行模式：{'只读（readonly=on）' if ro else '正常（readonly=off）'}",
            f" 当前目标：{self.session.target or '（未设置）'}",
            f" 待审批：{n} 条" + ("（/guard pending 查看）" if n else ""),
            "",
            " 各级规则：",
            " ─ L0 只读查询     有条件允许，仍受 目标范围/身份/环境绑定 约束",
            " ─ L1 测试数据操作 仅隔离测试环境允许",
            " ─ L2 高风险操作   逐请求审批；上传需专门测试环境；删除需单独审批",
            " ─ L3 禁止操作     永久拒绝（SQL 注入验证/命令执行/批量删除/定时任务）",
            " ─ UNKNOWN        一律 DENY",
            "",
            " 等级命令（/guard L0..L3）只用于查看规则，不是解锁开关。",
            " 用法：/guard status · /guard pending · /guard approve|deny|revoke <id>",
            "       /guard readonly on|off（退出只读不突破矩阵）",
        ]
        print("\n".join(lines))

    def _guard_status(self) -> None:
        from policy.guard_registry import environment_for_target, get_registry

        reg = get_registry(self.cfg.data_dir)
        ro = bool(getattr(self.cfg.scan, "readonly", True))
        env = environment_for_target(self.cfg, self.session.target)
        pend = reg.pending(self.session.session_id)
        tid = getattr(self.session.result, "target_id", "")
        rid = getattr(self.session.result, "current_run_id", "")
        sight = reg.last_l3_sighting(self.session.session_id)
        lines = [
            " GUARD 状态",
            f" 会话       {self.session.session_id}",
            f" 目标       {self.session.target or '（未设置）'}  target_id={tid}",
            f" run_id     {rid}",
            f" 环境       {env or 'unknown'}",
            f" 只读模式   {'开' if ro else '关'}（readonly={'on' if ro else 'off'}）",
            f" 待审批     {len(pend)} 条",
        ]
        for r in pend:
            left = max(0, int(r.expires_at - time.time()))
            lines.append(f"   · {r.summary()}（剩余 {left}s）")
        lines += [
            "",
            " 等级状态：",
            " ─ L0 只读查询     有条件允许（受目标范围/身份/环境绑定约束）",
            " ─ L1 测试数据操作 仅隔离测试环境允许",
            " ─ L2 高风险操作   逐请求审批（上传需专门测试环境 / 删除需单独审批）",
            " ─ L3 禁止操作     永久拒绝",
            " ─ UNKNOWN        一律 DENY",
        ]
        lines.append(f" L3 最近识别 {'：' + sight['operation'] if sight else '：无'}")
        lines.append(f" 命令总数   {len(COMMANDS)}（含 /guard）")
        print("\n".join(lines))

    def _guard_level(self, level: str) -> None:
        from policy.guard_registry import environment_for_target, get_registry

        reg = get_registry(self.cfg.data_dir)
        env = environment_for_target(self.cfg, self.session.target)
        print("════════════════════════════════════════════════")
        print(_LEVEL_RULES[level])
        print(f"\n 当前环境：{env or 'unknown'} · 当前目标：{self.session.target or '（未设置）'}")
        if level == "L3":
            print()
            print("！你知道你在干什么了！")
            sight = reg.last_l3_sighting(self.session.session_id)
            if sight:
                print(f" 操作名称   {sight.get('operation', '')}")
                print(f" 目标       {sight.get('target', '')}")
                print(f" 请求来源   {sight.get('source', '')}")
                print(f" 风险等级   {sight.get('level', '')}")
                print(f" DENY 原因  {sight.get('reason', '')}")
            else:
                print(" 本会话尚未识别到 L3 请求。")
            print(" 此警告仅用于风险提醒，不是解锁密码或授权机制。")
        elif level == "L1":
            ok = env == "isolated_test"
            print(f" 当前环境{'满足' if ok else '不满足'} L1 生效条件"
                  f"{'' if ok else '（仅 isolated_test 允许）'}")
        elif level == "L2":
            pend = [r for r in reg.pending(self.session.session_id) if r.level == "L2"]
            print(f" 待审批的 L2 请求：{len(pend)} 条（/guard pending 查看）")
        print("════════════════════════════════════════════════")

    def _guard_pending(self) -> None:
        from policy.guard_registry import get_registry

        reg = get_registry(self.cfg.data_dir)
        pend = reg.pending(self.session.session_id)
        if not pend:
            print("当前没有待审批请求。")
            return
        print(f"待审批请求（{len(pend)} 条，票据有效期 {int(reg._ttl)}s）：")
        for r in pend:
            left = max(0, int(r.expires_at - time.time()))
            print(f"  {r.request_id}")
            print(f"    操作：{r.kind or r.command}（{r.level} / {r.method}）")
            print(f"    目标：{r.url}")
            print(f"    身份：{r.identity} · 剩余 {left}s")
            if r.reason:
                print(f"    原因：{r.reason[:120]}")
        print("\n处理：/guard approve <id> 放行本次请求（一次性）· /guard deny <id> 拒绝")

    # ── 审批动作 ─────────────────────────────────────────────────
    def _guard_target_id(self) -> str:
        """与 ``ToolRunner._policy_scope`` 同口径：result 缺失时回落 target。"""
        return (
            getattr(self.session.result, "target_id", "")
            or getattr(self.session, "target", "")
        )

    def _guard_decision(self, request_id: str, *, action: str) -> None:
        from policy.guard_registry import environment_for_target, get_registry

        request_id = (request_id or "").strip()
        if not request_id:
            print(f"用法：/guard {action} <request_id>（编号见 /guard pending）")
            return
        reg = get_registry(self.cfg.data_dir)
        approver = self._approver_label()
        env = environment_for_target(self.cfg, self.session.target)
        if action == "approve":
            ok, msg, tok = reg.approve(
                request_id, session_id=self.session.session_id,
                target_id=self._guard_target_id(),
                environment=env, approver=approver,
            )
            if ok:
                print(f"已签发票据（{request_id}）。{msg}")
                print("请重新发起同一请求；URL / 参数 / 请求体 / 目标 / 账号 / POC")
                print("任一变化都会使票据失效并重新进入待审批。")
            else:
                print(f"审批被拒绝：{msg}")
        elif action == "deny":
            ok, msg = reg.deny(
                request_id, session_id=self.session.session_id, approver=approver,
            )
            print(msg if ok else f"拒绝失败：{msg}")
        else:  # revoke
            ok, msg = reg.revoke(
                request_id, session_id=self.session.session_id, approver=approver,
            )
            print(msg if ok else f"撤销失败：{msg}")

    # ── 补全支持 ─────────────────────────────────────────────────
    def _completer_args(self, cmd: str) -> list[str]:
        """命令参数候选（供测试与补全器共用）。"""
        args_map = {
            "guard": [
                "status", "L0", "L1", "L2", "L3", "pending",
                "approve", "deny", "revoke", "readonly", "on", "off",
            ],
        }
        return args_map.get(cmd.lstrip("/").lower(), [])
