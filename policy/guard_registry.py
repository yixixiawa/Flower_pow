"""GUARD 请求审批台账 —— ``/guard`` 命令的后端。

职责单一：把「逐请求人工审批」从运行期回调通道（``runner.approver``）扩展成
**可登记、可查看、可事后审批**的请求台账。纪律不变：

* **票据只属于具体请求**——绑定（规范化 URL, 方法, 请求内容指纹, POC,
  target_id, run_id, session_id, 身份, 过期时间），任何一项不匹配即失效；
* **L3 与 UNKNOWN 永远不进入可审批队列**（注册即拒，双保险见
  ``ToolRunner._policy_review``）；
* **审批主体必须是真实身份**（``interactive:<用户>`` 等），空主体拒签；
* **审计不可持久化 → 敏感操作（审批/拒绝/撤销）一律拒绝**（schedule §6）。

并发模型：进程内单例（按 data_dir 键），``threading.Lock`` 保护——REPL 命令
与 Runner 门闸在不同协程/线程里访问同一份台账。
"""

from __future__ import annotations

import fnmatch
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from policy.api_policy import Environment
from policy.audit_logger import PolicyAudit

__all__ = ["GuardRequest", "GuardRegistry", "get_registry", "environment_for_target"]

# 票据有效期（秒）。与 ApprovalLedger 同口径。
DEFAULT_TTL = 300


@dataclass
class GuardRequest:
    """一条待审批/已审批的具体请求。"""

    request_id: str
    session_id: str
    target_id: str
    run_id: str
    url: str                # 规范化 URL
    method: str
    fingerprint: str        # request_fingerprint(method/url/params/body/poc)
    level: str              # L1 | L2（L3/UNKNOWN 注册即拒）
    command: str
    environment: str
    identity: str
    kind: str               # delete / upload / create / ...
    reason: str
    created_at: float
    expires_at: float
    status: str = "PENDING"  # PENDING/APPROVED/DENIED/CONSUMED/REVOKED/EXPIRED/INVALID
    approver: str = ""
    token: str = ""

    def summary(self) -> str:
        op = self.kind or self.command or self.method
        return f"{self.request_id} · {op} · {self.method} {self.url} · {self.level}"


def environment_for_target(cfg, target: str) -> str:
    """按 config 的 ``policy.environments`` 通配表解析目标环境。"""
    table = getattr(getattr(cfg, "policy", None), "environments", None) or {}
    host = urlparse(target).netloc if target else ""
    for pattern, env in table.items():
        pat = str(pattern)
        if fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(str(target), pat):
            return str(env)
    return Environment.UNKNOWN


class GuardRegistry:
    """按会话隔离的请求审批台账。"""

    def __init__(self, data_dir: str | Path, *, audit_enabled: bool = True) -> None:
        self.audit = PolicyAudit(data_dir, enabled=audit_enabled)
        self._lock = threading.RLock()
        self._items: dict[str, GuardRequest] = {}
        self._l3: dict[str, dict] = {}
        # 票据有效期（approve 时写入 expires_at）；待审批请求单独给更长的
        # 登记保留期——票据 300s 是消费窗口，不是排队窗口。
        self._ttl = DEFAULT_TTL
        self._pending_ttl = 3600
        self._seq = 0

    # ── 内部 ─────────────────────────────────────────────────────
    def _new_id(self) -> str:
        self._seq += 1
        return f"GRD-{int(time.time()) % 100000:05d}-{secrets.token_hex(3)}"

    def _sweep(self) -> None:
        now = time.time()
        for r in self._items.values():
            if r.status in ("PENDING", "APPROVED") and r.expires_at < now:
                r.status = "EXPIRED"

    def _audit(self, event: str, r: GuardRequest | None, *, decision: str,
               approver: str = "", reason: str = "", extra: dict | None = None) -> bool:
        """审计；持久化失败返回 False（调用方据此拒绝敏感操作）。"""
        e = dict(extra or {})
        if r is not None:
            e.setdefault("request_id", r.request_id)
            e.setdefault("session_id", r.session_id)
            e.setdefault("identity", r.identity)
            e.setdefault("kind", r.kind)
        return self.audit.log(
            event, command=(r.command if r else ""), level=(r.level if r else ""),
            decision=decision, url=(r.url if r else ""),
            target_id=(r.target_id if r else ""), run_id=(r.run_id if r else ""),
            reason=reason, extra=e or None,
        )

    # ── 登记 ─────────────────────────────────────────────────────
    def register(
        self, *, session_id: str, target_id: str, run_id: str, url: str,
        method: str, fingerprint: str, level: str, command: str,
        environment: str, identity: str, kind: str, reason: str,
    ) -> tuple[GuardRequest | None, str]:
        """登记一条待审批请求。L3 / UNKNOWN 拒绝登记（无审批出路）。"""
        if str(level).upper() in ("L3", "UNKNOWN"):
            return None, (
                f"等级 {level} 不允许人工审批（L3 永久拒绝 / UNKNOWN 默认拒绝），"
                "不进入可审批队列"
            )
        with self._lock:
            self._sweep()
            # 去重：同会话同指纹且仍待审批 → 复用既有编号
            for r in self._items.values():
                if (
                    r.session_id == session_id
                    and r.fingerprint == fingerprint
                    and r.status == "PENDING"
                ):
                    return r, ""
            now = time.time()
            req = GuardRequest(
                request_id=self._new_id(), session_id=session_id,
                target_id=target_id, run_id=run_id, url=url.rstrip("/"),
                method=(method or "GET").upper(), fingerprint=fingerprint,
                level=str(level).upper(), command=command, environment=environment,
                identity=identity, kind=kind, reason=reason,
                created_at=now, expires_at=now + self._pending_ttl,
            )
            self._items[req.request_id] = req
            self._audit("guard_pending", req, decision="PENDING",
                        reason="L2/L1 请求被拦截，等待人工审批")
            return req, ""

    # ── 查看 ─────────────────────────────────────────────────────
    def pending(self, session_id: str) -> list[GuardRequest]:
        with self._lock:
            self._sweep()
            return [
                r for r in self._items.values()
                if r.session_id == session_id and r.status == "PENDING"
            ]

    # ── 审批 ─────────────────────────────────────────────────────
    def approve(
        self, request_id: str, *, session_id: str, target_id: str,
        environment: str, approver: str,
    ) -> tuple[bool, str, str]:
        """审批一条请求：逐项核对（存在/会话/目标/等级/环境/主体）后签发一次性票据。"""
        with self._lock:
            self._sweep()
            r = self._items.get(request_id)
            if r is None:
                return False, "请求编号不存在（或已过期被清理）", ""
            if r.session_id != session_id:
                return False, "请求属于其它会话，不可跨会话审批", ""
            if r.target_id != target_id:
                return False, "请求属于其它目标，不可跨目标审批", ""
            if r.status != "PENDING":
                return False, f"请求当前状态为 {r.status}，不可审批", ""
            if not (approver or "").strip():
                return False, "审批主体缺失（需要真实身份，如 interactive:<用户>）", ""
            # 环境规则（schedule §2/§3.6）：L1 仅隔离测试环境；
            # L2 上传需专门/隔离测试环境，其余 L2 操作也仅限测试环境
            if r.level == "L1" and environment != Environment.ISOLATED_TEST:
                return False, (
                    f"L1 仅在隔离测试环境允许（当前 {environment or 'unknown'}）"
                ), ""
            if r.level == "L2" and environment not in Environment.TEST_ENVS:
                return False, (
                    f"L2 高风险操作仅在测试环境允许审批（当前 {environment or 'unknown'}）"
                ), ""
            token = f"guard-{secrets.token_hex(12)}"
            r.status = "APPROVED"
            r.approver = approver.strip()
            r.token = token
            r.expires_at = time.time() + self._ttl
            persisted = self._audit(
                "guard_issue", r, decision="APPROVED", approver=r.approver,
                reason="人工审批通过，签发一次性票据（仅本请求有效）",
                extra={"approver": r.approver, "expires_at": r.expires_at,
                       "authenticated_approver": True, "environment": environment},
            )
            if not persisted:
                # 审计落盘失败 → 敏感操作必须拒绝（schedule §6），回滚
                r.status = "PENDING"
                r.approver = ""
                r.token = ""
                return False, "审计无法持久化，审批被拒绝", ""
            return True, "已签发一次性票据（仅本请求有效，内容/目标/会话变化即失效）", token

    # ── 消费 ─────────────────────────────────────────────────────
    def consume(
        self, token: str, *, session_id: str, target_id: str, run_id: str,
        url: str, method: str, fingerprint: str, identity: str,
    ) -> tuple[bool, str]:
        """消费票据：逐项比对（会话/目标/轮次/URL/方法/指纹/身份），任一不匹配即失效。"""
        with self._lock:
            self._sweep()
            r = next((x for x in self._items.values() if x.token == token), None)
            if r is None:
                return False, "票据不存在"
            if r.status == "EXPIRED" or r.expires_at < time.time():
                r.status = "EXPIRED"
                return False, "票据已过期"
            if r.status != "APPROVED":
                return False, f"票据状态为 {r.status}，不可消费（单次有效）"
            mismatch = []
            if r.session_id != session_id:
                mismatch.append("session")
            if r.target_id != target_id:
                mismatch.append("target")
            if r.run_id != run_id:
                mismatch.append("run")
            if r.url.rstrip("/") != url.rstrip("/"):
                mismatch.append("URL")
            if r.method != (method or "GET").upper():
                mismatch.append("method")
            if r.fingerprint != fingerprint:
                mismatch.append("请求内容（参数/请求体/POC）")
            if r.identity != identity:
                mismatch.append("账号身份")
            if mismatch:
                # 内容/目标/会话任一变化 → 票据立即作废，必须重新审批
                r.status = "INVALID"
                r.token = ""
                self._audit(
                    "guard_consume_failed", r, decision="DENY",
                    reason="票据绑定字段不匹配，票据作废：" + "、".join(mismatch),
                    extra={"mismatch": mismatch, "approver": r.approver},
                )
                return False, "票据绑定不匹配（" + "、".join(mismatch) + "），票据已作废，请重新审批"
            r.status = "CONSUMED"
            r.token = ""
            self._audit(
                "guard_consume", r, decision="ALLOW",
                reason="一次性票据消费成功（单次执行）",
                extra={"approver": r.approver, "identity": identity},
            )
            return True, ""

    def match_approved(
        self, *, session_id: str, target_id: str, run_id: str, url: str,
        method: str, fingerprint: str, identity: str,
    ) -> tuple[bool, str, str]:
        """Runner 门闸用：查找与本请求精确匹配的已审批票据并消费。

        返回 (是否放行, 拒绝原因, 审批人)。找不到匹配票据时**不**作废
        任何票据（允许 approver 回调通道继续）。
        """
        with self._lock:
            self._sweep()
            r = next(
                (x for x in self._items.values()
                 if x.status == "APPROVED"
                 and x.session_id == session_id
                 and x.fingerprint == fingerprint
                 and x.url.rstrip("/") == url.rstrip("/")
                 and x.method == (method or "GET").upper()
                 and x.target_id == target_id),
                None,
            )
            if r is None:
                # 没有匹配票据：不作废任何东西，让 approver 回调通道继续
                return False, "", ""
            approver = r.approver
            token = r.token
        ok, why = self.consume(
            token, session_id=session_id, target_id=target_id, run_id=run_id,
            url=url, method=method, fingerprint=fingerprint, identity=identity,
        )
        return ok, why, approver

    # ── 拒绝 / 撤销 ───────────────────────────────────────────────
    def deny(self, request_id: str, *, session_id: str, approver: str) -> tuple[bool, str]:
        with self._lock:
            self._sweep()
            r = self._items.get(request_id)
            if r is None or r.session_id != session_id:
                return False, "请求编号不存在或不属于当前会话"
            if r.status != "PENDING":
                return False, f"请求当前状态为 {r.status}，无需拒绝"
            r.status = "DENIED"
            persisted = self._audit(
                "guard_deny", r, decision="DENIED", approver=approver,
                reason="人工拒绝该请求", extra={"approver": approver},
            )
            if not persisted:
                r.status = "PENDING"
                return False, "审计无法持久化，拒绝操作未生效，请重试"
            return True, f"已拒绝 {request_id}"

    def revoke(self, request_id: str, *, session_id: str, approver: str) -> tuple[bool, str]:
        with self._lock:
            self._sweep()
            r = self._items.get(request_id)
            if r is None or r.session_id != session_id:
                return False, "请求编号不存在或不属于当前会话"
            if r.status != "APPROVED":
                return False, f"请求当前状态为 {r.status}，没有可撤销的活跃票据"
            r.status = "REVOKED"
            r.token = ""
            persisted = self._audit(
                "guard_revoke", r, decision="REVOKED", approver=approver,
                reason="人工撤销未消费票据", extra={"approver": approver},
            )
            if not persisted:
                r.status = "APPROVED"
                return False, "审计无法持久化，撤销操作未生效，请重试"
            return True, f"已撤销 {request_id} 的票据（未消费即作废）"

    # ── L3 识别（仅记录 + 提醒，绝不授权）────────────────────────
    def record_l3(self, *, session_id: str, operation: str, target: str,
                  source: str, level: str, reason: str) -> None:
        sight = {
            "operation": operation, "target": target, "source": source,
            "level": level, "reason": reason, "ts": round(time.time(), 3),
        }
        with self._lock:
            self._l3[session_id] = sight
        self._audit("guard_l3", None, decision="DENY", reason=reason,
                    extra={"session_id": session_id, **sight})

    def last_l3_sighting(self, session_id: str) -> dict | None:
        with self._lock:
            return self._l3.get(session_id)


# ── 进程内单例（按 data_dir + 审计开关键）────────────────────────────

_REGS: dict[tuple[str, bool], GuardRegistry] = {}
_REGS_LOCK = threading.Lock()


def get_registry(data_dir: str, *, audit_enabled: bool = True) -> GuardRegistry:
    key = (str(Path(data_dir).resolve()), audit_enabled)
    with _REGS_LOCK:
        reg = _REGS.get(key)
        if reg is None:
            reg = GuardRegistry(data_dir, audit_enabled=audit_enabled)
            _REGS[key] = reg
        return reg
