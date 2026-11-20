"""测试对象生命周期约束（111.md 模块职责之三）。

**test_transaction 约束的是"对象"，不是"权限"**——它不授予任何执行权，
只回答一个生命周期问题：**这个测试对象是我们这次测试建立的吗？**

为什么需要它：删除类操作（L2）最危险的形态是删到**不属于本次测试的
数据**。"测试环境允许删除测试用户"的前提是删的是测试用户；如果连
对象是不是本次会话创建/登记过的都不知道，"删除测试数据"就退化成
"对生产数据盲删"。

登记纪律（P0-② 整改）：

* **四元组匹配**：删除判定要求 目标 + run + 账号身份 + 具体对象标识
  全部对得上——换目标、换轮次、换身份，登记都不可复用；
  **任一维度缺失即判未知**（第二轮整改：空参数不再当通配符）；
* **创建成功才登记**：台账只记"确实创建/上传成功并取得了对象标识"
  的对象。闸门放行 ≠ 对象存在，登记发生在 handler 执行成功之后
  （由 runner 的 pending-ledger 机制驱动），不是决策放行的那一刻；
* 对象标识：创建类操作从响应提取（JSON ``id`` / Location 头），
  提取不到就不登记——之后删除它一律按未知对象拒绝（宁可误拦）。

审批纪律（第二轮整改 #5）::

    删除类 REVIEW 的运行期审批不再是"当场一个布尔值"，而是一张
    :class:`UseOnceApproval` 票据（:class:`ApprovalLedger` 签发）：

    * **精确匹配**——票据绑定（对象 URL, 命令, 目标, 轮次, 身份）
      五元组，任何一项对不上即拒绝消费；
    * **单次消费**——消费一次即作废，重放/复用一律拒绝；
    * **带过期时间**——默认 300 秒，过期票据自动清除并拒绝。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse
from uuid import uuid4

from policy.request_guard import normalize_url_path

# 响应里的对象标识：JSON 的 "id"/"uuid"/"slug"/"user_id" 等字段值
_ID_FIELD_RE = re.compile(
    r'["\'](?:[a-z_]+_)?(?:id|uuid|slug|token)["\']\s*[:=]\s*["\']?([A-Za-z0-9_\-]{4,64})["\']',
    re.I,
)
# Location / self link 头里的尾段
_LOCATION_RE = re.compile(r"[Ll]ocation\s*[:=]\s*\S*?/([A-Za-z0-9_\-]{4,64})(?:\s|$|\?)")


def extract_object_id(url: str, response_text: str = "", *, url_first: bool = True) -> str:
    """从 URL 或响应里提取**具体对象标识**。

    优先级（``url_first=True``，资源型端点如 /api/users/33）：
    Location 头尾段 → 响应体 JSON id 字段 → URL 尾段（短数字 id 或
    4 位以上的标识）。
    ``url_first=False``（创建/上传打在集合端点 /api/users 上，URL 尾段
    是集合名**不是对象 id**）：只从响应提取（Location / JSON id），
    绝不拿集合名充当标识——取不到就返回空串，调用方不得登记。
    """
    try:
        m = _LOCATION_RE.search(response_text or "")
        if m:
            return m.group(1)
        m = _ID_FIELD_RE.search(response_text or "")
        if m:
            return m.group(1)
        if url_first:
            p = urlparse(url or "")
            segs = [s for s in (p.path or "").split("/") if s]
            if segs:
                tail = segs[-1]
                if re.fullmatch(r"\d{1,64}", tail) or re.fullmatch(r"[A-Za-z0-9_\-]{4,64}", tail):
                    return tail
    except Exception:  # noqa: BLE001 —— 提取失败宁可空，不得抛
        return ""
    return ""


def candidate_ids(url: str) -> list[str]:
    """删除 URL 里可能的对象标识：全部路径段 + query 的 id 类参数值。"""
    out: list[str] = []
    try:
        p = urlparse(url or "")
        out.extend(s for s in (p.path or "").split("/") if s)
        for part in (p.query or "").split("&"):
            k, _, v = part.partition("=")
            if re.search(r"id|uuid|slug", k, re.I) and v:
                out.append(v)
    except Exception:  # noqa: BLE001
        pass
    return out


@dataclass(slots=True)
class TrackedObject:
    """一个被本次测试生命周期 touches 过的对象。"""

    url: str                 # 对象定位（接口 URL，含 id 类定位符）
    action: str              # create | update | upload | delete
    run_id: str              # 产生该动作的扫描轮次（三层隔离）
    target_id: str           # 所属目标
    at: float = field(default_factory=time.time)
    identity: str = ""       # 操作时的账号身份（边界 1 的绑定信息）
    object_id: str = ""      # **具体对象标识**（创建/上传成功后从响应取得）


class TestLedger:
    """测试对象台账。**约束职责，不是授权职责**：

    * ``record`` —— 执行成功并取得对象标识的创建/修改/上传，落一条台账；
    * ``known`` —— 四元组（目标/run/身份）+ 对象标识的匹配判定；
    * ``delete_verdict`` —— 删除前的生命周期判定：四元组对得上才放行，
      未知对象必须有**绑定到本次请求**的单独审批。
    """

    def __init__(self) -> None:
        self._objects: list[TrackedObject] = []

    def record(
        self, url: str, action: str, run_id: str = "", target_id: str = "",
        identity: str = "", object_id: str = "",
    ) -> TrackedObject | None:
        """登记一个对象动作。**生命周期纪律（整改）**：

        * ``run_id`` / ``target_id`` 必须显式提供——对象必须挂在明确的
          目标与轮次下，缺任一维度的登记一律拒绝（否则等于登记一笔
          跨目标/跨轮次永久有效的"僵尸对象"，之后删除判定会被它放行）；
        * 创建/上传没有对象标识就不登记（P0-②：仅在创建成功并取得
          对象标识后登记）。

        返回登记条目或 None。
        """
        if not target_id or not run_id:
            # 生命周期规则：target/run 是归属的结构化事实，缺了就不得
            # 入账——之后 known() 的严格四元组也永远对不上它。
            return None
        if action in ("create", "upload") and not object_id:
            # 创建/上传没拿到标识：登记无意义（删除判定靠标识匹配），
            # 不登记 → 之后删除按未知对象走审批，安全方向不会错。
            return None
        obj = TrackedObject(
            url=self._key(url),
            action=action,
            run_id=run_id,
            target_id=target_id,
            identity=identity,
            object_id=object_id or "",
        )
        self._objects.append(obj)
        return obj

    def known(
        self, url: str, *, run_id: str = "", target_id: str = "",
        identity: str = "",
    ) -> bool:
        """对象是否被登记过。**四元组严格匹配**（P0-② + 第二轮整改）：

        * 任一维度（目标/run/身份）**缺失即判未知**——空参数不再当
          通配符（旧行为：``known(url)`` 不带维度会命中任何台账条目，
          这是漏匹配的根源：调用方少传一个参数就等于放行整个台账）；
        * ``target_id`` —— 换目标后旧目标的同名 path 不能算"已知"；
        * ``run_id`` —— 旧轮次登记的对象对新 run 不可复用；
        * ``identity`` —— 换了账号身份（实名↔匿名、不同凭证）不可复用；
        * 对象标识 —— URL key 完全一致，或删除 URL 中的候选 id 命中
          登记时的 ``object_id``；
        * **跨端点按 id 命中必须同主机且在登记路径前缀之下**——修复
          误匹配：旧实现仅凭 id 数字命中，删 ``/api/other/33`` 也会
          放行在 ``/api/users`` 创建的 33 号对象。
        """
        if not target_id or not run_id or not identity:
            # 维度缺失 = 无法确认归属 = 未知（fail-closed，宁可误拦）
            return False
        key = self._key(url)
        cands = candidate_ids(url)
        # P1-3（第六轮整改）：删除 URL 里**提不出任何对象标识候选** →
        # 无从确认"删的就是登记的那个对象" → 一律按未知处理，不得凭
        # "台账里有条目"放行（比如打在集合端点、根路径的删除请求）。
        if not cands:
            return False
        for o in reversed(self._objects):
            # 四元组逐一相等（含空值相等）：任何一维对不上都跳过
            if o.target_id != target_id or o.run_id != run_id or o.identity != identity:
                continue
            if o.url == key:
                # 完全同键：若登记带了标识，删除 URL 里也得能对上号
                # （防止"集合端点登记、集合端点删除"把整个集合当对象）
                if o.object_id and cands and o.object_id not in cands:
                    continue
                return True
            # 键不同：靠**具体对象标识**命中（创建在 /api/users、
            # 删除在 /api/users/33 —— 两个端点，一个对象）。
            # 但必须**同主机**且删除路径落在登记路径的前缀之下：
            # 防止"/api/other/33"凭同名 id 删掉"/api/users"登记的 33。
            if o.object_id and o.object_id in cands:
                try:
                    p_reg = urlparse(o.url or "")
                    p_del = urlparse(key)
                except ValueError:
                    continue
                if (p_reg.netloc or "") != (p_del.netloc or ""):
                    continue
                base_dir = (p_reg.path or "").rstrip("/")
                del_path = p_del.path or "/"
                if not base_dir or not del_path.startswith(base_dir + "/"):
                    continue
                return True
        return False

    def delete_verdict(
        self, url: str, *, run_id: str = "", target_id: str = "",
        identity: str = "", environment: str = "", approved: bool = False,
    ) -> tuple[bool, str]:
        """删除前的生命周期判定，返回 (是否放行, 理由)。

        * 环境不是测试环境 → 拒（测试环境的删除权限不得推导到生产，
          这条边界在这里再拦一道，即使决策层已经判过）；
        * **本次创建/上传且取得对象标识**的对象（四元组对得上）→ 放行
          （第四轮整改 #3：仅**修改过**的既有对象、无法识别对象标识的
          对象**不得**认定为本次创建——它们不是本次测试建立的，删了
          就是删到别人的数据；对它们的删除一律走单独审批）；
        * 对象未知 + **绑定本次请求**的单独审批 → 放行（如预置测试
          用户清理——审批由运行期通道逐请求给出，参数变化即重新审批）；
        * 对象未知 + 无审批 → 拒。
        """
        from policy.api_policy import Environment

        if environment == Environment.PRODUCTION:
            return False, "目标为生产环境：删除测试数据的权限不得推导到生产环境"
        if environment not in Environment.TEST_ENVS:
            return False, f"目标环境为 {environment or '未知'}，不满足测试环境条件"
        if self._deletable(url, run_id=run_id, target_id=target_id, identity=identity):
            return True, "四元组（目标/run/身份/对象标识）匹配台账：本次测试创建/上传并取得标识的对象"
        if approved:
            return True, "对象不在台账中，但已获绑定本次请求的单独审批（逐请求，不可复用）"
        return (
            False,
            "对象不在本次测试生命周期台账中且无单独审批——"
            "删除范围只能覆盖本次建立的测试对象",
        )

    def _deletable(
        self, url: str, *, run_id: str, target_id: str, identity: str,
    ) -> bool:
        """删除判定的**严格口径**（第四轮整改 #3）：

        只有 ``action in ("create", "upload")`` 且带具体 ``object_id`` 的
        登记条目才算"本次测试建立的对象"：

        * ``update`` 条目 = **修改过的既有对象**——对象是别人建的，
          修改过不代表有权删，一律不进删除判定（走单独审批）；
        * 无 ``object_id`` 的条目（delete 记录、历史遗留）同样不算——
          无法识别对象标识就无从确认"删的就是建的那个"。
        """
        if not target_id or not run_id or not identity:
            return False
        key = self._key(url)
        cands = candidate_ids(url)
        # P1-3（第六轮整改）：候选集为空 → 无法把删除请求对到具体对象
        # → 不得走台账放行（同 known() 的 fail-closed 口径）。
        if not cands:
            return False
        for o in reversed(self._objects):
            if o.action not in ("create", "upload") or not o.object_id:
                continue
            if o.target_id != target_id or o.run_id != run_id or o.identity != identity:
                continue
            if o.url == key:
                # 完全同键：登记的标识必须能在删除 URL 里对上号
                if cands and o.object_id not in cands:
                    continue
                return True
            # 跨端点按 id 命中：同主机 + 删除路径在登记路径前缀之下
            if o.object_id in cands:
                try:
                    p_reg = urlparse(o.url or "")
                    p_del = urlparse(key)
                except ValueError:
                    continue
                if (p_reg.netloc or "") != (p_del.netloc or ""):
                    continue
                base_dir = normalize_url_path(p_reg.path or "").rstrip("/")
                del_path = normalize_url_path(p_del.path or "/")
                if not base_dir or not del_path.startswith(base_dir + "/"):
                    continue
                return True
        return False

    def objects_of(self, run_id: str = "") -> list[TrackedObject]:
        if not run_id:
            return list(self._objects)
        return [o for o in self._objects if o.run_id == run_id]

    def clear(self, run_id: str | None = None) -> int:
        """清台账（换目标/重置时调用）。返回清除条数。"""
        if run_id is None:
            n = len(self._objects)
            self._objects.clear()
            return n
        keep = [o for o in self._objects if o.run_id != run_id]
        n = len(self._objects) - len(keep)
        self._objects = keep
        return n

    @staticmethod
    def _key(url: str) -> str:
        """对象键：剥掉 query 后的 URL。同一资源的不同 query 不算不同对象。"""
        try:
            p = urlparse(url or "")
            return f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else (url or "").split("?")[0]
        except ValueError:
            return url or ""


# ── 运行期审批台账（第二轮整改 #5 + 第三轮整改 #5）────────────────
# 精确匹配 + 单次消费 + 过期时间。审批票据由 runner 的运行期审批通道
# 签发并当场消费：人点头 = 给**这一次**请求发一张票，票面写着给谁
# （目标/run/身份）、干什么（命令 + 风险等级）、对哪个对象（URL +
# 方法 + 请求内容指纹）、谁批的（审批人）——参数变了、方法变了、
# 换了目标/轮次/身份，票面对不上就是另一张票，旧票永不复用。

APPROVAL_TTL = 300.0  # 审批票据默认有效期（秒）


def request_fingerprint(
    method: str = "", url: str = "", params=None, body: str = "",
    poc_id: str = "",
) -> str:
    """请求内容指纹（审批绑定用，sha256 前 16 位）。

    覆盖 方法 / URL / 参数 / 请求体 / POC 声明——任何一项变更指纹即
    变更，旧票据随之失效（必须重新审批）。params 以排序 JSON 规范化，
    避免键序差异逃过比对。
    """
    import hashlib
    import json as _json

    try:
        p = _json.dumps(params, sort_keys=True, ensure_ascii=False, default=str) if params else ""
    except (TypeError, ValueError):
        p = str(params)[:200]
    raw = "\x1f".join([
        (method or "").upper(), url or "", p, body or "", poc_id or "",
    ])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass(slots=True)
class UseOnceApproval:
    """一张一次性审批票据。字段即票面，消费校验逐项比对。"""

    token: str            # 票据号（随机，进审计可追踪）
    url: str              # 绑定的对象 URL（规范化键，剥 query）
    command: str          # 绑定的权限矩阵命令
    target_id: str        # 绑定的目标
    run_id: str           # 绑定的扫描轮次
    identity: str         # 绑定的账号身份
    issued_at: float      # 签发时刻（monotonic）
    expires_at: float     # 过期时刻（monotonic）
    method: str = ""      # 绑定的请求方法（大写）
    request_digest: str = ""  # 绑定的请求内容指纹（request_fingerprint）
    level: str = ""       # 绑定的风险等级（L0-L3）
    approver: str = ""    # 审批人标识（审批通道名）
    consumed_at: float = 0.0  # 非 0 = 已消费（单次有效）


class ApprovalLedger:
    """运行期审批票据台账。**签发与消费都 fail-closed**：

    * ``issue`` —— 人审批通过后签发，票据绑定（URL/命令/目标/轮次/
      身份/方法/请求指纹/风险等级/审批人）与过期时间；
      **L3 命令拒绝签发**（L3 不得通过任何审批放行）；
    * ``consume`` —— 消费一张票：票据不存在 / 已消费 / 已过期 /
      票面任一项不符 → 拒绝。成功消费即标记作废。
    """

    def __init__(self, ttl: float = APPROVAL_TTL) -> None:
        self.ttl = ttl
        self._issued: dict[str, UseOnceApproval] = {}

    def issue(
        self, *, url: str, command: str, target_id: str,
        run_id: str, identity: str, ttl: float | None = None,
        method: str = "", request_digest: str = "", level: str = "",
        approver: str = "",
    ) -> UseOnceApproval:
        """签发一张绑定票面的一次性审批票据。L3 命令抛 ValueError。"""
        from policy.api_policy import PermissionLevel, rule_for_command

        rule = rule_for_command(command or "")
        if rule is not None and rule.level == PermissionLevel.L3:
            # L3 默认禁止且**审批不设出路**——票据通道同样不签发，
            # 双保险（决策层已在 decide() 短路，这里是结构性兜底）。
            raise ValueError(f"L3 命令「{command}」不得签发审批票据（审批无出路）")
        self._purge()
        now = time.monotonic()
        ap = UseOnceApproval(
            token=uuid4().hex[:16],
            url=self._norm(url),
            command=command or "",
            target_id=target_id or "",
            run_id=run_id or "",
            identity=identity or "",
            issued_at=now,
            expires_at=now + (self.ttl if ttl is None else ttl),
            method=(method or "").upper(),
            request_digest=request_digest or "",
            level=level or "",
            approver=approver or "",
        )
        self._issued[ap.token] = ap
        return ap

    def consume(
        self, token: str, *, url: str, command: str, target_id: str,
        run_id: str, identity: str, method: str = "",
        request_digest: str = "", level: str = "",
    ) -> tuple[bool, str]:
        """消费一张票据。返回 (是否成功, 理由)——理由进审计，可对账。"""
        ap = self._issued.get(token or "")
        if ap is None:
            return False, "审批票据不存在（从未签发或已消费/已清除）"
        if ap.consumed_at:
            self._issued.pop(token, None)
            return False, "审批票据已被消费（单次有效，不得复用）"
        now = time.monotonic()
        if now >= ap.expires_at:
            self._issued.pop(token, None)
            return False, "审批票据已过期（签发后未及时消费）"
        mismatches: list[str] = []
        if ap.url != self._norm(url):
            mismatches.append(f"对象 URL（票面 {ap.url} ≠ 请求 {self._norm(url)}）")
        if ap.command != (command or ""):
            mismatches.append(f"命令（票面 {ap.command} ≠ 请求 {command}）")
        if ap.method != (method or "").upper():
            mismatches.append(f"方法（票面 {ap.method or '-'} ≠ 请求 {(method or '').upper() or '-'}）")
        if ap.request_digest != (request_digest or ""):
            mismatches.append("请求内容（参数/请求体/POC 变更 → 必须重新审批）")
        if ap.level != (level or ""):
            mismatches.append(f"风险等级（票面 {ap.level} ≠ 请求 {level}）")
        if ap.target_id != (target_id or ""):
            mismatches.append("目标")
        if ap.run_id != (run_id or ""):
            mismatches.append("轮次")
        if ap.identity != (identity or ""):
            mismatches.append("身份")
        if mismatches:
            return False, "审批票据与本次请求不符（精确匹配）：" + "、".join(mismatches)
        # 单次消费：标记消费时刻并**保留票根**——重放请求会得到精确的
        # "已被消费（单次有效）"拒绝，而不是笼统的"票据不存在"，
        # 审计上也能区分"重放"与"伪造"两种攻击形态。
        ap.consumed_at = now
        return True, f"审批票据 {ap.token} 消费成功（单次有效，绑定 {ap.url}）"

    def _purge(self) -> int:
        """清掉过期票据与超过保留期的消费票根。返回清除数。"""
        now = time.monotonic()
        stale = [
            t for t, ap in self._issued.items()
            if now >= ap.expires_at or (ap.consumed_at and now - ap.consumed_at > self.ttl)
        ]
        for t in stale:
            self._issued.pop(t, None)
        return len(stale)

    def outstanding(self) -> int:
        """当前有效（未消费、未过期）的票据数——审计可见（票根不计入）。"""
        self._purge()
        return sum(1 for ap in self._issued.values() if not ap.consumed_at)

    @staticmethod
    def _norm(url: str) -> str:
        try:
            p = urlparse(url or "")
            return f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else (url or "").split("?")[0]
        except ValueError:
            return url or ""
