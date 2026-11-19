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
* **创建成功才登记**：台账只记"确实创建/上传成功并取得了对象标识"
  的对象。闸门放行 ≠ 对象存在，登记发生在 handler 执行成功之后
  （由 runner 的 pending-ledger 机制驱动），不是决策放行的那一刻；
* 对象标识：创建类操作从响应提取（JSON ``id`` / Location 头），
  提取不到就不登记——之后删除它一律按未知对象拒绝（宁可误拦）。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

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
        """登记一个对象动作。**创建/上传没有对象标识就不登记**（P0-②：
        仅在创建成功并取得对象标识后登记）。返回登记条目或 None。"""
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
        """对象是否被登记过。**四元组匹配**（P0-②）：

        * ``target_id`` —— 换目标后旧目标的同名 path 不能算"已知"；
        * ``run_id`` —— 旧轮次登记的对象对新 run 不可复用；
        * ``identity`` —— 换了账号身份（实名↔匿名、不同凭证）不可复用；
        * 对象标识 —— URL key 完全一致，或删除 URL 中的候选 id 命中
          登记时的 ``object_id``。
        """
        key = self._key(url)
        cands = candidate_ids(url)
        for o in reversed(self._objects):
            if target_id and o.target_id != target_id:
                continue
            if run_id and o.run_id != run_id:
                continue
            if identity and o.identity != identity:
                continue
            if o.url == key:
                # 完全同键：若登记带了标识，删除 URL 里也得能对上号
                # （防止"集合端点登记、集合端点删除"把整个集合当对象）
                if o.object_id and cands and o.object_id not in cands:
                    continue
                return True
            # 键不同：靠**具体对象标识**命中（创建在 /api/users、
            # 删除在 /api/users/33 —— 两个端点，一个对象）
            if o.object_id and o.object_id in cands:
                return True
        return False

    def delete_verdict(
        self, url: str, *, run_id: str = "", target_id: str = "",
        identity: str = "", environment: str = "", approved: bool = False,
    ) -> tuple[bool, str]:
        """删除前的生命周期判定，返回 (是否放行, 理由)。

        * 环境不是测试环境 → 拒（测试环境的删除权限不得推导到生产，
          这条边界在这里再拦一道，即使决策层已经判过）；
        * 四元组（目标/run/身份/对象标识）对得上 → 放行；
        * 对象未知 + **绑定本次请求**的单独审批 → 放行（如预置测试
          用户清理——审批由运行期通道逐请求给出，参数变化即重新审批）；
        * 对象未知 + 无审批 → 拒。
        """
        from policy.api_policy import Environment

        if environment == Environment.PRODUCTION:
            return False, "目标为生产环境：删除测试数据的权限不得推导到生产环境"
        if environment not in Environment.TEST_ENVS:
            return False, f"目标环境为 {environment or '未知'}，不满足测试环境条件"
        if self.known(url, run_id=run_id, target_id=target_id, identity=identity):
            return True, "四元组（目标/run/身份/对象标识）匹配台账：本次测试生命周期内建立/修改过"
        if approved:
            return True, "对象不在台账中，但已获绑定本次请求的单独审批（逐请求，不可复用）"
        return (
            False,
            "对象不在本次测试生命周期台账中且无单独审批——"
            "删除范围只能覆盖本次建立的测试对象",
        )

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
