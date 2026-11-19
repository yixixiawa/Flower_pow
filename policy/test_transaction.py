"""测试对象生命周期约束（111.md 模块职责之三）。

**test_transaction 约束的是"对象"，不是"权限"**——它不授予任何执行权，
只回答一个生命周期问题：**这个测试对象是我们这次会话建立的吗？**

为什么需要它：删除类操作（L2）最危险的形态是删到**不属于本次测试的
数据**。"测试环境允许删除测试用户"的前提是删的是测试用户；如果连
对象是不是本次会话创建/登记过的都不知道，"删除测试数据"就退化成
"对生产数据盲删"。

台账按**三层隔离的 run_id** 分桶（core/state/models.py 的三层模型）：
换目标或新开一轮扫描后，旧 run 的对象不会污染新 run 的判定。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(slots=True)
class TrackedObject:
    """一个被本次测试生命周期 touches 过的对象。"""

    url: str                 # 对象定位（接口 URL，含 id 类定位符）
    action: str              # create | update | upload | delete
    run_id: str              # 产生该动作的扫描轮次（三层隔离）
    target_id: str           # 所属目标
    at: float = field(default_factory=time.time)
    identity: str = ""       # 操作时的账号身份（边界 1 的绑定信息）


class TestLedger:
    """测试对象台账。**约束职责，不是授权职责**：

    * ``record`` —— 允许执行的创建/修改/上传/删除，落一条台账；
    * ``known`` —— 对象是否在当前 run（或本会话其他 run）出现过；
    * ``delete_verdict`` —— 删除前的生命周期判定：已知对象放行，
      未知对象要求单独审批（没有审批通道时拒绝）。
    """

    def __init__(self) -> None:
        self._objects: list[TrackedObject] = []

    def record(
        self, url: str, action: str, run_id: str = "", target_id: str = "",
        identity: str = "",
    ) -> TrackedObject:
        obj = TrackedObject(
            url=self._key(url),
            action=action,
            run_id=run_id,
            target_id=target_id,
            identity=identity,
        )
        self._objects.append(obj)
        return obj

    def known(
        self, url: str, *, current_run_only: bool = False, run_id: str = "",
        target_id: str = "",
    ) -> bool:
        """对象是否被登记过。默认看**本会话全部** run：本轮创建、
        上一轮修改过的对象都是"已知"的；``current_run_only`` 收紧到
        当前轮次（供更严格的场景用）。

        统一隔离口径（P1-8）：给 ``target_id`` 时**只认同目标的登记**——
        换目标后旧目标的同名 path 不能被误认成"已知对象"（两个不同
        站点都有 /api/users/123，台账按目标隔离才不串）。
        """
        key = self._key(url)
        for o in reversed(self._objects):
            if o.url != key:
                continue
            if current_run_only and run_id and o.run_id != run_id:
                continue
            if target_id and o.target_id != target_id:
                continue
            return True
        return False

    def delete_verdict(
        self, url: str, *, run_id: str = "", target_id: str = "",
        environment: str = "", approved: bool = False,
    ) -> tuple[bool, str]:
        """删除前的生命周期判定，返回 (是否放行, 理由)。

        * 环境不是测试环境 → 拒（测试环境的删除权限不得推导到生产，
          这条边界在这里再拦一道，即使决策层已经判过）；
        * 对象已知（**同目标**的本次测试生命周期内建立/修改过）→ 放行；
        * 对象未知 + 有单独审批 → 放行（如删除预置测试用户）；
        * 对象未知 + 无审批 → 拒。
        """
        from policy.api_policy import Environment

        if environment == Environment.PRODUCTION:
            return False, "目标为生产环境：删除测试数据的权限不得推导到生产环境"
        if environment not in Environment.TEST_ENVS:
            return False, f"目标环境为 {environment or '未知'}，不满足测试环境条件"
        if self.known(url, run_id=run_id, current_run_only=False, target_id=target_id):
            return True, "对象在本次测试生命周期内建立/修改过（台账已知）"
        if approved:
            return True, "对象不在台账中，但已获单独审批（如预置测试用户清理）"
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
