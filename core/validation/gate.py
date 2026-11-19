"""导出前的最后一道复核——闸门的"兜底"那一半。

为什么提交时校验了、导出时还要再查一遍
--------------------------------------
提交路径不止一条，而且**会话是可以恢复的**：

* 老版本登记的发现没有 ``trigger`` / ``impact``（那时还没这道闸门）；
* 快照可能被手改过，或者由外部脚本注入；
* 将来新增一条写 ``result.findings`` 的路径，很容易忘了走校验。

报告是最终交付物，一旦把不合格的东西印成"已确认漏洞"就收不回来了。
所以导出前按同一套判据再扫一遍：**只扫 Agent 手工登记的发现**
（``detector == "manual"``）——自动探针的证据链由
:class:`detectors.second_pass.SecondPassVerifier` 的六维评分把关，两者
职责不重叠（探针发现从来没经过 Agent 的手，用文本契约去卡它只会误伤
静态分析类发现）。

被复核拦下的发现不会消失：状态降到「待人工复核」，同时登记成待验证线索，
报告附录里能看到它为什么被拦。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.state.enums import FindingStatus
from core.state.models import ScanResult
from core.validation.validator import FindingValidator


@dataclass(slots=True)
class BlockedItem:
    poc_id: str
    name: str
    url: str
    clue_id: str
    reason: str


@dataclass(slots=True)
class AuditReport:
    """一次导出前复核的结果。"""

    checked: int = 0
    blocked: list[BlockedItem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blocked

    def line(self) -> str:
        if not self.checked:
            return "报告闸门：没有需要复核的手工发现"
        if not self.blocked:
            return f"报告闸门：复核 {self.checked} 条手工发现，全部通过"
        head = (
            f"报告闸门：复核 {self.checked} 条手工发现，"
            f"**拦下 {len(self.blocked)} 条**（已转待验证线索，未写入报告）"
        )
        detail = [
            f"  · {b.name}（{b.url[:60]}）：{b.reason} → {b.clue_id}"
            for b in self.blocked[:8]
        ]
        if len(self.blocked) > 8:
            detail.append(f"  · …另有 {len(self.blocked) - 8} 条，见 /clues")
        return "\n".join([head] + detail)


def ensure_reportable(result: ScanResult) -> AuditReport:
    """报告写出前的统一入口——三个 writer 都在最前面调它。

    幂等：第一次把不合格项降级后，它们就不再是"已确认"，重复调用不会
    重复登记线索。之所以放在 writer 里而不是只放在导出工具里：写报告的
    入口有四条（工具、REPL ``/report``、CLI、调度器），只有放在最底层
    才能保证"绕不过去"。
    """
    return audit_for_report(result, base_url=getattr(result, "target", "") or "")


def audit_for_report(result: ScanResult, *, base_url: str = "") -> AuditReport:
    """就地复核并降级不合格的手工发现。返回统计供导出工具回显。"""
    v = FindingValidator()
    audit = AuditReport()
    for f in result.findings:
        if not f.confirmed or f.dismissed:
            continue
        if (f.detector or "") != "manual":
            # 自动探针不走七字段文本契约（它没有"模型写的说明"，只有结构化
            # 证据），但也不是"没校验"——第二次验证的六维评分就是它的准入
            # 检查。这里如实标注来源，避免消费方把 validated=False 误读成
            # "没通过任何检查"。
            f.validated = True
            f.validation_note = "自动探针：由二次验证的证据评分把关（不适用七字段契约）"
            continue
        audit.checked += 1
        res = v.validate_finding(
            f, base_url=base_url or result.target, profile="agent"
        )
        if res.ok:
            f.validated = True
            f.validation_note = res.reason
            continue
        f.validated = False
        f.validation_note = res.reason
        f.status = FindingStatus.NEEDS_REVIEW
        f.status_reason = f"报告闸门拦截：{res.reason}"
        clue = v.to_clue(
            v.from_finding(f, base_url=base_url or result.target, profile="agent"),
            res,
            source="report-audit",
            name=f.name,
            severity=f.severity.label,
        )
        stored = result.add_clue(clue)
        audit.blocked.append(
            BlockedItem(
                poc_id=f.poc_id,
                name=f.name,
                url=f.matched_at,
                clue_id=stored.clue_id,
                reason=res.reason,
            )
        )
    return audit
