"""上下文变量池与攻击链登记工具。"""

from __future__ import annotations

import time
from typing import Any

from core.state import AttackChain, AttackStep, Severity


class ChainMixin:
    """让 Agent 能保存线索，并把多条发现串成可复核攻击链。"""

    async def _h_extract_variable(
        self,
        session,
        name: str = "",
        value: str = "",
        evidence: str = "",
        source: str = "",
    ) -> str:
        key = (name or "").strip()
        if not key or not key.replace("_", "").replace("-", "").isalnum():
            return "变量保存失败：name 只能包含字母、数字、下划线或连字符"
        if not value:
            return f"变量保存失败：{key} 的 value 不能为空"
        session.result.context_vars[key] = {
            "value": str(value),
            "evidence": str(evidence or ""),
            "source": str(source or ""),
            "updated_at": time.time(),
        }
        return f"已记住变量 {key}（来源：{source or '当前工具结果'}），后续请求可使用 ${{{key}}}"

    async def _h_context_get(self, session, name: str = "") -> str:
        import json

        pool = session.result.context_vars
        if name:
            item = pool.get(name)
            if item is None:
                return f"变量不存在：{name}"
            return json.dumps({name: item}, ensure_ascii=False)
        return json.dumps(pool, ensure_ascii=False)

    async def _h_record_attack_chain(
        self,
        session,
        title: str = "",
        entry_point: str = "",
        final_impact: str = "",
        severity: str = "high",
        chain_id: str = "",
        steps: list[dict[str, Any]] | None = None,
        finding_ids: list[str] | None = None,
    ) -> str:
        title = (title or "").strip()
        entry_point = (entry_point or "").strip()
        final_impact = (final_impact or "").strip()
        if not title or not entry_point or not final_impact:
            return "攻击链登记失败：title、entry_point、final_impact 都不能为空"

        # ── 校验 1：引用的发现必须真实存在 ─────────────────────────
        # 引用不存在的 poc_id 等于编造攻击链步骤：报告里会出现一条
        # "利用发现 X"而 X 根本不在 findings 里，交付方一查就穿帮。
        known_ids = {f.poc_id for f in session.result.findings}
        unknown_refs = [fid for fid in (finding_ids or []) if fid not in known_ids]
        if unknown_refs:
            return (
                "攻击链登记失败：finding_ids 引用了不存在的发现："
                + "、".join(unknown_refs)
                + "。只能引用已登记的 poc_id（用 findings 工具查看）；"
                "漏登的发现先 record_finding 登记进来再串链。"
            )

        # ── 校验 2：chain_id 不得静默覆盖已有链 ────────────────────
        # add_attack_chain 对同 ID 是"新增或整条替换"，模型重复传同一个
        # id 会把已登记的链悄悄覆盖掉。同 id 同标题视为幂等重放放行，
        # 同 id 不同标题一律拒绝——覆盖必须显式换 id，不能无声发生。
        existing = {c.chain_id: c for c in session.result.attack_chains}
        chain_id = (chain_id or "").strip()
        if chain_id:
            dup = existing.get(chain_id)
            if dup is not None:
                if dup.title == title:
                    return f"攻击链 {chain_id} 已登记过（{title}），未重复登记。"
                return (
                    f"攻击链登记失败：chain_id {chain_id} 已被「{dup.title}」占用，"
                    "同名登记会把已有步骤整条覆盖。请换一个新 chain_id 重新登记。"
                )
        else:
            # 自动编号也要防撞：模型可能已手动用过 chain-1/chain-2，
            # 顺位生成的 id 撞上已有链同样会触发覆盖。
            n = len(session.result.attack_chains) + 1
            chain_id = f"chain-{n}"
            while chain_id in existing:
                n += 1
                chain_id = f"chain-{n}"
        try:
            chain_severity = Severity.parse(severity)
        except Exception:  # noqa: BLE001
            chain_severity = Severity.HIGH

        raw_steps = list(steps or [])
        if not raw_steps:
            # finding_ids 简化登记：自动补一步。result 不能留空——
            # 下面"每步至少 action 和 result"的校验会把空 result 的步骤
            # 全部丢弃，导致 finding_ids 这条合法入口永远登记失败。
            # result 复用该发现已登记的证据，链与发现互为印证。
            by_id = {f.poc_id: f for f in session.result.findings}
            raw_steps = [
                {
                    "action": f"利用发现 {finding_id}",
                    "finding_id": finding_id,
                    "evidence": (by_id[finding_id].evidence.body_excerpt
                                 if finding_id in by_id and by_id[finding_id].evidence
                                 else ""),
                    "result": f"该发现已登记在案（{finding_id}），证据见其 PoC",
                }
                for finding_id in (finding_ids or [])
            ]
        if not raw_steps:
            return "攻击链登记失败：至少需要一个 steps 或 finding_ids"

        chain_steps: list[AttackStep] = []
        bad_step_refs: list[str] = []
        for index, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                continue
            finding_id = str(raw.get("finding_id") or "").strip()
            if finding_id and finding_id not in known_ids:
                bad_step_refs.append(finding_id)
                continue
            step = AttackStep(
                action=str(raw.get("action") or "").strip(),
                finding_id=finding_id,
                evidence=str(raw.get("evidence") or "").strip(),
                result=str(raw.get("result") or "").strip(),
            )
            if not step.action or not step.result:
                continue
            chain_steps.append(step)
            for finding in session.result.findings:
                if finding.poc_id == finding_id:
                    finding.chain_id = chain_id
                    finding.step_index = index
                    finding.exploit_payload = str(raw.get("exploit_payload") or "")
                    break

        if bad_step_refs:
            return (
                "攻击链登记失败：steps 里引用了不存在的 finding_id："
                + "、".join(sorted(set(bad_step_refs)))
                + "。步骤只能挂在已登记的发现上，先登记发现再串链。"
            )
        if not chain_steps:
            return "攻击链登记失败：每一步至少需要 action 和 result"
        chain = AttackChain(
            chain_id=chain_id,
            title=title,
            entry_point=entry_point,
            final_impact=final_impact,
            severity=chain_severity,
            steps=chain_steps,
        )
        session.result.add_attack_chain(chain)
        return (
            f"已记录攻击链 {chain_id}：{title}，共 {len(chain_steps)} 步；"
            f"最终影响：{final_impact}"
        )
