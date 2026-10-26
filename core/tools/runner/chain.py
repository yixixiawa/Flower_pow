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

        if not chain_id:
            chain_id = f"chain-{len(session.result.attack_chains) + 1}"
        try:
            chain_severity = Severity.parse(severity)
        except Exception:  # noqa: BLE001
            chain_severity = Severity.HIGH

        raw_steps = list(steps or [])
        if not raw_steps:
            raw_steps = [
                {
                    "action": f"利用发现 {finding_id}",
                    "finding_id": finding_id,
                    "evidence": "",
                    "result": "",
                }
                for finding_id in (finding_ids or [])
            ]
        if not raw_steps:
            return "攻击链登记失败：至少需要一个 steps 或 finding_ids"

        chain_steps: list[AttackStep] = []
        for index, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                continue
            finding_id = str(raw.get("finding_id") or "")
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
