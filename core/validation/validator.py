"""Finding Validator：Agent 与正式报告之间的质量闸门。

定位
----
Agent 用 ``record_finding`` 登记一条漏洞，**不等于**这条漏洞就可以进报告。
模型很擅长把"看起来像漏洞"的东西写成一段结论，而报告一旦把没有原始报文、
没有成立依据、没有具体影响的东西印成"已确认漏洞"，就是在给甲方递假证据。

所以这里做一次**准入校验**：七项信息齐全、具体、可核实，才发正式发现；
否则一律拦下、登记为**待验证线索**（``PendingClue``），并明确告诉模型缺什么。

两条路径的分界
--------------
* 正式漏洞发现：七项全过 → ``Finding`` → 计数 / 报告 / 知识库；
* 待验证线索：任一项不过 → ``PendingClue`` → 只进会话快照与线索清单，
  **不进报告、不计入漏洞数、不许描述成已确认**。

为什么"模糊"也要拦
------------------
只校验"有没有填"是不够的：模型被要求必填时，会写「存在安全风险」
「详见响应」「待补充」这种语法完整、信息为零的内容。长度达标不等于内容
可用，所以每个字段都要过一遍占位/套话/可核对性检查（判据见 ``spec``）。

判错代价的不对称
----------------
拦错一条真漏洞，用户补填一次就能过——成本是一次工具调用；
放过一条假漏洞，报告交付出去就收不回来了。所以闸门**默认从严**：
拿不准就拦，把"要不要认定为已确认"的决定权交回给人。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from core.rawmsg import looks_like_analysis, parse_raw_request, parse_raw_response
from core.state.models import Evidence, Finding, PendingClue
from core.validation.spec import (
    LABELS,
    REQUIRED_FIELDS,
    has_observable,
    is_empty_impact,
    is_generic_type,
    is_placeholder,
    looks_like_request_line,
    looks_like_status_line,
    norm,
)


# ── 输入 / 输出 ────────────────────────────────────────────────────


@dataclass(slots=True)
class Submission:
    """一次"漏洞提交"——七项契约字段 + 定位用的元信息。

    刻意**不直接接收 Finding**：提交可能根本成不了 Finding（被拦），
    而校验器要能在对象还没构造出来之前就给出结论。
    """

    vuln_type: str = ""
    url: str = ""
    trigger: str = ""
    raw_request: str = ""
    raw_response: str = ""
    basis: str = ""
    impact: str = ""
    # 以下只用于线索登记与去重，不参与校验
    name: str = ""
    severity: str = ""
    category: str = ""
    cve: list[str] = field(default_factory=list)
    base_url: str = ""


@dataclass(slots=True)
class FieldIssue:
    """一个字段为什么不达标。``kind`` 决定拦截文案的语气与补填方向。"""

    key: str
    label: str
    kind: str  # missing | placeholder | vague | unverifiable
    detail: str

    def line(self) -> str:
        verb = {
            "missing": "未提供",
            "placeholder": "是占位内容",
            "vague": "过于笼统",
            "unverifiable": "无法核实",
        }.get(self.kind, "不达标")
        return f"{self.label}：{verb}——{self.detail}"


@dataclass(slots=True)
class ValidationResult:
    """校验结论。``ok=False`` 时 ``issues`` 一定非空。"""

    ok: bool
    issues: list[FieldIssue] = field(default_factory=list)
    # 实际校验了多少项（探针类发现可能豁免"原始报文"两项）
    checked: int = len(REQUIRED_FIELDS)
    # 豁免的字段（静态分析类发现没有 HTTP 报文，属于 by design）
    waived: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """通过率。只是给模型一个进度感，**不是**漏洞可信度。"""
        if not self.checked:
            return 1.0
        return round((self.checked - len(self.issues)) / self.checked, 3)

    @property
    def missing(self) -> list[str]:
        return [i.label for i in self.issues if i.kind == "missing"]

    @property
    def weak(self) -> list[str]:
        return [i.label for i in self.issues if i.kind != "missing"]

    @property
    def reason(self) -> str:
        """一句话结论（落进 ``status_reason`` / 线索记录）。"""
        if self.ok:
            return f"七项信息齐全（通过率 {self.score:.0%}）"
        parts = []
        if self.missing:
            parts.append("缺失 " + "、".join(self.missing))
        if self.weak:
            parts.append("不达标 " + "、".join(self.weak))
        return "；".join(parts)

    def block_message(self, clue_id: str = "", *, headline: str = "") -> str:
        """给 Agent 看的拦截文案：**必须说清缺什么、怎么补**。

        Agent 只有读到具体字段名才知道下一轮该补什么；笼统地说"证据不足"
        只会让它把同一段内容再提交一次。
        """
        head = f"【已拦截 · 未写入正式报告】{headline}".rstrip()
        lines = [head]
        if clue_id:
            lines.append(
                f"已登记为**待验证线索** `{clue_id}`：不计入漏洞数量，"
                "不会出现在报告或漏洞列表里。"
            )
        if self.missing:
            lines.append("缺失字段：" + "、".join(self.missing))
        if self.weak:
            lines.append("不达标字段：")
            lines += [f"  · {i.line()}" for i in self.issues if i.kind != "missing"]
        for i in self.issues:
            if i.kind == "missing":
                # 缺失项也给出填写提示——只说"缺"等于让模型猜
                lines.append(f"  · {i.label}：{i.detail}")
        lines.append(
            "补齐后用**同一 URL + 同一漏洞类型**重新调用 record_finding 即可升级为"
            "正式发现（会自动销掉这条线索）；查看全部线索：/clues"
        )
        return "\n".join(lines)


# ── 校验器 ─────────────────────────────────────────────────────────


class FindingValidator:
    """七字段准入校验。**无状态**，可以随手实例化。"""

    def validate(self, sub: Submission) -> ValidationResult:
        issues: list[FieldIssue] = []
        # **只 strip，不压缩空白**：raw_request / raw_response 是报文，换行是
        # 结构的一部分；把多行压成一行，"首行是不是请求行/状态行"的判断
        # 就永远不成立（实测踩过：合格样例被判成"只有状态码"）。
        # 需要忽略空白做比较的地方由 spec 里的 norm() 负责。
        vals = {
            f.key: str(getattr(sub, f.key, "") or "").strip()
            for f in REQUIRED_FIELDS
        }

        # 1) 通用检查：空 / 占位 / 过短
        for spec in REQUIRED_FIELDS:
            v = vals[spec.key]
            if not v:
                issues.append(
                    FieldIssue(spec.key, spec.label, "missing", spec.hint)
                )
                continue
            if is_placeholder(v):
                issues.append(
                    FieldIssue(
                        spec.key,
                        spec.label,
                        "placeholder",
                        f"填的是占位内容「{v[:20]}」，等于没填。{spec.hint}",
                    )
                )
                continue
            # URL 不做长度门槛：相对路径（``/api/x``）本身很短，补上 base_url
            # 才是完整地址；结构合法性由下面的专项检查负责（更严格）。
            if len(v) < spec.min_chars and spec.key != "url":
                issues.append(
                    FieldIssue(
                        spec.key,
                        spec.label,
                        "vague",
                        f"只有 {len(v)} 个字符，信息量不足：「{v[:40]}」。{spec.hint}",
                    )
                )

        # 2) 逐字段专项检查。**只对已通过通用检查的字段做**——
        #    否则一个空字段会被报两次（"没填"+"格式不对"），噪声掩盖重点。
        passed = {i.key for i in issues}
        checks = (
            ("vuln_type", self._check_type),
            ("url", self._check_url),
            ("trigger", self._check_trigger),
            ("raw_request", self._check_request),
            ("raw_response", self._check_response),
            ("basis", self._check_basis),
            ("impact", self._check_impact),
        )
        for key, fn in checks:
            if key in passed:
                continue
            issue = fn(vals[key], vals, sub)
            if issue:
                issues.append(issue)

        # 3) 跨字段一致性：触发条件与实际影响写成同一句 → 两项都没说清
        if (
            "trigger" not in {i.key for i in issues}
            and "impact" not in {i.key for i in issues}
            and norm(vals["trigger"]) == norm(vals["impact"])
        ):
            issues.append(
                FieldIssue(
                    "impact",
                    LABELS["impact"],
                    "vague",
                    "触发条件与实际影响写成了同一句：这两项分别回答"
                    "「什么时候会触发」和「触发了能造成什么后果」",
                )
            )

        # 按契约顺序排序，拦截文案读起来稳定
        order = {f.key: i for i, f in enumerate(REQUIRED_FIELDS)}
        issues.sort(key=lambda i: order.get(i.key, 99))
        return ValidationResult(ok=not issues, issues=issues)

    # ── 各字段专项 ────────────────────────────────────────────────

    @staticmethod
    def _check_type(v: str, _vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        if is_generic_type(v):
            return FieldIssue(
                "vuln_type", LABELS["vuln_type"], "vague",
                f"「{v}」不是漏洞类型，报告里读者无法判断该按什么标准复核",
            )
        return None

    @staticmethod
    def _check_url(v: str, _vals: dict[str, str], sub: Submission) -> FieldIssue | None:
        from urllib.parse import urlparse

        raw = v if "://" in v else (
            f"{sub.base_url.rstrip('/')}/{v.lstrip('/')}"
            if v.startswith("/") and sub.base_url
            else f"http://{v}"
        )
        try:
            u = urlparse(raw)
        except ValueError:
            u = None
        # 主机名必须是可解析的 ASCII 形态。不加这条，"某接口" 会被补成
        # "http://某接口" 而通过——netloc 非空不等于地址可用。
        import re as _re

        host_ok = bool(
            u is not None
            and u.hostname
            and _re.fullmatch(r"[A-Za-z0-9._:\-\[\]]+", u.hostname)
        )
        if u is None or not u.netloc or u.scheme not in ("http", "https") or not host_ok:
            return FieldIssue(
                "url", LABELS["url"], "unverifiable",
                f"「{v[:60]}」不是可重放的完整 URL（需要 http(s)://主机/路径）",
            )
        return None

    @staticmethod
    def _check_trigger(v: str, vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        if norm(v) in (norm(vals["url"]), norm(vals["vuln_type"])):
            return FieldIssue(
                "trigger", LABELS["trigger"], "vague",
                "只是重复了 URL / 漏洞类型，没有说明触发前提"
                "（参数位置、所需权限、前置状态）",
            )
        return None

    @staticmethod
    def _check_request(v: str, _vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        if not looks_like_request_line(v):
            return FieldIssue(
                "raw_request", LABELS["raw_request"], "unverifiable",
                "首行不是请求行（应为「方法 路径 HTTP/1.1」）",
            )
        return None

    @staticmethod
    def _check_response(v: str, vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        resp = parse_raw_response(v)
        if resp.status_code is None and not looks_like_status_line(v):
            return FieldIssue(
                "raw_response", LABELS["raw_response"], "unverifiable",
                "没有状态行（HTTP/1.1 200），无法判断这是服务端返回还是模型描述",
            )
        if not resp.headers and not resp.body:
            return FieldIssue(
                "raw_response", LABELS["raw_response"], "vague",
                "只有状态码，没有响应头/响应体：无法核对任何漏洞特征"
                "（「只有 HTTP 200」是最弱的一档证据）",
            )
        # 老版本 record_finding 会把说明文字塞进响应体。响应位置出现模型的话，
        # 比留空更糟——它看起来像证据。
        if resp.body and looks_like_analysis(resp.body, vals["basis"]):
            return FieldIssue(
                "raw_response", LABELS["raw_response"], "unverifiable",
                "响应体与「成立依据」文字高度一致，像是把说明复制进了响应位置，"
                "不是服务端真实返回",
            )
        return None

    @staticmethod
    def _check_basis(v: str, vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        if not has_observable(v):
            return FieldIssue(
                "basis", LABELS["basis"], "unverifiable",
                "没有指出任何可核对的东西（命中特征、状态码、与基线的差异）——"
                "这仍是主观判断",
            )
        if norm(v) == norm(vals["raw_response"]):
            return FieldIssue(
                "basis", LABELS["basis"], "vague",
                "只是把响应原文又贴了一遍，没有说明为什么它能证明漏洞成立",
            )
        return None

    @staticmethod
    def _check_impact(v: str, _vals: dict[str, str], _sub: Submission) -> FieldIssue | None:
        if is_empty_impact(v):
            return FieldIssue(
                "impact", LABELS["impact"], "vague",
                f"「{v[:40]}」是套话：没有说明泄露了什么数据、越权到什么角色、"
                "执行了什么操作",
            )
        return None

    # ── 从 Finding 反推提交（导出前复核 / 旧会话兜底）──────────────

    @staticmethod
    def rebuild_response(ev: Evidence | None) -> str:
        """按证据字段重建一份可核对的响应报文。

        这不是"原始抓包"（原始报文在 ``artifact`` 里），而是**当次记录下来的
        状态码 + 响应头 + 响应体**。复核要判断的是"这些内容是否足以支撑结论"，
        重建版足够；报告正文仍然优先读落盘的原始报文。
        """
        if ev is None or ev.status_code is None:
            return ""
        lines = [f"HTTP/1.1 {ev.status_code}"]
        lines += [f"{k}: {v}" for k, v in (ev.response_headers or {}).items()]
        body = ev.body_excerpt or ""
        if body:
            lines += ["", body]
        return "\n".join(lines)

    @staticmethod
    def derive_trigger(f: Finding) -> str:
        """从证据里推一句触发条件。

        自动探针的"触发条件"就是它实际发出去的那条请求 + 命中的规则；
        这不是编造——两个事实都来自 ``Evidence``。模型手工登记的发现
        **不走这条推导**（必须自己写），否则等于替它补作业。
        """
        ev = f.evidence
        if ev is None:
            return ""
        payload = (ev.payload_sent or "").strip()
        hit = (ev.matched_pattern or "").strip()
        if payload:
            t = f"向 {f.matched_at or ev.url} 发送 {payload[:160]}"
            return t + (f"，命中判定规则：{hit}" if hit else "")
        line = (ev.request_line or "").strip().splitlines()
        if line:
            t = f"以 {line[0][:160]} 请求 {f.matched_at or ev.url}"
            return t + (f"，命中判定规则：{hit}" if hit else "")
        return ""

    def from_finding(
        self, f: Finding, *, base_url: str = "", profile: str = "agent"
    ) -> Submission:
        """Finding → 提交视图。

        **手工发现不从证据里推导 trigger / impact**：那两项是 Agent 的判断
        输出，替它补等于替它写作业——报告里会出现一条模型没说过、由程序
        拼出来的"实际影响"。自动探针是另一回事：它的触发条件就是实际发出去
        的那条请求，属于对既有证据的如实转写，不做推导反而是信息丢失。
        """
        ev = f.evidence
        raw_req = ""
        if ev is not None:
            raw_req = (ev.request_line or "").strip() or (ev.payload_sent or "").strip()
        if profile == "probe":
            trigger = (getattr(f, "trigger", "") or "").strip() or self.derive_trigger(f)
            basis = (
                (ev.matched_pattern if ev else "").strip()
                or (f.rationale or "").strip()
                or (f.description or "").strip()
            )
            impact = (getattr(f, "impact", "") or "").strip() or (f.description or "").strip()
        else:
            trigger = (getattr(f, "trigger", "") or "").strip()
            # 手工登记的 evidence 参数就存在 description 里（报告里是「漏洞说明」）
            basis = (f.description or "").strip() or (f.rationale or "").strip()
            impact = (getattr(f, "impact", "") or "").strip()
        return Submission(
            vuln_type=f.name or (f.category.value if f.category else ""),
            url=f.matched_at or (ev.url if ev else ""),
            trigger=trigger,
            raw_request=raw_req,
            raw_response=self.rebuild_response(ev),
            basis=basis,
            impact=impact,
            name=f.name,
            severity=f.severity.label if f.severity else "",
            category=f.category.value if f.category else "",
            cve=list(f.cve or []),
            base_url=base_url,
        )

    def validate_finding(
        self, f: Finding, *, base_url: str = "", profile: str = "agent"
    ) -> ValidationResult:
        """复核一条已存在的发现。

        ``profile="probe"`` 用于自动探针：静态分析类发现**没有 HTTP 报文**
        （证据只有文件路径与片段），这两项按"不适用"豁免，其余五项照查。
        豁免不是放水——静态发现的成立依据与影响仍必须写清。
        """
        sub = self.from_finding(f, base_url=base_url, profile=profile)
        res = self.validate(sub)
        if profile == "probe" and f.evidence is not None:
            ev = f.evidence
            no_exchange = ev.status_code is None and not (ev.request_line or "").strip()
            if no_exchange:
                kept = [i for i in res.issues if i.key not in ("raw_request", "raw_response")]
                res = ValidationResult(
                    ok=not kept,
                    issues=kept,
                    checked=len(REQUIRED_FIELDS) - 2,
                    waived=["raw_request", "raw_response"],
                )
        return res

    # ── 线索登记 ──────────────────────────────────────────────────

    @staticmethod
    def clue_id_for(sub: Submission) -> str:
        """稳定 ID：同一条线索反复提交时能认出来（不靠时间戳）。"""
        seed = "|".join(
            (norm(sub.vuln_type), norm(sub.url), norm(sub.name or sub.vuln_type))
        ).lower()
        return "clue_" + hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:10]

    def to_clue(
        self,
        sub: Submission,
        result: ValidationResult,
        *,
        source: str = "agent",
        name: str = "",
        severity: str = "",
    ) -> PendingClue:
        """把一个被拦下的提交落成线索。字段原样保留，便于后续补填。"""

        def clip(t: str, n: int = 4000) -> str:
            t = str(t or "").strip()
            return t if len(t) <= n else t[:n] + "\n…（线索记录截断）"

        return PendingClue(
            clue_id=self.clue_id_for(sub),
            created_at=time.time(),
            vuln_type=clip(sub.vuln_type, 200),
            name=clip(name or sub.name or sub.vuln_type, 200),
            severity=(severity or sub.severity or "").strip(),
            url=clip(sub.url, 1000),
            trigger=clip(sub.trigger),
            raw_request=clip(sub.raw_request, 8000),
            raw_response=clip(sub.raw_response, 8000),
            basis=clip(sub.basis),
            impact=clip(sub.impact),
            missing=list(result.missing),
            reasons=[i.line() for i in result.issues],
            source=source,
        )


def summarize_issues(result: ValidationResult) -> list[dict[str, Any]]:
    """给 JSON / 工具输出用的结构化问题清单。"""
    return [
        {"field": i.key, "label": i.label, "kind": i.kind, "detail": i.detail}
        for i in result.issues
    ]
