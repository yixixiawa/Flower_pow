"""第二次独立验证：把「一次命中」变成「可交付的结论」。

为什么需要第二次验证
--------------------
POC 命中只说明**这一次请求**符合匹配规则。误报的最大来源恰恰在这里：

* 站点对任意路径都返回同一个 200 页面（软 404）；
* 匹配词（"success" / "admin" / "index of"）在正常页面上本来就存在；
* 一次网络抖动导致状态码/正文异常，第二次就正常了。

所以命中之后必须再做一遍独立取证，四步走（顺序不能换）：

1. **证据完整性检查**：状态行、响应头、响应体、请求 URL、实际长度是否齐备。
   缺项的命中无法复核，也就无法确认。
2. **反向验证**：拿同一站点的**随机不存在路径**和**首页**做基线，比对正文
   相似度与长度。与基线几乎一致的，属于站点通用响应，不是这条路径的证据。
3. **独立复测**：再发一次同样的请求，看结论是否一致。**只复测幂等方法**
   （GET/HEAD）——重放一个上传/删除请求就是破坏性操作，宁可标记"未复测"。
4. **最终定级**：证据分达标才进 ``CONFIRMED``，否则 ``NEEDS_REVIEW``；
   证据本身无效（无响应 / 通用响应）才是 ``REJECTED``。

打分与定级规则在 :mod:`core.state.quality`，这里只负责**取证**。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.state import Category, Evidence, Finding, FindingStatus, POC
from core.state.quality import EvidenceQuality, decide_status
from detectors.base import _SOFT404_EXTRA, normalize_body, random_path, similarity

# 复测只对幂等方法做：重放 POST/PUT 会把"验证"变成"再打一次"
_SAFE_METHODS = {"GET", "HEAD"}

# 能证明"实际影响"的内容特征。判据要硬——宁可漏判（降为待复核），
# 也不能把一句普通文案当成敏感数据泄露。
_IMPACT_PATTERNS: tuple[str, ...] = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",   # 私钥
    r"root:[^:\n]*:0:0:",                     # /etc/passwd
    r"\bAKIA[0-9A-Z]{16}\b",                  # 阿里云/AWS 访问密钥
    r"\bASIA[0-9A-Z]{16}\b",
    r"jdbc:[a-z]+://",                        # 数据库连接串
    r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb|redis)://[^\s\"']+:[^\s\"']+@",
    r"(?im)^\s*(?:DB_PASSWORD|SECRET_KEY|API_KEY|ACCESS_TOKEN)\s*=",  # .env
    r"(?i)\b(?:mysql|mariadb|postgresql|microsoft sql server)\b[^\n]{0,24}"
    r"\d+\.\d+\.\d+",                          # 数据库版本回显
    r"(?m)^\s*\[core\]\s*$",                   # .git/config
    r"uid=\d+\(",                              # 命令执行回显
)

# 这几类由专用探针产出，探针的命中条件本身就已经证明了影响
# （读到数据库版本号 / 读出文件内容 / 有回显），不需要再猜。
_IMPACT_CATEGORIES = {Category.INJECTION, Category.RCE, Category.FILE_OP}


class SecondPassVerifier:
    """对一批原始命中做第二次独立验证。

    ``det`` 只需提供 ``async send_request(url, poc=..., method=..., headers=...,
    body=...)``（:class:`detectors.base.Detector` 就是这个契约）；测试里可以
    传一个假的实现，因此本模块**不依赖网络**即可验证。
    """

    def __init__(
        self,
        det: Any,
        *,
        base_url: str = "",
        poc_lookup: dict[str, POC] | None = None,
        retest_enabled: bool = True,
    ) -> None:
        self.det = det
        self.base_url = (base_url or "").rstrip("/")
        self.poc_lookup = poc_lookup or {}
        self.retest_enabled = retest_enabled
        # host → [(归一化正文, 状态码, 长度)]，同一 host 只抓一次
        self._baselines: dict[str, list[tuple[str, int | None, int]]] = {}

    # ── 对外入口 ──────────────────────────────────────────────────
    async def run(self, findings: list[Finding]) -> dict[str, int]:
        """逐条验证并就地写回 ``status`` / ``evidence_score`` / ``quality``。"""
        stats = {
            "checked": 0,
            "confirmed": 0,
            "needs_review": 0,
            "rejected": 0,
            "retested": 0,
            "retest_skipped": 0,
            "baseline_failed": 0,
        }
        for f in findings:
            try:
                await self.evaluate(f)
            except Exception as exc:  # noqa: BLE001
                # 二次验证是增强，绝不能因为它把整批发现弄丢
                f.status = FindingStatus.NEEDS_REVIEW
                f.status_reason = f"二次验证异常（{type(exc).__name__}: {exc}），转人工复核"
                f.verify_notes = [f"二次验证异常：{type(exc).__name__}: {exc}"]
            stats["checked"] += 1
            stats[f.status.value] += 1
            if f.verify_notes and any("复测" in n and "跳过" in n for n in f.verify_notes):
                stats["retest_skipped"] += 1
            elif f.quality is not None and f.quality.retest_attempted:
                stats["retested"] += 1
            if f.quality is not None and not f.quality.baseline_different:
                stats["baseline_failed"] += 1
        return stats

    async def evaluate(self, f: Finding) -> EvidenceQuality:
        """单条：完整性 → 反向验证 → 独立复测 → 定级。"""
        ev = f.evidence
        poc = self.poc_lookup.get(f.poc_id)
        notes: list[str] = []
        q = EvidenceQuality()

        # 1) 证据完整性 -------------------------------------------------
        if ev is None:
            q.response_valid = False
            notes.append("完整性：没有证据对象")
        else:
            q.response_valid = bool(ev.status_code is not None and not ev.error)
            q.evidence_complete = _is_complete(ev)
            notes.append(
                "完整性：" + ("齐备（状态行/响应头/响应体/URL/长度）"
                              if q.evidence_complete
                              else "缺 " + "、".join(_missing(ev)))
            )
            if ev.error:
                notes.append(f"请求错误：{ev.error}")

        q.signature_specific = _is_specific(f, poc)
        notes.append(
            "专属特征：" + ("命中该 POC 声明的匹配规则" if q.signature_specific
                            else "只有状态码/通用条件，判别力弱")
        )

        # 2) 反向验证 ---------------------------------------------------
        if ev is None or not q.response_valid:
            q.baseline_different = False
            q.baseline_similarity = 1.0
        elif f.category is Category.HEADER_CHECK:
            # 响应头缺失是站点级配置属性，与路径无关，路径基线不适用
            q.baseline_different = True
            q.baseline_similarity = 0.0
            notes.append("反向验证：响应头类发现不适用路径基线对照")
        else:
            ok, sim, why = await self._reverse_verify(f)
            q.baseline_different = ok
            q.baseline_similarity = sim
            notes.append(f"反向验证：{why}")

        # 3) 独立复测 ---------------------------------------------------
        if not self.retest_enabled:
            notes.append("独立复测：已按配置关闭")
        elif ev is None or not q.response_valid:
            notes.append("独立复测：跳过（没有有效首次响应）")
        elif (ev.method or "GET").upper() not in _SAFE_METHODS:
            notes.append(
                f"独立复测：跳过（{ev.method} 非幂等，按非破坏性原则不重放）"
            )
        else:
            q.retest_attempted = True
            ok, status, why = await self._retest(f, poc)
            q.reproducible = ok
            q.retest_status = status
            notes.append(f"独立复测：{why}")

        # 4) 影响可证 ---------------------------------------------------
        q.impact_proven = _impact_proven(f)
        notes.append(
            "影响可证：" + ("响应中出现可证明影响的内容" if q.impact_proven
                            else "未取得能证明实际影响的内容")
        )

        # 5) 定级 -------------------------------------------------------
        f.quality = q
        f.evidence_score = q.score
        f.status, f.status_reason = decide_status(
            q,
            verdict=f.verdict,
            llm_confidence=f.confidence,
            evidence_score=q.score,
        )
        notes.append(f"定级：{f.status.label}（证据分 {q.score:.2f}）")
        f.verify_notes = notes
        return q

    # ── 反向验证 ──────────────────────────────────────────────────
    async def _reverse_verify(self, f: Finding) -> tuple[bool, float, str]:
        ev = f.evidence
        assert ev is not None
        if ev.status_code == 404:
            return False, 1.0, "首次响应已是 404，不构成该路径存在的证据"

        baseline = await self._baseline_of(ev.url)
        if not baseline:
            # 拿不到基线时**不能因此判成"通用响应"**：判错方向的代价不对称，
            # 多留一条可疑项只是噪音，冤枉一条真漏洞是事故。
            return True, 0.0, "基线不可用（请求失败），本项按未知处理，不作驳回"

        norm = normalize_body(ev.body_excerpt)
        worst = 0.0
        for base_norm, base_status, base_size in baseline:
            sim = similarity(norm, base_norm)
            worst = max(worst, sim)
            if sim >= 0.85:
                return False, sim, f"与基线正文相似度 {sim:.0%}（≥85%），属站点通用响应"
            # 长度几乎一致 + 正文高度重合 → 同一张模板页换了几个字
            if base_size and abs(ev.body_size - base_size) <= 2 and sim >= 0.6:
                return (
                    False,
                    sim,
                    f"与基线响应长度几乎一致（{ev.body_size} vs {base_size} 字节），"
                    "属通用响应",
                )
        for marker in _SOFT404_EXTRA:
            if marker in norm:
                return False, max(worst, 0.9), f"正文含通用错误提示「{marker}」"

        return True, worst, f"与基线最大相似度仅 {worst:.0%}，响应内容可区分"

    async def _baseline_of(self, url: str) -> list[tuple[str, int | None, int]]:
        """取（并缓存）该 host 的基线：首页 + 随机不存在路径。"""
        u = urlparse(url)
        root = f"{u.scheme}://{u.netloc}/"
        if root in self._baselines:
            return self._baselines[root]

        rows: list[tuple[str, int | None, int]] = []
        for target in (root, root + random_path()):
            try:
                ev = await self.det.send_request(target)
            except Exception:  # noqa: BLE001
                continue
            if ev.error or ev.status_code is None or not ev.body_excerpt:
                continue
            rows.append(
                (normalize_body(ev.body_excerpt), ev.status_code, ev.body_size)
            )
        # 空列表也缓存：同一 host 失败一次就别再重试几十遍
        self._baselines[root] = rows
        return rows

    # ── 独立复测 ──────────────────────────────────────────────────
    async def _retest(self, f: Finding, poc: POC | None) -> tuple[bool, int, str]:
        ev = f.evidence
        assert ev is not None
        method = (ev.method or "GET").upper()
        body = poc.request.body if poc is not None else ""
        headers = dict(poc.request.headers if poc is not None else {})
        try:
            ev2 = await self.det.send_request(
                ev.url, poc=poc, method=method, headers=headers, body=body
            )
        except Exception as exc:  # noqa: BLE001
            return False, -1, f"复测请求异常（{type(exc).__name__}），无法确认可重现"
        if ev2.error or ev2.status_code is None:
            return False, -1, f"复测未拿到响应（{ev2.error or '空响应'}），无法确认可重现"
        if ev2.status_code != ev.status_code:
            return (
                False,
                ev2.status_code,
                f"复测状态码不一致（首次 {ev.status_code}，复测 {ev2.status_code}）",
            )

        same = _same_conclusion(f, poc, ev, ev2)
        if same:
            return True, ev2.status_code, f"复测一致（HTTP {ev2.status_code}，同一判定特征仍成立）"
        return (
            False,
            ev2.status_code,
            f"复测状态码一致但判定特征未重现（HTTP {ev2.status_code}）",
        )


# ── 证据完整性 ────────────────────────────────────────────────────


def _missing(ev: Evidence) -> list[str]:
    out: list[str] = []
    if ev.status_code is None:
        out.append("状态行")
    if not ev.url:
        out.append("请求 URL")
    if not ev.response_headers:
        out.append("响应头")
    if ev.body_size <= 0:
        out.append("响应体")
    return out or ["未知项"]


def _is_complete(ev: Evidence) -> bool:
    """状态行 + URL + 响应头 + 实际长度，四项都得有。

    **长度单独算一项**：正文可能被截断（``max_body_capture``），有长度
    才能判断"我看到的正文是不是全部"——这正是"响应被截断导致误判"的解药。
    """
    if ev.status_code is None or not ev.url:
        return False
    if not ev.response_headers:
        return False
    return ev.body_size > 0


# ── 判别力 ────────────────────────────────────────────────────────


def _is_specific(f: Finding, poc: POC | None) -> bool:
    """命中的是不是"这条 POC 专属"的特征。

    只有 ``expect_status``（例如"返回 200 就算命中"）的 POC 判别力最弱——
    正常页面本来就返回 200。这类命中即使能复现，也进不了"已确认"。
    """
    if poc is not None and poc.rules:
        return True
    if f.evidence is not None and f.evidence.matched_pattern:
        # 专用探针写进证据的判定依据（"响应出现 version() 输出"这类）
        if "状态码" not in f.evidence.matched_pattern:
            return True
    return f.category in _IMPACT_CATEGORIES and f.detector == "exploit"


def _impact_proven(f: Finding) -> bool:
    """响应里是否有能证明实际安全影响的内容。"""
    if f.category in _IMPACT_CATEGORIES and f.detector == "exploit":
        # 探针的命中条件本身就是"读到了版本号/文件内容/命令回显"
        return True
    ev = f.evidence
    if ev is None:
        return False
    blob = ev.body_excerpt or ""
    if not blob:
        return False
    import re

    for pat in _IMPACT_PATTERNS:
        try:
            if re.search(pat, blob):
                return True
        except re.error:
            continue
    return False


def _same_conclusion(f: Finding, poc: POC | None, ev: Evidence, ev2: Evidence) -> bool:
    """复测的两次响应是否给出同一个结论。

    有可用规则时以**规则是否仍命中**为准（正文里常有时间戳/随机 nonce，
    纯相似度会误判为"不一致"）；没有规则时退回正文相似度。
    """
    if poc is not None and poc.id == f.poc_id and poc.rules and f.detector == "http":
        try:
            return bool(poc.rules_match(ev2.body_excerpt, ev2.response_headers))
        except Exception:  # noqa: BLE001
            pass
    return similarity(
        normalize_body(ev.body_excerpt), normalize_body(ev2.body_excerpt)
    ) >= 0.9
