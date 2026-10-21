"""POC 声明模型——对应 ``poc/*.yaml``。

原 :mod:`core.state` 的「POC 声明」段。这里只描述**怎么匹配**，
不涉及任何运行时状态；``Finding`` 才挂证据（在 :mod:`core.state.models`）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.state.enums import Category, Severity
from core.state.util import re_search


# ── POC 声明（对应 poc/*.yaml）──────────────────────────────────


class MatchTarget(str, Enum):
    BODY = "body"
    HEADER = "header"
    ALL = "all"          # body + 响应头拼在一起


class MatchOp(str, Enum):
    CONTAINS = "contains"      # 任一 pattern 命中（默认）
    ALL = "all"# 全部 pattern 命中
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    MISSING = "missing"        # 指定的 header 不存在
    ABSENT = "absent"# header 存在但不含 value_regex


@dataclass(slots=True)
class MatchRule:
    """一条匹配规则。对应 YAML 里的 ``match:`` 列表项。

    多规则的组合语义
    ----------------
    默认是**全部满足**（AND）——最常见的用法，如"既要含 keyword 也要含 error"。
    但响应头检查经常是**任一满足**（OR），例如"Server 或 X-Powered-By 任一
    暴露了版本号就算泄露"、"Cookie 缺 HttpOnly **或** 缺 Secure 就算有问题"。

    为此提供两种写法，不要靠写多条规则硬凑（AND 语义下 OR 永远不成立）：

    * ``any_of: true`` —— 列表里任一规则命中即算命中
    * 或拆成多个独立 POC

    实测踩坑：``hdr-server-disclosure`` 若用 AND 语义写"Server 有版本号 且
    X-Powered-By 有版本号"，那么只暴露 Server 的目标会被漏报。
    """

    patterns: list[str] = field(default_factory=list)
    match_all: bool = False
    op: MatchOp = MatchOp.CONTAINS
    target: MatchTarget = MatchTarget.ALL
    # header 名（小写），target=header 时使用
    header: str = ""
    # header 存在时额外要满足的正则，如 version 泄露要匹配 \\d+\\.\\d+
    value_regex: str = ""
    # 命中即排除的干扰模式（如统一错误页里的 "error"）
    exclude: list[str] = field(default_factory=list)
    # 命中即视为软 404，用于抑制误报
    soft_404_markers: list[str] = field(default_factory=list)
    # 组合语义：True=列表内任一规则命中即可（OR）；False=全部命中（AND，默认）
    any_of: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MatchRule":
        raw_op = str(d.get("op") or ("all" if d.get("match_all") else "contains")).lower()
        raw_target = str(d.get("target") or "all").lower()
        patterns = d.get("patterns") or ([d["pattern"]] if d.get("pattern") else [])
        return cls(
            patterns=[str(p) for p in patterns],
            match_all=bool(d.get("match_all", raw_op == "all")),
            op=MatchOp(raw_op) if raw_op in {o.value for o in MatchOp} else MatchOp.CONTAINS,
            target=(
                MatchTarget(raw_target)
                if raw_target in {t.value for t in MatchTarget}
                else MatchTarget.ALL
            ),
            header=str(d.get("header") or "").lower(),
            value_regex=str(d.get("value_regex") or ""),
            exclude=[str(x) for x in (d.get("exclude") or [])],
            soft_404_markers=[str(x) for x in (d.get("soft_404") or [])],
            any_of=bool(d.get("any_of", False)),
        )

    def evaluate(self, body: str, headers: dict[str, str] | None = None) -> bool:
        """单条规则求值。组合语义由 :meth:`POC.rules_match` 处理。"""
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        low_body = (body or "").lower()

        if self.exclude and any(x.lower() in low_body for x in self.exclude):
            return False
        if self.soft_404_markers and any(x.lower() in low_body for x in self.soft_404_markers):
            return False

        if self.target is MatchTarget.HEADER:
            return self._eval_header(headers)
        if self.target is MatchTarget.BODY:
            return self._eval_body(low_body)

        hay = low_body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        if self.op is MatchOp.MISSING:
            return not headers.get(self.header)
        return self._eval_hay(hay)

    def _eval_body(self, low_body: str) -> bool:
        if self.op is MatchOp.MISSING:
            return True
        return self._eval_hay(low_body)

    def _eval_header(self, headers: dict[str, str]) -> bool:
        val = headers.get(self.header)
        if self.op is MatchOp.MISSING:
            return val is None
        if self.op is MatchOp.ABSENT:
            if val is None:
                return False
            return not self.value_regex or not re_search(self.value_regex, val)
        if val is None:
            return False
        # 后两者的区别只在"要不要正则"：
        #   contains → 头存在，且（若有 value_regex）匹配它
        #   regex    → 头存在，且（若有 patterns）匹配其中之一
        # 没有 patterns 也没有 value_regex 时无法判断"包含什么"，
        # 视为配置错误 → 恒假（宁可漏报也不要凭空报警）。
        if self.op is MatchOp.REGEX:
            return any(re_search(p, val) for p in self.patterns) if self.patterns else False
        if self.value_regex:
            return re_search(self.value_regex, val)
        return bool(self.patterns) and any(p.lower() in val.lower() for p in self.patterns)

    def _eval_hay(self, hay: str) -> bool:
        if not self.patterns:
            # 没给patterns 时，value_regex 存在即视为命中
            return bool(self.value_regex)
        if self.op is MatchOp.NOT_CONTAINS:
            return not any(p.lower() in hay for p in self.patterns)
        if self.op is MatchOp.ALL or self.match_all:
            return all(p.lower() in hay for p in self.patterns)
        if self.op is MatchOp.REGEX:
            return any(re_search(p, hay) for p in self.patterns)
        return any(p.lower() in hay for p in self.patterns)


@dataclass(slots=True)
class RequestSpec:
    """POC 的请求模板。对应 YAML 里的 ``request:``。"""

    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str = ""
    expect_status: list[int] = field(default_factory=lambda: [200, 401, 403])

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "RequestSpec":
        d = d or {}
        paths = d.get("paths") or ([d["path"]] if d.get("path") else [])
        expect = d.get("expect_status") or d.get("expect")
        return cls(
            method=str(d.get("method") or "GET").upper(),
            paths=[str(p) for p in paths],
            headers={str(k): str(v) for k, v in (d.get("headers") or {}).items()},
            params={str(k): str(v) for k, v in (d.get("params") or {}).items()},
            body=str(d.get("body") or ""),
            expect_status=[int(x) for x in expect] if expect else [200, 401, 403],
        )

    @property
    def search_paths(self) -> list[str]:
        """至少要打一个请求（空路径 = 打站点根）。"""
        return self.paths or [""]


@dataclass(slots=True)
class POC:
    """一个 POC 定义——由 ``poc/*.yaml`` 编译而来。"""

    id: str
    name: str
    category: Category
    severity: Severity
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    request: RequestSpec = field(default_factory=RequestSpec)
    rules: list[MatchRule] = field(default_factory=list)
    # 该 POC 针对的指纹（命中这些指纹才提高检索优先级）
    applies_to: list[str] = field(default_factory=list)
    # 是否需要写操作（只读模式下跳过）
    intrusive: bool = False
    # 通用基线：与技术栈无关的必查项，绕过 RAG 直接执行。
    # 用于 .git/config 泄露、source map 这类"与指纹毫无相似度"的漏洞
    # ——纯检索必然漏掉它们，必须显式声明（详见 kb/retriever.py 的说明）。
    always_run: bool = False
    tags: list[str] = field(default_factory=list)
    # 来源 YAML 路径，便于报告溯源
    source: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], source: str = "") -> "POC":
        return cls(
            id=str(d["id"]),
            name=str(d.get("name") or d["id"]),
            category=Category(str(d.get("category") or "content_match")),
            severity=Severity.parse(d.get("severity") or "info"),
            description=str(d.get("description") or ""),
            remediation=str(d.get("remediation") or ""),
            references=[str(x) for x in (d.get("references") or [])],
            cve=[str(x) for x in (d.get("cve") or [])],
            request=RequestSpec.from_dict(d.get("request")),
            rules=[MatchRule.from_dict(x) for x in (d.get("match") or [])],
            applies_to=[str(x).lower() for x in (d.get("applies_to") or [])],
            intrusive=bool(d.get("intrusive", False)),
            always_run=bool(d.get("always_run", False)),
            tags=[str(x).lower() for x in (d.get("tags") or [])],
            source=source,
        )

    def index_document(self) -> str:
        """生成用于向量化 / 检索的文本表示。

        注意：这里必须包含 ``match`` 规则里的响应头名与正则，否则
        header_check 类 POC 在索引里没有任何信号——实测它们的融合得分
        是 0.000，因为"name/描述"里根本不会出现 ``set-cookie``、
        ``httponly`` 这些词。这是检索层的先天盲区，索引时补齐能缓解
        （但不能根治，所以 kb/retriever.py 里还有一层"响应头类无条件必查"）。
        """
        bits = [
            self.id,
            self.name,
            self.description,
            self.remediation,
            " ".join(self.tags),
            " ".join(self.applies_to),
            " ".join(self.cve),
            self.category.value,
            " ".join(self.request.paths[:12]),
        ]
        for r in self.rules:
            if r.header:
                bits.append(r.header)
            bits.extend(r.patterns[:6])
            if r.value_regex:
                # 正则里的转义符（\d\.）会让分词器切出无意义的碎片，
                # 只取字母数字部分
                bits.append("".join(ch for ch in r.value_regex if ch.isalnum()))
        return "\n".join(b for b in bits if b)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "tags": self.tags,
            "applies_to": self.applies_to,
            "cve": self.cve,
            "intrusive": self.intrusive,
            "always_run": self.always_run,
            "source": self.source,
        }

    def rules_match(self, body: str, headers: dict[str, str] | None = None) -> bool:
        """求值全部规则。

        组合语义：默认全部满足（AND）；**任意一条规则标了** ``any_of: true``
        时转为任一满足（OR）。

        "任意一条标记即切换"而不是"所有规则都标记才切换"，是因为实际
        写法就是这样——只想把其中一条变成可选项时不必再标记其余的。
        """
        if not self.rules:
            return True
        if any(r.any_of for r in self.rules):
            return any(r.evaluate(body, headers) for r in self.rules)
        return all(r.evaluate(body, headers) for r in self.rules)


