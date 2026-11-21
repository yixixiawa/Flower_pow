"""历史会话归档：**事件流 + Markdown 导出 + 复盘摘要 + 知识恢复**。

为什么需要它
------------
``session.json`` 存的是**当前状态**（目标、发现、任务台账、对话历史），
它有两件事做不到：

* 恢复不出"当时是怎么一步步走过来的"——工具调了哪些、哪次被策略拦下、
  哪个后台任务超时了，快照里只留最终结果；
* 不能当知识库检索——它是单个 JSON，没有按事件切分的粒度。

所以另立一套**只追加**的事件记录：每个会话一个目录，一条事件一行 JSONL，
Markdown 从事件流**重新渲染**。两者的关系是"状态"与"日志"，互不覆盖：

    data/conversations/YYYY/MM/session_<id>/
        events.jsonl     结构化事件（唯一事实来源，只追加）
        conversation.md  从事件流渲染的完整对话（可反复重渲染）
        summary.md       复盘摘要（Agent 生成的总结，与原始记录分开）
        artifacts/       大型工具结果（正文不入 Markdown，只留引用）
        meta.json        会话外形（目标/环境/状态/计数）

几条硬约束
----------
* **幂等**：``event_id`` 是主键。同一 ``idem`` 键重复写入只留一条——
  进程重启、任务恢复、重复 ``/history save`` 都不会把同一件事记两遍。
* **先脱敏后落盘**：密码、Token、Cookie、Authorization 在写 JSONL 之前
  就被替换（见 :mod:`core.session.redact`）。脱敏发生在**持久化前**，
  不是导出时——否则原文已经在磁盘上躺过一遍了。
* **大结果走 artifact**：超过 ``MAX_INLINE_RESULT`` 的工具输出落到
  ``artifacts/``，事件里只留预览 + 路径 + SHA256 + 大小。引用只能指向
  本会话目录内的文件（:meth:`EventJournal.resolve_artifact` 用 resolve
  比对，挡住 ``..`` 与符号链接逃逸），因此**不可能跨会话引用**。
* **写失败必须可见**：:meth:`append` 写不进去就抛 :class:`JournalError`；
  集成点用宽容版 :meth:`record`，把错误记进 ``last_error`` 并向 stderr
  告警一次——不允许"以为存了其实没存"。
* **恢复只给知识，不给权限**：:meth:`resume_context` 只输出可见对话、
  已确认事实、失败路径与 artifact 引用；审批票据、Token、Cookie、
  授权状态一律不进恢复上下文（见 ``_RESUME_DENY_KEYS``）。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from core.session.redact import redact

# ── 目录与文件约定 ────────────────────────────────────────────────
SESSION_PREFIX = "session_"
EVENTS_FILE = "events.jsonl"
CONVERSATION_FILE = "conversation.md"
SUMMARY_FILE = "summary.md"
META_FILE = "meta.json"
ARTIFACT_DIR = "artifacts"

#: 超过这个字符数的工具结果落 artifact 文件（正文不进 Markdown）
MAX_INLINE_RESULT = 4000

#: 事件里保存的参数/结果预览上限
PREVIEW_CHARS = 800

#: 支持的事件类型（任务书 三.支持的事件类型）
EVENT_TYPES = (
    "USER_MESSAGE",
    "ASSISTANT_MESSAGE",
    "TOOL_CALL",
    "TOOL_RESULT",
    "POLICY_DECISION",
    "TASK_STARTED",
    "TASK_COMPLETED",
    "TASK_FAILED",
    "FINDING_CREATED",
    "REPORT_CREATED",
    "SESSION_RESUMED",
)

#: 恢复上下文里**永不出现**的字段（按 key 判，大小写不敏感）
_RESUME_DENY_KEYS = frozenset(
    {
        "ticket", "tickets", "approval", "approved", "approval_ticket",
        "token", "access_token", "refresh_token", "api_key", "apikey",
        "cookie", "cookies", "authorization", "password", "passwd", "pwd",
        "secret", "credential", "credentials", "session_cookie", "auth",
    }
)

#: 键名里出现这些片段就当凭据处理（``approval_token`` / ``x_api_key`` 这类
#: 组合名靠上面的精确集合会漏，按片段判更稳）
_DENY_FRAGMENTS = (
    "ticket", "token", "approval", "cookie", "password", "passwd", "pwd",
    "secret", "credential", "authorization", "apikey", "api_key",
)


def _is_sensitive_key(key: str) -> bool:
    k = str(key or "").strip().lower()
    if not k:
        return False
    if k in _RESUME_DENY_KEYS:
        return True
    return any(f in k for f in _DENY_FRAGMENTS)

#: 事件类型 → Markdown 里的一级章节
_SECTION = {
    "USER_MESSAGE": "二、用户与 Agent 对话",
    "ASSISTANT_MESSAGE": "二、用户与 Agent 对话",
    "TOOL_CALL": "三、工具调用记录",
    "TOOL_RESULT": "三、工具调用记录",
    "POLICY_DECISION": "四、Policy 判定与拦截记录",
    "FINDING_CREATED": "五、发现与证据",
}

_FAIL_STATUS = frozenset({"blocked", "error", "badargs", "unknown", "timeout", "failed"})


class JournalError(Exception):
    """事件写不进去 / artifact 非法 —— 调用方必须让用户看见。"""


# ── 事件 ──────────────────────────────────────────────────────────
@dataclass
class JournalEvent:
    """一条归档事件。字段与任务书 三.记录字段一一对应。"""

    event_id: str
    session_id: str
    event_type: str
    ts: float = field(default_factory=time.time)
    role: str = ""
    content: str = ""
    tool_name: str = ""
    tool_arguments: str = ""
    tool_result: str = ""
    execution_status: str = ""
    policy_decision: str = ""
    artifact_reference: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "ts": round(float(self.ts), 3),
            "role": self.role,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_arguments": self.tool_arguments,
            "tool_result": self.tool_result,
            "execution_status": self.execution_status,
            "policy_decision": self.policy_decision,
        }
        if self.artifact_reference:
            d["artifact_reference"] = self.artifact_reference
        if self.extra:
            d["extra"] = self.extra
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "JournalEvent | None":
        """**字段级容错**：坏行返回 None，绝不把整份记录带崩。"""
        if not isinstance(d, dict):
            return None
        eid = str(d.get("event_id") or "").strip()
        et = str(d.get("event_type") or "").strip()
        if not eid or et not in EVENT_TYPES:
            return None
        ref = d.get("artifact_reference")
        return cls(
            event_id=eid,
            session_id=str(d.get("session_id") or ""),
            event_type=et,
            ts=_as_float(d.get("ts"), time.time()),
            role=str(d.get("role") or ""),
            content=str(d.get("content") or ""),
            tool_name=str(d.get("tool_name") or ""),
            tool_arguments=str(d.get("tool_arguments") or ""),
            tool_result=str(d.get("tool_result") or ""),
            execution_status=str(d.get("execution_status") or ""),
            policy_decision=str(d.get("policy_decision") or ""),
            artifact_reference=dict(ref) if isinstance(ref, dict) else None,
            extra=dict(d.get("extra") or {}) if isinstance(d.get("extra"), dict) else {},
        )

    # 便捷视图（Markdown/搜索用）
    @property
    def at_text(self) -> str:
        return _fmt_time(self.ts)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _fmt_time(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (ValueError, OSError, OverflowError):
        return "?"


def _fmt_short(ts: float) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except (ValueError, OSError, OverflowError):
        return "?"


def _safe(text: str, limit: int = 0) -> str:
    """文件名安全化（与项目其它处同一套口径：非 word 字符压成下划线）。"""
    out = re.sub(r"[^\w.\-]+", "_", str(text or ""))[:limit or 60].strip("._")
    return out or "x"


def _clip(text: str, limit: int = PREVIEW_CHARS) -> str:
    t = str(text or "")
    if len(t) <= limit:
        return t
    return t[:limit] + f"\n…（已截断，共 {len(t)} 字符）"


# ── 事件流 ────────────────────────────────────────────────────────
class EventJournal:
    """一个会话的事件流。构造不落盘，第一次写事件时才建目录。"""

    def __init__(
        self,
        root: str | Path,
        session_id: str,
        *,
        created_at: float | None = None,
        target: str = "",
        environment: str = "",
        phase: str = "",
    ) -> None:
        self.root = Path(root)
        self.session_id = str(session_id or "unknown")
        self.created_at = float(created_at or time.time())
        self._target = target
        self._environment = environment
        self._phase = phase
        self._dir: Path | None = None
        self._ids: set[str] = set()
        self._count = 0
        self._seq = 0
        self._loaded = False
        self._corrupt: list[dict[str, Any]] = []
        self._duplicates: list[str] = []
        self.last_error = ""
        self._warned = False
        self._artifact_seq = 0
        self._meta_cache: dict[str, Any] = {}

    # ── 路径 ──────────────────────────────────────────────────────
    @property
    def dir(self) -> Path:
        if self._dir is None:
            stamp = time.localtime(self.created_at)
            name = SESSION_PREFIX + _safe(self.session_id, 80)
            self._dir = (
                self.root / time.strftime("%Y", stamp) / time.strftime("%m", stamp) / name
            )
        return self._dir

    @property
    def events_path(self) -> Path:
        return self.dir / EVENTS_FILE

    @property
    def conversation_path(self) -> Path:
        return self.dir / CONVERSATION_FILE

    @property
    def summary_path(self) -> Path:
        return self.dir / SUMMARY_FILE

    @property
    def artifacts_dir(self) -> Path:
        return self.dir / ARTIFACT_DIR

    def __len__(self) -> int:
        self._load()
        return self._count

    # ── 读取 ──────────────────────────────────────────────────────
    def _load(self) -> None:
        """载入已有事件，建立去重集合。损坏行只统计、不抛。"""
        if self._loaded:
            return
        self._loaded = True
        p = self.events_path
        if not p.is_file():
            return
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.last_error = f"读取事件流失败：{exc}"
            return
        for i, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as exc:
                # 写到一半被 Ctrl+C 截断的行会落在这里：跳过，但记下来
                self._corrupt.append({"line": i, "error": exc.msg})
                continue
            ev = JournalEvent.from_dict(d)
            if ev is None:
                self._corrupt.append({"line": i, "error": "字段不完整或事件类型未知"})
                continue
            if ev.event_id in self._ids:
                self._duplicates.append(ev.event_id)
                continue
            self._ids.add(ev.event_id)
            self._count += 1
            self._seq = max(self._seq, _seq_from_id(ev.event_id))

    def events(self) -> list[JournalEvent]:
        """按**写入顺序**返回全部事件（损坏行已跳过）。"""
        self._load()
        p = self.events_path
        if not p.is_file():
            return []
        out: list[JournalEvent] = []
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = JournalEvent.from_dict(d)
            if ev is not None:
                out.append(ev)
        return out

    def verify(self) -> dict[str, Any]:
        """完整性检查：行数 / 有效事件 / 坏行 / 重复 id。"""
        self._load()
        events = self.events()
        return {
            "path": str(self.events_path),
            "exists": self.events_path.is_file(),
            "events": len(events),
            "corrupt": list(self._corrupt),
            "duplicates": list(self._duplicates),
            "ok": not self._corrupt and not self._duplicates,
        }

    # ── 写入 ──────────────────────────────────────────────────────
    def append(
        self,
        event_type: str,
        *,
        role: str = "",
        content: str = "",
        tool_name: str = "",
        tool_arguments: Any = "",
        tool_result: Any = "",
        execution_status: str = "",
        policy_decision: str = "",
        artifact_reference: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        idem: str = "",
        ts: float | None = None,
        keep_result_inline: bool = False,
    ) -> JournalEvent | None:
        """追加一条事件并**立即落盘**（flush + fsync）。

        ``idem`` 给出幂等键时，重复写入返回既有事件之前的 ``None``——
        调用方据此知道"这次没产生新记录"。写失败抛 :class:`JournalError`。
        """
        if event_type not in EVENT_TYPES:
            raise JournalError(f"未知事件类型：{event_type}（可用：{', '.join(EVENT_TYPES)}）")
        self._load()
        at = float(ts if ts is not None else time.time())

        if idem:
            eid = "idem:" + hashlib.sha256(
                f"{self.session_id}|{event_type}|{idem}".encode("utf-8")
            ).hexdigest()[:20]
            if eid in self._ids:
                return None
        else:
            self._seq += 1
            eid = f"{self.session_id}#{self._seq}"

        result_text = _to_text(tool_result)
        ref = dict(artifact_reference) if artifact_reference else None
        # 大结果 → artifact。只在没有显式引用时自动落盘。
        if result_text and ref is None and not keep_result_inline:
            if len(result_text) > MAX_INLINE_RESULT:
                ref = self._save_artifact(result_text, tool_name or event_type.lower())
                result_text = (
                    f"（完整结果 {len(result_text)} 字符已存 artifact：{ref['path']}，"
                    f"sha256={ref['sha256'][:12]}…）\n{ref.get('preview', '')}"
                )

        ev = JournalEvent(
            event_id=eid,
            session_id=self.session_id,
            event_type=event_type,
            ts=at,
            role=str(role or ""),
            content=redact(str(content or "")),
            tool_name=str(tool_name or ""),
            tool_arguments=redact(_to_text(tool_arguments)) if tool_arguments else "",
            tool_result=redact(result_text) if result_text else "",
            execution_status=str(execution_status or ""),
            policy_decision=str(policy_decision or ""),
            artifact_reference=ref,
            extra=_sanitize_extra(extra),
        )
        self._write_line(ev)
        self._ids.add(eid)
        self._count += 1
        self._touch_meta()
        return ev

    def record(self, event_type: str, **kw: Any) -> JournalEvent | None:
        """宽容版 :meth:`append`：写不进去只告警一次，不打断执行链。

        归档是旁路——它挂了不能让工具调用跟着挂。但"悄悄丢"是不允许的：
        错误进 ``last_error``，并且**每个会话至少向 stderr 说一次**。
        """
        try:
            return self.append(event_type, **kw)
        except JournalError as exc:
            self.last_error = str(exc)
            if not self._warned:
                self._warned = True
                print(f"[journal] 会话归档写入失败：{exc}", file=sys.stderr)
            return None

    def _write_line(self, ev: JournalEvent) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(ev.to_dict(), ensure_ascii=False) + "\n"
        try:
            # 上次若被 Ctrl+C 杀在写一半，文件尾没有换行符——直接追加会把
            # **新事件粘到坏行后面**，一次崩溃连带丢掉之后的事件。
            # 追加前补一个换行，坏行留在原地（verify 会报出来）。
            needs_nl = False
            if self.events_path.is_file() and self.events_path.stat().st_size > 0:
                with self.events_path.open("rb") as probe:
                    probe.seek(-1, 2)
                    needs_nl = probe.read(1) != b"\n"
            with self.events_path.open("a", encoding="utf-8") as f:
                if needs_nl:
                    f.write("\n")
                f.write(line)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # 某些文件系统（网络盘/容器卷）不支持 fsync：flush 已足够
                    pass
        except OSError as exc:
            raise JournalError(f"事件落盘失败（{self.events_path}）：{exc}") from exc

    # ── artifact ──────────────────────────────────────────────────
    def _save_artifact(self, text: str, name: str) -> dict[str, Any]:
        self._artifact_seq += 1
        fname = f"{_safe(name, 24)}_{self._artifact_seq}.txt"
        path = self.artifacts_dir / fname
        # 必须以**字节**写：Windows 文本模式会把 "\n" 翻成 "\r\n"，
        # 落盘大小与记录的 SHA256 就对不上（多行响应实测差出 2KB）。
        # 记录里的 sha256/size 是"这份文件本身"的指纹，不是"这份文本"的。
        data = text.encode("utf-8")
        try:
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as exc:
            raise JournalError(f"artifact 落盘失败（{path}）：{exc}") from exc
        return {
            "id": f"{_safe(name, 24)}_{self._artifact_seq}",
            "path": f"{ARTIFACT_DIR}/{fname}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "preview": _clip(text, 400),
            "at": round(time.time(), 3),
        }

    def resolve_artifact(self, rel: str) -> Path:
        """把引用解析成**本会话目录内**的真实文件；越界一律拒绝。"""
        raw = str(rel or "").strip().replace("\\", "/")
        if not raw:
            raise JournalError("artifact 引用为空")
        if raw.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", raw):
            raise JournalError("artifact 只接受会话目录内的相对路径")
        if ".." in raw.split("/"):
            raise JournalError("artifact 路径包含 '..'，拒绝访问会话目录之外")
        base = (self.dir / ARTIFACT_DIR).resolve()
        target = (self.dir / raw).resolve()
        try:
            target.relative_to(base)
        except ValueError as exc:
            raise JournalError(f"artifact 不在本会话产物目录内：{raw}") from exc
        if not target.is_file():
            raise JournalError(f"artifact 不存在：{raw}")
        return target

    # ── meta ──────────────────────────────────────────────────────
    def meta(self) -> dict[str, Any]:
        if self._meta_cache:
            return dict(self._meta_cache)
        d: dict[str, Any] = {}
        p = self.dir / META_FILE
        if p.is_file():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    d = raw
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                d = {}
        self._meta_cache = d
        return dict(d)

    def sync(self, **fields: Any) -> dict[str, Any]:
        """更新会话外形（目标/环境/阶段/状态/计数），原子写回 meta.json。"""
        meta = self.meta()
        meta.update({k: v for k, v in fields.items() if v is not None})
        meta.setdefault("session_id", self.session_id)
        meta.setdefault("created_at", self.created_at)
        meta["updated_at"] = time.time()
        meta["event_count"] = len(self)
        self._meta_cache = dict(meta)
        self._write_meta(meta)
        return meta

    def _touch_meta(self) -> None:
        """事件写入后维护 updated_at/event_count（失败不阻断事件）。

        目标/环境/阶段只做 ``setdefault``：交互层 :meth:`sync` 写进来的
        是现算的权威值，这里补的只是"还没 sync 过"时的初值——否则一份
        只写过事件、没触发会话保存的归档，Markdown 抬头会是"未设定"。
        """
        try:
            meta = self.meta()
            meta.setdefault("session_id", self.session_id)
            meta.setdefault("created_at", self.created_at)
            if self._target:
                meta.setdefault("target", self._target)
            if self._environment:
                meta.setdefault("environment", self._environment)
            if self._phase:
                meta.setdefault("phase", self._phase)
            meta.setdefault("status", "进行中")
            meta["updated_at"] = time.time()
            meta["event_count"] = self._count
            self._meta_cache = dict(meta)
            self._write_meta(meta)
        except OSError:
            pass

    def _write_meta(self, meta: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.dir / META_FILE, json.dumps(meta, ensure_ascii=False, indent=1))

    # ── 检索 ──────────────────────────────────────────────────────
    def search(self, keyword: str, *, limit: int = 20) -> list[tuple[JournalEvent, str]]:
        """按关键字搜本会话事件，返回 ``[(事件, 命中片段)]``。"""
        kw = (keyword or "").strip().lower()
        if not kw:
            return []
        out: list[tuple[JournalEvent, str]] = []
        for ev in self.events():
            hay = " ".join(
                [ev.content, ev.tool_name, ev.tool_arguments, ev.tool_result,
                 ev.policy_decision, json.dumps(ev.extra, ensure_ascii=False)]
            )
            if kw in hay.lower():
                out.append((ev, _snippet(hay, kw)))
                if len(out) >= limit:
                    break
        return out

    # ── 渲染 ──────────────────────────────────────────────────────
    def render_markdown(self) -> str:
        """事件流 → 完整 Markdown。**每次都从事件重渲染，不叠加旧的。**"""
        events = self.events()
        meta = self.meta()
        target = meta.get("target") or self._target or "（未设定）"
        env = meta.get("environment") or self._environment or "（未知）"
        status = meta.get("status") or "进行中"
        first = meta.get("created_at") or self.created_at
        last = meta.get("updated_at") or (events[-1].ts if events else first)

        lines: list[str] = [
            "# 会话基本信息",
            "",
            f"- Session ID：`{self.session_id}`",
            f"- 创建时间：{_fmt_time(float(first))}",
            f"- 最后更新：{_fmt_time(float(last))}",
            f"- 测试目标：{target}",
            f"- 测试环境：{env}",
            f"- 会话状态：{status}",
            f"- 事件总数：{len(events)}",
            "",
            "> 本文由事件流（`events.jsonl`）渲染生成；第七章为复盘摘要，"
            "与第一至六章的原始记录**分开存放**，摘要不覆盖原始记录。",
            "",
        ]
        lines += self._render_background(events, meta)
        lines += self._render_dialog(events)
        lines += self._render_tools(events)
        lines += self._render_policy(events)
        lines += self._render_findings(events)
        lines += self._render_failures(events)
        lines += self._render_conclusion(meta)
        lines += self._render_next(meta)
        return "\n".join(lines).rstrip() + "\n"

    def _render_background(
        self, events: list[JournalEvent], meta: dict[str, Any]
    ) -> list[str]:
        first_user = next((e for e in events if e.event_type == "USER_MESSAGE"), None)
        out = ["# 一、测试背景", ""]
        out.append(f"- 目标：{meta.get('target') or self._target or '（未设定）'}")
        out.append(f"- 环境：{meta.get('environment') or self._environment or '（未知）'}")
        if meta.get("phase"):
            out.append(f"- 起始阶段：{meta['phase']}")
        resumed = [e for e in events if e.event_type == "SESSION_RESUMED"]
        if resumed:
            out.append(
                "- 恢复记录：" + "；".join(_fmt_time(e.ts) for e in resumed[-3:])
            )
        out.append("")
        if first_user:
            out += [
                "首条需求（原始记录）：",
                "",
                "```text",
                _clip(first_user.content, 1000),
                "```",
                "",
            ]
        else:
            out += ["（本会话没有用户输入记录）", ""]
        return out

    def _render_dialog(self, events: list[JournalEvent]) -> list[str]:
        out = ["# 二、用户与 Agent 对话", ""]
        turns = [e for e in events if e.event_type in ("USER_MESSAGE", "ASSISTANT_MESSAGE")]
        if not turns:
            out += ["（没有对话记录）", ""]
            return out
        out.append("> 原始对话，逐条按发生顺序记录，未做改写。")
        out.append("")
        for e in turns:
            who = "用户" if e.event_type == "USER_MESSAGE" else "Agent"
            out.append(f"### [{_fmt_short(e.ts)}] {who}")
            out.append("")
            body = (e.content or "").strip() or "（空）"
            out.append("\n".join("> " + ln if ln else ">" for ln in body.splitlines()))
            out.append("")
        return out

    def _render_tools(self, events: list[JournalEvent]) -> list[str]:
        calls = [e for e in events if e.event_type == "TOOL_CALL"]
        results = {e.extra.get("call_id"): e for e in events if e.event_type == "TOOL_RESULT"}
        known = {c.extra.get("call_id") for c in calls}
        orphans = [e for e in events
                   if e.event_type == "TOOL_RESULT" and e.extra.get("call_id") not in known]
        out = ["# 三、工具调用记录", ""]
        if not calls and not orphans:
            out += ["（没有工具调用记录）", ""]
            return out
        if calls:
            out += [
                f"共 {len(calls)} 次调用。",
                "",
                "| # | 时间 | 工具 | 状态 | 耗时 | 结果 |",
                "|---|------|------|------|------|------|",
            ]
            for i, c in enumerate(calls, 1):
                r = results.get(c.extra.get("call_id"))
                status = (r.execution_status if r else "未返回") or "-"
                ms = (r.extra.get("ms") if r else None) or "-"
                size = len(r.tool_result) if r else 0
                out.append(
                    f"| {i} | {_fmt_short(c.ts)} | `{c.tool_name}` | {status} | "
                    f"{ms}ms | {size} 字符 |"
                )
            out.append("")
        for i, c in enumerate(calls, 1):
            r = results.get(c.extra.get("call_id"))
            out += [f"## 调用 {i} · `{c.tool_name}`（{_fmt_short(c.ts)}）", ""]
            out += ["参数：", "", "```json", _clip(c.tool_arguments, 1200), "```", ""]
            if r is None:
                out += ["（该调用没有结果事件——可能被中断）", ""]
                continue
            out += self._render_result(r)
        # 配对不上的结果（CALL 那条写失败/被截断时只剩它）：不能因此丢内容
        for e in orphans:
            out += [f"## 未配对的结果 · `{e.tool_name}`（{_fmt_short(e.ts)}）", ""]
            out += self._render_result(e)
        return out

    def _render_result(self, r: JournalEvent) -> list[str]:
        """渲染一条工具结果的正文（大结果只给 artifact 引用）。"""
        out = [f"状态：`{r.execution_status or '-'}`", ""]
        if r.artifact_reference:
            ref = r.artifact_reference
            out += [
                "大型结果已存 artifact（正文不进 Markdown）：",
                "",
                f"- Artifact ID：`{ref.get('id')}`",
                f"- 路径：`{ref.get('path')}`",
                f"- SHA256：`{ref.get('sha256')}`",
                f"- 大小：{ref.get('size')} 字节",
                f"- 产生时间：{_fmt_time(float(ref.get('at') or r.ts))}",
                "",
                "内容摘要：",
                "",
                "```text",
                _clip(str(ref.get("preview") or ""), 600),
                "```",
                "",
            ]
        else:
            out += ["结果：", "", "```text", _clip(r.tool_result, 1500), "```", ""]
        return out

    def _render_policy(self, events: list[JournalEvent]) -> list[str]:
        out = ["# 四、Policy 判定与拦截记录", ""]
        pol = [e for e in events if e.event_type == "POLICY_DECISION"]
        if not pol:
            out += ["（没有策略判定记录）", ""]
            return out
        out += [
            "| 时间 | 判定 | 等级 | 命令 | 目标 | 理由 |",
            "|------|------|------|------|------|------|",
        ]
        for e in pol:
            x = e.extra
            out.append(
                f"| {_fmt_short(e.ts)} | {e.policy_decision or '-'} | "
                f"{x.get('level', '-')} | {x.get('command', '-')} | "
                f"`{_one_line(x.get('url', ''), 60)}` | {_one_line(e.content, 120)} |"
            )
        out.append("")
        denied = [e for e in pol
                   if (e.policy_decision or "").upper() in ("DENY", "UNKNOWN", "REVIEW")]
        if denied:
            out += ["## 被拦截明细", ""]
            for e in denied:
                out += [
                    f"### [{_fmt_short(e.ts)}] {e.policy_decision} · "
                    f"{e.extra.get('command', '') or '未知操作'}",
                    "",
                    f"- 目标：`{e.extra.get('url', '')}`",
                    f"- 等级：{e.extra.get('level') or '-'}",
                ]
                if e.extra.get("signals"):
                    out.append(f"- 信号：{'；'.join(str(s) for s in e.extra['signals'][:5])}")
                out += ["", "```text", _clip(e.content, 800), "```", ""]
        return out

    def _render_findings(self, events: list[JournalEvent]) -> list[str]:
        out = ["# 五、发现与证据", ""]
        fs = [e for e in events if e.event_type == "FINDING_CREATED"]
        if not fs:
            out += ["（没有登记发现）", ""]
            return out
        for e in fs:
            x = e.extra
            out += [
                f"## [{x.get('severity', '-')}] {x.get('name', '') or '（未命名）'}",
                "",
                f"- 位置：`{x.get('matched_at', '')}`",
                f"- PoC ID：`{x.get('poc_id', '')}`",
                f"- 时间：{_fmt_time(e.ts)}",
            ]
            if x.get("status"):
                out.append(f"- 状态：{x['status']}")
            out.append("")
            if e.content:
                out += ["说明：", "", _clip(e.content, 1000), ""]
            if e.artifact_reference:
                ref = e.artifact_reference
                out += [
                    f"- 证据 artifact：`{ref.get('path')}`"
                    f"（sha256 `{str(ref.get('sha256'))[:16]}…`，{ref.get('size')} 字节）",
                    "",
                ]
        return out

    def _render_failures(self, events: list[JournalEvent]) -> list[str]:
        out = ["# 六、失败路径和排除项", ""]
        items: list[str] = []
        for e in events:
            if (
                e.event_type == "TOOL_RESULT"
                and e.execution_status in _FAIL_STATUS
                # 策略拒绝已经在第四章逐条列出，这里再抄一遍只会让读者
                # 以为"失败了两次"。非策略类阻断（只读模式、反死循环）仍保留。
                and not e.tool_result.startswith("【已拦截】（策略）")
            ):
                items.append(
                    f"- [{_fmt_short(e.ts)}] `{e.tool_name}` → `{e.execution_status}`："
                    f"{_one_line(e.tool_result, 160)}"
                )
            elif e.event_type == "TASK_FAILED":
                items.append(
                    f"- [{_fmt_short(e.ts)}] 后台任务 {e.extra.get('task_id', '')} 失败："
                    f"{_one_line(e.content, 160)}"
                )
            elif e.event_type == "POLICY_DECISION" and (
                e.policy_decision or ""
            ).upper() in ("DENY", "UNKNOWN", "REVIEW"):
                items.append(
                    f"- [{_fmt_short(e.ts)}] 策略拦截 `{e.extra.get('command') or '未知操作'}`"
                    f"（{e.policy_decision}）：{_one_line(e.content, 160)}"
                )
            elif e.event_type == "FINDING_CREATED" and e.extra.get("status") == "线索":
                items.append(
                    f"- [{_fmt_short(e.ts)}] 未通过质量闸门（转为待验证线索）："
                    f"{e.extra.get('name', '')}"
                )
        if items:
            out += items + [""]
        else:
            out += ["（没有失败或被排除的路径）", ""]
        return out

    def _render_conclusion(self, meta: dict[str, Any]) -> list[str]:
        out = ["# 七、最终结论", ""]
        body = meta.get("conclusion")
        out.append("> 以下为复盘摘要（Agent 生成或按事件统计得出），**不是原始记录**。")
        out.append("")
        if isinstance(body, str) and body.strip():
            out += [body.strip(), ""]
        else:
            out += [
                "（尚未生成复盘摘要。运行 `/history summary <id>` 生成。）",
                "",
            ]
        return out

    def _render_next(self, meta: dict[str, Any]) -> list[str]:
        out = ["# 八、后续工作", ""]
        steps = meta.get("next_steps") or []
        if isinstance(steps, str):
            steps = [steps]
        if steps:
            out += [f"{i}. {s}" for i, s in enumerate(steps, 1)] + [""]
        else:
            out += ["（没有记录后续工作项）", ""]
        return out

    # ── 导出 ──────────────────────────────────────────────────────
    def export_markdown(self, dest: str | Path | None = None) -> Path:
        """渲染并原子写 ``conversation.md``（或指定路径）。"""
        return self.write_all(dest=dest, summary=False)

    def write_summary(self, dest: str | Path | None = None) -> Path:
        return self.write_all(dest=dest, markdown=False)

    def write_all(
        self,
        *,
        dest: str | Path | None = None,
        markdown: bool = True,
        summary: bool = True,
    ) -> Path:
        """写出 Markdown / 摘要（两个都写时返回 conversation.md 路径）。"""
        self.dir.mkdir(parents=True, exist_ok=True)
        md_path = Path(dest) if dest else self.conversation_path
        out = md_path
        if markdown:
            _atomic_write(md_path, self.render_markdown())
        if summary:
            sp = self.summary_path
            if dest and markdown:
                sp = Path(dest).with_name(SUMMARY_FILE)
            _atomic_write(sp, self.render_summary())
            if not markdown:
                out = sp
        return out

    def render_summary(self) -> str:
        """复盘摘要：只做**统计与归类**，不臆造结论。"""
        events = self.events()
        meta = self.meta()
        users = [e for e in events if e.event_type == "USER_MESSAGE"]
        assists = [e for e in events if e.event_type == "ASSISTANT_MESSAGE"]
        calls = [e for e in events if e.event_type == "TOOL_CALL"]
        results = [e for e in events if e.event_type == "TOOL_RESULT"]
        denied = [
            e for e in events
            if e.event_type == "POLICY_DECISION"
            and (e.policy_decision or "").upper() in ("DENY", "UNKNOWN", "REVIEW")
        ]
        findings = [e for e in events if e.event_type == "FINDING_CREATED"]
        tasks = [e for e in events if e.event_type in ("TASK_STARTED", "TASK_COMPLETED", "TASK_FAILED")]
        failures = [
            e for e in results
            if e.execution_status in _FAIL_STATUS
            # 策略拒绝已经在"拦截"一节逐条列出，别在"失败"里再抄一遍
            and not e.tool_result.startswith("【已拦截】（策略）")
        ]
        tool_count: dict[str, int] = {}
        for c in calls:
            tool_count[c.tool_name] = tool_count.get(c.tool_name, 0) + 1

        first = meta.get("created_at") or self.created_at
        last = meta.get("updated_at") or (events[-1].ts if events else first)
        lines = [
            f"# 复盘摘要 · {self.session_id}",
            "",
            "> 本摘要由事件流统计得出（`/history summary` 可重新生成），"
            "与 `conversation.md` 的原始记录分开存放。",
            "",
            "## 概览",
            "",
            f"- 目标：{meta.get('target') or self._target or '（未设定）'}",
            f"- 环境：{meta.get('environment') or self._environment or '（未知）'}",
            f"- 时间：{_fmt_time(float(first))} → {_fmt_time(float(last))}",
            f"- 对话：用户 {len(users)} 条 / Agent {len(assists)} 条",
            f"- 工具调用：{len(calls)} 次（结果 {len(results)} 条，失败 {len(failures)} 条）",
            f"- 策略拦截：{len(denied)} 次",
            f"- 登记发现：{len(findings)} 条",
            f"- 后台任务事件：{len(tasks)} 条",
            "",
            "## 用到的工具",
            "",
        ]
        if tool_count:
            for name, n in sorted(tool_count.items(), key=lambda kv: -kv[1]):
                lines.append(f"- `{name}` × {n}")
        else:
            lines.append("- （没有工具调用）")
        lines += ["", "## 已确认发现", ""]
        if findings:
            for e in findings:
                x = e.extra
                lines.append(
                    f"- [{x.get('severity', '-')}] {x.get('name', '')}"
                    f" @ `{x.get('matched_at', '')}`"
                )
        else:
            lines.append("- （无）")
        lines += ["", "## 被拦截 / 失败", ""]
        if denied or failures:
            for e in denied:
                lines.append(
                    f"- 拦截：`{e.extra.get('command') or '未知操作'}`"
                    f"（{e.policy_decision}）— {_one_line(e.content, 120)}"
                )
            for e in failures:
                lines.append(
                    f"- 失败：`{e.tool_name}`（{e.execution_status}）— "
                    f"{_one_line(e.tool_result, 120)}"
                )
        else:
            lines.append("- （无）")
        lines += ["", "## 结论", ""]
        body = meta.get("conclusion")
        lines.append(str(body).strip() if body else "（尚未生成）")
        lines += ["", "## 后续工作", ""]
        steps = meta.get("next_steps") or []
        if isinstance(steps, str):
            steps = [steps]
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)] or ["（无）"]
        return "\n".join(lines).rstrip() + "\n"

    # ── 恢复上下文（只给知识，不给权限）──────────────────────────
    def resume_context(self, *, max_chars: int = 8000) -> str:
        """构造可注入模型的"历史知识"文本。

        **只允许**：可见对话、已确认事实、目标资产描述、完成的任务摘要、
        已确认/排除的发现、失败路径、artifact 引用。

        **禁止**：审批票据、GUARD 授权状态、Token、Cookie、密码、
        旧会话的可执行权限。历史记录只作为知识与证据来源，不成为新的执行授权。
        """
        events = self.events()
        meta = self.meta()
        parts: list[str] = [
            "【历史会话记录（只读知识）】",
            f"会话：{self.session_id}",
            f"当时目标：{meta.get('target') or self._target or '（未记录）'}",
            f"当时环境：{meta.get('environment') or self._environment or '（未记录）'}",
            "",
            "注意：以下内容仅作知识与证据参考，**不构成任何执行授权**。",
            "目标、环境、身份与授权条件必须在当前会话重新确认后才能发请求；",
            "历史里的审批、票据、Token、Cookie 一概不予恢复。",
            "",
        ]
        dialog = [e for e in events if e.event_type in ("USER_MESSAGE", "ASSISTANT_MESSAGE")]
        if dialog:
            parts += ["## 对话要点", ""]
            for e in dialog[-12:]:
                who = "用户" if e.event_type == "USER_MESSAGE" else "Agent"
                parts.append(f"- {who}（{_fmt_short(e.ts)}）：{_one_line(e.content, 300)}")
            parts.append("")
        findings = [e for e in events if e.event_type == "FINDING_CREATED"]
        if findings:
            parts += ["## 已登记发现（当时结论，需重新验证）", ""]
            for e in findings:
                x = e.extra
                parts.append(
                    f"- [{x.get('severity', '-')}] {x.get('name', '')} @ "
                    f"`{x.get('matched_at', '')}`（{x.get('status') or '已确认'}）"
                )
            parts.append("")
        blocked = [
            e for e in events
            if e.event_type == "POLICY_DECISION"
            and (e.policy_decision or "").upper() in ("DENY", "UNKNOWN", "REVIEW")
        ]
        if blocked:
            parts += ["## 当时被拦截的操作（不代表现在也被授权）", ""]
            for e in blocked[-6:]:
                parts.append(
                    f"- `{e.extra.get('command', '') or '未知'}`：{_one_line(e.content, 160)}"
                )
            parts.append("")
        arts = [e for e in events if e.artifact_reference]
        if arts:
            parts += ["## 可回查的 artifact（会话内相对路径）", ""]
            for e in arts[-8:]:
                ref = e.artifact_reference or {}
                parts.append(
                    f"- `{ref.get('path')}`（{ref.get('size')} 字节，"
                    f"sha256 `{str(ref.get('sha256'))[:12]}…`）"
                )
            parts.append("")
        tasks = [e for e in events if e.event_type in ("TASK_COMPLETED", "TASK_FAILED")]
        if tasks:
            parts += ["## 已完成/失败的后台任务", ""]
            for e in tasks[-8:]:
                parts.append(
                    f"- {e.extra.get('task_id', '')}：{e.event_type} — "
                    f"{_one_line(e.content, 120)}"
                )
            parts.append("")

        text = "\n".join(parts).rstrip()
        if len(text) > max_chars:
            text = text[:max_chars] + "\n…（历史上下文已截断）"
        # 双保险：即使某条事件在写入时没被规则命中，这里再脱敏一次
        return redact(text)


# ── 工具函数 ──────────────────────────────────────────────────────
def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _one_line(text: Any, limit: int = 160) -> str:
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    return s if len(s) <= limit else s[:limit] + "…"


def _snippet(text: str, keyword: str, width: int = 60) -> str:
    low = text.lower()
    i = low.find(keyword)
    if i < 0:
        return _one_line(text, width * 2)
    lo = max(0, i - width)
    hi = min(len(text), i + len(keyword) + width)
    return ("…" if lo else "") + text[lo:hi].replace("\n", " ") + ("…" if hi < len(text) else "")


def _seq_from_id(event_id: str) -> int:
    m = re.search(r"#(\d+)$", event_id or "")
    return int(m.group(1)) if m else 0


def _sanitize_extra(extra: dict[str, Any] | None) -> dict[str, Any]:
    """extra 只放可序列化的浅层数据，并统一脱敏字符串值。"""
    if not extra:
        return {}
    out: dict[str, Any] = {}
    for k, v in extra.items():
        key = str(k)
        if _is_sensitive_key(key):
            # 敏感字段连"有没有"都不记：归档是长期留存物，键名也是线索
            continue
        if isinstance(v, str):
            out[key] = redact(v)
        elif isinstance(v, (int, float, bool)) or v is None:
            out[key] = v
        elif isinstance(v, (list, tuple)):
            out[key] = [redact(str(x)) if isinstance(x, str) else x for x in list(v)[:20]]
        elif isinstance(v, dict):
            out[key] = {
                str(kk): redact(str(vv)) if isinstance(vv, str) else vv
                for kk, vv in list(v.items())[:20]
                if not _is_sensitive_key(str(kk))
            }
        else:
            out[key] = redact(str(v))
    return out


def _atomic_write(path: Path, text: str) -> Path:
    """先写临时文件再 ``os.replace``：中途崩溃不会留下半份 Markdown。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


# ── 目录级操作（列表 / 打开 / 检索 / 清理）──────────────────────────
def journal_root(data_dir: str | Path) -> Path:
    """``data/conversations`` —— 归档根目录（单点定义）。"""
    return Path(data_dir) / "conversations"


def _iter_dirs(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return []
    out: list[Path] = []
    for y in sorted(root.iterdir()):
        if not y.is_dir() or not y.name.isdigit():
            continue
        for m in sorted(y.iterdir()):
            if not m.is_dir() or not m.name.isdigit():
                continue
            for s in sorted(m.iterdir()):
                if s.is_dir() and s.name.startswith(SESSION_PREFIX):
                    out.append(s)
    return out


def list_journals(root: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    """列出全部归档会话（按事件文件 mtime 倒序）。

    读不出来（目录里没有 events.jsonl）的跳过——归档目录可能被手删过。
    """
    root = Path(root)
    items: list[dict[str, Any]] = []
    for d in _iter_dirs(root):
        f = d / EVENTS_FILE
        if not f.is_file():
            continue
        meta: dict[str, Any] = {}
        mp = d / META_FILE
        if mp.is_file():
            try:
                raw = json.loads(mp.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    meta = raw
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                meta = {}
        try:
            mt = f.stat().st_mtime
            size = f.stat().st_size
        except OSError:
            continue
        items.append(
            {
                "id": d.name[len(SESSION_PREFIX):],
                "dir": str(d),
                "name": d.name,
                "mtime": mt,
                "size": size,
                "meta": meta,
            }
        )
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items if limit is None else items[: max(0, int(limit))]


def open_journal(root: str | Path, ref: str) -> "EventJournal | None":
    """按 ``目录名 / 会话 id / 唯一子串`` 打开一个归档会话。"""
    ref = (ref or "").strip()
    items = list_journals(root)
    if not items or not ref:
        return None
    if ref.isdigit():
        n = int(ref)
        if 1 <= n <= len(items):
            items = [items[n - 1]]
    hits = [
        it for it in items
        if ref in (it["name"], it["id"], it["dir"]) or ref.lower() in it["name"].lower()
    ]
    if not hits:
        return None
    it = hits[0]
    meta = it["meta"]
    j = EventJournal(
        root,
        it["id"],
        created_at=float(meta.get("created_at") or it["mtime"]),
        target=str(meta.get("target") or ""),
        environment=str(meta.get("environment") or ""),
        phase=str(meta.get("phase") or ""),
    )
    # 目录名可能与 session_id 的 slug 化结果不同（旧目录/手改过）——直接钉死
    j._dir = Path(it["dir"])
    j._load()
    return j


def search_all(
    root: str | Path, keyword: str, *, limit: int = 30
) -> list[dict[str, Any]]:
    """跨会话检索事件（``/history search``）。

    返回 ``[{session_id, dir, event, snippet}]``，按事件时间倒序。
    """
    kw = (keyword or "").strip()
    if not kw:
        return []
    hits: list[dict[str, Any]] = []
    for it in list_journals(root):
        j = open_journal(root, it["name"])
        if j is None:
            continue
        for ev, snip in j.search(kw, limit=limit):
            hits.append(
                {
                    "session_id": it["id"],
                    "dir": it["dir"],
                    "event": ev,
                    "snippet": snip,
                    "mtime": it["mtime"],
                }
            )
    hits.sort(key=lambda h: h["event"].ts, reverse=True)
    return hits[: max(0, int(limit))]


def prune(
    root: str | Path, *, keep_days: float = 0.0, keep_sessions: int = 0
) -> list[str]:
    """按保留策略清理归档目录，返回被删的目录名。

    两条规则**任一命中即删**（都是显式调用才生效，列表不会自动删）：

    * ``keep_days > 0`` 且最后写入早于该天数；
    * ``keep_sessions > 0`` 且按时间排序后落在保留名额之外。

    只删含 ``events.jsonl`` 的归档目录——别的目录不归这里管。
    """
    import shutil

    root = Path(root)
    items = list_journals(root)
    removed: list[str] = []
    keep: set[str] = set()
    if keep_sessions > 0:
        keep = {it["dir"] for it in items[:keep_sessions]}
    now = time.time()
    for it in items:
        d = Path(it["dir"])
        if keep_sessions > 0 and it["dir"] in keep:
            continue
        if keep_days > 0 and (now - it["mtime"]) < keep_days * 86400:
            continue
        if keep_days <= 0 and keep_sessions <= 0:
            break
        try:
            shutil.rmtree(d)
            removed.append(it["name"])
        except OSError:
            continue
    return removed


# ── 集成辅助（会话对象 / 工具执行处调用）──────────────────────────
def record(session: Any, event_type: str, **kw: Any) -> JournalEvent | None:
    """给会话记一条事件；没有绑定归档时静默跳过（不构造、不落盘）。"""
    j = getattr(session, "journal", None)
    if j is None:
        return None
    return j.record(event_type, **kw)


def record_tool_call(
    session: Any, *, call_id: int, tool: str, args: Any
) -> JournalEvent | None:
    return record(
        session,
        "TOOL_CALL",
        tool_name=tool,
        tool_arguments=args,
        extra={"call_id": call_id},
    )


def record_tool_result(
    session: Any,
    *,
    call_id: int,
    tool: str,
    result: str,
    status: str,
    ms: int = 0,
) -> JournalEvent | None:
    return record(
        session,
        "TOOL_RESULT",
        tool_name=tool,
        tool_result=result,
        execution_status=status,
        artifact_reference=None,
        extra={"call_id": call_id, "ms": int(ms)},
    )


def record_policy(
    session: Any,
    *,
    decision: str,
    command: str = "",
    level: str = "",
    category: str = "",
    url: str = "",
    reason: str = "",
    signals: list[str] | None = None,
) -> JournalEvent | None:
    return record(
        session,
        "POLICY_DECISION",
        content=reason,
        policy_decision=str(decision or "").upper(),
        extra={
            "command": command,
            "level": level,
            "category": category,
            "url": url,
            "signals": list(signals or [])[:6],
        },
    )


__all__ = [
    "EVENT_TYPES",
    "EventJournal",
    "JournalEvent",
    "JournalError",
    "MAX_INLINE_RESULT",
    "journal_root",
    "list_journals",
    "open_journal",
    "prune",
    "record",
    "record_policy",
    "record_tool_call",
    "record_tool_result",
    "search_all",
]
