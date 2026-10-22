"""一次交互式测试的完整状态。

持有轮次推进、发现台账、资产合并与快照读写；**``load`` 是类方法**，
``data/sessions/<id>/session.json`` 就是它的 ``to_dict``。"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any
from core.state import Finding
from core.state import ScanResult
from core.state import Severity
from core.state import safe_name
from core.session.redact import redact_messages
from core.session.models import Phase
from core.session.models import Turn
from core.session.models import ConversationTurn
from core.session.models import BusinessModel


class Session:
    """一次交互式测试的完整状态。"""

    VERSION = 2

    def __init__(
        self,
        target: str,
        session_id: str | None = None,
        phase: Phase = Phase.RECON,
        result: ScanResult | None = None,
        model: BusinessModel | None = None,
        turns: list[Turn] | None = None,
        credentials: dict[str, str] | None = None,
        created_at: float | None = None,
        history: list[dict[str, Any]] | None = None,
        conversations: list[ConversationTurn] | None = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.session_id = session_id or f"{int(time.time())}"
        # 磁盘上的目录名。多数时候与 session_id 相同；从旧快照载入时可能
        # 不同（旧版目录名是纯数字，而 id 字段是另一串），所以单独记一份。
        self._dir_name = ""
        self.phase = phase
        self.result = result or ScanResult(target=self.target, session_id=self.session_id)
        # 从旧快照载入时 ``result.target`` 常是空串（那次会话是在聊天里用
        # set_target 设的目标，SyncResult 没跟上）。报告命名与正文都读
        # ``result.target``，不补上的话文件名会退化成 report_<日期>_target。
        if self.target and not self.result.target:
            self.result.target = self.target
        self.model = model or BusinessModel()
        self.turns: list[Turn] = turns or []
        self.credentials = credentials or {}   # 测试用凭证，仅内存 + 快照，不进报告
        self.created_at = created_at or time.time()
        # Agent 对话历史：恢复会话时喂回模型，否则它完全不记得上次聊过什么。
        # 落盘前统一脱敏（见 redact_messages）。
        self.history: list[dict[str, Any]] = history or []
        # 每轮对话的标题索引（见 ConversationTurn）
        self.conversations: list[ConversationTurn] = conversations or []
        self.updated_at = self.created_at

    # ── 轮次 ──────────────────────────────────────────────────────
    @property
    def turn_no(self) -> int:
        return len(self.turns) + 1

    def begin_turn(self, intent: str = "") -> Turn:
        return Turn(no=self.turn_no, phase=self.phase, intent=intent)

    def end_turn(
        self,
        turn: Turn,
        *,
        assets_before: int,
        findings_before: int,
        suggestions: list[str] | None = None,
    ) -> Turn:
        turn.new_assets = len(self.result.assets) - assets_before
        turn.new_findings = len(self.result.findings) - findings_before
        turn.suggestions = suggestions or []
        turn.elapsed = time.time() - turn.at
        self.turns.append(turn)
        return turn

    def advance(self) -> Phase:
        """推进到下一阶段。EXPLOIT 之后始终留在 ITERATE。"""
        self.phase = self.phase.next
        return self.phase

    def set_phase(self, phase: Phase) -> Phase:
        self.phase = phase
        return self.phase

    # ── 视图 ──────────────────────────────────────────────────────
    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        return self.result.by_severity()

    def counts(self) -> dict[str, int]:
        return self.result.counts()

    def new_findings_since(self, n: int) -> list[Finding]:
        """最近 n 轮的发现——迭代阶段用来决定"接着挖什么"。"""
        if not self.turns:
            return list(self.result.findings)
        turn = self.turns[-1]
        return self.result.findings[: max(0, len(self.result.findings) - turn.new_findings)]

    def status_line(self) -> str:
        c = self.counts()
        top = [f"{Severity(k).label} {v}" for k, v in c.items() if v]
        return (
            f"目标 {self.target} | 第 {self.turn_no} 轮 | 阶段 {self.phase.label} | "
            f"资产 {len(self.result.assets)} | 发现 {sum(c.values())}"
            + (f"（{' '.join(top)}）" if top else "")
        )

    # ── 持久化 ────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "target": self.target,
            "session_id": self.session_id,
            "phase": self.phase.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": self.result.to_dict(),
            "model": self.model.to_dict(),
            "turns": [t.to_dict() for t in self.turns],
            # 凭证只记"有没有"，不记内容——快照可能被分享出去
            "credentials": {k: "***set***" for k in self.credentials},
            # 对话历史落盘前脱敏：里面有工具返回的原始响应
            "history": redact_messages(self.history),
            "conversations": [c.to_dict() for c in self.conversations],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        return cls(
            target=str(d.get("target") or ""),
            session_id=str(d.get("session_id") or ""),
            phase=Phase(d.get("phase") or Phase.RECON.value),
            result=ScanResult.from_dict(d.get("result") or {}),
            model=BusinessModel.from_dict(d.get("model") or {}),
            turns=[Turn.from_dict(t) for t in (d.get("turns") or [])],
            created_at=float(d.get("created_at") or time.time()),
            history=list(d.get("history") or []),
            conversations=[
                ConversationTurn.from_dict(c) for c in (d.get("conversations") or [])
            ],
        )

    @property
    def display_title(self) -> str:
        """给人看的会话标题 = **第一轮对话的标题**。

        为什么取第一轮而不是最后一轮：第一句通常就是"这次要测什么"
        （"帮我测一下 aigc-api"），最后一轮往往是收尾的"出报告"。
        按第一句命名，恢复列表才像一份任务清单而不是一串操作记录。

        早期版本的 ``session_id`` 是纯 ``int(time.time())``，于是
        ``/sessions`` 和 ``/resume <Tab>`` 列出来全是 ``1789...``——
        用户抱怨"以数字作为留存，看不出是哪次对话"就是这个。
        """
        for c in self.conversations:
            t = (c.title or "").strip()
            if t:
                return t
        if self.target:
            return self.target
        return self.session_id

    @property
    def slug(self) -> str:
        """会话目录名：``日期_标题``，可读且稳定。

        日期在前是为了**字典序 == 时间序**，`ls` 出来天然有序；
        标题在后是为了人一眼能认出是哪次。同一会话的 slug 一经确定
        就不再变（见 :meth:`save`），否则每追加一轮对话目录都会改名，
        老快照就找不回来了。
        """
        stamp = time.strftime("%Y%m%d", time.localtime(self.created_at))
        t = safe_name(self.display_title, limit=40)
        return f"{stamp}_{t}" if t else f"{stamp}_{self.session_id}"

    def _target_dir(self, root: Path) -> Path:
        """决定这次落盘该用哪个目录。

        规则只有一条：**目录一旦存在就不再改名**。改名会让旧路径失效、
        `/resume` 与 `--resume` 找不到自己刚存的会话。所以只在首次落盘、
        且已经有对话标题时把数字 id 升级成「日期_标题」。
        """
        existing = root / self.dir_path
        if existing.is_dir():
            return existing
        if not self.conversations:
            # 还没有对话可命名（例如刚启动就退出），先按 id 存
            return root / self.session_id
        return root / self.slug

    def save(self, base_dir: str | Path) -> Path:
        self.updated_at = time.time()
        root = Path(base_dir)
        p = self._target_dir(root)
        self.session_id = p.name          # 目录名即权威 id
        self._dir_name = p.name
        p.mkdir(parents=True, exist_ok=True)
        f = p / "session.json"
        f.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
        return f

    @classmethod
    def load(cls, path: str | Path) -> "Session | None":
        p = Path(path)
        if p.is_dir():
            p = p / "session.json"
        if not p.is_file():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        # v1 快照没有对话历史，但其余字段可用——放行而不是整个丢弃
        ver = int(d.get("version") or 0)
        if ver not in (1, cls.VERSION):
            return None
        s = cls.from_dict(d)
        # **目录名才是权威 id**——旧快照的目录名可能是纯数字，而内部 id 字段
        # 是另一串（甚至缺失）。不认目录名的话，删除/续存都会指到不存在的路径。
        s._dir_name = p.parent.name
        s.session_id = p.parent.name
        return s

    # ── 对话历史 ──────────────────────────────────────────────────
    def sync_history(self, history: list[dict[str, Any]]) -> None:
        """从 Agent 侧同步对话历史（每次保存前调用）。"""
        self.history = list(history)

    def add_conversation(
        self,
        title: str,
        tools: list[str] | None = None,
    ) -> "ConversationTurn":
        """追加一轮对话的标题条目（同一 no 会覆盖，便于 /title 修正）。"""
        ct = ConversationTurn(
            no=len(self.conversations) + 1, title=title, tools=list(tools or [])
        )
        self.conversations.append(ct)
        return ct

    @property
    def history_turns(self) -> int:
        """历史里用户与助手各说了多少轮（用于恢复时提示）。"""
        return sum(1 for m in self.history if m.get("role") == "user")

    # ── 空会话判定与清理 ──────────────────────────────────────────
    def is_empty(self) -> bool:
        """这次会话到底有没有产生过内容。

        "空"= 用户进来又原样出去了：没设目标、没说一句话、没有资产/发现/笔记。
        这种快照只有价值为 0 的噪音——它会在 ``/sessions`` 列表里占位、
        在 ``/resume <Tab>`` 里参与补全，还会把有用的那次挤出最近 N 条。

        **判定要严**：任一项非空就保留。因为"误删"是不可逆的，
        而"多留一个空壳"只是难看一点。特别地：
        - ``credentials`` 也算内容（有人取过凭证却没说话，下次还要用）；
        - 非 RECON 阶段算内容（有人 /phase 推了阶段）；
        - ``conversations`` 有标题算内容（会显示成会话名）。

        历史里若只有 ``system`` 消息（开场白）也不算数——那不是用户说的。
        """
        if self.target:
            return False
        if self.phase is not Phase.RECON:
            return False
        if self.credentials:
            return False
        if self.turns or self.conversations:
            return False
        if self.history_turns:
            return False
        r = self.result
        if r.assets or r.findings or r.notes:
            return False
        return True

    def delete(self, base_dir: str | Path, *, name: str | None = None) -> bool:
        """把这次会话的落盘目录整个删掉，返回是否真的删了。

        只删自己那个目录，且**必须**含 ``session.json``（避免误删同名的
        非会话目录）。删不掉就返回 False，让调用方打印提示——
        会话清理是"顺手做的家务"，不该因为一个被占用的文件就中断退出流程。

        :meth:`load` 会把磁盘目录名认作权威 id，所以正常路径下
        ``root / self.session_id`` 就是对的。``name`` 只是给调用方
        （如 :func:`purge_empty_sessions` 已经握着目录名）一个显式入口。
        """
        root = Path(base_dir)
        p = root / (name or self.session_id)
        if not (p / "session.json").is_file():
            return False
        try:
            shutil.rmtree(p)
        except OSError:
            return False
        return True

    @property
    def dir_path(self) -> str:
        """会话在磁盘上的目录名（:meth:`load` 后等于来源目录名）。"""
        return self._dir_name or self.session_id

