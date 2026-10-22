"""证据留存——把原始请求/响应落盘，供复现与审计。

为什么单独一个模块
------------------
报告里的「响应片段」只截前几百字节，够人看、够模型研判，但**不够复现**。
本模块把每条发现的完整请求行、请求头、响应头、响应体存成独立文件，
文件名带 ``fingerprint`` 短哈希去重（同一个软 404 页面不会被存 50 份）。

目录结构::

    output/
    ├── evidence/
    │   ├── index.json                  # 指纹 → 文件名 的映射
    │   ├── <fp>.http#                 # 可直接 curl / Burp 复现的原始报文
    │   └── <fp>.body#                 # 完整响应体
    └── scan_<target>_<ts>.json         # 结构化结果
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.state import Evidence, Finding, ScanResult


class EvidenceStore:
    """证据落盘管理器。"""

    def __init__(self, root: str | Path = "./output/evidence", enabled: bool = True) -> None:
        self.root = Path(root)
        self.enabled = enabled
        self._index: dict[str, str] = {}
        self._saved = 0
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)
            self._load_index()

    def _load_index(self) -> None:
        p = self.root / "index.json"
        if p.is_file():
            try:
                self._index = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._index = {}

    def save_index(self) -> Path | None:
        if not self.enabled:
            return None
        p = self.root / "index.json"
        try:
            p.write_text(
                json.dumps(self._index, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return p
        except OSError:
            return None

    # ── 单条证据 ──────────────────────────────────────────────────
    def save(self, ev: Evidence) -> str:
        """保存一条证据，返回相对路径（未启用或失败时返回空串）。"""
        if not self.enabled or ev is None:
            return ""

        fp = ev.fingerprint()
        # 同指纹复用——软 404 场景能省下大量重复文件
        if fp in self._index and (self.root / self._index[fp]).exists():
            ev.artifact = self._index[fp]
            return ev.artifact

        name = f"{ev.status_code or 0}_{fp}"
        http_path = self.root / f"{name}.http"
        body_path = self.root / f"{name}.body"

        try:
            # ① 可直接复现的原始报文
            lines = [ev.request_line or f"{ev.method} {ev.url} HTTP/1.1"]
            lines.append("")
            lines.append("[RESPONSE]")
            lines.append(f"HTTP/1.1 {ev.status_code or 0}")
            for k, v in ev.response_headers.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(ev.body_excerpt)
            http_path.write_text("\n".join(lines), encoding="utf-8")

            # ② 完整响应体（如果有超出截断部分的内容）
            body_path.write_text(ev.body_excerpt, encoding="utf-8")
        except OSError:
            return ""

        rel = http_path.name
        self._index[fp] = rel
        ev.artifact = rel
        self._saved += 1
        return rel

    # ── 批量 ──────────────────────────────────────────────────────
    def save_result(self, result: ScanResult) -> dict[str, int]:
        """保存一次扫描的全部证据。返回统计。"""
        if not self.enabled:
            return {"saved": 0, "reused": 0, "total": 0}

        before = self._saved
        for f in result.findings:
            if f.evidence:
                self.save(f.evidence)
        for a in result.assets:
            if a.kind == "secret":
                self._write_secret(a.value)

        self.save_index()
        reused = len([1 for f in result.findings if f.evidence]) - (self._saved - before)
        return {
            "saved": self._saved - before,
            "reused": max(0, reused),
            "total": len(result.findings),
        }

    def _write_secret(self, value: str) -> None:
        """疑似硬编码凭据单独存档（权限收紧，因为这是最敏感的一类证据）。"""
        try:
            p = self.root / "secrets.txt"
            with p.open("a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {value[:200]}\n")
            try:  # Windows 下尽量只让当前用户读
                p.chmod(0o600)
            except OSError:
                pass
        except OSError:
            pass

    def stats(self) -> dict[str, int]:
        return {
            "files": len(list(self.root.glob("*.http"))) if self.enabled else 0,
            "indexed": len(self._index),
        }