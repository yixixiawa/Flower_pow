"""MCP 服务层：把 flower_pow 的能力翻译成"纯 dict 返回值"。

这一层的存在意义是**让测试不依赖 MCP 协议**。工具函数本身只做三件事：取参数、
调这里、把 dict 原样返回；所有与配置/文件/索引打交道的逻辑都在本模块，可以被
普通 ``scripts/*_test.py`` 直接调用来验。

三个约定
--------
1. **返回值必然是 dict 或 list**，不含 dataclass / Enum / Path——MCP 的
   structured output 只认 JSON 可序列化的东西，这里就地转掉，别把脏数据漏到协议层。
2. **不打印任何东西**。stdout 在 MCP 里是协议通道（虽然 SDK 会把 fd1 拨到 stderr，
   但依赖这个行为会让本地调试时看不到输出）。
3. **失败返回 ``{"error": "..."}`` 而不是抛异常**。工具调用抛异常在客户端只显示
   "tool failed"，而真实原因（POC 目录不存在、索引没建）恰恰是用户要看的。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from core.config_loader import Config, load_config, sessions_dir


# ── 配置 ──────────────────────────────────────────────────────────


def load_cfg(config: str = "") -> Config:
    """加载配置。``config`` 为空时走默认 ``config.yaml`` + 环境变量。"""
    return load_config(config or None)


# ── 序列化 ────────────────────────────────────────────────────────


def _enum_value(obj: Any, attr: str = "value") -> str:
    return str(getattr(obj, attr, "") or "")


def finding_brief(f: Any) -> dict[str, Any]:
    """一条发现压成"够看、够判"的摘要。

    刻意不带完整响应体：报告里已经有全文，工具返回里塞几千字会让模型上下文
    瞬间打满，而且它对"判断这条要不要跟进"没有帮助。
    """
    return {
        "poc_id": getattr(f, "poc_id", ""),
        "name": getattr(f, "name", ""),
        "severity": _enum_value(getattr(f, "severity", None)),
        "category": _enum_value(getattr(f, "category", None)),
        "matched_at": getattr(f, "matched_at", ""),
        "verdict": getattr(f, "verdict", ""),
        "confidence": round(float(getattr(f, "confidence", 0.0) or 0.0), 2),
        "confirmed": bool(getattr(f, "confirmed", True)),
        "dismissed": bool(getattr(f, "dismissed", False)),
        "dismiss_reason": getattr(f, "dismiss_reason", ""),
        "cve": list(getattr(f, "cve", []) or []),
        "rationale": (getattr(f, "rationale", "") or getattr(f, "description", ""))[:400],
    }


def result_summary(result: Any, *, max_findings: int = 40) -> dict[str, Any]:
    """``ScanResult`` → 摘要。字段够复述结论，不够就别塞。"""
    findings = list(getattr(result, "findings", []) or [])
    active = [f for f in findings if not getattr(f, "dismissed", False)]
    active.sort(key=lambda f: getattr(getattr(f, "severity", None), "rank", 0), reverse=True)
    fps = [
        {
            "target": getattr(fp, "target", ""),
            "server": getattr(fp, "server", ""),
            "tech": list(getattr(fp, "tech", []) or [])[:10],
        }
        for fp in (getattr(result, "fingerprints", []) or [])[:5]
    ]
    return {
        "target": getattr(result, "target", ""),
        "session_id": getattr(result, "session_id", ""),
        "duration_s": round(float(getattr(result, "duration", 0.0) or 0.0), 2),
        "counts": getattr(result, "counts", lambda: {})() if callable(
            getattr(result, "counts", None)
        ) else {},
        "findings_total": len(findings),
        "findings_active": len(active),
        "findings_dismissed": len(findings) - len(active),
        "asset_count": len(getattr(result, "assets", []) or []),
        "pocs_loaded": getattr(result, "pocs_loaded", 0),
        "pocs_selected": getattr(result, "pocs_selected", 0),
        "pocs_executed": getattr(result, "pocs_executed", 0),
        "rag_enabled": bool(getattr(result, "rag_enabled", False)),
        "llm_enabled": bool(getattr(result, "llm_enabled", False)),
        "fingerprints": fps,
        "findings": [finding_brief(f) for f in active[:max_findings]],
        "phases": {
            str(k): round(float(v), 2)
            for k, v in (getattr(result, "phases", {}) or {}).items()
        },
        "notes": list(getattr(result, "notes", []) or [])[:10],
        "errors": list(getattr(result, "errors", []) or [])[:10],
    }


# ── POC 库 ────────────────────────────────────────────────────────


def _poc_brief(poc: Any, score: float = 0.0) -> dict[str, Any]:
    return {
        "id": getattr(poc, "id", ""),
        "name": getattr(poc, "name", ""),
        "category": _enum_value(getattr(poc, "category", None)),
        "severity": _enum_value(getattr(poc, "severity", None)),
        "tags": list(getattr(poc, "tags", []) or [])[:8],
        "applies_to": list(getattr(poc, "applies_to", []) or [])[:8],
        "intrusive": bool(getattr(poc, "intrusive", False)),
        "source": Path(getattr(poc, "source", "") or "").name,
        "score": round(float(score), 3) if score else 0.0,
    }


def poc_list(cfg: Config, query: str = "", limit: int = 40) -> dict[str, Any]:
    """POC 清单。给了 ``query`` 就走向量检索（按相关度），否则按危害等级排。"""
    from detectors.poc_loader import load_poc_map

    pocs, errors = load_poc_map(cfg.rag.poc_dir)
    if not pocs:
        return {"count": 0, "items": [], "errors": errors, "hint": f"POC 目录 {cfg.rag.poc_dir} 下没有可用规则"}

    if (query or "").strip():
        hits = _search_pocs(cfg, query.strip(), limit)
        if hits is None:
            return {
                "count": len(pocs),
                "items": [_poc_brief(p) for p in list(pocs.values())[:limit]],
                "errors": errors,
                "hint": "向量索引未就绪，已退化为按目录顺序列出；先跑 `flower_pow kb index` 可获得相关度排序",
            }
        return {"count": len(hits), "total": len(pocs), "query": query, "items": hits, "errors": errors}

    order = sorted(
        pocs.values(),
        key=lambda p: getattr(getattr(p, "severity", None), "rank", 0),
        reverse=True,
    )
    return {
        "count": len(pocs),
        "items": [_poc_brief(p) for p in order[:limit]],
        "errors": errors,
        "hint": "传 query 可按语义检索，例如 query='spring actuator 未授权'",
    }


def _search_pocs(cfg: Config, query: str, limit: int) -> list[dict[str, Any]] | None:
    """向量召回 POC。索引不存在/损坏时返回 None，由调用方降级。"""
    from detectors.poc_loader import load_poc_map
    from kb.indexer import VectorStore

    db = Path(cfg.rag.db_dir) / "poc_index.json"
    store = VectorStore.load(db) if db.is_file() else None
    if store is None:
        return None
    pocs, _ = load_poc_map(cfg.rag.poc_dir)
    out: list[dict[str, Any]] = []
    for poc_id, score in store.search(query, top_k=limit, min_score=0.0):
        poc = pocs.get(poc_id)
        if poc is not None:
            out.append(_poc_brief(poc, score))
    return out


def poc_show(cfg: Config, poc_id: str) -> dict[str, Any]:
    """单条 POC 全文——含原始 YAML，方便排查"为什么它没命中"。"""
    from detectors.poc_loader import load_poc_map

    pocs, _ = load_poc_map(cfg.rag.poc_dir)
    poc = pocs.get((poc_id or "").strip())
    if poc is None:
        near = [k for k in pocs if (poc_id or "").strip().lower() in k.lower()][:8]
        return {"error": f"没有 id 为 {poc_id!r} 的 POC", "similar": near}

    src = Path(getattr(poc, "source", "") or "")
    raw = ""
    if src.is_file():
        try:
            raw = src.read_text(encoding="utf-8")
        except OSError as exc:
            raw = f"（读取失败：{exc}）"
    data = _poc_brief(poc)
    data.update(
        {
            "description": getattr(poc, "description", ""),
            "remediation": getattr(poc, "remediation", ""),
            "cve": list(getattr(poc, "cve", []) or []),
            "references": list(getattr(poc, "references", []) or [])[:10],
            "raw": raw,
        }
    )
    return data


# ── 知识库 ────────────────────────────────────────────────────────


def kb_search(cfg: Config, query: str, k: int = 8) -> dict[str, Any]:
    """同时检索两侧：POC 库（能跑什么）+ 沉淀知识（上次测过什么）。

    为什么要两边一起给：模型问"这个站有什么可测的"，答案既可能是一条现成规则，
    也可能是上次同站留的经验。只给一侧，另一侧就得再问一遍。
    """
    if not (query or "").strip():
        return {"error": "query 不能为空"}

    pocs = _search_pocs(cfg, query.strip(), k) or []
    knowledge: list[dict[str, Any]] = []
    try:
        from kb.knowledge import KnowledgeStore

        db = Path(getattr(cfg.rag, "knowledge_db", "") or "")
        if db.is_file():
            ks = KnowledgeStore.open(db, dim=cfg.rag.dim)
            for rid, score in ks.search(query.strip(), top_k=k):
                rec = ks.records.get(rid, {})
                knowledge.append(
                    {
                        "id": rid,
                        "score": round(float(score), 3),
                        "target": rec.get("meta", {}).get("target", ""),
                        "summary": str(rec.get("text", ""))[:400],
                    }
                )
    except Exception as exc:  # noqa: BLE001 - 知识库坏掉不该让整次检索失败
        knowledge = [{"error": f"{type(exc).__name__}: {exc}"}]

    return {"query": query, "pocs": pocs, "knowledge": knowledge}


# ── 会话与发现 ────────────────────────────────────────────────────


def sessions(cfg: Config, limit: int = 5) -> dict[str, Any]:
    """最近的会话快照（每次扫描/对话结束都会落一份）。

    返回值是给模型/客户端看的清单，所以要**自带可读信息**：标题、阶段、
    更新时间（epoch + 文本）、对话条数。以前只有 ``session_id`` 和
    ``created_at`` 浮点数——调用方看不出"这是哪次测试、什么时候的"，
    也就无从挑选要恢复哪一个。``limit<=0`` 表示全部。
    """
    import time as _t

    from core.session.store import list_sessions

    try:
        items = list_sessions(sessions_dir(cfg), limit=None)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}

    total = len(items)
    shown = items if int(limit) <= 0 else items[: max(1, int(limit))]
    out = []
    for sid, sess in shown:
        result = getattr(sess, "result", None)
        updated = getattr(sess, "updated_at", 0) or getattr(sess, "created_at", 0) or 0
        try:
            text = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(updated))
        except (ValueError, OSError, OverflowError):
            text = ""
        # 有效发现数（已排除误报）与原始条数分开给，避免两个入口数字不一致
        try:
            valid = sum(sess.counts().values())
        except Exception:  # noqa: BLE001
            valid = len(getattr(result, "findings", []) or [])
        out.append(
            {
                "session_id": sid,
                "title": (getattr(sess, "display_title", "") or "").strip(),
                "target": getattr(sess, "target", "") or getattr(result, "target", ""),
                "phase": getattr(getattr(sess, "phase", None), "value", ""),
                "updated_at": updated,
                "updated_at_text": text,
                "history_turns": getattr(sess, "history_turns", 0),
                "findings": valid,
                "findings_raw": len(getattr(result, "findings", []) or []),
                "assets": len(getattr(result, "assets", []) or []),
            }
        )
    return {"count": len(out), "total": total, "items": out}


def session_findings(cfg: Config, session_id: str = "", limit: int = 60) -> dict[str, Any]:
    """取某个会话的发现清单；不传 ``session_id`` 时用最新一份。"""
    from core.session.store import latest_session, list_sessions

    sess = None
    if (session_id or "").strip():
        for sid, item in list_sessions(sessions_dir(cfg), limit=50):
            if sid == session_id.strip():
                sess = item
                break
        if sess is None:
            return {"error": f"没有 session_id 为 {session_id!r} 的会话"}
    else:
        sess = latest_session(sessions_dir(cfg))
        if sess is None:
            return {"error": "还没有任何会话，先跑一次扫描"}

    result = getattr(sess, "result", None)
    if result is None:
        return {"error": "该会话没有扫描结果"}
    data = result_summary(result, max_findings=max(1, int(limit)))
    data["session_id"] = getattr(sess, "session_id", "") or session_id
    return data


# ── 体检 ──────────────────────────────────────────────────────────


def doctor(cfg: Config) -> dict[str, Any]:
    """环境体检：依赖、外部工具、POC 库与索引、代理、只读模式。

    不打 Key 本身，只说"有没有"—工具返回值会被写进对话上下文，凭据不该出现在那里。
    """
    from detectors.poc_loader import load_poc_map
    from kb.indexer import index_is_stale

    pocs, poc_errors = load_poc_map(cfg.rag.poc_dir)
    db = Path(cfg.rag.db_dir) / "poc_index.json"
    stale = True
    try:
        stale = index_is_stale(cfg.rag.poc_dir, db)
    except Exception:  # noqa: BLE001 - 索引判断失败就当过期
        stale = True

    tools: list[dict[str, Any]] = []
    tool_errors: list[str] = []
    try:
        from core.tools.probe import probe_external

        probes, tool_errors = probe_external(versions=False)
        tools = [
            {
                "key": p.spec.key,
                "found": bool(p.found),
                "intrusive": bool(p.spec.intrusive),
                "path": p.path,
            }
            for p in probes
        ]
    except Exception as exc:  # noqa: BLE001
        tool_errors = [f"{type(exc).__name__}: {exc}"]

    return {
        "python": sys.version.split()[0],
        "llm": {
            "enabled": bool(cfg.llm.enabled),
            "api_key_present": bool(cfg.llm.api_key),
            "model": cfg.llm.model,
            "base_url": cfg.llm.base_url,
        },
        "scan": {
            "readonly": bool(cfg.scan.readonly),
            "proxy": cfg.scan.proxy or "",
            "concurrency": cfg.scan.concurrency,
            "timeout": cfg.scan.timeout,
        },
        "poc": {
            "dir": str(cfg.rag.poc_dir),
            "count": len(pocs),
            "errors": poc_errors[:10],
        },
        "index": {
            "path": str(db),
            "exists": db.is_file(),
            "stale": bool(stale),
            "hint": "跑 `flower_pow kb index` 重建" if (stale or not db.is_file()) else "",
        },
        "tools": {"found": [t["key"] for t in tools if t["found"]], "errors": tool_errors[:5]},
        "dirs": {"output": str(cfg.output_dir), "data": str(cfg.data_dir)},
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
