"""历史对话归档（``core/session/journal.py``）专项测试。

逐条对应 export_session.md §十 的 15 条必测项：

  1. 用户消息正确保存
  2. Agent 消息正确保存
  3. 工具调用与工具结果正确关联
  4. Policy 拦截事件正确保存
  5. 后台任务状态变化正确保存
  6. 同一事件重复写入不会重复记录（幂等）
  7. 异常退出后能够读取已持久化事件（含损坏行检测）
  8. Markdown 导出顺序正确
  9. 大型工具结果使用 Artifact 引用
 10. Artifact 不会跨 Session 引用
 11. 密码和 Token 自动脱敏
 12. 历史搜索正确
 13. 恢复会话不恢复旧审批票据
 14. 恢复会话不恢复旧 Token
 15. 旧 Snapshot 仍然能够兼容读取

附加：保留策略清理、``/history`` 命令各子命令、会话快照不含归档字段。

全部离线：不发任何真实请求（被拦截的请求走策略拒绝，根本不出网）。

运行：``.venv/Scripts/python.exe scripts/journal_test.py``（退出码 0 = 全过）。
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
import tempfile
import contextlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_loader import Config
from core.session import Session
from core.session.journal import (
    MAX_INLINE_RESULT,
    EventJournal,
    JournalError,
    journal_root,
    list_journals,
    open_journal,
    prune,
    search_all,
)
from core.tools.runner import ToolRunner

PASS = 0
FAIL: list[str] = []


def check(cond: bool, name: str) -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  OK   {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}")


def section(title: str) -> None:
    print(f"\n{title}")


def quiet(fn, *a, **kw):
    """跑一个会打印的命令函数，吞掉输出（命令本身的返回值/副作用才断言）。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **kw)
    return r, buf.getvalue()


def cfg_for(tmp: Path, env: str = "isolated_test") -> Config:
    cfg = Config()
    cfg.data_dir = str(tmp / "data")
    cfg.output_dir = str(tmp / "output")
    cfg.llm.enabled = False
    cfg.rag.enabled = False
    cfg.policy.default_environment = env
    cfg.policy.environments = {"127.0.0.1": env}
    return cfg


def new_journal(tmp: Path, sid: str = "s1", **kw) -> EventJournal:
    return EventJournal(journal_root(cfg_for(tmp).data_dir), sid, **kw)


# ── 1 / 2 对话事件 ────────────────────────────────────────────────
def scenario_dialog(tmp: Path) -> None:
    section("1/2 用户消息与 Agent 消息")
    j = new_journal(tmp, "s-dialog", target="http://127.0.0.1:8080")
    j.record("USER_MESSAGE", role="user", content="先收集信息")
    j.record("ASSISTANT_MESSAGE", role="assistant", content="好，我先看首页。")
    ev = j.events()
    check(len(ev) == 2, f"两条事件都落了盘（实 {len(ev)}）")
    check(ev[0].event_type == "USER_MESSAGE" and ev[0].role == "user"
          and ev[0].content == "先收集信息", "用户消息内容/角色正确")
    check(ev[1].event_type == "ASSISTANT_MESSAGE" and ev[1].content.startswith("好，"),
          "Agent 消息内容正确")
    check(ev[0].ts <= ev[1].ts, "事件按发生顺序（时间单调）")
    check(ev[0].event_id != ev[1].event_id, "event_id 唯一")
    raw = j.events_path.read_text(encoding="utf-8")
    check(raw.count("\n") == 2 and raw.endswith("\n"), "JSONL 一行一条、以换行结尾")


# ── 3 工具调用与结果关联 ──────────────────────────────────────────
def scenario_tool_pairing(tmp: Path) -> None:
    section("3 工具调用与工具结果关联")
    cfg = cfg_for(tmp)
    s = Session(target="http://127.0.0.1:8080")
    s.bind_journal(journal_root(cfg.data_dir), environment="isolated_test")
    runner = ToolRunner(cfg, root=tmp)
    out = asyncio.run(runner.execute("set_target", {"url": "http://127.0.0.1:8080"}, s))
    check("目标已设定" in out, f"工具真的执行了：{out[:40]}")
    ev = s.journal.events()
    calls = [e for e in ev if e.event_type == "TOOL_CALL"]
    results = [e for e in ev if e.event_type == "TOOL_RESULT"]
    check(len(calls) == 1 and len(results) == 1, "一次调用产生 CALL + RESULT 两条")
    cid = calls[0].extra.get("call_id")
    check(cid is not None and results[0].extra.get("call_id") == cid,
          f"call_id 配对一致（{cid}）")
    check(calls[0].tool_name == "set_target" and "127.0.0.1" in calls[0].tool_arguments,
          "调用事件带工具名与参数")
    check(results[0].execution_status == "ok" and "目标已设定" in results[0].tool_result,
          "结果事件带状态与返回文本")


# ── 4 Policy 拦截 ─────────────────────────────────────────────────
def scenario_policy(tmp: Path) -> None:
    section("4 Policy 拦截事件")
    cfg = cfg_for(tmp)
    s = Session(target="http://127.0.0.1:8080")
    s.bind_journal(journal_root(cfg.data_dir), environment="isolated_test")
    runner = ToolRunner(cfg, root=tmp)
    # 换主机 → 范围校验直接拒绝，请求根本不会发出（离线可证）
    out = asyncio.run(runner.execute(
        "http_request", {"url": "http://127.0.0.2:9/x", "method": "GET"}, s
    ))
    check("已拦截" in out, f"越界请求被拒：{out.splitlines()[0][:50]}")
    pol = [e for e in s.journal.events() if e.event_type == "POLICY_DECISION"]
    check(len(pol) == 1, f"记了一条策略判定（实 {len(pol)}）")
    check(pol and str(pol[0].policy_decision).upper() in ("DENY", "UNKNOWN"),
          f"判定值合法：{pol[0].policy_decision if pol else '-'}")
    check(pol and "127.0.0.2" in str(pol[0].extra.get("url", "")),
          "判定事件带目标 URL")
    blocked = [e for e in s.journal.events()
               if e.event_type == "TOOL_RESULT" and e.execution_status == "blocked"]
    check(bool(blocked), "工具结果状态记为 blocked（不是 ok）")


# ── 5 后台任务状态变化 ────────────────────────────────────────────
def scenario_tasks(tmp: Path) -> None:
    section("5 后台任务状态变化")

    async def run() -> list:
        cfg = cfg_for(tmp)
        s = Session(target="http://127.0.0.1:8080")
        s.bind_journal(journal_root(cfg.data_dir), environment="isolated_test")
        runner = ToolRunner(cfg, root=tmp)
        await runner._h_background_run(session=s, tool="set_target",
                                       args={"url": "http://127.0.0.1:8080"},
                                       purpose="归档测试")
        for h in list(runner._bg_handles.values()):
            await h

        # 失败路径：起一个立刻抛异常的后台协程
        async def boom():
            raise RuntimeError("模拟失败")

        t = s.tasks.start(tool="boom", label="会失败的任务")
        runner._spawn(s, t, boom())
        for h in list(runner._bg_handles.values()):
            with contextlib.suppress(Exception):
                await h
        return s.journal.events()

    ev = asyncio.run(run())
    started = [e for e in ev if e.event_type == "TASK_STARTED"]
    done = [e for e in ev if e.event_type == "TASK_COMPLETED"]
    failed = [e for e in ev if e.event_type == "TASK_FAILED"]
    check(len(started) >= 2, f"两次启动都记了 TASK_STARTED（实 {len(started)}）")
    check(len(done) == 1, f"成功任务记 TASK_COMPLETED（实 {len(done)}）")
    check(len(failed) == 1 and failed[0].execution_status == "failed",
          "失败任务记 TASK_FAILED 且状态为 failed")
    check(failed and "模拟失败" in failed[0].content, "失败事件带错误原因")
    check(all(e.extra.get("task_id") for e in started + done + failed),
          "任务事件都带 task_id")


# ── 6 幂等 ────────────────────────────────────────────────────────
def scenario_idempotent(tmp: Path) -> None:
    section("6 重复事件不重复记录")
    j = new_journal(tmp, "s-idem")
    a = j.append("TASK_STARTED", content="端口扫描", idem="task:bg-1:started",
                 extra={"task_id": "bg-1"})
    b = j.append("TASK_STARTED", content="端口扫描", idem="task:bg-1:started",
                 extra={"task_id": "bg-1"})
    check(a is not None and b is None, "同一 idem 第二次写入返回 None（未新增）")
    check(len(j.events()) == 1, "磁盘上只有一条")

    # 模拟进程重启：新实例重新载入同一目录
    j2 = EventJournal(journal_root(cfg_for(tmp).data_dir), "s-idem",
                      created_at=None)
    j2._dir = j.dir
    j2.record("TASK_STARTED", content="端口扫描", idem="task:bg-1:started",
              extra={"task_id": "bg-1"})
    check(len(j2.events()) == 1, "重启后同一 idem 仍不重复")
    check(j2.verify()["duplicates"] == [], "没有产生重复 id 行")


# ── 7 异常退出后读取 ──────────────────────────────────────────────
def scenario_crash_recovery(tmp: Path) -> None:
    section("7 异常退出后读取已持久化事件")
    j = new_journal(tmp, "s-crash")
    j.append("USER_MESSAGE", role="user", content="第一句")
    j.append("TOOL_CALL", tool_name="http_request", tool_arguments={"url": "http://a/x"},
             extra={"call_id": 1})
    # 模拟写到一半被杀：文件尾部留下半行 JSON
    with j.events_path.open("a", encoding="utf-8") as f:
        f.write('{"event_id": "s-crash#3", "event_type": "TOOL_RES')
    j2 = EventJournal(journal_root(cfg_for(tmp).data_dir), "s-crash")
    j2._dir = j.dir
    ev = j2.events()
    check(len(ev) == 2, f"已写入的事件全部可读（实 {len(ev)}）")
    info = j2.verify()
    check(len(info["corrupt"]) == 1 and info["corrupt"][0]["line"] == 3,
          f"损坏行被识别并定位（{info['corrupt']}）")
    check(not info["ok"], "verify() 如实报告不完整（不粉饰）")
    # 重启后还能继续追加，且序号不倒退
    j2.append("ASSISTANT_MESSAGE", role="assistant", content="继续")
    ev2 = j2.events()
    check(len(ev2) == 3, f"损坏行不影响后续追加（实 {len(ev2)} 条有效事件）")
    ids = [e.event_id for e in ev2]
    check(len(set(ids)) == len(ids), "追加后 event_id 仍唯一")


# ── 8 Markdown 顺序 ──────────────────────────────────────────────
def scenario_markdown(tmp: Path) -> None:
    section("8 Markdown 导出顺序")
    cfg = cfg_for(tmp)
    s = Session(target="http://127.0.0.1:8080")
    s.bind_journal(journal_root(cfg.data_dir), environment="isolated_test")
    j = s.journal
    j.record("USER_MESSAGE", role="user", content="第一问")
    j.record("TOOL_CALL", tool_name="http_request", tool_arguments={"url": "http://a/1"},
             extra={"call_id": 1})
    j.record("TOOL_RESULT", tool_name="http_request", tool_result="200 OK",
             execution_status="ok", extra={"call_id": 1})
    j.record("POLICY_DECISION", content="拒绝", policy_decision="DENY",
             extra={"command": "删除测试数据", "level": "L2"})
    j.record("ASSISTANT_MESSAGE", role="assistant", content="第一答")
    j.record("USER_MESSAGE", role="user", content="第二问")
    j.record("FINDING_CREATED", content="越权", extra={"name": "IDOR", "severity": "高",
                                                       "matched_at": "http://a/1",
                                                       "poc_id": "manual_1"})
    md = j.render_markdown()
    heads = ["# 会话基本信息", "# 一、测试背景", "# 二、用户与 Agent 对话",
             "# 三、工具调用记录", "# 四、Policy 判定与拦截记录",
             "# 五、发现与证据", "# 六、失败路径和排除项",
             "# 七、最终结论", "# 八、后续工作"]
    idx = [md.find(h) for h in heads]
    check(all(i >= 0 for i in idx), f"八个章节齐全：{[i for i in idx if i < 0]}")
    check(all(idx[i] < idx[i + 1] for i in range(len(idx) - 1)), "章节顺序正确")
    i1 = md.find("第一问")
    i2 = md.find("第一答")
    i3 = md.find("第二问")
    check(-1 < i1 < i2 < i3, "对话按发生顺序（问 → 答 → 下一问）")
    check("摘要不覆盖原始记录" in md or "不是原始记录" in md,
          "Markdown 明确标注摘要与原始记录分开")
    check(md.index("## 调用 1") > md.index("# 三、工具调用记录"),
          "工具明细落在第三章内")


# ── 9 大结果 artifact ────────────────────────────────────────────
def scenario_artifact(tmp: Path) -> None:
    section("9 大型工具结果使用 artifact 引用")
    j = new_journal(tmp, "s-art")
    # 多行文本：Windows 文本模式会把 \n 翻成 \r\n，SHA256/大小就会与文件不符
    big = "\n".join(f'{{"path": "/api/users/{i}", "status": 200}}' for i in range(400))
    check(len(big) > MAX_INLINE_RESULT, "样本确实超过内联上限")
    ev = j.append("TOOL_RESULT", tool_name="http_request", tool_result=big,
                  execution_status="ok", extra={"call_id": 1})
    check(ev is not None and ev.artifact_reference is not None, "超限结果产生了 artifact 引用")
    ref = ev.artifact_reference or {}
    check(ref.get("path", "").startswith("artifacts/"), f"引用路径在 artifacts/ 下：{ref.get('path')}")
    check(len(str(ref.get("sha256"))) == 64, "记录了 SHA256")
    check(int(ref.get("size") or 0) == len(big.encode("utf-8")), "记录了字节大小")
    check(len(ev.tool_result) < MAX_INLINE_RESULT, "事件里只留预览，不塞全文")
    f = j.resolve_artifact(ref["path"])
    import hashlib
    data = f.read_bytes()
    check(data == big.encode("utf-8"), "artifact 内容与原文逐字节一致（含换行）")
    check(hashlib.sha256(data).hexdigest() == ref.get("sha256"),
          "记录的 SHA256 就是文件本身的指纹")
    check(len(data) == int(ref.get("size") or -1), "记录的大小就是文件大小")
    md = j.render_markdown()
    check(ref["path"] in md and "SHA256" in md, "Markdown 里是引用而不是全文")
    check(big not in md, "全文没有进 Markdown")
    # 小结果不落 artifact
    ev2 = j.append("TOOL_RESULT", tool_name="x", tool_result="small", execution_status="ok",
                   extra={"call_id": 2})
    check(ev2 is not None and ev2.artifact_reference is None, "小结果不产生 artifact")


# ── 10 artifact 不跨会话 ─────────────────────────────────────────
def scenario_artifact_scope(tmp: Path) -> None:
    section("10 Artifact 不会跨 Session 引用")
    ja = new_journal(tmp, "s-a")
    jb = new_journal(tmp, "s-b")
    ev = ja.append("TOOL_RESULT", tool_name="http_request",
                   tool_result="B" * (MAX_INLINE_RESULT + 10), execution_status="ok",
                   extra={"call_id": 1})
    ref = (ev.artifact_reference or {})["path"]
    try:
        jb.resolve_artifact(ref)
        ok = False
        why = "没有抛异常"
    except JournalError as exc:
        ok = True
        why = str(exc)
    check(ok, f"别的会话解析同一个相对路径被拒：{why}")
    check(ja.resolve_artifact(ref).is_file(), "本会话内可正常解析")
    for bad in ("../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "artifacts/../events.jsonl"):
        try:
            jb.resolve_artifact(bad)
            rejected = False
        except JournalError:
            rejected = True
        check(rejected, f"越界路径被拒：{bad}")
    check(str(ja.dir) != str(jb.dir), "两个会话目录不同（引用天然隔离）")


# ── 11 脱敏 ──────────────────────────────────────────────────────
def scenario_redaction(tmp: Path) -> None:
    section("11 密码与 Token 自动脱敏")
    j = new_journal(tmp, "s-redact")
    secrets = ["P@ssw0rd!", "hunter2", "AAAABBBBCCCCDDDD", "jsession-xyz"]
    j.append("USER_MESSAGE", role="user", content="账号 admin，密码：P@ssw0rd!")
    j.append(
        "TOOL_CALL", tool_name="http_request",
        tool_arguments={
            "url": "http://a/login",
            "method": "POST",
            "body": '{"username":"admin","password":"hunter2"}',
            "headers": {"Authorization": "Bearer AAAABBBBCCCCDDDD",
                        "Cookie": "JSESSIONID=jsession-xyz"},
        },
        extra={"call_id": 1},
    )
    j.append("TOOL_RESULT", tool_name="http_request",
             tool_result='HTTP/1.1 200 OK\nSet-Cookie: JSESSIONID=jsession-xyz\n'
                         '{"access_token":"AAAABBBBCCCCDDDD"}',
             execution_status="ok", extra={"call_id": 1})
    j.write_all()
    raw = j.events_path.read_text(encoding="utf-8")
    md = j.conversation_path.read_text(encoding="utf-8")
    for sec in secrets:
        check(sec not in raw, f"JSONL 不含明文 {sec!r}")
        check(sec not in md, f"Markdown 不含明文 {sec!r}")
    check("***" in raw, "脱敏标记可见（保留上下文而不是整段删除）")
    check("password" in raw.lower(), "键名保留，便于排查是哪类凭据")


# ── 12 搜索 ──────────────────────────────────────────────────────
def scenario_search(tmp: Path) -> None:
    section("12 历史搜索")
    j1 = new_journal(tmp, "s-search1")
    j1.append("FINDING_CREATED", content="订单越权读取", extra={
        "name": "IDOR 读取订单", "severity": "高", "matched_at": "http://a/orders/1",
        "poc_id": "manual_idor_1",
    })
    j1.append("ASSISTANT_MESSAGE", role="assistant", content="这轮没有别的发现了。")
    j2 = new_journal(tmp, "s-search2")
    j2.append("TOOL_RESULT", tool_name="http_request",
              tool_result="GET /api/orders/2 -> 200", execution_status="ok",
              extra={"call_id": 1})
    root = journal_root(cfg_for(tmp).data_dir)
    hits = search_all(root, "orders")
    check(len(hits) >= 2, f"跨会话命中（实 {len(hits)}）")
    check({h["session_id"] for h in hits} == {"s-search1", "s-search2"},
          "两个会话都被搜到")
    check(any("IDOR" in h["snippet"] or "越权" in h["snippet"] for h in hits),
          "命中片段带上下文")
    check(search_all(root, "不存在的关键词xyz") == [], "无命中返回空")
    check(len(j1.search("越权")) == 1, "单会话搜索也对")


# ── 13 / 14 恢复上下文 ───────────────────────────────────────────
def scenario_resume_context(tmp: Path) -> None:
    section("13/14 恢复不还原审批票据与凭据")
    j = new_journal(tmp, "s-resume", target="http://127.0.0.1:8080")
    j.append("USER_MESSAGE", role="user", content="先测登录")
    j.append("POLICY_DECISION", content="审批通过：上传测试文件",
             policy_decision="APPROVAL",
             extra={
                 "command": "上传测试文件", "level": "L2",
                 "approval_token": "TICKET-9f8e7d6c",
                 "approver": "interactive:yixix",
                 "url": "http://127.0.0.1:8080/upload",
             })
    j.append("TOOL_RESULT", tool_name="http_request",
             tool_result="Authorization: Bearer LEAKED-TOKEN-123456\nCookie: sid=COOKIE-9",
             execution_status="ok", extra={"call_id": 1})
    j.append("FINDING_CREATED", content="越权", extra={
        "name": "IDOR", "severity": "高", "matched_at": "http://a/1",
        "poc_id": "manual_1", "status": "已登记",
    })
    # 一条大结果 → artifact 引用（恢复时应当能把"哪里有证据"带回来）
    j.append("TOOL_RESULT", tool_name="http_request",
             tool_result="C" * (MAX_INLINE_RESULT + 100),
             execution_status="ok", extra={"call_id": 2})
    j.write_all()
    ctx = j.resume_context()
    for bad in ("TICKET-9f8e7d6c", "LEAKED-TOKEN-123456", "COOKIE-9", "approval_token"):
        check(bad not in ctx, f"恢复上下文不含 {bad!r}")
    check("不构成任何执行授权" in ctx, "恢复上下文明确声明不是授权")
    check("需要重新确认" in ctx or "重新确认" in ctx, "要求重新确认目标与授权")
    check("IDOR" in ctx, "已确认发现作为知识保留")
    check("artifact" in ctx.lower() or "可回查" in ctx, "artifact 引用可带回")
    # 归档本身也不存票据：extra 里的 approval_token 被丢弃
    raw = j.events_path.read_text(encoding="utf-8")
    check("TICKET-9f8e7d6c" not in raw, "审批票据根本没有落进 JSONL")


# ── 15 旧快照兼容 ────────────────────────────────────────────────
def scenario_legacy_snapshot(tmp: Path) -> None:
    section("15 旧 Snapshot 仍然兼容读取")
    cfg = cfg_for(tmp)
    sessions = Path(cfg.data_dir) / "sessions"
    d = sessions / "1791789725"
    d.mkdir(parents=True, exist_ok=True)
    legacy = {
        "version": 1,
        "target": "http://127.0.0.1:8080",
        "session_id": "1791789725",
        "phase": "recon",
        "created_at": 1791789725.0,
        "result": {"target": "http://127.0.0.1:8080", "assets": [], "findings": []},
        "model": {},
        "turns": [],
    }
    (d / "session.json").write_text(json.dumps(legacy), encoding="utf-8")
    s = Session.load(d / "session.json")
    check(s is not None, "v1 快照能载入（返回 Session）")
    check(s is not None and s.target == "http://127.0.0.1:8080", "字段读回正确")
    check(s is not None and s.journal is None, "载入后归档默认为空（不会自动造目录）")
    # 绑定归档后照常工作，且快照本身不含归档字段
    s.bind_journal(journal_root(cfg.data_dir), environment="isolated_test")
    s.journal.record("SESSION_RESUMED", content="从旧快照恢复")
    check(len(s.journal.events()) == 1, "旧快照恢复后可以写归档")
    snap = s.to_dict()
    check("journal" not in snap and "events" not in snap,
          "session.json 不含归档字段（两套数据互不污染）")
    # 版本号不认识仍然拒绝（不猜）
    bad = dict(legacy, version=99)
    (d / "session.json").write_text(json.dumps(bad), encoding="utf-8")
    check(Session.load(d / "session.json") is None, "未知版本仍按不可读处理")


# ── 附加：保留策略 ───────────────────────────────────────────────
def scenario_prune(tmp: Path) -> None:
    section("附加 保留策略清理")
    # 独立的 data 目录：清理会删目录，不能拿别的场景的归档当试验品
    root = journal_root(tmp / "prune-data")
    for i in range(3):
        j = EventJournal(root, f"s-prune{i}")
        j.append("USER_MESSAGE", role="user", content=f"第{i}个")
    check(len(list_journals(root)) == 3, f"三个归档目录（实 {len(list_journals(root))}）")
    removed = prune(root, keep_sessions=1)
    check(len(removed) == 2, f"只保留 1 个，删了 {len(removed)} 个")
    check(len(list_journals(root)) == 1, "剩余 1 个")
    check(prune(root, keep_days=0, keep_sessions=0) == [], "没有策略就不删（不明确不动手）")


# ── 附加：/history 命令 ──────────────────────────────────────────
def scenario_history_commands(tmp: Path) -> None:
    section("附加 /history 各子命令")
    from core.repl import Repl

    cfg = cfg_for(tmp)
    s = Session(target="http://127.0.0.1:8080")
    repl = Repl(cfg, s, agent=False, probes=[])
    j = s.journal
    check(j is not None, "REPL 构造时自动绑定归档")
    j.record("USER_MESSAGE", role="user", content="帮我测 8080")
    j.record("ASSISTANT_MESSAGE", role="assistant", content="好的，先看首页。")

    _, out = quiet(repl._history, "")
    check("事件数" in out, f"/history 显示状态：{out.strip().splitlines()[0] if out.strip() else ''}")

    _, out = quiet(repl._history, "save")
    check("对话稿" in out and j.conversation_path.is_file(), "/history save 渲染 Markdown")

    _, out = quiet(repl._history, "list")
    check("历史会话归档" in out, "/history list 列出归档")

    _, out = quiet(repl._history, "show 1")
    check("会话" in out and "帮我测 8080" in out, "/history show 显示摘要")

    _, out = quiet(repl._history, "search 8080")
    check("匹配" in out, "/history search 命中")

    _, out = quiet(repl._history, "summary 1")
    check(j.summary_path.is_file(), "/history summary 写出 summary.md")
    summary = j.summary_path.read_text(encoding="utf-8")
    check("结论" in summary and "后续工作" in summary, "摘要含结论与后续工作")
    check("IDOR" in summary or "发现" in summary, "摘要含发现统计")

    _, out = quiet(repl._history, "export 1")
    check(j.conversation_path.is_file() and "已导出" in out, "/history export 导出全文")

    # resume：注入的是**只读知识**，不改目标、不还原授权
    class _FakeAgent:
        def __init__(self) -> None:
            self.history: list[dict] = []
            self.session = s

    repl.agent = _FakeAgent()          # type: ignore[assignment]
    _, out = quiet(repl._history, "resume 1")
    check(bool(repl.agent.history), f"/history resume 注入了历史（{len(repl.agent.history)} 条）")
    injected = repl.agent.history[-1]["content"]
    check("不构成任何执行授权" in injected, "注入内容声明不是授权")
    check(repl.agent.history[-1]["role"] == "system", "注入为 system 记录（不是用户指令）")
    check(s.target == "http://127.0.0.1:8080", "目标未被历史改写（仍需重新确认）")
    check("未恢复目标" in out, "提示里说明未恢复目标/审批")

    _, out = quiet(repl._history, "prune")
    check("必须给出保留策略" in out, "/history prune 没有参数时拒绝删除")


# ── main ─────────────────────────────────────────────────────────
def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "data").mkdir(parents=True, exist_ok=True)
        scenario_dialog(tmp)
        scenario_tool_pairing(tmp)
        scenario_policy(tmp)
        scenario_tasks(tmp)
        scenario_idempotent(tmp)
        scenario_crash_recovery(tmp)
        scenario_markdown(tmp)
        scenario_artifact(tmp)
        scenario_artifact_scope(tmp)
        scenario_redaction(tmp)
        scenario_search(tmp)
        scenario_resume_context(tmp)
        scenario_legacy_snapshot(tmp)
        scenario_prune(tmp)
        scenario_history_commands(tmp)

    print()
    if FAIL:
        print(f"失败 {len(FAIL)} 项：")
        for f in FAIL:
            print(f"  - {f}")
    print(f"结果：{PASS}/{PASS + len(FAIL)} 通过")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
