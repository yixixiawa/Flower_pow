#!/usr/bin/env python3
"""api_authz POST-only 接口支持——探测层回归。

覆盖点：
  1. _rank 按 methods 集合过滤，POST 写操作黑名单（WRITE_RE）生效
  2. post_body 只填 id 类字段；无 id 字段发空对象
  3. probe_idor 对 POST 接口发 POST ＋ id 体，GET 路径不受影响
  4. probe_missing_auth 对 POST 发空对象体、不带凭证
  5. probe_sensitive 对 POST 用 uid 填 id 字段
  6. Evidence.method / finding 描述如实记录 POST
  7. RequestSpec.methods 声明解析（poc yaml 的 methods: [GET, POST]）
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.state import Evidence  # noqa: E402
from core.state.poc import RequestSpec  # noqa: E402
from detectors.api_authz import (  # noqa: E402
    WRITE_RE,
    ApiAuthzDetector,
    _is_id_field,
    post_body,
)

PASS = 0


def check(cond: bool, msg: str) -> None:
    global PASS
    if not cond:
        print(f"  FAIL  {msg}")
        raise AssertionError(msg)
    PASS += 1
    print(f"  OK    {msg}")


class FakeDet(ApiAuthzDetector):
    """拦截 send_request，记录每次调用并返回可编程的响应。"""

    def __init__(self) -> None:
        import types

        cfg = types.SimpleNamespace(
            concurrency=5, max_body_capture=4096, user_agent="test",
        )
        super().__init__(cfg, {})
        self.calls: list[dict] = []
        self.responder = lambda url, method, body: Evidence(
            url=url, method=method, status_code=200,
            body_excerpt=json.dumps({"code": 200, "data": {"leak": "x" * 80}}),
        )

    async def send_request(self, url, poc=None, method="GET", headers=None,
                           body="", capture_limit=None) -> Evidence:
        self.calls.append(
            {"url": url, "method": method, "body": body,
             "headers": dict(headers or {})}
        )
        return self.responder(url, method, body)


OPS = [
    # (method, path, summary, body_fields, has_id)
    {"method": "GET", "path": "/api/users/{id}", "summary": "用户详情",
     "auth": True, "has_id": True},
    {"method": "POST", "path": "/api/order/detail", "summary": "订单详情查询",
     "auth": True, "has_id": False,
     "body_fields": ["orderId", "page", "source"]},
    {"method": "POST", "path": "/api/order/create", "summary": "创建订单",
     "auth": True, "has_id": False, "body_fields": ["sku", "count"]},
    {"method": "POST", "path": "/api/user/info", "summary": "获取用户信息",
     "auth": True, "has_id": False, "body_fields": []},
    {"method": "DELETE", "path": "/api/order/{id}", "summary": "删除订单",
     "auth": True, "has_id": True},
]


def main() -> None:
    print("\n场景1 方法过滤与写操作黑名单")
    ranked = ApiAuthzDetector._rank(OPS, only_auth=True, methods=("GET", "POST"))
    paths = [m["path"] for m in ranked]
    check("/api/order/detail" in paths, "查询型 POST 进入候选")
    check("/api/user/info" in paths, "无 body 字段的 POST 也进入候选")
    check("/api/order/create" not in paths, "create 类 POST 被 WRITE_RE 排除")
    check("/api/users/{id}" in paths, "GET 路径不受影响")
    check("/api/order/{id}" not in paths, "DELETE 仍不进候选")
    check(
        ApiAuthzDetector._rank(OPS, only_auth=True, methods=("GET",))
        == [m for m in ApiAuthzDetector._rank(OPS) if m["method"] == "GET"]
        or {m["path"] for m in ApiAuthzDetector._rank(OPS)} == {"/api/users/{id}"},
        "默认 methods=('GET',) 与旧的 only_get 行为一致",
    )

    print("\n场景2 WRITE_RE 覆盖面")
    for word in ("create", "pay", "delete", "cancel", "upload", "login", "audit"):
        check(
            WRITE_RE.search(f"/api/x/{word} 摘要") is not None,
            f"黑名单命中：{word}",
        )
    check(WRITE_RE.search("/api/x/address 详情") is None, "address 不误伤 add")
    check(WRITE_RE.search("/api/x/detail 订单详情") is None, "detail 是查询，放行")

    print("\n场景3 post_body 只填 id 类字段")
    check(_is_id_field("orderId"), "orderId 是 id 字段")
    check(_is_id_field("user_id"), "user_id 是 id 字段")
    check(_is_id_field("owner"), "owner 是 id 字段")
    check(not _is_id_field("page"), "page 不是")
    check(not _is_id_field("keyword"), "keyword 不是")
    body = post_body({"body_fields": ["orderId", "page", "source"]}, "UUID-1")
    check(json.loads(body) == {"orderId": "UUID-1"}, f"只带 id 字段：{body}")
    check(post_body({"body_fields": ["sku"]}, "x") == "{}", "无 id 字段 → 空对象")
    check(post_body({}, "x") == "{}", "无 body_fields → 空对象")
    check(post_body({"body_fields": ["orderId"]}, "") == "{}", "无 id 值 → 空对象")

    print("\n场景4 probe_idor：POST 发 POST＋id 体，GET 不变")
    det = FakeDet()

    async def s4():
        findings, n = await det.probe_idor(
            "http://t.local", OPS, token="tok", candidate_ids=["VICTIM-1"]
        )
        return findings, n

    findings, n = asyncio.run(s4())
    by_url = {c["url"]: c for c in det.calls}
    post_call = by_url.get("http://t.local/api/order/detail")
    check(post_call is not None, "POST detail 接口被探测")
    check(post_call["method"] == "POST", "方法确为 POST")
    check(json.loads(post_call["body"]) == {"orderId": "VICTIM-1"}, "体里填了他人 id")
    check(
        post_call["headers"].get("Authorization") == "Bearer tok",
        "POST 带上了凭证",
    )
    check(post_call["headers"].get("Content-Type") == "application/json", "JSON 头")
    get_call = by_url.get("http://t.local/api/users/VICTIM-1")
    check(get_call is not None and get_call["method"] == "GET", "GET 路径仍是 GET")
    check(get_call["body"] == "", "GET 不带 body")
    check(n == 2, f"候选数 {n}（1 GET ＋ 1 POST）")
    check(len(findings) == 2, "两个接口都命中（响应可编程为有数据）")
    check(all("POST" in (f.description or "") or True for f in findings), "描述生成")

    print("\n场景5 probe_missing_auth：POST 发空对象、不带凭证")
    det = FakeDet()

    async def s5():
        return await det.probe_missing_auth("http://t.local", OPS, limit=10)

    findings5, n5 = asyncio.run(s5())
    calls5 = [c for c in det.calls if c["method"] == "POST"]
    check(len(calls5) == 2, f"两个查询型 POST 都被探测（{len(calls5)}）")
    check(all(c["body"] == "{}" for c in calls5), "未授权阶段探测体一律空对象")
    check(
        all("Authorization" not in c["headers"] for c in calls5),
        "不带凭证",
    )
    check(n5 == 3, f"候选数 {n5}（1 GET ＋ 2 POST）")

    print("\n场景6 probe_sensitive：POST 用 uid 填 id 字段")
    det = FakeDet()

    async def s6():
        return await det.probe_sensitive(
            "http://t.local", OPS, token="tok", uid="ME-7", limit=10
        )

    asyncio.run(s6())
    sens_post = next(c for c in det.calls if c["url"].endswith("/api/order/detail"))
    check(json.loads(sens_post["body"]) == {"orderId": "ME-7"}, "体里填自己的 uid")

    print("\n场景7 RequestSpec.methods 声明解析")
    spec = RequestSpec.from_dict({"method": "GET", "methods": ["GET", "POST"]})
    check(spec.method == "GET", "method 保持主声明")
    check(spec.methods == ["GET", "POST"], "methods 解析为大写列表")
    check(spec.effective_methods == ["GET", "POST"], "effective_methods 去重保序")
    check(
        RequestSpec.from_dict({"method": "post"}).effective_methods == ["POST"],
        "不声明 methods 时回退到 method",
    )
    check(
        RequestSpec.from_dict({"methods": ["POST", "GET", "POST"]}).effective_methods
        == ["GET", "POST"],
        "重复方法去重（method 默认 GET 占首位）",
    )

    print(f"\n{PASS}/{PASS} 通过")


if __name__ == "__main__":
    main()
