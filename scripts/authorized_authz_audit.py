"""授权渗透测试：三账号只读越权审计（sgxmgl.fjny.edu.cn）。

用途
----
在**已获得书面授权**的目标上，用普通账号 / 管理员账号交叉验证接口的
权限隔离。全程只读：

* 唯一的非 GET 请求是 ``POST /system/auth/login``（认证取 token，非业务增删）；
* 其余全部为 GET；**不实现任何 create/update/delete/upload/export/approve**
  等写操作——这些只在报告里列为"需手工测试"，脚本绝不发起。
* 判定落到业务码 ``code`` + 响应是否真有数据（复用
  :func:`detectors.api_authz.biz_ok`），不只看 HTTP 200。

凭据来源
--------
密码从环境变量 ``FLOWERPW`` 读取（也可 ``--pw-env`` 指定其它变量名），
**不写进源码、不写进报告**。用法::

    FLOWERPW='xxxx' .venv/Scripts/python.exe scripts/authorized_authz_audit.py

输出为 JSON（结构化事实），由调用方整理进 Markdown 文档。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detectors.api_authz import biz_ok  # noqa: E402

BASE_DEFAULT = "https://sgxmgl.fjny.edu.cn"
PREFIX = "/admin-api"
TENANT = "166"  # 实测该站点的有效租户 ID（文档"前置的166"）


def _client() -> httpx.Client:
    return httpx.Client(verify=False, timeout=25, trust_env=False)


def login(base: str, user: str, password: str) -> dict:
    with _client() as c:
        r = c.post(
            base + PREFIX + "/system/auth/login",
            json={"username": user, "password": password},
            headers={"tenant-id": TENANT},
        )
    d = r.json()
    data = d.get("data") or {}
    return {
        "user": user,
        "ok": d.get("code") == 0,
        "token": data.get("accessToken", ""),
        "uid": data.get("userId"),
        "http": r.status_code,
        "msg": d.get("msg", ""),
    }


def perm_info(base: str, token: str) -> dict:
    with _client() as c:
        r = c.get(
            base + PREFIX + "/system/auth/get-permission-info",
            headers={"Authorization": "Bearer " + token, "tenant-id": TENANT},
        )
    d = r.json()
    data = d.get("data") or {}
    u = data.get("user") or {}
    return {
        "code": d.get("code"),
        "uid": u.get("id"),
        "username": u.get("username"),
        "nickname": u.get("nickname"),
        "deptId": u.get("deptId"),
        "roles": data.get("roles") or [],
        "permissions": data.get("permissions") or [],
    }


def get(base: str, path: str, token: str | None, params: dict | None = None,
        tenant: str = TENANT) -> dict:
    """一次只读 GET。返回结构化事实，不抛异常。"""
    headers = {"tenant-id": tenant}
    if token:
        headers["Authorization"] = "Bearer " + token
    url = base + PREFIX + path if path.startswith("/") else base + PREFIX + "/" + path
    try:
        with _client() as c:
            r = c.get(url, headers=headers, params=params or {})
        text = r.text
        try:
            d = r.json()
        except Exception:  # noqa: BLE001
            d = {}
        data = d.get("data") if isinstance(d, dict) else None
        has_data = False
        size = None
        if isinstance(data, dict):
            lst = data.get("list") or data.get("records") or []
            if isinstance(lst, list):
                size = len(lst)
            has_data = biz_ok(text)
        elif isinstance(data, list):
            size = len(data)
            has_data = biz_ok(text)
        return {
            "path": path,
            "params": params or {},
            "http": r.status_code,
            "code": d.get("code") if isinstance(d, dict) else None,
            "msg": (d.get("msg") if isinstance(d, dict) else "") or "",
            "has_data": has_data,
            "size": size,
            "keys": list(data.keys())[:10] if isinstance(data, dict) else None,
            "excerpt": text[:300],
        }
    except Exception as e:  # noqa: BLE001
        return {"path": path, "params": params or {}, "error": f"{type(e).__name__}: {e}"}


# ── 测试用例（全部只读 GET）─────────────────────────────────────
# 每项: (用例名, 接口 path, params, 期望语义)
# "垂直越权"=普通账号访问管理接口，期望被拒(code=403)；
# "未授权"=不带 token 访问，期望被拒(code=401)；
# "数据隔离"=两普通账号对比，观察是否看到相同数据。

ADMIN_ENDPOINTS = [
    ("用户分页", "/system/user/page", {"pageNo": 1, "pageSize": 5}),
    ("用户列表", "/system/user/list", {"ids": "1"}),
    ("角色分页", "/system/role/page", {"pageNo": 1, "pageSize": 5}),
    ("部门列表", "/system/dept/list", {}),
    ("菜单列表", "/system/menu/list", {}),
    ("岗位分页", "/system/post/page", {"pageNo": 1, "pageSize": 5}),
    ("字典类型", "/system/dict-data/simple-list", {}),
]

BUSINESS_ENDPOINTS = [
    ("项目分页", "/xm/project/page", {"pageNo": 1, "pageSize": 20}),
    ("项目类型", "/xm/project-type/page", {"pageNo": 1, "pageSize": 5}),
    ("教师分页", "/xm/teacher/page", {"pageNo": 1, "pageSize": 5}),
    ("个人工作台概览", "/xm/personal-workbench/overview", {}),
    ("个人工作台文件", "/xm/personal-workbench/files", {}),
    ("费用分页", "/xm/project-expense/page", {"pageNo": 1, "pageSize": 5}),
    ("任务待办", "/xm/project-task-todo/page", {"pageNo": 1, "pageSize": 5}),
    ("预警监控概览", "/xm/warning-monitor/overview", {}),
    ("系统参数", "/xm/system-parameter/page", {"pageNo": 1, "pageSize": 5}),
    ("AI 配置", "/xm/ai-config/list", {}),
    ("SSO 统计", "/xm/sso/stats", {}),
]

# 文档标注"疑似未授权"但实测已失效的旧路径（404），一并留证
STALE_ENDPOINTS = [
    "/system/user/query/1551",
    "/project/list",
    "/project/1",
]


def run(base: str, password: str) -> dict:
    out: dict = {"base": base, "tenant": TENANT, "accounts": {}, "tests": {}}

    # 1. 登录 + 身份
    for u in ("cs01", "cs02", "csadmin"):
        lg = login(base, u, password)
        out["accounts"][u] = {"login": {k: v for k, v in lg.items() if k != "token"}}
        if lg["ok"]:
            out["accounts"][u]["token"] = lg["token"]
            out["accounts"][u]["perm"] = perm_info(base, lg["token"])
        else:
            out["accounts"][u]["token"] = ""
    toks = {u: out["accounts"][u]["token"] for u in out["accounts"]}

    # 2. 未授权访问：不带 token 打管理接口
    out["tests"]["unauthenticated"] = [
        get(base, path, None, params) for _, path, params in ADMIN_ENDPOINTS
    ]

    # 3. 垂直越权：普通账号(cs01) 打管理接口
    t = toks.get("cs01", "")
    out["tests"]["vertical_cs01"] = [
        {**get(base, path, t, params), "name": name}
        for name, path, params in ADMIN_ENDPOINTS
    ] if t else []

    # 4. 管理员可见性对照：csadmin 打管理接口
    ta = toks.get("csadmin", "")
    out["tests"]["admin_control"] = [
        {**get(base, path, ta, params), "name": name}
        for name, path, params in ADMIN_ENDPOINTS
    ] if ta else []

    # 5. 业务接口：cs01 / cs02 / csadmin 对照
    for who in ("cs01", "cs02", "csadmin"):
        tk = toks.get(who, "")
        out["tests"][f"biz_{who}"] = [
            {**get(base, path, tk, params), "name": name}
            for name, path, params in BUSINESS_ENDPOINTS
        ] if tk else []

    # 6. 旧路径失效验证
    out["tests"]["stale_paths"] = [
        get(base, p, toks.get("cs01", "")) for p in STALE_ENDPOINTS
    ]

    # 7. 只需手工测试的写操作候选（不执行，仅列清单）
    out["manual_only"] = [
        "system/user/create|update|delete — 用户增删改（越权写入验证）",
        "system/role/* — 角色与数据权限变更",
        "xm/warning-monitor/refresh?projectId=N — 跨项目刷新（文档已观察 projectId=1/2）",
        "xm/project/*/update|delete|submit|approve — 项目与审批流写操作",
        "system/user/export / xm/teacher/export — 批量导出（数据外带）",
        "文件.xz 上传类接口 — 任意文件上传（需 dedicated 环境 + 逐请求审批）",
    ]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE_DEFAULT)
    ap.add_argument("--pw-env", default="FLOWERPW", help="密码所在环境变量名")
    ap.add_argument("--out", default="output/authz_audit.json")
    args = ap.parse_args()
    pw = os.environ.get(args.pw_env, "")
    if not pw:
        print(f"缺少密码：请设置环境变量 {args.pw_env}", file=sys.stderr)
        raise SystemExit(2)

    result = run(args.base.rstrip("/"), pw)
    p = Path(args.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已写入：{p}")

    # 控制台摘要
    for u, info in result["accounts"].items():
        lg = info["login"]
        perm = info.get("perm", {})
        print(f"  {u:9s} login={'OK' if lg['ok'] else 'FAIL'} "
              f"uid={perm.get('uid')} roles={perm.get('roles')}")
    for key in ("unauthenticated", "vertical_cs01", "admin_control"):
        print(f"\n[{key}]")
        for r in result["tests"][key]:
            flag = "DATA" if r.get("has_data") else "----"
            print(f"  {r.get('path','?'):40s} http={r.get('http')} code={r.get('code')} "
                  f"msg={r.get('msg','')[:14]!r} {flag}")


if __name__ == "__main__":
    main()
