"""端点响应信号检测回归测试。

背景（两个真实事故）：
1. 信号最初对**完整返回文本**做 md5——那里面混着 elapsed_ms，每次请求
   耗时都在 200~300ms 抖动，md5 永远不同，"响应完全相同"永远不成立，
   18 连发一次都没触发。现在信号是结构化三元组
   (status_code, body_size, body_hash)，在 _h_http_request 拼装文本前算。
2. 端点按 path 计，模型每 5 次换一个 path 就能清零绕过——加了主机级
   （netloc）兜底，阈值放宽到 15。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.tools.runner.base import (
    ENDPOINT_SIGNAL_LIMIT,
    HOST_SIGNAL_LIMIT,
    _ToolRunnerBase,
    ToolBlocked,
)

PASS = 0


def check(cond: bool, msg: str, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  OK   {msg}")
    else:
        print(f"  FAIL {msg}" + (f"（实={detail}）" if detail else ""))
        raise SystemExit(1)


class FakeCfg:
    class scan:
        readonly = False
        evidence_dir = ""

    class rag:
        poc_dir = ""

    def __init__(self):
        self.output_dir = "."
        self.data_dir = "."


class R(_ToolRunnerBase):
    def __init__(self):
        self.cfg = FakeCfg()
        self.probes = {}
        self.calls = []
        self._det_cache = {}
        self._endpoint_signal = {}
        self._endpoint_streak = {}
        self._host_signal = {}
        self._host_streak = {}


URL = "https://x.com/api/dealer?callback=alert(1)"
SAME = ("200", 2, "{}")     # 状态码 / 正文大小 / 正文 全同


def main() -> int:
    print("场景1 端点级：第 5 次完全相同才拦（前 4 次放行）")
    r = R()
    for i in range(ENDPOINT_SIGNAL_LIMIT - 1):
        r._check_endpoint_signal(URL, *SAME)
    check(r._endpoint_streak.get("/api/dealer") == 4, "前 4 次连击计到 4")
    try:
        r._check_endpoint_signal(URL, *SAME)
        check(False, "第 5 次必须拦")
    except ToolBlocked as exc:
        check(f"连续 {ENDPOINT_SIGNAL_LIMIT} 次响应信号完全相同" in str(exc), "拦截文案含端点名")
    check(r._endpoint_streak == {}, "拦完清零（换手法回来从 1 重计）")

    print("\n场景2 信号不含耗时：仅 elapsed_ms 不同也算'完全相同'")
    r = R()
    for i in range(ENDPOINT_SIGNAL_LIMIT - 1):
        # 模拟真实日志：状态码/大小/正文一致，只是每次耗时不同
        r._check_endpoint_signal(URL, *SAME)
    try:
        r._check_endpoint_signal(URL, *SAME)
        check(False, "仅耗时不同也必须拦（这是修复前的漏拦根因）")
    except ToolBlocked:
        check(True, "仅耗时不同也判定为完全相同")

    print("\n场景3 响应有实质变化 → 连击断，不误伤正常渗透")
    r = R()
    for i in range(6):
        r._check_endpoint_signal(URL, "200", 2 + i, "{}")   # 正文大小每次不同
    check(r._endpoint_streak == {"/api/dealer": 1}, "大小变化连击重置为 1")
    for i in range(6):
        r._check_endpoint_signal(URL, "200", 2, f"body-{i}")  # 正文变化
    check(r._endpoint_streak == {"/api/dealer": 1}, "正文变化连击重置为 1")
    r._check_endpoint_signal(URL, "500", 2, "{}")             # 状态码变化
    check(r._endpoint_streak == {"/api/dealer": 1}, "状态码变化连击重置为 1")

    print("\n场景4 主机级兜底：每 5 次换 path 绕端点检测 → 第 15 次拦")
    r = R()
    for i in range(HOST_SIGNAL_LIMIT - 1):
        r._check_endpoint_signal(f"https://x.com/api/p{i}?a=1", *SAME)
    try:
        r._check_endpoint_signal("https://x.com/api/pzz?b=2", *SAME)
        check(False, "主机级第 15 次必须拦")
    except ToolBlocked as exc:
        check(f"连续 {HOST_SIGNAL_LIMIT} 次" in str(exc) and "x.com" in str(exc),
              "拦截文案点名主机")
    check(r._host_streak == {}, "主机级拦完清零")

    print("\n场景5 不同主机互不传染")
    r = R()
    for i in range(HOST_SIGNAL_LIMIT - 1):
        r._check_endpoint_signal(f"https://a.com/p{i}", *SAME)
    r._check_endpoint_signal("https://b.com/x", *SAME)   # 换主机，不继承连击
    check(r._host_streak.get("b.com") == 1 and r._host_streak.get("a.com") >= 1,
          "换主机从 1 重计", str(r._host_streak))

    print(f"\n结果：{PASS} 项断言全过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
