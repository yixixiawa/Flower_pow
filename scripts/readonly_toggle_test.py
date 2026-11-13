"""``/readonly`` 运行期切换只读模式的回归测试。

守住的语义：

1. ``/readonly`` 在命令表与帮助里，补全带 on/off 候选；
2. **off 即时生效**：external_tool 的攻击性拦截、``_blocked`` 文案、
   Agent 系统提示的模式行全部现读 ``cfg.scan.readonly``；
3. **on 收回**：恢复拦截；
4. 不带参数只看状态，不动配置；
5. 文案明确"只影响本次运行，不写回 config.yaml"——会话内的临时放开
   不能泄漏成下次启动的默认值。

运行：.venv/Scripts/python.exe scripts/readonly_toggle_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.repl import COMMANDS, HELP, Repl  # noqa: E402


class FakeScan:
    readonly = True


class FakeCfg:
    scan = FakeScan()
    data_dir = "."


class FakeReader:
    completer = None


def make_repl() -> Repl:
    repl = Repl.__new__(Repl)
    repl.cfg = FakeCfg()
    repl.session = None
    repl.reader = FakeReader()
    return repl


def main() -> int:
    ok = total = 0

    def check(cond, label, extra=""):
        nonlocal ok, total
        total += 1
        ok += bool(cond)
        print(f"  {'OK  ' if cond else 'FAIL'} {label}")
        if not cond and extra:
            print(f"        {extra}")

    # _blocked 只看 spec 本体（key/intrusive/note），最小替身即可
    class FakeSpec:
        key = "sqlmap"
        intrusive = True
        note = "会向目标发送攻击性 payload"

    from core.tools.runner import ToolRunner

    print("场景1 命令注册与帮助")
    check("/readonly" in COMMANDS, "/readonly 在命令表里")
    check("/readonly" in HELP, "HELP 说明了 /readonly 用法")
    check("不写回 config.yaml" in HELP, "HELP 明确不持久化")
    from core.repl.context import _ContextMixin
    import inspect

    csrc = inspect.getsource(_ContextMixin._completer)
    check('"readonly": ["on", "off"]' in csrc, "补全器带 on/off 参数候选")

    print("\n场景2 off 放行 → on 收回（闸门现读 cfg）")
    runner = ToolRunner.__new__(ToolRunner)
    repl = make_repl()
    runner.cfg = repl.cfg
    check(runner._blocked(FakeSpec()) is not None, "默认只读：攻击性工具被拦")
    blocked_text = runner._blocked(FakeSpec()) or ""
    check("/readonly off" in blocked_text, f"拦截文案引导 /readonly off：{blocked_text[-40:]!r}")

    repl._set_readonly("/readonly off")
    check(repl.cfg.scan.readonly is False, "/readonly off 后 cfg.scan.readonly=False")
    check(runner._blocked(FakeSpec()) is None, "拦截即时解除（无需重建 runner）")

    repl._set_readonly("/readonly on")
    check(repl.cfg.scan.readonly is True, "/readonly on 恢复只读")
    check(runner._blocked(FakeSpec()) is not None, "拦截重新生效")

    print("\n场景3 幂等与状态查看")
    repl._set_readonly("/readonly on")
    check(repl.cfg.scan.readonly is True, "重复 on 幂等（已是只读，无变化）")
    repl._set_readonly("/readonly off")
    repl._set_readonly("")          # 不带参数=只看状态
    repl._set_readonly("/readonly") # 裸命令=只看状态
    check(repl.cfg.scan.readonly is False, "查看状态不动配置")
    repl._set_readonly("/readonly nonsense")
    check(repl.cfg.scan.readonly is False, "无法识别的参数也只看状态")

    print("\n场景4 别名解析")
    repl._set_readonly("/readonly 1")
    check(repl.cfg.scan.readonly is True, "1 = on")
    repl._set_readonly("/readonly false")
    check(repl.cfg.scan.readonly is False, "false = off")

    print(f"\n{ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
