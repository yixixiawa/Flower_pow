"""命令表、帮助文本与阶段别名——**补全与 ``/help`` 共用这一份**，避免两处不同步。

任何模块都从这里取，所以它排在依赖链最底。"""

from __future__ import annotations

from core.session import (
    Phase,
    Session,
    latest_session,
    list_sessions,
    purge_empty_sessions,
)


COMMANDS = [
    "/help", "/status", "/assets", "/findings", "/model",
    "/title", "/chats", "/reset", "/report", "/sessions", "/resume",
    "/backfill", "/clean", "/agent", "/target", "/tools", "/key", "/turns",
    "/next", "/run", "/poll", "/phase", "/kickoff", "/auto", "/quit",
]

BANNER = """
╭─────────────────────────────────────────────────────────╮
│  flower_pow · 交互式测试会话                            │
│  一轮对话 = 一轮测试，状态全程保留                      │
│  输入 /help 看命令，直接回车 = 跑下一轮                 │
╰─────────────────────────────────────────────────────────╯"""

BANNER_AGENT = """
╭─────────────────────────────────────────────────────────╮
│  flower_pow · AI Agent 会话                             │
│  说人话即可——模型会调用本机工具去拿事实，再给判断       │
│  /help 看命令 · 回车让模型继续 · /quit 退出             │
╰─────────────────────────────────────────────────────────╯"""

HELP = """
Tab 补全：命令名与参数都能补全。补命令连按两次 Tab 看候选，↑↓ 翻历史。

通用命令：
  /help         显示本帮助
  /status       当前状态概览
  /assets [类型] 资产清单（port|path|api|endpoint|secret|internal|js）
  /findings     发现列表（按严重度，带编号）
  /model        查看当前业务模型
  /chats        对话索引：每轮对话的标题与用到的工具
  /title <编号> <标题>    手工改某轮对话的标题
  /reset        **彻底重置**：销毁当前所有数据（目标/资产/发现/凭证/对话
                历史/盘上快照），换一把全新的椅子
  /report [格式] 导出报告（md/html/json/all）
  /sessions     列出可恢复的会话
  /resume [id]  载入会话（不给 id 则取最近一次），连对话历史一起恢复
  /clean        删除所有空会话（没目标、没对话、没结果）。恢复时也会自动清
  /quit         退出（自动保存；空会话不保存）

模式与配置：
  /agent [on|off]   切换 AI Agent / 剧本模式
  /target [URL]     设定或查看目标（**换成别的目标会自动清空上一目标的
                    全部资产与发现**，防报告串线）
  /tools            列出本机可调用工具与版本
  /key              重新设置 API Key（写入 .env）
  /turns            历史轮次
  /kickoff          让模型自我介绍一轮（启动时默认不说，省一轮 token）
  /auto             一键全自动：给警告 → 确认 → 跑完整条流水线（等价 Alt+Shift）

剧本模式专用：
  <回车>        跑下一轮（自动推进阶段）
  /next         推进到下一阶段并跑一轮
  /run          在当前阶段再跑一轮
  /poll [轮数]  **自动连续跑轮，穷尽了才停**——不用一直敲回车
                停止条件：连续 2 轮没有新增资产/发现/建模项
                （只看硬状态——"建议"是阶段驱动的旁白，每轮都有，不能当停止依据）
                不给轮数就用配置上限（scan.auto_max_rounds，默认 12；0=不限）
                Ctrl-C 随时中断，会话照常保存
  /phase 名称   切换阶段（recon|model|exploit|iterate）

Agent 模式下也可以直接说：
  先收集信息 / 重点测越权 / 这个接口有风险吗 / 出报告
"""

# 全自动执行前的警告。**内容必须是真的会发生的事**，不能写成免责声明——
# 用户要的是"知道接下来会挨什么"，不是"出了问题概不负责"。
AUTO_WARN = """
╭─────────────────────────────────────────────────────────╮
│  ⚠ 全自动模式（Alt+Shift / /auto）                       │
╰─────────────────────────────────────────────────────────╯
  目标：{target}

  确认后将对上述目标完整跑一遍，中途**不再向你确认任何事情**：

  1. 信息收集：端口、目录、接口、JS 里的密钥（含外部工具全量调用）
  2. POC 匹配与验证：命中规则的漏洞直接发验证请求
  3. SQL 注入：**放行全部规则**，目标是拿到数据库版本号；
     拿不到则退一步取数据库名；任一项拿到就停止后续注入
  4. 任意文件上传：**本次不再逐条询问**，会真实向目标写入文件
     （文件名形如 fp_<随机>.php，内容仅含随机标记）
  5. 结果研判与报告导出

  需要你知道的后果：
  · 请求量不做节流，取决于站点规模
  · 上传动作会在目标上**留下文件，需要你事后手工清理**
  · 期间只能靠 Ctrl+C 中断，已发出的请求无法撤回

  只在你有明确授权的目标上执行。"""

# /report 每次调用都会重写这些执行说明。用一个**不可能出现在自然语言里**的
# 前缀标记，下次调用时按前缀清掉旧的再重写，避免重复累积
# （曾实测一份报告里出现 10 遍相同的会话头）。
_REPORT_NOTE_PREFIX = "\x00report:"


def _report_note(text: str) -> str:
    """给 /report 生成的执行说明加哨兵前缀，便于下次调用时先清掉旧的。"""
    return _REPORT_NOTE_PREFIX + text


def _call_name(call: dict) -> str:
    """从一条工具调用记录里取工具名，兼容 ``tool`` / ``name`` 两种键。

    这两个键名在项目里长期并存（ToolRunner 写 ``tool``、repl 读 ``name``），
    已经导致过一次「每轮对话结束就 KeyError: 'name'」。取值集中在这里，
    下次谁再改记录结构也只改一个地方。
    """
    if not isinstance(call, dict):
        return ""
    return str(call.get("name") or call.get("tool") or "")

PHASE_ALIAS = {
    "recon": Phase.RECON, "1": Phase.RECON, "信息收集": Phase.RECON, "收集": Phase.RECON,
    "model": Phase.MODEL, "2": Phase.MODEL, "业务建模": Phase.MODEL, "建模": Phase.MODEL,
    "exploit": Phase.EXPLOIT, "3": Phase.EXPLOIT, "渗透测试": Phase.EXPLOIT, "测试": Phase.EXPLOIT,
    "iterate": Phase.ITERATE, "4": Phase.ITERATE, "迭代": Phase.ITERATE, "深挖": Phase.ITERATE,
}

NATURAL = {
    "recon": ("收集", "信息", "资产", "侦察", "recon", "摸底"),
    "model": ("建模", "业务", "流程", "理解", "model", "走一遍"),
    "exploit": ("测试", "渗透", "攻击", "验证", "exploit", "开打"),
    "iterate": ("继续", "深挖", "迭代", "再测", "扩大", "iterate"),
}



def _console():
    from rich.console import Console

    return Console()
