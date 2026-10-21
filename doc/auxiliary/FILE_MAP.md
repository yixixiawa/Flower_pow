# flower_pow 文件地图（架构 + 引用关系）

> **本文件由 `scripts/gen_file_map.py` 自动生成**，数据来源为 AST 解析的
> 真实 import 语句——`引用` 一节没有手写内容，改完代码重跑一次即可刷新。

共 142 个 Python 文件：源码 113 个 + `scripts/` 测试与工具 29 个。

> 记法：引用表（§2/§3）里的 `core.repl` 这类**包名**指该包的 `__init__.py` 门面；
> §1 表格里显示的是真实相对路径。
## 0. 全局架构：一条扫描请求怎么流过去

```
flower_pow.py            CLI 入口（typer），触发注册 + 调起 Typer
   │
   ├─ cli/*              18 个子命令的实现（scan / chat / kb / probe / ledger …）
   ├─ core/bootstrap.py  环境体检：外部工具、依赖、索引、API Key
   ├─ core/config_loader.py  配置：环境变量 > config.yaml > 默认值
   │
   ▼
core/scheduler/        一次性扫描编排（五阶段 mixin：recon/match/verify/report）
core/planner.py        剧本模式（固定四阶段，可复现不烧 token）
core/agent.py          交互式 Agent（模型决定调什么工具，流式输出）
   │
   ├─ collectors/*       资产采集（端口/路径/OpenAPI/JS/子域/dirsearch）
   ├─ kb/*               向量索引（余弦+BM25）→ 召回 → LLM 重排；CVE 情报；知识沉淀
   ├─ detectors/*        POC 验证（HTTP/鉴权/高危探针/JS 逻辑）+ 公开性核验
   ├─ core/tools/*       工具层：声明(builtins/external) → 探测(probe)
   │                     → 归一(args) → 执行(runner/*，唯一安全边界)
   ├─ llm/*              OpenAI 兼容客户端 + 模型注册表 + 提示词模板
   └─ output/*           证据落盘 + JSON / Markdown / HTML 报告

core/state/*            数据模型事实来源（枚举/POC/ Finding/Evidence/ScanResult）
core/session/*          会话状态（Phase/Turn/ConversationTurn + 落盘/脱敏）
core/repl/*             交互终端（命令分发 mixin）+ core/completer/* 自实现行编辑
```

| 驱动 | 入口 | 特点 |
|---|---|---|
| 一次性扫描 | `core.scheduler.Scheduler.scan()` | 五阶段流水线，跑完出报告 |
| 交互式 Agent | `core.agent.Agent` + `core.tools.runner.ToolRunner` | 模型自由发挥，流式输出 |
| 剧本模式 | `core.planner.Planner` | 固定四阶段，可复现、不烧 token |

## 1. 分包结构与文件职责

### `根目录` —— CLI 入口 + 各顶层包的 __init__ 门面（7 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `cli/__init__.py` | 47 | 1 |
| `collectors/__init__.py` | 1 | 0 |
| `core/__init__.py` | 1 | 6 |
| `detectors/__init__.py` | 1 | 0 |
| `flower_pow.py` | 47 | 0 |
| `kb/__init__.py` | 1 | 0 |
| `llm/__init__.py` | 1 | 4 |

### `cli/` —— CLI 子命令实现（typer）（13 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `cli/app.py` | 31 | 13 |
| `cli/ask.py` | 121 | 0 |
| `cli/boot.py` | 155 | 9 |
| `cli/chat.py` | 242 | 0 |
| `cli/engines.py` | 175 | 1 |
| `cli/initcmd.py` | 206 | 0 |
| `cli/kb.py` | 185 | 0 |
| `cli/ledger.py` | 325 | 0 |
| `cli/models.py` | 82 | 0 |
| `cli/probe.py` | 355 | 0 |
| `cli/scan.py` | 78 | 0 |
| `cli/subs.py` | 346 | 0 |
| `cli/summary.py` | 73 | 1 |

### `core/` —— 编排 / 状态 / 工具 / 会话 / 交互（64 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `core/agent.py` | 552 | 3 |
| `core/auth.py` | 248 | 3 |
| `core/backfill.py` | 213 | 4 |
| `core/bootstrap.py` | 430 | 3 |
| `core/completer/__init__.py` | 44 | 10 |
| `core/completer/candidate.py` | 69 | 2 |
| `core/completer/keys.py` | 110 | 3 |
| `core/completer/layout.py` | 120 | 3 |
| `core/completer/paint.py` | 120 | 2 |
| `core/completer/reader.py` | 413 | 3 |
| `core/completer/width.py` | 67 | 5 |
| `core/config_loader.py` | 493 | 27 |
| `core/envfile.py` | 133 | 3 |
| `core/exclusions.py` | 316 | 2 |
| `core/fsops.py` | 371 | 2 |
| `core/planner.py` | 527 | 3 |
| `core/progress.py` | 191 | 3 |
| `core/proxy.py` | 431 | 8 |
| `core/rawmsg.py` | 289 | 3 |
| `core/repl/__init__.py` | 60 | 7 |
| `core/repl/auto.py` | 134 | 1 |
| `core/repl/base.py` | 51 | 1 |
| `core/repl/commands.py` | 275 | 1 |
| `core/repl/consts.py` | 152 | 7 |
| `core/repl/context.py` | 101 | 1 |
| `core/repl/entry.py` | 30 | 1 |
| `core/repl/history.py` | 119 | 1 |
| `core/repl/loop.py` | 265 | 1 |
| `core/repl/session.py` | 319 | 1 |
| `core/scheduler/__init__.py` | 41 | 8 |
| `core/scheduler/base.py` | 43 | 1 |
| `core/scheduler/helpers.py` | 32 | 2 |
| `core/scheduler/match.py` | 166 | 1 |
| `core/scheduler/recon.py` | 264 | 1 |
| `core/scheduler/report.py` | 96 | 1 |
| `core/scheduler/verify.py` | 214 | 1 |
| `core/session/__init__.py` | 31 | 23 |
| `core/session/models.py` | 184 | 2 |
| `core/session/redact.py` | 66 | 3 |
| `core/session/session.py` | 315 | 2 |
| `core/session/store.py` | 93 | 1 |
| `core/state/__init__.py` | 53 | 61 |
| `core/state/enums.py` | 80 | 3 |
| `core/state/models.py` | 456 | 1 |
| `core/state/poc.py` | 286 | 2 |
| `core/state/util.py` | 54 | 3 |
| `core/subdomain.py` | 538 | 1 |
| `core/tools/__init__.py` | 78 | 17 |
| `core/tools/args.py` | 180 | 2 |
| `core/tools/builtins.py` | 542 | 2 |
| `core/tools/external.py` | 416 | 6 |
| `core/tools/pathscan.py` | 142 | 1 |
| `core/tools/probe.py` | 199 | 4 |
| `core/tools/runner/__init__.py` | 72 | 1 |
| `core/tools/runner/base.py` | 387 | 3 |
| `core/tools/runner/evidence.py` | 350 | 1 |
| `core/tools/runner/export.py` | 92 | 1 |
| `core/tools/runner/external.py` | 197 | 1 |
| `core/tools/runner/files.py` | 134 | 1 |
| `core/tools/runner/intel.py` | 80 | 1 |
| `core/tools/runner/recon.py` | 324 | 1 |
| `core/tools/runner/report.py` | 315 | 1 |
| `core/tools/runner/verify.py` | 97 | 1 |
| `core/tools/wordlist.py` | 36 | 1 |

### `collectors/` —— 资产采集层（6 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `collectors/dirsearch_runner.py` | 356 | 3 |
| `collectors/js_analyze.py` | 509 | 6 |
| `collectors/openapi.py` | 268 | 3 |
| `collectors/path_scan.py` | 208 | 4 |
| `collectors/port_scan.py` | 191 | 3 |
| `collectors/subdomain_extract.py` | 683 | 4 |

### `detectors/` —— 验证层（POC 执行与探针）（16 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `detectors/api_authz.py` | 332 | 3 |
| `detectors/base.py` | 475 | 8 |
| `detectors/exploit/__init__.py` | 54 | 4 |
| `detectors/exploit/attack.py` | 205 | 1 |
| `detectors/exploit/consts.py` | 30 | 4 |
| `detectors/exploit/ops.py` | 90 | 5 |
| `detectors/exploit/payloads.py` | 43 | 2 |
| `detectors/exploit/probe.py` | 133 | 1 |
| `detectors/exploit/run.py` | 72 | 1 |
| `detectors/exploit/sqli_mixin.py` | 324 | 1 |
| `detectors/exploit/sqli_rules.py` | 194 | 2 |
| `detectors/exploit/template.py` | 71 | 2 |
| `detectors/http_detector.py` | 172 | 6 |
| `detectors/js_logic.py` | 525 | 5 |
| `detectors/poc_loader.py` | 141 | 10 |
| `detectors/public_check.py` | 467 | 3 |

### `kb/` —— 检索与知识（向量索引 / 情报 / 沉淀）（4 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `kb/indexer.py` | 478 | 6 |
| `kb/intel.py` | 423 | 3 |
| `kb/knowledge.py` | 391 | 4 |
| `kb/retriever.py` | 361 | 6 |

### `llm/` —— 大模型接入（客户端 / 注册表 / 提示词）（3 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `llm/client.py` | 524 | 5 |
| `llm/models.py` | 233 | 4 |
| `llm/prompt.py` | 497 | 1 |

### `scripts/` —— 测试与工具脚本（无 pytest，直接跑）（29 个文件）

| 文件 | 行数 | 被引用次数 |
|---|---:|---:|
| `scripts/_srcs.py` | 40 | 1 |
| `scripts/_terminal_sim.py` | 316 | 0 |
| `scripts/agent_loop_test.py` | 360 | 0 |
| `scripts/autopilot_test.py` | 369 | 0 |
| `scripts/backfill_test.py` | 358 | 0 |
| `scripts/burp_report_test.py` | 294 | 0 |
| `scripts/completer_candidates_test.py` | 142 | 0 |
| `scripts/completer_editing_test.py` | 167 | 0 |
| `scripts/completer_terminal_test.py` | 454 | 0 |
| `scripts/config_test.py` | 241 | 0 |
| `scripts/dirsearch_throttle_test.py` | 150 | 0 |
| `scripts/dismiss_finding_test.py` | 321 | 0 |
| `scripts/empty_session_test.py` | 221 | 0 |
| `scripts/export_report_test.py` | 263 | 0 |
| `scripts/fsops_test.py` | 331 | 0 |
| `scripts/gen_file_map.py` | 237 | 0 |
| `scripts/js_analyze_test.py` | 282 | 0 |
| `scripts/knowledge_test.py` | 221 | 0 |
| `scripts/naming_test.py` | 204 | 0 |
| `scripts/output_spill_test.py` | 152 | 0 |
| `scripts/progress_test.py` | 314 | 0 |
| `scripts/proxy_test.py` | 239 | 0 |
| `scripts/public_check_test.py` | 390 | 0 |
| `scripts/record_finding_test.py` | 228 | 0 |
| `scripts/report_test.py` | 205 | 0 |
| `scripts/run_tests.py` | 92 | 0 |
| `scripts/secret_scan.py` | 197 | 0 |
| `scripts/session_resume_test.py` | 193 | 0 |
| `scripts/subdomain_extract_test.py` | 513 | 0 |

## 2. 引用关系（正向：每个文件 import 了谁）

- **`cli`** → `cli.app`
- **`cli.app`** → `core.state`
- **`cli.ask`** → `cli.app`、`cli.boot`、`core.scheduler`、`core.state`、`detectors.poc_loader`、`kb.intel`、`kb.retriever`
- **`cli.boot`** → `cli.app`、`core.bootstrap`、`core.config_loader`、`core.repl`、`core.session`、`llm.models`
- **`cli.chat`** → `cli.app`、`cli.boot`、`core.backfill`、`core.bootstrap`、`core.planner`、`core.progress`、`core.repl`、`core.session`、`core.state`
- **`cli.engines`** → `cli.app`、`cli.boot`、`core.scheduler`、`core.state`、`detectors.js_logic`、`detectors.poc_loader`、`kb.indexer`
- **`cli.initcmd`** → `cli.app`
- **`cli.kb`** → `cli.app`、`cli.boot`、`detectors.poc_loader`、`kb.indexer`、`kb.knowledge`
- **`cli.ledger`** → `cli.app`、`cli.boot`、`core`、`core.proxy`、`core.session`、`core.tools`
- **`cli.models`** → `cli.app`、`cli.boot`、`llm.models`
- **`cli.probe`** → `cli.app`、`cli.boot`、`cli.engines`、`collectors.openapi`、`core.state`、`core.tools`、`detectors.exploit`、`detectors.js_logic`、`detectors.poc_loader`
- **`cli.scan`** → `cli.app`、`cli.boot`、`cli.summary`、`core.config_loader`、`core.scheduler`
- **`cli.subs`** → `cli.app`、`cli.boot`、`collectors.dirsearch_runner`、`core.state`、`core.subdomain`、`core.tools`
- **`cli.summary`** → `cli.app`、`core.state`
- **`collectors.dirsearch_runner`** → `core.state`
- **`collectors.js_analyze`** → `core.config_loader`、`core.state`、`detectors.base`
- **`collectors.openapi`** → `core.proxy`、`core.state`
- **`collectors.path_scan`** → `collectors.dirsearch_runner`、`core.config_loader`、`core.state`、`detectors.base`
- **`collectors.port_scan`** → `core.config_loader`、`core.state`
- **`collectors.subdomain_extract`** → `core.proxy`、`core.state`
- **`core.agent`** → `core.tools`、`llm`
- **`core.auth`** → `core.proxy`、`core.state`
- **`core.backfill`** → `core.rawmsg`、`detectors.base`
- **`core.bootstrap`** → `core.config_loader`、`core.envfile`、`core.tools`、`detectors.poc_loader`、`kb.indexer`、`llm.client`
- **`core.completer`** → `core.completer.candidate`、`core.completer.keys`、`core.completer.layout`、`core.completer.paint`、`core.completer.reader`、`core.completer.width`
- **`core.completer.layout`** → `core.completer`、`core.completer.width`
- **`core.completer.paint`** → `core.completer`、`core.completer.layout`、`core.completer.width`
- **`core.completer.reader`** → `core.completer`、`core.completer.candidate`、`core.completer.keys`、`core.completer.layout`、`core.completer.paint`、`core.completer.width`
- **`core.config_loader`** → `core.envfile`、`core.exclusions`、`core.proxy`、`llm.models`
- **`core.planner`** → `collectors.js_analyze`、`collectors.openapi`、`collectors.path_scan`、`collectors.port_scan`、`collectors.subdomain_extract`、`core.auth`、`core.session`、`core.state`、`detectors.api_authz`、`detectors.http_detector`、`detectors.poc_loader`
- **`core.repl`** → `core.repl.auto`、`core.repl.base`、`core.repl.commands`、`core.repl.consts`、`core.repl.context`、`core.repl.entry`、`core.repl.history`、`core.repl.loop`、`core.repl.session`
- **`core.repl.auto`** → `core.repl.consts`、`core.scheduler`
- **`core.repl.base`** → `core.completer`、`core.config_loader`、`core.session`
- **`core.repl.commands`** → `core.auth`、`core.bootstrap`、`core.envfile`、`core.progress`、`core.repl.consts`、`core.state`、`core.tools`
- **`core.repl.consts`** → `core.session`
- **`core.repl.context`** → `core.agent`、`core.completer`、`core.planner`、`core.repl.consts`、`core.session`、`core.tools`、`llm.client`
- **`core.repl.entry`** → `core.config_loader`、`core.repl`、`core.session`
- **`core.repl.history`** → `core.repl.consts`
- **`core.repl.loop`** → `core.completer`、`core.repl.consts`、`core.session`
- **`core.repl.session`** → `core`、`core.backfill`、`core.repl.consts`、`core.session`、`core.tools`
- **`core.scheduler`** → `core.scheduler.base`、`core.scheduler.match`、`core.scheduler.recon`、`core.scheduler.report`、`core.scheduler.verify`
- **`core.scheduler.base`** → `core.config_loader`、`core.state`、`llm.client`
- **`core.scheduler.helpers`** → `core.state`、`llm.prompt`
- **`core.scheduler.match`** → `core.scheduler.helpers`、`core.state`、`detectors.poc_loader`、`kb.intel`、`kb.retriever`
- **`core.scheduler.recon`** → `collectors.js_analyze`、`collectors.path_scan`、`collectors.port_scan`、`collectors.subdomain_extract`、`core.config_loader`、`core.scheduler.helpers`、`core.state`、`detectors.http_detector`、`detectors.js_logic`、`detectors.public_check`
- **`core.scheduler.report`** → `core.state`、`core.tools`
- **`core.scheduler.verify`** → `core.state`、`detectors.exploit`、`detectors.http_detector`、`kb.knowledge`
- **`core.session`** → `core.session.models`、`core.session.redact`、`core.session.session`、`core.session.store`
- **`core.session.models`** → `core.session.redact`
- **`core.session.redact`** → `core.state`
- **`core.session.session`** → `core.session.models`、`core.session.redact`、`core.state`
- **`core.session.store`** → `core.session.session`
- **`core.state`** → `core.state.enums`、`core.state.models`、`core.state.poc`、`core.state.util`
- **`core.state.models`** → `core.exclusions`、`core.state.enums`、`core.state.poc`、`core.state.util`
- **`core.state.poc`** → `core.state.enums`、`core.state.util`
- **`core.subdomain`** → `collectors.js_analyze`、`core.config_loader`、`core.scheduler`、`core.state`、`detectors.http_detector`
- **`core.tools`** → `core.tools.args`、`core.tools.builtins`、`core.tools.external`、`core.tools.pathscan`、`core.tools.probe`、`core.tools.runner`、`core.tools.wordlist`
- **`core.tools.args`** → `core.tools.builtins`、`core.tools.external`、`core.tools.probe`
- **`core.tools.pathscan`** → `core.tools.external`
- **`core.tools.probe`** → `core.tools.external`
- **`core.tools.runner`** → `core.tools.runner.base`、`core.tools.runner.evidence`、`core.tools.runner.export`、`core.tools.runner.external`、`core.tools.runner.files`、`core.tools.runner.intel`、`core.tools.runner.recon`、`core.tools.runner.report`、`core.tools.runner.verify`
- **`core.tools.runner.base`** → `core.state`、`core.tools.args`、`core.tools.external`、`core.tools.probe`、`detectors.poc_loader`
- **`core.tools.runner.evidence`** → `core.backfill`、`core.rawmsg`、`core.state`、`detectors.base`
- **`core.tools.runner.external`** → `core.tools.external`、`core.tools.probe`、`core.tools.runner.base`
- **`core.tools.runner.files`** → `core.fsops`
- **`core.tools.runner.intel`** → `core.state`、`kb.intel`、`kb.retriever`
- **`core.tools.runner.recon`** → `collectors.js_analyze`、`collectors.openapi`、`collectors.path_scan`、`collectors.port_scan`、`collectors.subdomain_extract`、`core.state`、`core.tools.runner.base`、`detectors.exploit`、`detectors.http_detector`、`detectors.js_logic`
- **`core.tools.runner.report`** → `core`、`core.state`、`detectors.public_check`
- **`core.tools.runner.verify`** → `core.auth`、`core.scheduler`、`detectors.api_authz`
- **`core.tools.wordlist`** → `collectors.path_scan`
- **`detectors.api_authz`** → `core.state`、`detectors.base`、`detectors.poc_loader`
- **`detectors.base`** → `core.config_loader`、`core.proxy`、`core.state`
- **`detectors.exploit`** → `detectors.exploit.attack`、`detectors.exploit.ops`、`detectors.exploit.probe`、`detectors.exploit.run`、`detectors.exploit.sqli_mixin`、`detectors.exploit.sqli_rules`
- **`detectors.exploit.attack`** → `core.state`、`detectors.exploit.consts`、`detectors.exploit.ops`、`detectors.exploit.payloads`、`detectors.exploit.template`
- **`detectors.exploit.ops`** → `detectors.exploit.consts`
- **`detectors.exploit.probe`** → `core.state`、`detectors.base`、`detectors.exploit.consts`、`detectors.exploit.ops`、`detectors.exploit.payloads`
- **`detectors.exploit.run`** → `core.state`、`detectors.exploit.ops`
- **`detectors.exploit.sqli_mixin`** → `core.state`、`detectors.exploit.consts`、`detectors.exploit.ops`、`detectors.exploit.sqli_rules`、`detectors.exploit.template`
- **`detectors.exploit.template`** → `core.state`
- **`detectors.http_detector`** → `core.config_loader`、`core.state`、`detectors.base`
- **`detectors.js_logic`** → `collectors.js_analyze`、`core.state`、`detectors.api_authz`、`detectors.base`
- **`detectors.poc_loader`** → `core.state`
- **`detectors.public_check`** → `core.config_loader`、`core.proxy`、`core.state`
- **`flower_pow`** → `cli`
- **`kb.indexer`** → `core.state`、`detectors.poc_loader`
- **`kb.knowledge`** → `core.state`、`kb.indexer`
- **`kb.retriever`** → `core.config_loader`、`core.state`、`kb.indexer`
- **`llm.client`** → `core.config_loader`、`core.state`、`kb.retriever`、`llm`、`llm.models`
- **`llm.prompt`** → `core.state`、`kb.retriever`
- **`scripts.agent_loop_test`** → `core.agent`
- **`scripts.autopilot_test`** → `core.completer`、`core.config_loader`、`core.repl`、`core.session`、`core.state`、`detectors.exploit`
- **`scripts.backfill_test`** → `core.backfill`、`core.config_loader`、`core.rawmsg`、`core.session`、`core.state`、`core.tools`
- **`scripts.burp_report_test`** → `core.config_loader`、`core.state`、`detectors.http_detector`
- **`scripts.completer_candidates_test`** → `core.completer`、`core.session`
- **`scripts.completer_editing_test`** → `core.completer`、`core.completer.reader`
- **`scripts.completer_terminal_test`** → `core.completer`、`core.completer.keys`、`core.completer.reader`、`core.completer.width`
- **`scripts.config_test`** → `core`、`core.config_loader`
- **`scripts.dirsearch_throttle_test`** → `collectors.dirsearch_runner`
- **`scripts.dismiss_finding_test`** → `core`、`core.repl`、`core.session`、`core.state`、`core.tools`、`kb.knowledge`
- **`scripts.empty_session_test`** → `core.repl`、`core.session`、`core.state`
- **`scripts.export_report_test`** → `core.config_loader`、`core.session`、`core.state`、`core.tools`
- **`scripts.fsops_test`** → `core.config_loader`、`core.fsops`、`core.session`、`core.state`、`core.tools`
- **`scripts.js_analyze_test`** → `collectors.js_analyze`、`core.config_loader`、`detectors.js_logic`、`scripts._srcs`
- **`scripts.knowledge_test`** → `core.config_loader`、`core.scheduler`、`core.state`、`kb.indexer`、`kb.knowledge`
- **`scripts.naming_test`** → `core.session`、`core.state`
- **`scripts.output_spill_test`** → `core.config_loader`、`core.session`、`core.tools`
- **`scripts.progress_test`** → `core.config_loader`、`core.progress`、`core.repl`、`core.session`、`core.state`
- **`scripts.proxy_test`** → `core.proxy`
- **`scripts.public_check_test`** → `core`、`core.config_loader`、`core.session`、`core.state`、`core.tools`、`detectors.public_check`
- **`scripts.record_finding_test`** → `core.session`、`core.state`、`core.tools`、`llm`、`llm.client`
- **`scripts.report_test`** → `core.state`、`llm`、`llm.client`
- **`scripts.session_resume_test`** → `core.agent`、`core.session`、`core.state`
- **`scripts.subdomain_extract_test`** → `collectors.subdomain_extract`、`core.planner`、`core.scheduler`、`core.state`、`core.tools`、`kb.retriever`

## 3. 引用关系（反向：每个文件被谁 import）

- **`cli`** ← `flower_pow`
- **`cli.app`** ← `cli`、`cli.ask`、`cli.boot`、`cli.chat`、`cli.engines`、`cli.initcmd`、`cli.kb`、`cli.ledger`、`cli.models`、`cli.probe`、`cli.scan`、`cli.subs`、`cli.summary`
- `cli.ask` —— 无内部调用方（入口 / 叶子 / 测试）
- **`cli.boot`** ← `cli.ask`、`cli.chat`、`cli.engines`、`cli.kb`、`cli.ledger`、`cli.models`、`cli.probe`、`cli.scan`、`cli.subs`
- `cli.chat` —— 无内部调用方（入口 / 叶子 / 测试）
- **`cli.engines`** ← `cli.probe`
- `cli.initcmd` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.kb` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.ledger` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.models` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.probe` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.scan` —— 无内部调用方（入口 / 叶子 / 测试）
- `cli.subs` —— 无内部调用方（入口 / 叶子 / 测试）
- **`cli.summary`** ← `cli.scan`
- `collectors` —— 无内部调用方（入口 / 叶子 / 测试）
- **`collectors.dirsearch_runner`** ← `cli.subs`、`collectors.path_scan`、`scripts.dirsearch_throttle_test`
- **`collectors.js_analyze`** ← `core.planner`、`core.scheduler.recon`、`core.subdomain`、`core.tools.runner.recon`、`detectors.js_logic`、`scripts.js_analyze_test`
- **`collectors.openapi`** ← `cli.probe`、`core.planner`、`core.tools.runner.recon`
- **`collectors.path_scan`** ← `core.planner`、`core.scheduler.recon`、`core.tools.runner.recon`、`core.tools.wordlist`
- **`collectors.port_scan`** ← `core.planner`、`core.scheduler.recon`、`core.tools.runner.recon`
- **`collectors.subdomain_extract`** ← `core.planner`、`core.scheduler.recon`、`core.tools.runner.recon`、`scripts.subdomain_extract_test`
- **`core`** ← `cli.ledger`、`core.repl.session`、`core.tools.runner.report`、`scripts.config_test`、`scripts.dismiss_finding_test`、`scripts.public_check_test`
- **`core.agent`** ← `core.repl.context`、`scripts.agent_loop_test`、`scripts.session_resume_test`
- **`core.auth`** ← `core.planner`、`core.repl.commands`、`core.tools.runner.verify`
- **`core.backfill`** ← `cli.chat`、`core.repl.session`、`core.tools.runner.evidence`、`scripts.backfill_test`
- **`core.bootstrap`** ← `cli.boot`、`cli.chat`、`core.repl.commands`
- **`core.completer`** ← `core.completer.layout`、`core.completer.paint`、`core.completer.reader`、`core.repl.base`、`core.repl.context`、`core.repl.loop`、`scripts.autopilot_test`、`scripts.completer_candidates_test`、`scripts.completer_editing_test`、`scripts.completer_terminal_test`
- **`core.completer.candidate`** ← `core.completer`、`core.completer.reader`
- **`core.completer.keys`** ← `core.completer`、`core.completer.reader`、`scripts.completer_terminal_test`
- **`core.completer.layout`** ← `core.completer`、`core.completer.paint`、`core.completer.reader`
- **`core.completer.paint`** ← `core.completer`、`core.completer.reader`
- **`core.completer.reader`** ← `core.completer`、`scripts.completer_editing_test`、`scripts.completer_terminal_test`
- **`core.completer.width`** ← `core.completer`、`core.completer.layout`、`core.completer.paint`、`core.completer.reader`、`scripts.completer_terminal_test`
- **`core.config_loader`** ← `cli.boot`、`cli.scan`、`collectors.js_analyze`、`collectors.path_scan`、`collectors.port_scan`、`core.bootstrap`、`core.repl.base`、`core.repl.entry`、`core.scheduler.base`、`core.scheduler.recon`、`core.subdomain`、`detectors.base`、`detectors.http_detector`、`detectors.public_check`、`kb.retriever`、`llm.client`、`scripts.autopilot_test`、`scripts.backfill_test`、`scripts.burp_report_test`、`scripts.config_test`、`scripts.export_report_test`、`scripts.fsops_test`、`scripts.js_analyze_test`、`scripts.knowledge_test`、`scripts.output_spill_test`、`scripts.progress_test`、`scripts.public_check_test`
- **`core.envfile`** ← `core.bootstrap`、`core.config_loader`、`core.repl.commands`
- **`core.exclusions`** ← `core.config_loader`、`core.state.models`
- **`core.fsops`** ← `core.tools.runner.files`、`scripts.fsops_test`
- **`core.planner`** ← `cli.chat`、`core.repl.context`、`scripts.subdomain_extract_test`
- **`core.progress`** ← `cli.chat`、`core.repl.commands`、`scripts.progress_test`
- **`core.proxy`** ← `cli.ledger`、`collectors.openapi`、`collectors.subdomain_extract`、`core.auth`、`core.config_loader`、`detectors.base`、`detectors.public_check`、`scripts.proxy_test`
- **`core.rawmsg`** ← `core.backfill`、`core.tools.runner.evidence`、`scripts.backfill_test`
- **`core.repl`** ← `cli.boot`、`cli.chat`、`core.repl.entry`、`scripts.autopilot_test`、`scripts.dismiss_finding_test`、`scripts.empty_session_test`、`scripts.progress_test`
- **`core.repl.auto`** ← `core.repl`
- **`core.repl.base`** ← `core.repl`
- **`core.repl.commands`** ← `core.repl`
- **`core.repl.consts`** ← `core.repl`、`core.repl.auto`、`core.repl.commands`、`core.repl.context`、`core.repl.history`、`core.repl.loop`、`core.repl.session`
- **`core.repl.context`** ← `core.repl`
- **`core.repl.entry`** ← `core.repl`
- **`core.repl.history`** ← `core.repl`
- **`core.repl.loop`** ← `core.repl`
- **`core.repl.session`** ← `core.repl`
- **`core.scheduler`** ← `cli.ask`、`cli.engines`、`cli.scan`、`core.repl.auto`、`core.subdomain`、`core.tools.runner.verify`、`scripts.knowledge_test`、`scripts.subdomain_extract_test`
- **`core.scheduler.base`** ← `core.scheduler`
- **`core.scheduler.helpers`** ← `core.scheduler.match`、`core.scheduler.recon`
- **`core.scheduler.match`** ← `core.scheduler`
- **`core.scheduler.recon`** ← `core.scheduler`
- **`core.scheduler.report`** ← `core.scheduler`
- **`core.scheduler.verify`** ← `core.scheduler`
- **`core.session`** ← `cli.boot`、`cli.chat`、`cli.ledger`、`core.planner`、`core.repl.base`、`core.repl.consts`、`core.repl.context`、`core.repl.entry`、`core.repl.loop`、`core.repl.session`、`scripts.autopilot_test`、`scripts.backfill_test`、`scripts.completer_candidates_test`、`scripts.dismiss_finding_test`、`scripts.empty_session_test`、`scripts.export_report_test`、`scripts.fsops_test`、`scripts.naming_test`、`scripts.output_spill_test`、`scripts.progress_test`、`scripts.public_check_test`、`scripts.record_finding_test`、`scripts.session_resume_test`
- **`core.session.models`** ← `core.session`、`core.session.session`
- **`core.session.redact`** ← `core.session`、`core.session.models`、`core.session.session`
- **`core.session.session`** ← `core.session`、`core.session.store`
- **`core.session.store`** ← `core.session`
- **`core.state`** ← `cli.app`、`cli.ask`、`cli.chat`、`cli.engines`、`cli.probe`、`cli.subs`、`cli.summary`、`collectors.dirsearch_runner`、`collectors.js_analyze`、`collectors.openapi`、`collectors.path_scan`、`collectors.port_scan`、`collectors.subdomain_extract`、`core.auth`、`core.planner`、`core.repl.commands`、`core.scheduler.base`、`core.scheduler.helpers`、`core.scheduler.match`、`core.scheduler.recon`、`core.scheduler.report`、`core.scheduler.verify`、`core.session.redact`、`core.session.session`、`core.subdomain`、`core.tools.runner.base`、`core.tools.runner.evidence`、`core.tools.runner.intel`、`core.tools.runner.recon`、`core.tools.runner.report`、`detectors.api_authz`、`detectors.base`、`detectors.exploit.attack`、`detectors.exploit.probe`、`detectors.exploit.run`、`detectors.exploit.sqli_mixin`、`detectors.exploit.template`、`detectors.http_detector`、`detectors.js_logic`、`detectors.poc_loader`、`detectors.public_check`、`kb.indexer`、`kb.knowledge`、`kb.retriever`、`llm.client`、`llm.prompt`、`scripts.autopilot_test`、`scripts.backfill_test`、`scripts.burp_report_test`、`scripts.dismiss_finding_test`、`scripts.empty_session_test`、`scripts.export_report_test`、`scripts.fsops_test`、`scripts.knowledge_test`、`scripts.naming_test`、`scripts.progress_test`、`scripts.public_check_test`、`scripts.record_finding_test`、`scripts.report_test`、`scripts.session_resume_test`、`scripts.subdomain_extract_test`
- **`core.state.enums`** ← `core.state`、`core.state.models`、`core.state.poc`
- **`core.state.models`** ← `core.state`
- **`core.state.poc`** ← `core.state`、`core.state.models`
- **`core.state.util`** ← `core.state`、`core.state.models`、`core.state.poc`
- **`core.subdomain`** ← `cli.subs`
- **`core.tools`** ← `cli.ledger`、`cli.probe`、`cli.subs`、`core.agent`、`core.bootstrap`、`core.repl.commands`、`core.repl.context`、`core.repl.session`、`core.scheduler.report`、`scripts.backfill_test`、`scripts.dismiss_finding_test`、`scripts.export_report_test`、`scripts.fsops_test`、`scripts.output_spill_test`、`scripts.public_check_test`、`scripts.record_finding_test`、`scripts.subdomain_extract_test`
- **`core.tools.args`** ← `core.tools`、`core.tools.runner.base`
- **`core.tools.builtins`** ← `core.tools`、`core.tools.args`
- **`core.tools.external`** ← `core.tools`、`core.tools.args`、`core.tools.pathscan`、`core.tools.probe`、`core.tools.runner.base`、`core.tools.runner.external`
- **`core.tools.pathscan`** ← `core.tools`
- **`core.tools.probe`** ← `core.tools`、`core.tools.args`、`core.tools.runner.base`、`core.tools.runner.external`
- **`core.tools.runner`** ← `core.tools`
- **`core.tools.runner.base`** ← `core.tools.runner`、`core.tools.runner.external`、`core.tools.runner.recon`
- **`core.tools.runner.evidence`** ← `core.tools.runner`
- **`core.tools.runner.export`** ← `core.tools.runner`
- **`core.tools.runner.external`** ← `core.tools.runner`
- **`core.tools.runner.files`** ← `core.tools.runner`
- **`core.tools.runner.intel`** ← `core.tools.runner`
- **`core.tools.runner.recon`** ← `core.tools.runner`
- **`core.tools.runner.report`** ← `core.tools.runner`
- **`core.tools.runner.verify`** ← `core.tools.runner`
- **`core.tools.wordlist`** ← `core.tools`
- `detectors` —— 无内部调用方（入口 / 叶子 / 测试）
- **`detectors.api_authz`** ← `core.planner`、`core.tools.runner.verify`、`detectors.js_logic`
- **`detectors.base`** ← `collectors.js_analyze`、`collectors.path_scan`、`core.backfill`、`core.tools.runner.evidence`、`detectors.api_authz`、`detectors.exploit.probe`、`detectors.http_detector`、`detectors.js_logic`
- **`detectors.exploit`** ← `cli.probe`、`core.scheduler.verify`、`core.tools.runner.recon`、`scripts.autopilot_test`
- **`detectors.exploit.attack`** ← `detectors.exploit`
- **`detectors.exploit.consts`** ← `detectors.exploit.attack`、`detectors.exploit.ops`、`detectors.exploit.probe`、`detectors.exploit.sqli_mixin`
- **`detectors.exploit.ops`** ← `detectors.exploit`、`detectors.exploit.attack`、`detectors.exploit.probe`、`detectors.exploit.run`、`detectors.exploit.sqli_mixin`
- **`detectors.exploit.payloads`** ← `detectors.exploit.attack`、`detectors.exploit.probe`
- **`detectors.exploit.probe`** ← `detectors.exploit`
- **`detectors.exploit.run`** ← `detectors.exploit`
- **`detectors.exploit.sqli_mixin`** ← `detectors.exploit`
- **`detectors.exploit.sqli_rules`** ← `detectors.exploit`、`detectors.exploit.sqli_mixin`
- **`detectors.exploit.template`** ← `detectors.exploit.attack`、`detectors.exploit.sqli_mixin`
- **`detectors.http_detector`** ← `core.planner`、`core.scheduler.recon`、`core.scheduler.verify`、`core.subdomain`、`core.tools.runner.recon`、`scripts.burp_report_test`
- **`detectors.js_logic`** ← `cli.engines`、`cli.probe`、`core.scheduler.recon`、`core.tools.runner.recon`、`scripts.js_analyze_test`
- **`detectors.poc_loader`** ← `cli.ask`、`cli.engines`、`cli.kb`、`cli.probe`、`core.bootstrap`、`core.planner`、`core.scheduler.match`、`core.tools.runner.base`、`detectors.api_authz`、`kb.indexer`
- **`detectors.public_check`** ← `core.scheduler.recon`、`core.tools.runner.report`、`scripts.public_check_test`
- `flower_pow` —— 无内部调用方（入口 / 叶子 / 测试）
- `kb` —— 无内部调用方（入口 / 叶子 / 测试）
- **`kb.indexer`** ← `cli.engines`、`cli.kb`、`core.bootstrap`、`kb.knowledge`、`kb.retriever`、`scripts.knowledge_test`
- **`kb.intel`** ← `cli.ask`、`core.scheduler.match`、`core.tools.runner.intel`
- **`kb.knowledge`** ← `cli.kb`、`core.scheduler.verify`、`scripts.dismiss_finding_test`、`scripts.knowledge_test`
- **`kb.retriever`** ← `cli.ask`、`core.scheduler.match`、`core.tools.runner.intel`、`llm.client`、`llm.prompt`、`scripts.subdomain_extract_test`
- **`llm`** ← `core.agent`、`llm.client`、`scripts.record_finding_test`、`scripts.report_test`
- **`llm.client`** ← `core.bootstrap`、`core.repl.context`、`core.scheduler.base`、`scripts.record_finding_test`、`scripts.report_test`
- **`llm.models`** ← `cli.boot`、`cli.models`、`core.config_loader`、`llm.client`
- **`llm.prompt`** ← `core.scheduler.helpers`
- **`scripts._srcs`** ← `scripts.js_analyze_test`
- `scripts._terminal_sim` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.agent_loop_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.autopilot_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.backfill_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.burp_report_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.completer_candidates_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.completer_editing_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.completer_terminal_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.config_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.dirsearch_throttle_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.dismiss_finding_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.empty_session_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.export_report_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.fsops_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.gen_file_map` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.js_analyze_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.knowledge_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.naming_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.output_spill_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.progress_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.proxy_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.public_check_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.record_finding_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.report_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.run_tests` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.secret_scan` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.session_resume_test` —— 无内部调用方（入口 / 叶子 / 测试）
- `scripts.subdomain_extract_test` —— 无内部调用方（入口 / 叶子 / 测试）

## 4. 关键枢纽（被引用最多的 15 个文件）

| 文件 | 被引用 |
|---|---:|
| `core.state` | 61 |
| `core.config_loader` | 27 |
| `core.session` | 23 |
| `core.tools` | 17 |
| `cli.app` | 13 |
| `core.completer` | 10 |
| `detectors.poc_loader` | 10 |
| `cli.boot` | 9 |
| `core.proxy` | 8 |
| `core.scheduler` | 8 |
| `detectors.base` | 8 |
| `core.repl` | 7 |
| `core.repl.consts` | 7 |
| `collectors.js_analyze` | 6 |
| `core` | 6 |

> 枢纽文件是改动的高危区：改签名要全文搜索调用方；反向引用表（§3）就是调用方清单。

## 5. 附录：想加一种新的漏洞检测，要动哪些文件

| 步骤 | 改哪里 |
|---|---|
| 1. 写检测规则 | 新增 `poc/<category>__<name>.yaml` |
| 2. 需要新类别 | `core/state/enums.py` 的 `Category` 枚举 |
| 3. 需要专用验证逻辑 | `detectors/` 新增类继承 `Detector`，实现 `verify()` |
| 4. 需要新采集能力 | `collectors/` 新增采集器 |
| 5. 暴露给 Agent | `core/tools/builtins.py` 加 `BuiltinTool` + `core/tools/runner/` 对应 mixin 加 `_h_xxx()` |
| 6. 能被检索到 | `kb/indexer.py` 自动索引新 YAML（`index` 命令重建） |
| 7. 补测试 | `scripts/` 下新增 `*_test.py`（会自动被 `run_tests.py` 收集） |
