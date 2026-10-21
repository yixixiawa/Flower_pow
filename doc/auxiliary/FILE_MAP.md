# flower_pow 文件地图

每个文件干什么、里面的模块点各自负责什么。
**本文件由代码结构直接核对生成**：150 个 Python 文件（122 个源码 + 27 个脚本 + 入口）、33 个 POC YAML、18 个 CLI 命令、30 个内置工具。
> **无一个文件超过 600 行**（最大 540）——「单文件过长会毁掉可读性」是本项目的硬约束：
> 超过就按职责切包，对外仍是一个名字（`from core.state import Finding` 照旧）。

---

## 0. 先看全局：一条扫描请求怎么流过去

```
flower_pow.py            CLI 入口（typer），解析子命令与全局参数
   │
   ├─ core/bootstrap.py   环境体检：外部工具、依赖、索引、API Key
   ├─ core/config_loader.py  配置：环境变量 > config.yaml > 默认值
   │
   ▼
core/scheduler/        编排：①指纹 ②侦察 ③RAG 匹配 ④验证 ⑤研判 ⑤b公开性核验 ⑥沉淀
   │
   ├─ detectors/*         指纹识别 / 路径 / 端口 / JS / 接口文档
   ├─ collectors/*        资产采集（端口、路径、OpenAPI、JS、dirsearch、子域枚举）
   ├─ kb/*                向量索引 → 召回 → 重排；外部情报；知识沉淀
   ├─ detectors/*         POC 验证（HTTP 匹配、鉴权、高危探针、JS 逻辑）
   │                      + public_check（回源核验"是不是站点自己公开的"→ 自动降误报）
   ├─ core/exclusions.py  误报排除清单（按目标落盘，重扫自动套用）
   ├─ llm/*               重排 / 研判 / 报告 / 修复建议
   └─ output/*            证据落盘 + JSON / Markdown / HTML 报告
```

两种驱动方式，共用同一套执行层：

| 驱动 | 入口 | 特点 |
|---|---|---|
| **一次性扫描** | `scheduler.scan()` | 五阶段流水线，跑完出报告 |
| **交互式 Agent** | `core/agent.py` + `core/tools/runner/` | 模型决定调什么工具，流式输出 |
| **剧本模式** | `core/planner.py` | 固定四阶段，可复现、不烧 token |

---

## 1. 根目录

### `flower_pow.py`（54 行）+ `cli/`（14 个模块）—— CLI 入口

**拆分**：入口只剩「触发注册 + 调起 Typer」两件事；18 个命令的实现搬进 `cli/` 的
13 个模块——`app`（Typer 对象）/ `boot`（无参入口）/ `scan` / `chat` / `kb`（index·knowledge·pocs）/ `ask`（ask·intel）/ `engines`（engines·jsaudit）/ `probe`（exploit·tools·discover）/ `models` / `subs` / `ledger`（sessions·findings·proxy）/ `initcmd` / `summary`。
**导入顺序 = `--help` 里的命令顺序**，要调顺序改 `cli/__init__.py`，别去动各模块。

typer 应用，18 个子命令。除了 `scan` / `chat` 这两个主入口，其余都是「单独调某个能力」的快捷方式。

| 命令 | 干什么 |
|---|---|
| `scan` | 一次性完整流水线扫描并出报告 |
| `chat` | 交互式会话（默认 Agent 模式，`--classic` 切剧本模式）；`--auto N` 固定 N 轮，`--poll` **自动跑到穷尽** |
| `index` | 重建 POC 向量索引 |
| `knowledge` | 知识库沉淀的查看 / 检索 / 清空 |
| `pocs` | 列出 POC 库 |
| `ask` | 只做 RAG 检索问答，不扫描 |
| `intel` | 查询 pocindex 的 CVE 情报 |
| `engines` | 环境体检（不扫描） |
| `jsaudit` | 单独跑前端 JS 逻辑审计 |
| `exploit` | 单独跑高危探针（SQLi / RCE / 文件读） |
| `tools` | 列出本机可调用工具、登记自定义工具 |
| `discover` | 扫描 PATH 找未登记的可执行文件 |
| `models` | 列出可用模型与能力画像 |
| `proxy` | 检测本机代理 + 查看某目标的走代理决策 |
| `subs` | 子域批量扫描 |
| `findings` | 复核已保存会话的发现、把误报排除掉；`--auto` 回源站核验公开性并自动排除、`--excluded` 看排除清单、`--json` 脚本消费 |
| `sessions` | 列出历史会话（显示 `日期_标题`），配 `--resume <会话名>` 续跑；`--clean` 清空会话 |
| `init` | 生成一份 `config.yaml` / `.env` 模板（与当前能力的全量参数同构） |

关键内部函数：
- `_cfg(path)` —— 载入配置
- `_boot(...)` —— 环境体检 + Banner + Key 校验，所有命令共用
- `_run_default()` —— 不带子命令时的默认行为（进会话）
- `_apply_model(cfg, model, deep_model)` —— 覆盖模型选择
- `_print_model_warnings(cfg)` —— 模型名过期/下线时提示
- `_load_targets(source, root)` / `_print_subs_summary` / `_subs_markdown` —— 子域扫描的输入解析与输出

### `config.yaml`（78 行）—— 三段配置

| 段 | 控制什么 |
|---|---|
| `scan` | 超时、并发、只读开关、端口/路径/JS 采集开关、高危探针开关 |
| `rag` | 索引路径、top_k、相似度阈值、LLM 重排；以及知识沉淀的门控（`knowledge_*`） |
| `llm` | base_url、模型名、temperature、max_tokens、是否关闭思考链 |

顶层还有 `output_dir` / `data_dir`。**密钥只从环境变量或这个文件读，绝不写进会话快照与报告。**

### `README.md`（1117 行）—— 主文档：设计取舍、踩坑记录、实测数据

### `pyproject.toml` / `requirements.txt` —— 依赖（核心只 `httpx` + `yaml`，其余可选）

---

## 2. `core/` —— 编排、状态、执行、交互

### `core/state/`（5 个模块）★ 数据模型的「事实来源」

**拆分**：`enums`（严重度 / 分类）/ `poc`（POC 声明模型）/ `models`（Evidence·Finding·ScanResult 与误报排除）/ `util`（正则缓存·文件名清洗·dataclass 序列化）。依赖单向无环：`util` ← `enums` ← `poc` ← `models`。

整个项目的数据字典。采集器往里写资产，检测器往里写发现，RAG 读它检索，调度器读它决策，报告层序列化它。

| 类 | 职责 |
|---|---|
| `Severity` | 严重度枚举，`rank` 用于排序、`parse` 容错解析 |
| `Category` | POC 类别，决定用哪个探测器 |
| `MatchTarget` / `MatchOp` | 匹配位置（body/header/status/all）与匹配方式（contains/regex/missing…） |
| `MatchRule` | 一条匹配规则。`evaluate()` 求值；**多规则默认 AND，响应头检查可切 OR**（`match_all=False`） |
| `RequestSpec` | POC 的请求模板（paths / params / headers / body / method） |
| `POC` | 由 YAML 编译的 POC 对象。`index_document()` 生成检索文本、`rules_match()` 跑规则 |
| `Evidence` | 原始 HTTP 证据。**反幻觉的地基**：存请求行、请求头、响应头、响应体片段，外加 `poc_id / payload_sent / expected / matched_pattern` 用于复现 |
| `Fingerprint` | 目标指纹（标题/技术栈/响应头/状态码），RAG query 的主要来源 |
| `Asset` | 侦察资产（port/path/api/endpoint/secret/internal/js） |
| `Finding` | 一条漏洞发现，含 `verdict`（真阳性/误报/待人工）与 `confidence`；**人工误报排除**用 `dismissed / dismiss_reason / dismissed_at` + `active` 属性表示 |
| `ScanResult` | 一次扫描的完整快照，会话文件就是它的序列化。`active_findings()` / `dismissed_findings()` 分流；**`counts()` 与 `by_severity()` 只算有效发现**（所以排除一条误报后报告概览、风险表、状态行全部自动正确） |

发现入库的**唯一收口**是 `ScanResult.add_findings()`：去重 → 套用误报排除清单 →
重排。以前各处直接 `result.findings.extend(...)`（planner 6 处、scheduler 3 处、
repl 1 处），任何"入库策略"都只能逐个调用点打补丁、漏一处漏一处——
误报排除就是第一个被这个坑到的策略（历史误报不会在重扫时被自动挂上标记）。

`dismiss_finding(f, reason)` / `restore_finding(f)`：标记与撤销。**刻意不动
`verdict` / `confirmed`**——那两个是探针与 LLM 研判的客观结论，"人工判定为误报"
是另一层信息；混着写会让撤销变成有损操作。

两条设计约束写死在这里：**证据优先**（没证据不允许进报告）、**可快照**（全部能 `to_dict` / `from_dict`）。

辅助：`safe_name()` 把任意字符串洗成安全文件名；`re_search()` 正则容错；`dataclass_to_dict()` 递归序列化。

### `core/rawmsg.py`（289 行）★★ 原始报文的解析与清洗（三个入口共用一套规则）

**解决的问题**：模型把一坨 Burp 风格文本粘进来这件事，有三个地方要处理——
`record_finding`（手工登记入库）、`core/backfill.py`（从会话历史还原）、
`output/report/`（渲染前清 Markdown 转义）。解析规则一旦分散在三处，
**同一条发现换个入口就换个样子**：报告里自动发现与手工发现的 PoC 格式不一致。

| 模块点 | 作用 |
|---|---|
| `RawRequest` / `RawResponse` | 解析结果。`ok=False` 表示"不像一条原始报文"，但**原文照留**——绝不因为格式不标准丢字段 |
| `unescape_md()` | 清 Markdown 转义 `` \` \* \_ \{ \} \[ \] \( \) \# \+ \- \. \! \| \> \~ ``，顺带剥行尾空格。**不动 `C:\Windows`**（反斜杠后是字母，不在集合里） |
| `split_exchange()` | 把"请求＋响应"混在一起的文本切成两半。认 `[RESPONSE]`、`>>> 请求:` / `<<< 响应:`，以及最朴素的首个状态行。首行即状态行 → 整段是纯响应（模型只贴响应，最常见）。切不开返回 `(text, "")` |
| `parse_raw_request()` / `parse_raw_response()` | 拆成 请求行/头/体、状态码/头/体。状态行缺失时 `ok=False` 但 `body` 仍是整段原文 |
| `parse_tool_result()` | 解析**会话历史里 `http_request` 的工具结果**（另一种格式，见 `ToolRunner._h_http_request`），供回填 |
| `looks_like_analysis()` | 判断某段文本是不是**说明文字**而不是响应体。放在这里而不是 `output/report/`，因为回填也要用同一判据决定"这条记录的响应体是不是假的" |

**`parse_tool_result` 的 `body_truncated` 是本文件最容易被写错的一处。**
早期实现只看标记行里有没有"截断"两个字 → 而旧版 `_h_http_request` **无论切没切
都写**「正文（截断 N 字符）」（N 是切片前的全长）→ 真实会话里 15 条**完整**响应
全被标成残缺版。现在的判据：

* 标记行里的 N > 实际拿到的字符数 ⇒ 真被切（旧格式 N 写全长）；
* 标记行 N ≥ 上限（1500）且实际拿到 ≥ 上限 ⇒ 真被切（新格式只在真切时写、恒等于上限）；
* 服务端声明的**字节数** > 实际字节数 ⇒ 上游（探针 4KB 上限）就只存了前一段。

比较字节数而不是字符数，否则中文正文（20 字符 = 60 字节）会被误判。两处都留 16
的余量，因为正文流经工具结果时做过一次 `strip`。

### `core/backfill.py`（213 行）★★ 从会话历史把真实报文补回发现

**解决的问题**：老报告的 PoC 只有请求、没有响应。那些数据**源头已经丢了**
（旧版 `record_finding` 就把说明砍到 500 字符、还把它同时塞进 `body_excerpt`），
但当时的真实请求/响应往往还在会话历史的工具结果里。所以
"恢复会话 → 回填 → 重导报告"能把老报告补成有真实报文的版本，比重跑一遍扫描便宜得多。

| 模块点 | 作用 |
|---|---|
| `_tool_results(history)` | 把成对的 `tool_call` / `tool` 消息按 `tool_call_id` 配起来。配不上直接跳过 |
| `collect_exchanges(history)` | 按发生顺序收集所有可识别的真实请求/响应（只认 `http_request`） |
| `_keys(url)` | 匹配键 = **主机 + 路径 + 排序后的 query**。刻意**不做**"忽略 query 的同路径匹配"——实测踩到：`/download?file=../proc/self/environ` 会被挂上 `?file=../etc/passwd` 的响应，报告里的 PoC 就成了伪造证据。宁少不错 |
| `_needs_fill(ev, desc)` | 缺不缺真实响应：无状态码 / 无任何响应痕迹 / **响应体是旧版塞进来的说明文字** |
| `_bogus_body(ev, desc)` | `body_excerpt` 是不是说明文字冒充的（`looks_like_analysis`） |
| `backfill_findings(session, evidence_dir)` | 主入口，返回 `{exchanges, candidates, filled, items}`；写 `result.notes` 留痕 |

两条纪律：**只补不覆盖**（已有字段一律不动，唯一例外是"说明冒充响应体"必须让位，
否则渲染端只能把假体清空、这条就白白变成"有请求没响应"）；**不做模糊匹配**。

### `core/fsops.py`（371 行）★★ 文件增删改的沙箱

**解决的问题**：报告导出过去每次生成新文件（`report_x.md` → `_2.md` → `_3.md`），
改一轮导一次就堆出一串近似重复的报告；智能体也没法"接着上一份改"，只能整篇重写。

| 模块点 | 作用 |
|---|---|
| `FileSandbox.resolve(rel, must_exist=)` | **所有闸门都在这一处**，五个工具共用。返回绝对路径或抛 `FileOpDenied` |
| `is_reparse_point(p)` | 判断符号链接**或目录联接**。`Path.is_symlink()` 在 Windows 上对目录联接返回 `False`（实测），只靠它等于没检查 |
| `check_ext(path)` | 扩展名**白名单**。报告类产物之外的格式一律不写 |
| `list_dir` / `read` / `write` / `edit` / `delete` | 五个操作。`write` 原子替换；`edit` 精确替换（出现次数不符即拒绝）；`delete` 只删文件 |
| `FileOp` / `log` | 操作审计记录（`delete` 还会写进 `result.notes`，进报告的「执行说明」） |
| `sandbox_for(cfg)` | 按配置建沙箱；`fs_ops_enabled=false` 时直接抛拒绝 |

四道**结构性**闸门（不靠提示词）：

1. **只能在 `output_dir` 内**：绝对路径 / 盘符 / UNC / `..` 全拒，最后再用
   `resolve()` 的结果做一次"必须在根之内"的校验。
2. **重解析点直接拒绝**：符号链接与**目录联接**都能把读写引到根外。
3. **扩展名白名单**：黑名单永远漏（`.phtml`/`.ps1xml`/…），而沙箱的用途是
   "写报告产物"，白名单能一句话说清边界。产物目录不能变成代码投放点。
4. **不写目录、不删目录**：删目录一条命令就能毁掉整个产物区，工具没这个场景。

**读取也关在同一个沙箱里**——读不关就等于钥匙漏了：`read_file("../../.env")`
拿到 API Key，再接一发 `http_request` 就出去了。

**和 `readonly` 无关**：`readonly` 管的是对**目标**的写操作，本模块管**本地产物**，
导报告本来就要写本地文件。整体关闭用 `scan.fs_ops_enabled` / `POCS_FS_OPS`。

`edit` 的关键约束：`old_text` 逐字符一致且出现次数与 `count` 相符（默认恰好 1 次）。
含糊的替换比不改更糟——它可能悄悄改掉别处的同一段文字。

### `core/progress.py`（191 行）★★ 轮次穷尽判定 + 自动轮询驱动

**解决的问题**：会话里每轮之间要**手工回车**才继续，跑一个站点十几轮就得一直守着敲；
"什么时候算测完"也只能靠人自己看。`/poll`（会话内）与 `--poll`（非交互）把
"循环"和"何时停"一起接管，两者**共用同一个模块**——行为不会出现两套。

| 模块点 | 作用 |
|---|---|
| `RoundOutcome` | 一轮的结果：`new_assets` / `new_findings` / `new_model` / `suggestions` / `elapsed`。`produced` = 三者任一 >0；`idle` = `not produced` |
| `Exhaustion` | 状态机。`observe(outcome)` → `""` / `"exhausted"` / `"capped"`；`verdict()` 给用户一句话 |
| `poll_until_done(run_round, ex=…, on_round=…, checkpoint=…)` | 循环驱动：反复 `await run_round(i)`，交给 `Exhaustion` 判停。`run_round` 由调用方提供（REPL 走 Agent/剧本，CLI 走 Planner），所以驱动层能测 |
| `IDLE_LIMIT=2` / `DEFAULT_MAX_ROUNDS=12` | 连续几轮无推进判穷尽 / 轮数安全阀 |

**判据只看硬状态**。最初把"没有下一步建议"也算作空转条件，**实测直接失败**：
`Planner._suggest()` 是阶段驱动的兜底文本（迭代阶段恒为"继续迭代或导出报告"），
**每轮都非空**，那个条件永远不成立 → "穷尽了才停"退化成"每次都跑到上限"。
建议文本是给人看的旁白，不是可依赖的负信号。

**`new_model` 为什么要单独数**：建模阶段的主要产出既不是资产也不是发现，
不数它会把"这一轮成功建好了业务模型"误判成空转。这是测试驱动出来的第三个信号。

**穷尽与到上限的措辞必须分开**（`verdict()`）：混着说的后果很实际——
用户会以为覆盖面完整了。所以 capped 的文案里写死"**不是测完了**"，
并给出调上限的位置。同一轮同时命中时**穷尽优先**（"真的没得测了"比"到上限了"更该说）。

`poll_until_done` **刻意不吞 `KeyboardInterrupt`**：吞掉的话 Ctrl-C 要等到下一轮
才响应。中断立刻穿透，由调用方收尾（会话是逐轮存盘的，中断不丢东西）。

### `core/exclusions.py`（316 行）★★ 误报排除清单（按目标持久化）

**解决的问题**：自动探针判不了"这是不是误报"。最典型的一类是**公开演示站点**——
站点本就建给人看，暴露的配置、默认账号、接口文档属于**设计而非漏洞**。
只在当前会话里标一次不够：同一目标重扫一遍，同一条又会作为"有效发现"冒出来。

| 模块点 | 作用 |
|---|---|
| `set_store_path()` / `store_path()` | 落点由 `load_config()` 设成 `<data_dir>/exclusions.json`（在一条公共路径上被查询，那条路径拿不到 cfg，所以走模块级设置） |
| `host_of(target)` | 目标 → host 键：去 userinfo、转小写、抹掉默认端口。`https://A.com:443/` 与 `a.com` 必须落到同一条 |
| `match_reason(target, poc_id, matched_at)` | 命中返回原因（可为空串），未命中返回 `None`。`matched_at` 留空的条目表示"该 POC 在本目标整体不可信" |
| `add()` / `remove()` / `entries()` / `summary()` | 增删查 |
| `_key(matched_at)` | 匹配键：**只把 host 部分转小写**。域名大小写不敏感是规范，路径不是——整串小写会放大排除范围 |

两条硬约束：

1. **原子写**（临时文件 + `os.replace` + `fsync`）。中途崩溃留下半个 JSON，
   下一次启动会因解析失败把整份排除清单丢掉。
2. **读失败一律当"没有排除项"**。排除清单只是便利功能，不该有能力让扫描崩掉。

命中判定在**入库时**做（`ScanResult.add_findings` → `_mark_if_excluded`），
不是在报告层过滤——报告层过滤只能让报告干净，会话里那条依旧是"有效发现"，
`/findings`、状态行、下一轮研判都会继续把它当真，用户会以为排除没生效。

### `core/scheduler/`（7 个模块）★ 一次性扫描的编排器

**拆分**：`helpers`（纯函数，依赖链最底）/ `base`（`_SchedulerBase`，构造与共享状态）/ `recon`（主流程 `scan` + 侦察 + 公开性核验）/ `match`（RAG 召回 + 基线合并 + 情报）/ `verify`（验证 + 探针 + 研判 + 沉淀）/ `report`（导出 + 自身描述）。
各阶段是 mixin，共享同一个 `self`——拆的是文件不是对象。

| 方法 | 阶段 | 做什么 |
|---|---|---|
| `scan()` | 入口 | 建会话、跑各阶段、填 `result.phases` 耗时 |
| `_phase2_recon()` | ① | 指纹 → 端口 → **子域枚举** → JS → OpenAPI → 路径爆破，产出完整资产面 |
| `_phase3_match()` | ② | 用指纹构造 query 走 RAG 召回 POC；`_merge_baseline()` 兜底（低分也至少跑基线项）；`_enrich_with_intel()` 用 CVE 情报补 tags |
| `_phase4_verify()` | ③ | 并发执行选中的 POC；内含 `_phase4b_exploit()` 高危探针 |
| `_phase5_triage()` | ④ | LLM 研判每条命中是真阳性还是误报 |
| **`_phase5b_public_check()`** | ④b | **公开性核验**：回源站根目录取证，判定为站点自己公开的资源就自动排除（受 `scan.auto_dismiss_public` 控制，默认开） |
| `_ingest_knowledge()` | ⑤ | 把确认过的发现沉淀进知识库（失败不影响主流程） |
| `report()` | ⑥ | 调 `llm.write_report()` 生成正文，再交给 output 层出三份产物 |

> `_phase5b_public_check` 放在研判**之后**：研判回答"这条命中技术上成不成立"，
> 公开性核验回答"就算技术成立，它是不是有意公开的"。后者需要一份已经收敛的
> 命中清单，且只值得为剩下的这些花请求。核验失败只写 `result.errors`，
> 绝不影响报告产出。

`_profile_text(result)` 把目标画像压成一段文本给模型看。

### `core/agent.py`（493 行）★ 流式 AI Agent 循环

用户说一句 → 模型决定先说什么、调哪个工具 → 本地执行 → 结果回灌 → 继续，直到模型认为这轮做完。

| 成员 | 作用 |
|---|---|
| `send(user_text, echo)` | 主循环：发消息、处理流式事件、执行 tool_call、回灌结果、循环 |
| `_fingerprint(name, args)` | 给「工具名+参数」算指纹 |
| `_looping(fingerprint)` | **死循环检测（软警告）**：同一工具+参数重复 `LOOP_REPEAT_LIMIT=3` 次判死循环，注入收尾指令让模型给结论 |
| `_skeleton(name, args)` / `_skeleton_looping()` | **换壳死循环检测**：`external_tool` 同一工具+同一套选项（**忽略取值**）连打 `LOOP_SKELETON_LIMIT=4` 次判无进展——拦"反复试 `curl -w %{...}` 碰运气"这类每次指纹都不同的排列组合。只对 external_tool 启用（http_request 换 payload 是正常渗透，骨架化会误伤）；中间穿插别的工具连击断开 |
| `_refusal_text(name, args)` | 硬拒绝时回灌给模型的工具结果文案：为什么拒 / 什么仍允许 / 退路是什么，三件事缺一不可 |
| `_refused` / `_refused_skel` | **硬拒绝集（第二道闸）**：触发死循环判定的指纹登记在此，之后**原样重调直接跳过执行**（请求根本不发出）。只在本轮 `send()` 内有效，`reset()`/`restore()` 一并清空——下一轮用户明确要求重试是合法的 |
| `_trim()` | 历史裁剪（`MAX_HISTORY_MSGS=40` / `MAX_HISTORY_CHARS=120000`） |
| `reset()` / `restore(history)` | 清空 / 恢复对话历史（会话恢复用） |
| `_system()` / `tool_names()` | 构造系统提示、暴露可用工具名 |

> **为什么需要硬拒绝**：实测中模型会"嘴上答应不再重试、下一轮照样发同一个包"，
> 屏幕上只有延迟在变（换手机热点时尤其容易被误判成不同请求）。软纠偏对
> 固执的模型无效，所以第二道闸必须拦在执行之前。

与 `planner.py` 的区别：**Planner 是固定剧本，Agent 是模型自由发挥**。前者可复现不烧 token，后者能应付没预设的情况。

### `core/tools/`（包）★★ 工具层——声明 / 探测 / 参数归一 / 执行

解决的核心问题：**价值不在于自己重新实现了多少检测逻辑，而在于把机器上已有的能力组织起来**。装了 nmap 端口指纹就更准，装了 dirsearch 字典大两个量级，没装也不影响跑——内置实现自动顶上。

对外只暴露一个入口：`from core.tools import ToolRunner`（以及 `BUILTINS`、`probe_deps` 等）。调用方不必知道某个东西住在哪个子模块，符号表只在 `__init__.py` 维护一处。

| 模块 | 作用 |
|---|---|
| **`__init__.py`** | 门面：re-export 全部公开符号 + `__all__` |
| `external.py` | `ExternalTool`（外部 CLI 描述，含 **flag 白名单**——开放 `--script=` 这类能加载任意脚本的开关等于把机器交给模型）、`EXTERNAL_TOOLS` 12 项内置清单、`load_user_tools()` / `write_user_tools_template()`（`data/tools.local.yaml`）、`scan` 未登记差集的输入 |
| `builtins.py` | `BuiltinTool`（内置能力，带 JSON Schema 参数定义）+ `BUILTINS` 30 项 |
| `probe.py` | `Probe` / `DepStatus` / `probe_external()`（并发探测外部工具在不在 PATH、什么版本）/ `probe_deps()`（Python 依赖：httpx / openai / yaml / rich …）/ `EnvReport`（一次完整体检，`ready()` 判定能不能跑）。**用户清单的解析错误单独存 `tool_errors`**——清单写错时探测结果依然有效，混在一起会让调用方分不清「没装」和「配错了」 |
| `args.py` | **`normalize_args()`**（按 schema 归一实参类型，`execute()` 单一收口：模型把布尔写成 `"false"` 在 Python 里恒为真、枚举写错大小写会静默落空；统一转 bool/int/枚举规范值，认不出来的原样下传不瞎猜）+ `llm_schemas()`（转 OpenAI function-calling）+ `describe_externals()` / `tool_help_text()` |
| `wordlist.py` | `wordlist_path()` / `write_wordlist()` 生成内置路径字典（gobuster / ffuf 必须给 `-w`，不导出会「报告说可用、一调就失败」） |
| `pathscan.py` | `scan_path_executables()` / `unregistered_executables()`（`discover` 命令用）。`_NOISE_EXACT` / `_NOISE_PATTERNS` 过滤 sed / grep / python 这类通用命令，避免把系统工具当安全工具列出来 |
| **`runner/`** | **执行器——唯一的安全边界**（下节） |

`external.py` 与 `builtins.py` 的分界不是「文件太大」：**声明**（有什么能力）与**探测**（这台机器实际能不能用）是两件事，合在一起就会出现「没装却出现在 schema 里」。

### `core/tools/runner/` ★★ 执行器——唯一的安全边界

模型可以要求执行任何东西，所以**所有约束都落在这里**，不指望提示词里那句「请勿越权」。

**三道闸门：**
1. **只读模式** —— `readonly=true` 时 `intrusive` 类工具（sqlmap / hydra / nikto / masscan）直接拒绝执行，不是提示是拒绝
2. **参数白名单** —— 外部工具只接受注册过的 flag，`_validate_argv()` / `_flag_allowed()` 把关
3. **路径约束** —— `_path_inside_root()` 保证写文件不出项目根目录

原来是一个 1787 行的 `ToolRunner` 大类；现在按**职责**拆成 9 个 mixin，由 `runner/__init__.py` 多继承组装成同一个 `ToolRunner`：

| 文件 | 职责 |
|---|---|
| `base.py` | `_ToolRunnerBase`：模块常量（`MAX_TOOL_OUTPUT` / `_BODY_PREVIEW` / `_FILE_FLAGS`…）、`__init__`、`execute()` 收口、`_spill()` 大输出落盘、编排类（`_h_set_target` / `_h_session_state`）、会话合并（`_merge_assets` / `_merge_findings`）。三大闸门都在这里 |
| `recon.py` | 侦察 handler：`_h_http_request`、`_h_recon_fingerprint` / `_ports` / `_paths` / `_js` / `_openapi` / `_subdomains`、`_h_js_audit`、`_h_sqli_probe`、`_h_exploit_probe` |
| `intel.py` | 检索 handler：`_h_rag_search` / `_h_poc_list` / `_h_cve_intel` |
| `verify.py` | 业务与验证 handler：`_h_login` / `_h_authz_probe` / `_h_run_pipeline` |
| `report.py` | 发现台账 handler：`_finding_list` / `resolve_finding` / `_h_findings` / `_h_dismiss_finding` / `dismiss` / `_h_check_public_finding` / `check_public` |
| `evidence.py` | 证据登记 handler：`_h_record_finding` / `_remember_exchange` / `_find_recent_exchange` / `_h_backfill_evidence` |
| `export.py` | `_h_export_report` |
| `files.py` | 文件操作 handler：`_h_list_files` / `_h_read_file` / `_h_write_file` / `_h_edit_file` / `_h_delete_file` |
| `external.py` | 外部 CLI 执行通道：`_h_external_tool` / `_validate_argv` / `_build_argv` / `_run_external` |

**mixin 是「按出处分文件」，不是「按继承改写行为」**：方法体逐行搬运、缩进不变，MRO 上没有重名，行为与拆分前一致。`ToolRunner.dismiss` / `ToolRunner.resolve_finding` 是类方法，`/fp` 与 CLI 直接复用同一套寻址逻辑；`ToolRunner` 只把它们拼起来，不新增实现。

内置工具处理器（模型实际能调的动作）：

内置工具处理器（模型实际能调的动作）：

| 处理器 | 能力 |
|---|---|
| `_h_set_target` / `_h_session_state` | 设定目标、查看当前状态。**`_h_set_target` 必须同步 `session.result.target`**——报告命名读的是后者，只改 session.target 会让文件名退化成 `report_<日期>_target`（真实事故） |
| `_h_http_request` | 发任意 HTTP 请求（手工验证的主力）。顺带 `_remember_exchange(ev)` 记下这次真实报文，供随后的 `record_finding` 自动附响应。结果里的正文预览上限 `_BODY_PREVIEW=1500`，**只有真被切时才写"截断"**——无条件写会让回填端把完整响应判成残缺版（真实事故） |
| `_h_recon_fingerprint` / `_h_recon_ports` / `_h_recon_paths` / `_h_recon_js` | 四项侦察 |
| `_h_recon_openapi` | 抓接口文档 |
| `_h_recon_subdomains` | 子域被动枚举（**5 源并发聚合** + 排列组合）。**末尾必须有 `return`**——曾因拆包丢过一次，导致"有结果时返回 `None`" |
| `_h_js_audit` | 前端 JS 逻辑审计 |
| `_h_sqli_probe` / `_h_exploit_probe` | 高危探针 |
| `_h_authz_probe` | 接口鉴权 / 越权探测 |
| `_h_rag_search` / `_h_poc_list` / `_h_cve_intel` | 检索与情报 |
| `_h_login` | 登录取凭证 |
| `_h_run_pipeline` | 跑完整流水线 |
| `_h_findings` | 列出发现（`include_dismissed` 可含已排除；编号与 `/fp` 同一套顺序） |
| **`_h_dismiss_finding`** | **把发现判为误报并排除**（薄壳，逻辑在 `ToolRunner.dismiss`） |
| **`resolve_finding`** | **引用解析**：编号 / 完整 poc_id / 唯一子串。命中多条一律拒绝，绝不替用户猜 |
| **`_h_check_public_finding`** | **回源站根目录核验公开性**（薄壳，逻辑在 `ToolRunner.check_public`） |
| **`_h_export_report`** | 导出报告。**默认就地覆盖同名文件**，返回逐条标 `[新建]`/`[覆盖]`；覆盖时警告"整篇重生成会盖掉 edit_file 改动"。**fmt 先归一后校验枚举**（非法值当场报错列出合法值，绝不静默"成功"）；三格式路径由 `plan_reports()` **一次性**决定（overwrite=false 也共用主干、不错位）；notes 会话头带哨兵前缀重写，不重复累积 |
| **`_h_list_files` / `_h_read_file` / `_h_write_file` / `_h_edit_file` / `_h_delete_file`** | 产物文件增删改查，**共用 `core/fsops.py` 的沙箱**（关在 output_dir 内）。拒绝一律当**返回值**喂回模型，不抛异常 |
| **`_h_record_finding`** | 登记手工验证的漏洞（`evidence` 与 `payload` 必填）。**入库即完整保留**：早期版本把说明砍到 500 字符、`matched_pattern` 400、`body_excerpt` 800，模型写的复现步骤直接丢；还把说明同时塞进 `body_excerpt`，报告里那段中文分析就成了"服务端返回"。现在 payload/response 都走 `core/rawmsg.py` 结构化，缺响应时会去 `_recent_http` 找最近一次同 URL 的真实响应附上，仍找不到才如实警告 |
| **`_h_backfill_evidence`** | **从会话历史回填原始报文**（薄壳，逻辑在 `core/backfill.py`）。给"报告 PoC 段只有请求没有响应"的老会话用；提示文本按实际是否截断区分措辞 |
| `_h_external_tool` | 调外部 CLI（走上面三道闸门） |

**大输出落盘（`_spill()`）**：`external_tool` 的结果超过 `MAX_TOOL_OUTPUT` 时，
完整内容写到 `output/tool-output/<时间戳>_<序号>_external_tool.txt`（超长单行折到
2000 字符，否则 read_file 按行分页没意义），截断提示里给出路径与 read_file 翻页
用法。**内置工具不落盘**——它们的输出是自己设计的分页视图，落盘会让 read_file
读 spill 文件再被截断再 spill，无限派生垃圾文件。不修这个的后果见
`output_spill_test.py` 文件头：模型连打十几次 `curl -w %{...}` 想看剩余输出。

合并逻辑：`_merge_assets()` 去重后写回会话；`_merge_findings()` 只是一个转发——
去重、误报排除、重排全在 `ScanResult.add_findings()` 里，不在这里再实现一遍。

`ToolRunner.dismiss()` 是**同步**核心逻辑：模型走 tools、人走 `/fp`、脚本走
`flower_pow findings`，三条入口共用它。各写一遍的下场是"模型能排除、命令行不能"
这类不一致，而且极难发现（每条入口单看都自洽）。

`ToolRunner.check_public()` 是**异步**的（要回源取证据）：取证 + 分档 + 把强档
交给 `dismiss()`。它刻意**不把"疑似"也删掉**——返回里明确区分
"自动排除 N 条 / 疑似待确认 M 条 / 保持有效 K 条"，只报"已排除 N 条"会让人
误以为剩下的都确认过了。
`ToolBlocked` 异常表示「被安全闸门拦下」——这不是错误，是设计如此。

### `core/session/`（5 个模块）—— 会话状态

**拆分**：`redact`（凭据脱敏，压成 `键: ***` 而非删段，保留键名便于排查）/ `models`（Phase·Turn·ConversationTurn·BusinessModel，纯数据可单独测）/ `session`（`Session` 本体，轮次推进与快照读写）/ `store`（列出·取最近·清扫空壳）。

一次性 `scan` 的问题是没有中间状态，真实渗透是多轮的，所以这里把「一轮 = 一次推进」变成一等概念。

| 类 | 职责 |
|---|---|
| `Phase` | 四阶段枚举（RECON → MODEL → EXPLOIT → ITERATE），带 `label` / `goal` / `next` |
| `Turn` | **剧本模式**一轮的记录：阶段、动作、耗时、新增资产/发现 |
| `ConversationTurn` | **Agent 模式**一轮对话的索引条目（标题 + 用到的工具 + 时间）。与 `Turn` 分开是因为它只是问答，没有阶段/耗时那些字段 |
| `BusinessModel` | 第 2 轮产物：从接口清单推导的业务理解。**测点选择完全依赖它**——不知道「充值/提现」是哪个接口，就不会去测那里的越权 |
| `Session` | 完整会话状态：轮次推进、资产与发现、对话历史、落盘/载入 |

`redact()` / `redact_messages()` —— 落盘前脱敏，凭证、token、API Key 一律不进快照。
`list_sessions()` / `latest_session()` —— 会话列表与最近一条（`/resume` 与 Tab 补全用）。
`purge_empty_sessions()` —— 清掉磁盘上的空会话壳，返回被删目录名（见下）。

**会话命名**（`Session.display_title` / `Session.slug` / `Session._target_dir`）：

```
data/sessions/20261011_测 aigc 接口越权与 OSS 写权限/session.json
```

| 规则 | 为什么 |
|---|---|
| 取**第一轮**对话标题 | 第一句才是"这次要测什么"；最后一轮往往是"出报告" |
| 日期在前（`%Y%m%d_标题`） | 字典序 == 时间序，`ls` 出来天然有序 |
| 标题清洗 + 截断到 40 字 | `<>:"/\|?*` 在 Windows 上写不出文件；超长会撞路径长度限制 |
| 目录已存在就**不改名** | 改名 = 旧路径失效，`--resume` 找不到自己刚存的会话 |
| 无标题时退回 target → session_id | 刚启动就退出也能存住 |

早期 `session_id` 是纯 `int(time.time())`，`/sessions` 与 `/resume <Tab>`
列出来全是 `1789...`，恢复时认不出哪次是哪次。旧数字目录仍可加载。

**`Session.load()` 把磁盘目录名认作权威 id**（覆盖快照里的 `session_id` 字段）：
旧快照的目录名是纯数字、而内部 id 字段可能是另一串甚至缺失，不统一的话
`delete` / 续存都会指到不存在的路径。

**空会话清理**（`Session.is_empty` / `Session.delete` / `purge_empty_sessions`）：

| 手段 | 位置 | 做什么 |
|---|---|---|
| `is_empty()` | 判定 | 没目标、没 `user` 消息、没凭证、没推阶段、没资产/发现/笔记 = 空 |
| `delete(base, name=)` | 单删 | 删自己那个目录；无 `session.json` 一律不碰 |
| `purge_empty_sessions(base)` | 批量 | 遍历 `sessions/` 删所有空壳，返回目录名列表；读不出的坏快照不动 |
| `repl._save()` | 第一层 | 空会话**不落盘**（返回 `None`），新噪音不再产生 |
| `repl._resume()` / CLI `--resume` | 第二层 | 恢复前顺手清扫历史遗留空壳 |
| `/clean` / `sessions --clean` | 第三层 | 手工全量清 |

判空**从严**——拿不准就保留（误删不可逆，多留一个空壳只是难看）；
只有 `system` 开场白不算用户内容。`purge_empty_sessions` 单独可调用而不塞进
`list_sessions`：列目录是只读操作，`/sessions` 不该悄悄删东西。

### `core/repl/`（10 个模块）★ 交互式终端

**拆分**：`consts`（命令表 / 帮助 / 阶段别名——补全与 `/help` 共用一份）/ `base`（构造与控制台）/ 六个命令域 mixin（`history` `auto` `context` `loop` `commands` `session`）/ `entry`（`run_repl`）。
`_handle` 是**唯一**的命令入口，在 `loop` 里；其余 mixin 只提供被它调用的方法。

两种模式的统一入口，也是所有 `/` 命令的分发处。

| 模块点 | 作用 |
|---|---|
| `Repl.loop()` | 主循环：读输入 → 命中 `HOTKEY_FULL_AUTO` 走全自动 → 命令 or 交给 Agent/Planner |
| `_handle(raw)` | 命令分发（`COMMANDS` 常量同时供 `/help` 与 Tab 补全使用，避免两处不同步） |
| `_autopilot()` | **一键全自动**：打警告(`AUTO_WARN`) → 确认 → `Scheduler.scan()` 跑完整条链 → 并回结果 → 导出报告 |
| `_auto_approve()` | 全自动期间的写操作通道：**不阻拦，但每次都打印并写进 notes**（"一键"不等于"无法审计"） |
| `_merge_scan(result)` | 把扫描结果并回会话（资产按 `(kind,value)` 去重；**发现交给 `ScanResult.add_findings`**，去重/误报排除/重排都在那一处。以前这里自己按 `(poc_id,name,matched_at)` 去重，与 `ToolRunner`（`core/tools/runner/`）的 `(poc_id,matched_at)` 不一致，还完全轮不到"误报排除"执行） |
| **`_findings()` / `_finding_rows()`** | 发现列表。编号**始终按含已排除的全表算**——按可见列表编号的话，排除一条之后后面编号全平移，之前记下的编号就指向别的漏洞了 |
| **`_fp(raw)`** | `/fp <编号> <原因>` 判误报、`/fp undo <编号>` 撤销、`/fp del <编号>` 彻底删、`/fp poc <编号> <原因>` 按 POC 整体排除。逻辑复用 `ToolRunner.dismiss`——人与模型必须同一套语义 |
| `_approve(desc)` | 手动模式下的**逐条**人工审核（每次上传都问一遍，不是"开一次一路放行"） |
| `_run_agent(text)` | 跑一轮 Agent，并 `_record_conversation()` 记录标题 |
| `_make_title()` | 生成对话标题：**优先小模型总结（≤20 字），失败退回取输入前 20 字**——标题是索引不是交付物，不占深度模型 |
| `_chats()` / `_set_title()` | `/chats` 看索引、`/title <编号> <新标题>` 改标题 |
| `_completer()` / `_refresh_completer()` | 建/重建补全器（会话变化后候选要跟着变） |
| `_session_ids()` | 扫 `data/sessions/` 取可恢复会话 id，供 `/resume <Tab>` 补全 |
| `_report()` | 导出报告：先清掉本函数上次写的说明（哨兵前缀 `\x00report:`），再调 LLM 生成正文 |
| **`_poll(raw)`** | `/poll [轮数]` —— **自动连续跑轮，穷尽了才停**。Agent 走 `_run_agent`、剧本走 `_advance_and_run`；循环与判定都在 `core/progress`（见该节）。Ctrl-C 立刻停，逐轮存盘 |
| `_advance_and_run()` | 推进阶段跑一轮并返回 `Turn`（返回 Turn 是为了让 `/poll` 拿到本轮建议） |
| `_save()` | 落盘；**空会话返回 `None` 不写盘**（见 `core/session/` 空会话清理） |
| `_resume(id)` | 载入会话；**先 `purge_empty_sessions` 清扫历史遗留空壳**，点名恢复空会话则删除并说明。恢复后**自动跑一次回填**（`_backfill(quiet=True)`），老快照里"只有请求没有响应"的发现会被历史里的真报文补上 |
| **`_backfill(quiet)`** | `/backfill` 的实体，也是 `/resume` 的收尾动作。调 `core/backfill.backfill_findings`，有补入就提示"`/report` 重导即生效" |
| `_clean_sessions()` | `/clean` 的实体：批量删空会话并列出被删目录 |
| `_login()` / `_status()` / `_assets()` / `_findings()` / `_tools()` / `_set_key()` | 各命令实现 |
| `run_repl()` | 对外入口 |

### `core/completer/`（7 个模块）★ Tab 补全 + 行编辑（自己实现）

**拆分**：按「一块屏幕需要的知识」切——`keys`（按键哨兵 + VT 开关）/ `width`（双宽字符·ANSI 剥离·按词跳转）/ `layout`（折行，右边缘留待定折行位）/ `paint`（重绘，不支持 VT 就退回单行裁剪重绘）/ `candidate`（**纯逻辑**，可脱离终端单测）/ `reader`（msvcrt / termios 裸模式 / input 降级）。
`_cols()` / `_enable_vt()` 在拆分后一律走**模块属性**调用（`width._cols()`），这样定义处就是唯一补丁点，改一处全部生效。

**Windows 没有 `readline`**——它是 POSIX 模块，CPython 在 win32 下不编译；`pyreadline3` 要额外装、tkinter 在精简版也没编。项目要求「只靠 httpx + yaml 就能跑」，所以自实现：

| 模块点 | 作用 |
|---|---|
| `available()` | 判断当前环境能不能启用补全 |
| `Completer.complete(buf)` | **两级补全**：命令名 + 各命令的参数。语义统一为「候选总是替换最后一个词」 |
| `PromptReader.read()` | 带补全与历史的提示符；异常一律退回 `input()` |
| `_split_prompt()` | 把 prompt 拆成「只打一次的前缀」与「参与重绘的行内部分」——修**输入框自动换行**的关键 |
| `_cell_width()` / `_display_width()` / `_cols()` | 按显示列宽算（CJK/全角算 2 列，先剥 ANSI 转义）。`_cell_width` 是**全项目唯一的字符宽定义** |
| `_layout(text, cols)` | **折行布局**：算出光标落在第几行第几列。`cols` 是**终端实际列数**；列号可等于 `cols`（右边缘"待定折行"）。双宽字符不会被劈成两半 |
| `_move_to(out, from_row, row, col)` | **相对**定位：`\x1b[<n>A/B` + `\r` + `\x1b[<n>C`。**绝不用绝对定位**（见下） |
| `_enable_vt()` | 给 Windows 控制台置上 `ENABLE_VIRTUAL_TERMINAL_PROCESSING`，进程级一次；拿不到句柄返回 False |
| `_repaint(..., cur_row=)` | 重画（**支持折行**）：相对上移回输入区首行 → `\x1b[J` 一次擦净 → 重写 → 相对移回光标位。**返回新的光标行号**，调用方存下、下次传回 |
| `_plain_row_text()` / `_repaint_plain()` | 无 ANSI 的兜底：**把内容裁进一行**再重画（不裁就会折行、输入区往下掉） |
| `_finish_line(..., cur_row=)` | 提交/中断收尾：相对移动到**整行输入末尾**再换行，避免折行残留 |
| `_erase_input(rows)` | Tab 候选列表前，上移 rows 行并清到屏幕末尾 |
| `PromptReader._show_candidates(..., cur_row=)` | 打印候选（每行一个）后重画输入区；**返回重画后的光标行号** |
| `_prev_word()` / `_next_word()` | `Ctrl+←/→` 按词跳转（只按空白切：`/report` 算一个词） |
| `_read_win()` | Windows：`msvcrt.getwch()` 逐键读（`\x00`/`\xe0` 是功能键前缀，下一个字节是扫描码） |
| `_read_posix()` / `_read_escape()` | POSIX：`termios` + `tty.setraw`；转义序列读到终止字节为止（`Ctrl+→` 是 6 字节 `\x1b[1;5C`） |
| `_mods_held()` / `HOTKEY_FULL_AUTO` | `Alt+Shift` 热键：只按组合键**不产生字符**，必须 `GetAsyncKeyState` 轮询 |

**行内光标**：维护 `pos`（`0..len(buf)` 的插入点），支持 `←/→`、`Home/End`、`Delete`、
`Ctrl+←/→`、`Ctrl+A/E/U/K`、`Ctrl+Backspace`。早期版本把 `buf` 当只能末尾追加的字符串，
左右方向键被 `continue` 吃掉——**打错一个字只能整行删掉重打**。

**折行**：`\r` 只回**当前物理行**行首，输入超过一行时它回不到逻辑行首，
清屏宽度又被钉在一行——表现是"每敲一字整个输入框往上跳 + 残留旧字符"。
现在自己按列宽折行，用 ANSI **相对**上移（`\x1b[<n>A`）回输入区首行、
`\x1b[J` 擦到屏幕末尾、再相对移回光标位。

**⚠ 绝对定位是这里的头号陷阱**：算出来的行列是**相对输入区首行**的，
一旦写成绝对定位 `\x1b[<行>;<列>H`，光标会被扔到屏幕左上角，下一次重绘就从
那里开始 `\x1b[J` 擦屏——**屏幕乱跳、上方输出被抹**。所以全程只用相对移动，
另外相对移动天然免疫屏幕滚动（输入区贴底时内容上滚，绝对坐标全失效）。

**`cur_row` 必须由调用方回传**：重画后光标停在 `prompt + buf[:pos]` 的末尾，
下一次重绘要知道"现在在第几行"才能上移回去。拿**新 prefix** 的行号替代是错的——
回删时新 prefix 更短、行号更小，会**移得不够**，每次回删输入区往下掉一行。

**非 TTY 时自动退回原生 `input()`**——管道输入、CI、脚本不能被补全拖垮。
环境变量 `FLOWER_POW_PLAIN_INPUT` 可强制退回（任何终端表现异常时的兜底开关）。

**无 ANSI 的兜底路径也不能折行**：`\r` 回不到折行后的逻辑行首、又没有上移手段，
所以按整行宽清屏 + 原样重写会让每次重画都折一次行，输入区每敲一个字往下掉一行
（实测 25 个字符掉 6 行、糊出 7 行残留）。现在先把内容裁进 `cols-1` 列、
清屏宽度固定，保证输出永不折行。

### `core/planner.py`（527 行）—— 剧本模式的四阶段执行器

| 阶段 | 做什么 |
|---|---|
| `_recon()` | 指纹 + 端口 + **子域枚举** + JS + 接口文档，产出完整资产面 |
| `_model()` | 从资产推导业务模型（业务流程、高价值资源） |
| `_exploit()` | 鉴权探测 + 高危探针 |
| `_iterate()` | 基于已有发现深挖 |
| `_walk_business_flow()` / `_fetch_identity()` / `_probe_core_resources()` | 走业务流程、取自身身份、探核心资源 |
| `_suggest()` | 给下一步建议 |

`_infer_flows()` 从接口名推断业务流程（创建/查询/更新/删除）；`HIGH_VALUE_PAT` 标出充值、余额、订单这类高价值接口。

### `core/auth.py`（248 行）—— 登录与验证码

**由接口清单驱动，不是为某个站写死路径**：登录端点 = 路径含 `login` 的 POST 操作；验证码端点 = 路径含 `captcha` 的 GET；字段名取 requestBody 的 schema 属性。

| 模块点 | 作用 |
|---|---|
| `pick_login_endpoint()` / `pick_captcha_endpoint()` | 从 OpenAPI 资产推导端点 |
| `Authenticator.login()` | 完成登录并提取 token |
| `fetch_captcha()` | 取验证码；**SVG 验证码直接解析 `<text>` 取文字**，图形验证码才落盘让人看 |
| `_find_token()` | 递归找响应里的 token（兼容 `token` / `accessToken` / `jwt` 等多种命名） |

### `core/bootstrap.py`（430 行）—— 初始化引导

第一次运行时如实说清三件事：**这台机器有什么、还缺什么、要连大模型得先给钥匙**。顺序不能反——先把体检做完再问 Key。

| 模块点 | 作用 |
|---|---|
| `run_checks()` | 环境体检 |
| `print_report()` | 打印工具表与组件表 |
| `ensure_api_key()` | 没 Key 时引导输入，写入 `.env` |
| `_verify_key()` | 连通性验证（顺便识别 Key 明显填错的情况） |
| `BootstrapResult.can_chat()` | 判定能不能进对话 |

### `core/config_loader.py`（470 行）—— 配置层

优先级：**环境变量 > config.yaml > 内置默认值**。

| 类 | 管什么 |
|---|---|
| `ScanConfig` | 扫描行为（超时、并发、只读、代理、各采集开关） |
| `RAGConfig` | 检索行为 + 知识沉淀门控 |
| `LLMConfig` | 大模型接入。**模型名以 `llm/models.py` 注册表为准，不在这里硬编码** |
| `Config` | 三段合一 |

`load_config()` 载入并做模型名解析；`sessions_dir(cfg)` 算会话目录。

**环境变量三条统一规则**（以前是三种脾气，同一批参数行为相反）：

| 规则 | 实现 | 修之前 |
|---|---|---|
| 空串 = 未设置 | `_env_raw()` 统一入口 | `POCS_READONLY=""` 会把只读**关掉**（危险方向），`POCS_PORT_SCAN=""` 却什么都不做 |
| 类型错 = 保留默认 + 一行警告 | `_env_int()` / `_env_float()` / `_env_bool()` | `POCS_TIMEOUT=abc` 直接 `ValueError` 崩在启动路径 |
| 不认识的值 = 保留默认 | `_env_bool()` 的 `_TRUE`/`_FALSE` 集合 | 静默当 `False`——对"关掉就有风险"的参数是最坏的默认 |

`_env_list(key, default, sep=",")` —— 列表型参数的统一解析（`POCS_NO_PROXY` 用），
逗号/分号皆可作分隔，去空白、丢空项。

`ScanConfig` 新增两个代理字段：`no_proxy: list[str]`、`proxy_autodetect: bool = True`。
`load_config()` 末尾（`_resolve_llm_models` 之前）会按 `proxy_autodetect` 决定是否调
`core/proxy.detect_and_apply()` 把探测结果写回 `cfg.proxy`。

`_apply_section()` 现在逐字段走 pydantic 校验：

| 模块点 | 作用 |
|---|---|
| `_apply_section(cfg, raw)` | yaml 段 → 配置对象，**逐字段 model_validate** |
| `_safe_dump(cfg)` | 取当前值且**不触发 pydantic 序列化告警**（否则配错一行刷一屏 UserWarning） |
| `_brief(exc)` | 把 4 行 ValidationError 压成一行，用户才看得见要改哪 |
| `_warn(msg)` | stderr 一行；`POCS_QUIET_CONFIG=1` 可关 |

退化路径的基线**只放本段已接受的字段**——用整段 `model_dump()` 当基线，
一个坏字段会让同段合法值一起被否掉（实测 `min_score=0.2` 也跟着丢）。

### `core/envfile.py`（133 行）—— 极小的 `.env` 读写

只用两个能力，不值得为一个 300 行的依赖多装一个包。

| 函数 | 作用 |
|---|---|
| `parse_env(text)` | 解析 `.env` 文本（支持 `export KEY=value`、引号） |
| `load_env_file()` | 读进 `os.environ`，**不覆盖已有环境变量** |
| `set_env_value()` | 写入并保留其他行 |
| `mask(secret)` | 脱敏显示（只留末 4 位） |

### `core/proxy.py`（431 行）★★ 本机代理探测与分流

**解决的问题**：渗透机上常同时挂着 env 代理（Burp/网关注入）和 Windows 系统代理
（Clash 分流）。项目原本一律 `trust_env=False`，两套全被无视 → "挂了代理却全程直连"。

**但"有代理" ≠ "所有目标都走代理"**，模块把两件事拆开：

| 函数 | 回答的问题 |
|---|---|
| `detect_proxy()` | 本机**有没有**代理？（只读 env + 注册表，**不发网络请求**） |
| `resolve_proxy_for(cfg, host)` | **这个**目标该不该走代理？ |
| `build_client_kwargs(cfg, url)` | 给 httpx 用的 kwargs（唯一出口，各客户端共用） |
| `detect_and_apply(cfg)` | 探测结果写回 `cfg.proxy` |

| 检测来源 | 实现 |
|---|---|
| 环境变量 | `_read_env()`：`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`（大小写各查一遍） |
| Windows 系统代理 | `_read_system_windows()`：读注册表 `Internet Settings` 的 `ProxyEnable`/`ProxyServer`/`ProxyOverride` |

**核心约束——内网/本机目标强制直连**：

```python
if is_local_host(host):   # 回环 / *.local / *.internal / 10. / 172.16-31. / 192.168. / 169.254.
    return None           # 绝不发给外部代理
```

> 被测目标常是**物理机网口 IP**。送给公网代理轻则全 502，
> 重则把内网存活情况泄露给代理方。Windows `ProxyOverride` 自带这张分流表，
> 裸环境变量没有——这就是两者差异的根源。

`_match_no_proxy()` 支持精确 / `.后缀` / CIDR（`10.0.0.0/8`）/ 通配前缀（`192.168.*`）/ `*`。

**安全设计**：探测路径**不 import `httpx`/`requests`/`socket`**，纯 env + 注册表读取，
所以在 `readonly=true` 下也安全（`scripts/proxy_test.py` 场景 8 用 `ast.parse` 守着这条）。

优先级：**显式配置 > 环境变量 > 系统代理**。`config.yaml`/`POCS_PROXY` 写死的永远最高。

> 端口扫描（`collectors/port_scan.py`）走**裸 TCP**，HTTP 代理无法转发任意 TCP，始终直连。

### `core/subdomain.py`（537 行）—— 子域批量扫描

`scan` 只接单个 URL，但更常见的是「一百个子域全扫一遍」。这个模块处理两个特有的坑：

1. **子域大多不可达** —— 不可达的如果照常跑完整流水线，报告里会塞满「连接失败」，把真发现淹掉。所以先 `probe` 探活再决定要不要跑全量
2. **输入格式混乱** —— 可能是纯文本、JSON、字典、带噪声域名（w3.org、schema.org 这类），统一解析收敛到主域

| 模块点 | 作用 |
|---|---|
| `normalize_host()` / `extract_hosts()` / `parse_input()` | 多格式输入解析与收敛 |
| `SubdomainScanner.run(urls, mode)` | 并发扫描；`mode=probe` 只探活，`mode=full` 跑全量 |
| `SubScanEntry` / `SubScanReport` | 单条结果与汇总（可达数、发现总数、按严重度分布） |
| `MAX_TARGETS = 500` | 上限保护 |

> **这个模块是"怎么扫"，不是"怎么找"。** 拿到主机名清单的活儿在
> `collectors/subdomain_extract.py`（多源被动枚举 + 排列组合）——
> 两者输入输出不同，分开维护。

---

## 3. `detectors/` —— 验证层

### `detectors/base.py`（464 行）★ 检测器基类

调度器只知道「给一个 POC 和目标，告诉我有没有发现」。怎么发请求、怎么抑制软 404、怎么留证据，全收敛在基类。

| 模块点 | 作用 |
|---|---|
| `send_request()` | 发请求并构造 `Evidence`，顺带填 `payload_sent` / `expected` / `full_body`（完整响应体上限 64KB，运行期专用不进快照） |
| `learn_soft404()` / `is_soft404()` | **软 404 抑制**（本模块最关键的逻辑）。路径探测误报的根源是目标对任何路径都返回 200，必须先探一个随机路径当基线再比对 |
| `similarity()` / `normalize_body()` | 响应相似度比对 |
| `rules_match()` / `rule_hit_reason()` | 跑匹配规则 / 解释「凭什么算命中」 |
| **`persist_evidence(evdir, ev, require_status=True)`** | **模块级函数**（不是方法）：把完整原始报文（请求 + `[RESPONSE]` + 响应）写到 `scan.evidence_dir`（默认 `<output_dir>/evidence`，`off` 关闭），返回 artifact 相对路径。**探针与手工登记共用同一份**——两个入口必须写同一种格式，否则报告里自动发现与手工发现的 PoC 会呈现两种样子。`require_status=False` 供手工登记用（模型粘贴的响应可能没抄状态行）。文件名哈希含 URL（/users/1 与 /users/2 返回相同页面不撞名）；`ev.body_size` 大于实际字节数时在文件尾附 `[TRUNCATED]` 标注 |
| **`_persist_evidence()`** | 一行委托给上面的模块级函数，只为保持 `Detector` 内部调用点不变 |
| `make_finding()` | 生成 `Finding`，把命中的规则写进 `Evidence.matched_pattern`，并落盘完整报文 |
| `probe_soft404()` | 探基线 |
| `run_many()` | 并发跑一批 POC |
| `verify()`（抽象方法） | 子类实现具体验证逻辑 |

**代理感知的客户端**：`client(url)` 会按 URL 主机名调 `resolve_proxy_for()`，
**决策变化时重建 client**（旧 client 异步关闭）——避免"这个目标走代理、那个直连"时
复用错连接。决策全部收敛在 `core/proxy.py`，不散落。

`_payload_of()` / `_expect_of()` —— 把 POC 定义翻成人话（`_OP_CN` / `_TARGET_CN` 做中英映射），供报告输出「怎么执行的」。

### `detectors/public_check.py`（467 行）★★ 公开性核验（降误报）

**解决的问题**：自动探针判不了"设计如此"。最典型的一类是**公开演示站点**——
站点本就建给人看，"泄露"出来的配置、默认账号、接口文档是有意公开的。
人工判定靠的也是证据，只是没被写成规则；这个模块把那些证据写成规则。

| 模块点 | 作用 |
|---|---|
| `PublicResourceChecker.context(base)` | 取（或复用）该 host 的证据：`GET /` + `/robots.txt` + `/sitemap.xml`，**一个 host 只抓一次** |
| `PublicResourceChecker.evaluate(ctx, finding)` | **纯函数判定**（不发请求），便于离线测试 |
| `check_many(base, findings)` | 一批发现共用一份 host 上下文——不会"每条都回源"把目标打一遍 |
| `HostContext` | 证据载体：`root_ok`（根页面真的拿到了没）/ `links`（首页同域链接）/ `sitemap_paths` / `robots_denied` |
| `PublicVerdict` | 判定结果：`score` + `confidence`(strong/suspect/weak/none) + `reasons` + `reason_text()` |
| `normalize_path()` / `path_of()` / `host_of()` | 路径与主机归一（小写、去尾斜杠、去默认端口） |
| `page_title()` / `page_text()` / `page_links()` / `sitemap_paths()` / `robots_disallows()` | 纯解析函数，全部正则可测 |

**权重与阈值**（`W_LINKED=3` / `W_SELF_DESC=2` / `W_WEAK_DESC=1` /
`W_PUBLIC_DIR=1` / `W_DEMO_HOST=1` / `W_ROBOTS_DENY=-2`；`SCORE_STRONG=3`）：

| 档位 | 分数 | 处置 |
|---|---|---|
| strong | ≥ 3 | **自动判误报**。两条路：站点自己公开挂了它的链接（资源级证据），或「自述演示站 + demo 主机名/公开目录」叠加 |
| suspect | = 2 | 不自动删，报"疑似公开，建议人工确认" |
| weak | = 1 | 只提示 |
| none | ≤ 0 | 不动 |

**门槛为什么不定在 2**：2 分 = 只有「根页面自述演示站」。而这类措辞在**真实产品
营销页**上随处可见（"请申请演示环境"就命中 `演示环境`）——拿它自动删掉整站所有
发现是在用误删风险换省事。**删掉一条真实漏洞的代价远大于多留一条误报。**

两条工程约束：

1. **网络失败绝不当成"公开"**：`root_ok=False` 时单独走一条分支、如实报
   "无证据不判定"。空 title/body 一路打分也算 0 分，但那会把"没查到"说成
   "查到没有"——两种结论对用户的意义完全不同。
2. **读取上限 256 KB**：只看首页/sitemap 的头部，不设上限会被一个几百 MB 的
   下载响应拖死。

`static` 常量 `_STRONG_SELF_DESC` 刻意**不收裸词 `demo`**——营销页上"预约演示"
"申请演示"随处可见，单独一个词不能说明站点是公开的，必须成句。

### `detectors/poc_loader.py`（140 行）—— POC YAML 编译

| 函数 | 作用 |
|---|---|
| `parse_poc_file()` | 单个 YAML → `POC` 对象（校验必填 `id` / `name`） |
| `load_poc_dir()` / `load_poc_map()` | 批量加载 / 加载成字典 |
| `filter_executable()` | 按只读模式与严重度下限过滤；`_DEDICATED_CATEGORIES`（injection / rce / file_op / js_logic）交给专用探测器，不走通用 HTTP 检测器 |

### `detectors/http_detector.py`（171 行）—— 通用 HTTP 检测器

覆盖 POC 库里的绝大多数类别。流程：对每个 path 发请求 → 是不是软 404 → 状态码或规则命中？→ 全部 match 规则求值 → 生成 Finding。

| 类 | 职责 |
|---|---|
| `HttpDetector` | `_verify_header()` 查响应头、`_verify_http()` 查路径与内容 |
| `FingerprintDetector` | 指纹识别。**单独成类是因为它的产物不是 Finding 而是目标画像**，且要读更大的响应体（技术栈线索常在 JS/CSS 里） |

### `detectors/api_authz.py`（332 行）—— 接口鉴权检测器（第 3 轮主力）

三条检查线，各对应一个 POC：

| 方法 | 检查 |
|---|---|
| `probe_missing_auth()` | 声明了鉴权却不带凭证也能读 → 未授权访问 |
| `probe_idor()` | 换掉资源 id 仍能读 → 越权 / IDOR |
| `probe_sensitive()` | 响应体里出现凭据材料 → 敏感字段出网 |
| `_rank()` | 按「高价值 + 有 id 参数 + GET」排序，优先测值钱的接口 |

两条必须记住的实现约束：**不能只看状态码**（业务码 200 但 `data` 为空其实是拒绝），所以 `biz_ok()` 会检查响应里有没有真正的 payload；`ERROR_ONLY_KEYS` 用来识别「只有错误字段」的空响应。

### `detectors/exploit/`（10 个模块）★★ 一次性高危探针

**拆分**：规则层 `consts`（WAF 特征 / 状态标记）/ `ops`（接口模型，按价值排序）/ `sqli_rules`（SQLi 判定规则与 payload 表）/ `payloads`（RCE / 文件读）/ `template`（四类漏洞的发现模板）；类拆 `probe`（`_ProbeBase`，构造与请求构造）/ `sqli_mixin`（两轮制：先试再升级）/ `attack`（RCE·文件读·上传，上传走人工审批）/ `run`。

SQL 注入（放行全规则，只取版本号/库名）/ RCE / 任意文件读 / 任意文件上传（开放但逐条审核）。

**四条设计原则：**
1. **每个接口、每类漏洞只尝试一次** —— 命中就停，没命中就跳。既是效率问题（40 接口 × 4 类 × N payload 会拖到几十分钟），也是边界问题
2. **SQLi 的目标是数据库版本号，底线是数据库名，拿到就停** —— 不拖库、不读表结构
3. **识别 WAF 拦截** —— `_looks_blocked()` 与 `_WAF_RES` 区分「真的没有」和「被挡了」
4. **上传已开放，但每次都要人工审核** —— 闸门从 `readonly` 换成 `approver`：没有审核通道就一个请求都不发

**SQL 注入的两轮制**（放行全部规则 ≠ 无节制发请求）：

| 轮次 | 做什么 |
|---|---|
| 第 1 轮 | 对每个接口只打 2 条最通用 payload，用 SQL 报错特征筛出候选点 |
| 第 2 轮 | 只对候选点放开**全部**规则（5 种 DBMS 报错 + 5 种 UNION × 1/2/3 列），先拼版本号、取不到再退到库名 |
| 终止 | `self.sqli_goal` 一旦有值，后续任何注入请求都不再发出（包括再次调用 `_sweep_sqli`） |

UNION 的值用**本轮唯一标记** `self.tag` 包起来：`页面出现了这个值` ≡ `它确实来自数据库`，
所以 `_classify_version()` 不再需要关键词佐证（这是与 `_sql_version()` 的唯一区别）。

| 模块点 | 作用 |
|---|---|
| `Op` / `ops_from_assets()` | 可探测接口（方法+路径+参数名）的抽象 |
| `sql_payloads()` / `rce_payloads()` / `lfi_payloads()` | 各类 payload 生成 |
| `sqli_plan()` | 全规则执行序列 `(goal, dbms, payload)`：版本号条目全部排在库名之前 |
| `_extract(body)` | 从网页返回取值：`UNION 标记 → 报错版本号 → 报错库名`，取不到返回 None |
| `_sweep_sqli()` | 两轮制 + `sqli_max_requests` 预算 + 拿到就停 |
| `_mk_sqli()` | 生成发现：版本号 → CRITICAL，库名 → HIGH |
| `_sweep()` | 统一的「打一轮 + 判定」骨架（rce / fileread） |
| `_upload_allowed()` | 上传闸门：`file_upload_probe_enabled` + **必须有 approver** |
| `probe_upload()` | 每个接口发起前都走一次 `approver(desc)`，异常按拒绝处理 |
| `_multipart()` | 构造 multipart 请求体 |

### `detectors/js_logic.py`（约 520 行）—— 前端 JS 逻辑审计

`collectors/js_analyze` 做的是「资产提取」（这里有什么），而前端真正值钱的漏洞藏在**逻辑**里：权限判断写在前端（`role === 'admin'`）、调试开关没关（`bypassAuth: true`）、加解密密钥硬编码。

| 模块点 | 作用 |
|---|---|
| `LogicRule` | 一条审计规则（正则 + 严重度 + 说明） |
| `JsSource` | 一份 JS 内容（外链或内联） |
| `collect()` | 抓页面所有 JS。**复用 `JsAnalyzer._crawl`**——只取 `<script src>` 会漏掉所有路由懒加载 chunk |
| `analyze()` | 跑逻辑规则、找硬编码密钥 |
| `endpoints()` | 走 `extract_endpoints`（同一提取器），按 `ep_rank()` 排序 |
| `ep_rank(v)` | 排序权重：后台类 → 带 `.aspx/.php/.do` → 段数多 → 短。放宽提取后**靠排序沉底噪声，不靠丢弃** |
| `probe_endpoints()` | 打一次免凭证 GET 验证未授权（名额 `js_logic_max_endpoints`，默认 60） |
| `_mk_logic()` | 生成逻辑漏洞发现 |

---

## 4. `collectors/` —— 资产采集层

### `collectors/port_scan.py`（190 行）—— 端口探测

两条路径自动降级：**原生 asyncio socket**（默认，零依赖，能区分 `closed` 与 `filtered`）→ **nmap**（若 PATH 中有，拿服务指纹但慢 100 倍）。只做 connect 扫描，不做 SYN 扫描。

> **端口扫描始终直连，不走代理**：走的是裸 TCP（`asyncio.open_connection`），
> HTTP 代理无法转发任意 TCP 连接。见 `core/proxy.py`。

### `collectors/path_scan.py`（207 行）—— 目录/路径爆破

- **自实现**（默认）：内置约 120 条高价值字典（配置泄露、备份文件、调试端点、管理后台、API 前缀），靠软 404 基线判断路径真存在
- **dirsearch**（若 PATH 中有）：字典更大、支持通配符与状态码过滤

不内置大规模字典——那是 dirsearch 的职责，重复造轮子没意义。

### `collectors/openapi.py`（268 行）★ 接口文档采集（第 1 轮主力）

**接口文档是最准确的资产清单**：目录爆破是在猜，文档是目标自己承认的东西（实测某目标：爆破命中个位数，文档直接给出 404 条路径 / 507 个操作）。

| 模块点 | 作用 |
|---|---|
| `find_spec()` | 按 `SPEC_CANDIDATES` 探测常见文档路径 |
| `fetch()` / `operations()` | 下载解析，产出操作清单 |
| `Operation` | 一个 API 操作，带 `is_admin` / `is_high_value` / `has_id` / `is_upload` 判定——**这些标记直接决定后面测什么** |
| `save_spec()` / `load_operations()` | 落盘复用，后续轮次不用重下 |

### `collectors/js_analyze.py`（约 420 行）—— JS 静态分析 ★

从 JS 里提取四类资产：endpoint（后端接口路径）、secret（硬编码密钥）、internal（内网地址）、map（source map）。`_INTERNAL_ALLOW` 过滤掉 127.0.0.1 / localhost 这类噪声。

**三个曾经把结果压到个位数的硬限制（已全部放开）**：

| 限制 | 旧 | 新 |
|---|---|---|
| 单文件抓取 | `max_body_capture` 4KB（只扫到 license 注释） | `js_max_bytes` 2MB，走 `send_request(capture_limit=)` |
| 接口路径 | 11 个业务前缀白名单（`api\|v\d\|rest\|…`） | **结构判别**，不猜业务词 |
| 脚本发现 | 只读 HTML 的 `<script src>` | 模块图 BFS 跟进 `import` / `from` / `require` / `import()` |

| 模块点 | 作用 |
|---|---|
| `extract_endpoints(text, base)` | 三路并集：绝对路径 / 函数调用实参（压缩别名 `o("path",t)`）/ url 字段。相对路径按 baseURL 拼绝对路径 |
| `extract_base_url(text)` | 取 `baseURL:"/api"`；完整 URL 的 base 只取 path（跨域拼 host 会破坏同源判定） |
| `_looks_like_path()` | 结构判别的眼：多段 + 含字母 + 非静态资源 + 非 MIME + 非 hash 路由 + 非 import 引用 |
| `_in_import_context()` | 命中位置前面紧邻 `from`/`import`/`require` → 模块引用，不是接口 |
| `import_edges(text, url)` | 模块图的边；裸模块名（`vue`）与非脚本文件跳过 |
| `_crawl(seeds)` | BFS 下载，`js_max_files` 是**跨层共享**的总预算，`js_max_depth` 是层数 |
| `run()` | 首页（也用 2MB 上限，否则 SPA 的内联脚本会截掉 `<script src>`）→ 爬 → 提取 → 去重 |

> **抓取上限必须和 `max_body_capture` 分开**：后者 4KB 是给"报告里贴一段响应"
> 用的，拿它截 JS 等于只扫文件头。这一条独立解释了实网里"只挖到 5 个接口"。

### `collectors/subdomain_extract.py`（324 行）—— 子域被动枚举 ★

``core/subdomain.py`` 负责"给我一批域名，我并发扫完"，起点是**已经拿到手的**主机名清单；本模块负责**怎么把这份清单拿到手**——两者输入输出都不一样，混一起只会互相拖累。

**只做被动枚举 + 简单排列组合**，不需要任何外部工具（都是 HTTP API，现有 httpx 即可）。
但**数据源必须多**——单源在实网里不可靠：

| 源 | 入口 | 坑 |
|---|---|---|
| `crt.sh` | `?q=%.X&output=json` | 证书透明日志，可信度最高；**会整站 502**（连根路径也 502） |
| `hackertarget` | `api.hackertarget.com/hostsearch/?q=X` | 命中率高；免费 50 次/天，超限返回**正文** `API count exceeded` 而非 HTTP 错误 |
| `rapiddns` | `rapiddns.io/subdomain/X?full=1` | 返回 **HTML**，域名在 `<tbody>` 每行第一个 `<td>`；"0 条"不是错，**结构变了**要报错 |
| `urlscan` | `urlscan.io/api/v1/search/?q=domain:X` | `domain:` 过滤**很松**，实测混进无关域名——结果必须逐条严格收敛 |
| `otx` | `otx.alienvault.com/.../passive_dns` | 限流严（429）；**404 是"没记录"不是失败** |

| 模块点 | 作用 |
|---|---|
| `query_passive()` | **并发**查全部源，返回 `{源名: 子域集}`。每源独立降级 + 源级硬超时（`SOURCE_TIMEOUT`） |
| `merge_sources()` | 合并去重；同一主机名按 `SOURCE_PRIORITY` 归给**最可信**的源 |
| `_src_*()` | 各源实现（crt_sh / hackertarget / rapiddns / urlscan / otx）。约定**只抛 `_SourceFail` 表达失败**，不自己吞；是否降级由聚合层决定 |
| `query_crtsh()` | 单源兼容出口（老调用方/测试用）。**新代码请用 `query_passive()`** |
| `_accept()` | 清洗记录：剥通配符 `*`、拆换行分隔的多域名、按主域收敛、逐标签校验挡脏数据。**所有源都过这道闸门** |
| `permute()` | 减前缀 / 换同级前缀。**只做这两种**，不做"给主域加服务前缀"的爆破 |
| `main_domain()` | 抽出**注册域**。多段公共后缀最长匹配（`PUBLIC_SUFFIXES`）；IP / 公共后缀本身 → 拒绝 |
| `SubdomainCandidate` | 带 `source`（任一被动源名 / `permutation`）与 `guessed` 标志——**区分"被动源里来的"和"猜的"** |
| `assets()` | 便捷出口，直接产出 `Asset(kind="subdomain")` |

**四个必踩的坑**（都已在测试里锁死）：

1. **crt.sh 会整站 502。** 实测连根路径 `https://crt.sh/` 都返回 nginx 502。曾经**只有一个源**，于是子域枚举彻底失效——`gdust.edu.cn` 一役颗粒无收，报告只能写"子域攻击面本轮未能覆盖"；事后 hackertarget 一查拿到 **21 个子域**（9 个是用户清单里没有的）。**教训：单点数据源不可接受，且失败必须留痕**（"源挂了"≠"源说没有"，前者静默就会被当成"该域没资产"）。
2. **主域不能"取最后两段"。** `gdust.edu.cn → edu.cn`、`example.com.cn → com.cn`、`x.example.co.uk → co.uk`。后果双重：查询 `%.edu.cn` 拉回全国高校域名（几十万条、必然超时且污染结果），排列组合产出 `dev.edu.cn` 垃圾。修法是内置精简公共后缀表做最长匹配（刻意不引 `publicsuffixlist`）。
3. **`name_value` 是换行分隔的。** `"a.example.com\nb.example.com"` 不拆就把整串当一个主机名。
4. **换前缀会堆叠。** 早期版本只看"最左段是不是环境前缀"，于是 `admin.portal.example.com` 被当成 `admin` + `portal.example.com`，产出 `dev.portal.example.com` / `portal.portal.example.com` 这类垃圾——实测 6 个真子域被放大成 **24 个噪音候选**。修法是加互斥条件：**仅当其余部分恰好就是主域时**才换前缀（修正后 24 → 11）。

### `collectors/dirsearch_runner.py`（356 行）—— dirsearch 统一封装

项目里有两处会调 dirsearch（单域爆破、子域批量），此前各自拼 argv，**谁都没处理「被 WAF/限流拦截」这个必然发生的情况**——dirsearch v0.4.3 没有内置 429/403 降速重试。

| 模块点 | 作用 |
|---|---|
| `run_with_throttle_retry()` | **核心**：检测到拦截就降速重试 |
| `looks_blocked()` | 判定是否被拦（识别 Cloudflare / 阿里云 / 安全狗等特征） |
| `build_argv()` / `parse_output()` | 拼参数、解析结果 |
| `to_assets()` | 转成 `Asset` 列表 |

---

## 5. `kb/` —— 检索与知识

### `kb/indexer.py`（477 行）★ 向量索引：混合检索（余弦 + BM25）

**为什么自己实现而不用 Chroma**——POC 库只有几十到几百条，引入 Chroma 意味着多一个 ~100MB 依赖树（chromadb → onnxruntime → …），收益几乎为零。所以用 **hashing trick + 稀疏余弦**在纯 Python 里实现。

**为什么必须混合**（实测踩出来的坑）：最初只用 TF-IDF 余弦，在 22 条 POC 的小语料上几乎不可用——query 向量的非零维度远多于文档向量，余弦值被稀释。加 BM25 才救回来。

| 模块点 | 作用 |
|---|---|
| `tokenize()` | 中英混合分词（`_WORD_RE` 英文、`_CJK_RE` 中文、`_EXTRA_TERMS` 补 CVE/RCE/SSRF 这类术语） |
| `VectorStore.add()` / `add_record()` | 加入索引；`_unaccount_df()` 在覆盖同 id 文档前**撤回旧词频**（增量写入的幂等性前提） |
| `search()` | 余弦 × BM25 混合打分 |
| `to_payload()` / `from_payload()` / `save()` / `load()` | 序列化。**必须连 BM25 词频表一起存**——向量是有损的，词频反推不出来 |
| `build_index()` / `index_is_stale()` | 建索引 / 按 mtime 判断索引是否过期 |
| `debug_search()` / `dump_index_stats()` | 调试用 |

### `kb/retriever.py`（360 行）—— RAG 检索器

流程：指纹 + 资产 → 构造 query → 向量召回 top_k → 技术栈降权 → （可选）LLM 重排 → 最终 POC 列表。

**为什么召回之后还要 LLM 重排**：纯向量检索是「词袋相似」，它无法理解「目标是 Spring Boot 2.x 而这条 POC 针对 1.x」这类关系。重排让模型基于结构化元数据做二次判断。

| 模块点 | 作用 |
|---|---|
| `build_query(result)` | 从指纹与资产构造检索 query |
| `Retriever.retrieve()` | 召回 + 降权 |
| `_mismatch_penalty()` | 技术栈不匹配时降权 |
| `_add_baseline()` | 兜底：低分也至少跑基线项 |
| `rerank_with_llm()` | LLM 重排 |
| `RetrievalResult.to_dict()` | 写进会话快照，便于复盘「为什么跑了这些 POC」 |

### `kb/intel.py`（422 行）—— 外部 CVE 情报（pocindex.io）

RAG 的第二知识源。公开 CVE 元数据索引站，提供若干可直接下载的 JSON 端点。

| 模块点 | 作用 |
|---|---|
| `IntelStore` | 本地缓存（24 小时 TTL），避免每次联网 |
| `lookup()` / `lookup_many()` | 查单条 / 批量 |
| `enrich()` | 用情报补充 POC 的 tags（比如某 CVE 在 KEV 名单里 → 优先级提高） |
| `_parse_epss()` / `_parse_kev()` / `_parse_nuclei()` | 解析各类情报端点 |
| `extract_cve_ids()` | 从文本里抽 CVE 编号 |

### `kb/knowledge.py`（379 行）★ 知识沉淀：把发现变回知识

原本 `kb/` 是**单向**的：人写 YAML → 建索引 → 检索。扫描结果只流向 `output/` 和 `data/sessions/`，终点是文件不是知识。同一个站反复测，每次都要从头踩坑。

**三道门控**（宁可漏沉淀，也不能让误报污染召回——误报入库 → 下次被召回 → 更倾向报成漏洞，是正反馈污染）：
1. 等级 ≥ medium
2. `confirmed` 且非误报
3. 有 `matched_at` 证据

**外加一条人工排除**：`dismissed=True` 的一律不沉淀。这一条**必须显式判**——
人工排除刻意不改 `verdict` / `confirmed`（那两个是客观结论，改了撤销就有损），
只靠上面第 2 条是拦不住的。`IngestReport` 里单列 `rejected_dismissed`
统计，避免跟 LLM 判的"误报"混在一起（否则用户会以为是自己研判出来的）。

| 模块点 | 作用 |
|---|---|
| `finding_to_record()` | 一条发现 → 知识记录 |
| `KnowledgeStore.ingest_findings()` | 批量沉淀，返回 `IngestReport`（含各类拒绝的归因统计） |
| `_fingerprint()` | 去重指纹 `sha1(目标|poc_id|分类|路径)`，**不含严重度与时间戳** |
| `_evict()` | 超容量按最后更新淘汰最旧 |
| `search()` / `recent()` / `summary()` | 检索与查看 |

**独立索引文件**（`knowledge_index.json`），不与 POC 索引混用——混在一起会破坏 `index_is_stale` 的 mtime 判定。

---

## 6. `llm/` —— 大模型接入

### `llm/client.py`（523 行）—— OpenAI 兼容客户端

覆盖 DeepSeek / OpenAI / vLLM / Ollama 等所有兼容 `/v1/chat/completions` 的服务，换厂商只需改 `base_url` 与 `model`。

**四个任务**：

| 方法 | 任务 |
|---|---|
| `rerank_pocs()` | RAG 召回后的 LLM 重排 |
| `triage()` | 研判命中是真阳性 / 误报 / 待人工 |
| `write_report()` | 生成报告正文 |
| `suggest_fix()` | 生成修复建议 |
| `ask()` / `stream_chat()` | 底层：非流式 / 流式对话 |

几个关键实现点：
- `model_for(role)` —— 按任务角色选模型（快模型 vs 深度模型）
- `STREAM_MIN_TOKENS = 8192` —— **流式默认下限**。曾经没传 `max_tokens` 导致回落到 2048，写长报告被静默截断，表现是「模型开始重复章节」看起来像发疯
- `stream_chat()` 检查 `finish_reason == "length"` —— 截断时抛错并提示分批处理，**且不再发 `done`**（否则上层把半截当完整结果）
- `_report_ok()` —— 报告校验器：长度不足 / 含「证据已充分」这类占位语 / 章节缺失 → 判定不可用，回退模板报告
- `_is_tools_unsupported()` —— 识别模型不支持 function calling 的情况并降级
- `rerank_by_vector()` —— LLM 不可用时的向量兜底排序

### `llm/models.py`（233 行）—— 模型注册表

**模型名在代码里散落成裸字符串时有两个具体后果**：改名要全文搜索（厂商调一次命名，五处都要改，漏一处就是线上跑旧名）；能力差异无处表达（pro 与 flash 成本差一个量级却没人知道）。

| 模块点 | 作用 |
|---|---|
| `ModelSpec` | 一个模型的能力与成本画像（`is_pro` 判定） |
| `specs()` / `names()` / `get()` | 注册表访问 |
| `resolve()` / `normalize()` | 旧名映射、别名归一 |
| `for_role(cfg_model, cfg_deep_model, role)` | 按角色选模型 |
| `describe_table()` / `describe_shorthand()` | 给 `models` 命令用 |
| `ROLE_FAST` / `ROLE_DEEP` | 两个角色常量 |

### `llm/prompt.py`（433 行）—— 提示词模板：本项目的提示工程核心资产

**四条设计原则**：
1. **角色 + 任务 + 约束 + 格式**四段式。模型对结构化约束的遵守率远高于散文式提问
2. **反幻觉约束写进 system 而不是靠祈祷**。每次研判都显式声明「只能依据给出的 HTTP 证据，禁止推测未出现的信息」
3. **给判断标准，不给形容词**。「认真分析」没用；「401/403 视为拒绝」才有用
4. **少样本示例（few-shot）比描述有效**——`TRIAGE_FEWSHOT` 直接给一个真实误报的判例

| 模板 | 用途 |
|---|---|
| `RERANK_SYSTEM` + `render_rerank()` | POC 重排打分 |
| `TRIAGE_SYSTEM` + `render_triage()` | 命中研判（含 few-shot） |
| `REPORT_SYSTEM` + `render_report()` | 报告正文。**只喂结构化素材，正文全由模型生成**——曾经喂了一份写好的骨架让模型「补三段」，模型以为自己在审稿，于是输出「证据已充分」 |
| `FIX_SUGGEST_SYSTEM` + `render_fix_suggest()` | 修复建议 |
| `AGENT_SYSTEM` + `render_agent()` | Agent 系统提示，含「手工验证必须登记」的纪律 |
| `render_profile()` | 目标画像 |

---

## 7. `output/` —— 产出层

### `output/report/`（8 个模块）—— 三份产物

**拆分**：`naming`（slugify / 主域名裁剪，依赖链的根）/ `paths`（落哪·叫什么·撞名怎么办，`overwrite` 只在这里定一次）/ `notes`（时间戳 + notes 去重，抽出后三份产物共用而不成环）/ `json` / `markdown`（含模板正文兜底）/ `evidence`（Burp 式报文转写）/ `html`。
`evidence` 必须被 markdown 与 html **共享**——否则同一条漏洞会贴出两份不一致的报文。

| 格式 | 分工 |
|---|---|
| **JSON** | 机器可读，给 CI / 二次分析。额外带 RAG 检索详情、LLM 调用统计、阶段耗时——**「为什么报了这条」能事后复盘**；顶层还带 `active_findings` / `excluded` 汇总，消费方不必自己遍历 `dismissed` 标记 |
| **Markdown** | 人读 / 交付给甲方的主格式。发现详情（`## 渗透测试结果`）按每条漏洞 `4.X [等级] 名称` 组织：`漏洞描述` → `PoC` → `安全建议`；PoC 段是 **Burp 式报文**（`>>> 请求:` / `<<< 响应:`，`_burp_transcript()`：artifact 落盘文件优先、字段重建兜底、截断如实标注；**请求完整展示**（仅 64KB 防爆上限），**响应只给大概内容**（6000 字符上限）——复现靠请求，判断漏洞成立靠「请求 + 命中特征」）。含**「已排除的发现（误报复核）」附录** |
| **HTML** | 自包含单文件（无外部 CSS/JS 依赖），可直接发邮件 |

**误报的处理**：`counts()` / `by_severity()` 只算有效发现（在 `ScanResult` 里定义），
所以概览数字、风险概览表、发现详情**自动**不含已排除项——不必在报告层到处加
过滤条件（加漏一处就会出现"报告里删了、概览里还在"）。

被排除的项**不能悄悄消失**：客户一定会问「上次报的 XX 怎么没了」。
所以单列一节复核附录，写明位置、原因、时间；被排除项本身留在
`result.findings` 里（`dismissed=True`），报告只是不把它计入统计。

| 模块点 | 作用 |
|---|---|
| `write_json()` / `write_markdown()` / `write_html()` | 三种格式。都带 `overwrite` 参数，**默认 True = 就地覆盖同一份文件** |
| `_target()` | 覆盖模式直接用 `<stem><suffix>`；`overwrite=False` 才走 `_unique_path()` 追加 `_2`/`_3` |
| `report_paths()` | 预先算出三种格式将写入的确定路径——调用方据此说明「新建了哪些、覆盖了哪些」（覆盖必须可见，不能静默） |

**为什么默认改成覆盖**：报告是**可重新生成的产物**（证据文件在 `evidence/` 里另存，
不受影响），覆盖丢掉的只是上一次渲染结果。而旧行为"每次都加 `_2`"的代价是实打实的：
用户得猜哪份是最新的，智能体也没法接着上一份改。要留档传 `overwrite=False`。
| `_render_template_md()` | 模板正文（**永远完整渲染发现详情，AI 正文只作补充，绝不替换**） |
| `_asset_section()` / `_model_rows()` | 资产表、业务模型表 |
| `_dedupe_notes()` | 把重复的执行说明折叠成「原句（重复 N 次）」 |
| **`_burp_transcript(ev, outdir, description)`** | 构造 Burp 式请求/响应对，返回 (请求, 响应, 备注)。**请求完整、响应概要**——`_cap_request` 只受 64KB 防爆上限约束，`_cap_response` 才是 6000 字符展示上限。早期版本对两者用同一个 6000 字符上限，等于**把复现所依赖的请求包也砍了尾巴**（少一个 Cookie / 路径参数，粘到 Repeater 就不是同一个请求）。数据源优先级：artifact 落盘文件 > Evidence 字段重建。**`description` 参数是防伪的关键**：老版本把说明文字同时塞进 `body_excerpt`，渲染时若直接信任它，`<<< 响应:` 下面就会出现一段中文分析——**把分析文字摆在响应位置比留空更糟，它看起来像证据**。命中 `_looks_like_analysis` 时清空正文并写明"已剔除" |
| `_looks_like_analysis()` | 判据的薄壳，实体在 `core.rawmsg.looks_like_analysis`（回填也要用同一个）。删空白后完全相同、或前 200 字相同（≥40 字）即判为分析文字 |
| `slugify()` | 目标 URL → 安全文件名 |
| `target_host(target)` | 只取主机名（保留端口）——报告名的主体 |
| `target_domain()` / `registrable_domain()` | **主域名**（去掉子域）：`www.ftitle.studio` → `ftitle.studio`。带两级公共后缀启发式（`a.b.co.uk` → `b.co.uk`），IP/单段主机名原样 |
| `target_host()` | 完整主机名（含端口），正文与区分端口时用 |
| `_report_stem(result, outdir)` | `report_<日期>_<主域名>`，三种格式共用。给了 `outdir` 时做**同名归属校验**（见下） |
| `_recorded_target()` / `_existing_owner()` / `_disambiguator()` | 撞名保护：从旧报告（json 的 `target` / md 的 `目标` 表行 / html 的标题）读回它属于谁 |
| `_unique_path()` | 同名加 `_2` `_3`（仅 `overwrite=False` 时用到） |
| `_SEV_COLOR` | 严重度配色 |

**产出命名**：`report_<日期>_<主域名>.{md,html,json}`，例 `report_20261012_ftitle.studio.md`。
命名演进：`report_<完整URL>_<unix时间戳>`（太长要猜）→ `report_<完整主机>_<日期>`
（子域没信息量、日期排在后面）→ 现在这版。日期在前是因为"先按时间定位"更自然，
文件按名排序也天然是时间序。

**主域名的代价与对策**：同一主域的 `www`/`api`/`m` 会归到同一个文件名——这正是想要的
（同一站点不该散成好几份）。但两个**不同子站**撞在一起就会互相覆盖，所以写入前会
读一下同名文件里记录的目标（json 的 `target`、md 的 `| 目标 |` 表行、html 的标题），
发现是**另一个目标**就自动加子域后缀（`..._api.md`）区分开。读不出归属时不动——
无法证明它属于别人，且用户本来就要求覆盖。

每条发现的 PoC 段输出这些复现信息：**触发 POC / 预期返回 / 响应元信息（状态·字节·耗时）/
Burp 式完整报文 / 发送 payload / 完整原始报文路径**。三条纪律：

* **漏洞说明**按独立段落渲染，不再塞进 `- 说明：xxx` 列表项（模型写的说明常常是多行，
  从第二行起 Markdown 会把它拆成独立段落，读起来像两段不相干的文字）；
* **`实际命中` 只在它带来新信息时才写**——手工登记的判定依据已经写在漏洞说明里，
  两处都写＝同一段话出现两遍（旧报告里每条漏洞都有这个重复段）；
* 只有请求没有响应时**必须说清楚**（`> ⚠ 本条只记录了请求，没有原始响应报文`）：
  读者会以为响应被省略了，其实是根本没记录。

所有字段渲染前过 `core.rawmsg.unescape_md()`：模型从 Markdown 里复制粘贴会把
`` \` ``、`\*` 一起带进来，报告里就出现 `\``——**交付物读起来像坏了**。
多行 payload 用 ` ```http ` 围栏块，行内反引号包不住多行内容。

### `output/evidence.py`（137 行）—— 证据留存

报告里的「响应片段」只截前几百字节，够人看、够模型研判，但**不够复现**。本模块把完整请求行、请求头、响应头、响应体存成独立文件，文件名带 `fingerprint` 短哈希去重（同一个软 404 页面不会被存 50 份）。

| 模块点 | 作用 |
|---|---|
| `EvidenceStore.save()` | 存单条证据 |
| `save_result()` | 批量存一次扫描的所有证据 |
| `save_index()` | 维护 `index.json`（指纹 → 文件名） |
| `stats()` | 统计 |

---

## 8. `scripts/` —— 测试与工具

**测试脚本（无 pytest 依赖，直接 `python scripts/xxx.py` 跑）：**

| 脚本 | 覆盖 | 项数 |
|---|---|---|
| `report_test.py` | 占位语拦截 / 截断识别 / 详情段不丢 / notes 去重 | 33 |
| `knowledge_test.py` | df 幂等 / 三道门控 / 去重 / 淘汰 / 索引隔离 | 39 |
| `record_finding_test.py` | 证据与 payload 必填 / 去重 / 进报告 / 流式截断 / **长文本入库不截断** / **不再输出与说明重复的「实际命中」** | 43 |
| `completer_candidates_test.py` | 命令与参数两级候选 / 非 TTY 降级 / 标题往返 / 脱敏 | 30 |
| `completer_editing_test.py` | 提示符拆分 / 列宽计算 / 行内光标与按词跳转 / **折行布局（含待定折行、ANSI 剥离）** / **输入框不自动换行** | 33 |
| `completer_terminal_test.py` | **终端模拟器验证输入区不漂移·上方不被擦·无残影·无绝对定位** / **超宽长输入·折行后退格回短输入·Tab 候选后继续打字** / **同一批动作再用真实按键循环跑一遍（假 msvcrt 喂键，覆盖键盘分发与 Tab 两段式）** / **无 ANSI 兜底也不折行** / `_finish_line`·`_erase_input` | 99 |
| `agent_loop_test.py` | 长任务不被截断 / 死循环检测 / 防误杀 / **换壳死循环（curl -w 连打）骨架检测** / 穿插其他工具断开连击 / 换选项集不误判 / **固执模型无视警告后的硬拒绝** / 拒绝只在本轮生效 | 39 |
| `output_spill_test.py` | **external_tool 大输出落盘**：截断给路径+read_file 出路 / 折行不丢字符 / spill 文件可分页读 / **内置工具不落盘（防无限派生）** / read_file 自身不派生 / 落盘失败退化不崩 / 文件名不撞 | 20 |
| `session_resume_test.py` | 历史往返 / v1 兼容 / 脱敏 / 会话列表 | 30 |
| `dirsearch_throttle_test.py` | dirsearch 拦截识别与降速重试 | 4 |
| `autopilot_test.py` | **SQLi 放行全规则+两轮制+拿到就停** / 上传审核四种路径 / Alt+Shift 哨兵 / `/auto` 分支 / 结果合并去重 | 64 |
| `config_test.py` | 环境变量三条规则 / 数值容错 / yaml 逐项校验降级 / **`_env_list` 列表解析** / **init 模板与 config.yaml 同构（含每个 `POCS_*` 必须出现在 .env.example）** | 49 |
| `naming_test.py` | 报告名 `report_<日期>_<主域名>` / **主域名裁剪（含 co.uk 两级后缀）** / **撞名时加子域后缀不静默合并** / `overwrite=false` 仍不覆盖 / 会话名取首轮标题 / 目录名稳定 / 旧数字目录兼容 | 45 |
| `empty_session_test.py` | 判空从严（凭证/阶段/系统开场白）/ 空会话不落盘 / `purge_empty_sessions` 幂等 / 坏快照不碰 / 点名恢复拦截 | 34 |
| `subdomain_extract_test.py` | 注册域抽取（IP 拒绝 / 多段前缀最长匹配 / 裸 `host:port` 剥端口 / 公共后缀本身拒绝）/ 记录清洗（通配符/多行/脏标签/urlscan 无关域名）/ 单源失败降级 / **多源聚合换源**（crt.sh 502 仍出结果、每源独立降级、失败留痕、来源归属）/ 各源正文级错误（额度用尽·结构变化·404）/ 排列组合不堆叠 / **工具处理器末尾必须有 `return`** / 工具注册与 planner·scheduler 接入 | 123 |
| `js_analyze_test.py` | 路径结构判别（`/role/getAll` 收、静态资源/MIME/日期/hash 挡）/ 压缩别名调用 `o("path",t)` + baseURL 拼接 / import 上下文排除 / 模块图边解析（裸模块名与非脚本不收）/ 抓取上限（`js_max_bytes` 与 `max_body_capture` 分离）/ **端到端：起本地 HTTP 服务验证懒加载 chunk 真被下载、4KB 之后的接口仍能提取** / `ep_rank` 排序沉底 | 50 |
| `proxy_test.py` | env/注册表探测 / 优先级链（显式 > env > 系统）/ 内网与回环强制直连 / `no_proxy` 五种匹配 / 空 host 保守直连 / **探测路径不依赖网络（AST 检查无 httpx·requests·socket）** | 74 |
| `dismiss_finding_test.py` | 排除字段往返与**旧快照兼容** / `counts`·`by_severity` 只算有效 / 报告复核附录与 JSON 汇总 / 排除清单持久化（host 归一·scope=poc·原子写·坏文件容错）/ **入库自动套用** / handler 行为（无原因被拒·编号越界·undo·purge）/ 引用解析不猜 / **编号排除后不平移** / 知识库不摄取 | 79 |
| `public_check_test.py` | 路径主机归一 / 首页与 sitemap 解析 / **三档阈值（只有 strong 自动删）** / robots 反向证据扣分 / **抓取失败不误删且如实报"无证据"** / **同 host 只回源一次** / 接入 ToolRunner 与报告复核附录 / apply=false 不改动 | 66 |

| `fsops_test.py` | 路径闸门（`../`·UNC·盘符·数据流·设备名·**重解析点**）/ 扩展名白名单 / 读写改删 / 编辑歧义拒绝 / **报告就地覆盖不产生 _2** / 覆盖时的"整篇重生成"警告 / readonly 不阻断 / 开关能整体关掉 | 101（跳过 1，环境不支持符号链接/联接重解析点） |

| `progress_test.py` | 推进/空转语义（含"有建议但零新增仍算空转"这条**实测纠正**）/ 连续两轮才判穷尽 / 中间产出清零 / **到上限 ≠ 已穷尽（措辞分开、穷尽优先）** / 0=不限 / Ctrl-C 穿透 / 驱动层轮次与回调 / `Repl._poll` 剧本与 Agent 两分支真跑 | 58 |

| `burp_report_test.py` | **命中落盘完整报文**（请求行/头/[RESPONSE]/响应头/超 4KB body）/ artifact 回填与**撞名防护** / off 与网络错误不落盘 / full_body 不进快照 / `_burp_transcript`：artifact 优先·字段重建·截断标注·`..` 穿行不读 / **请求不受 6000 字符展示上限约束（复现依赖它）·响应才截** / **4.X 结构与 >>> 请求 <<< 响应端到端** / payload 不重复单列 / **说明文字不得冒充响应体** / **多行 payload 围栏块** / **Markdown 转义清理不动 Windows 路径** / **落盘文件的截断标注去噪（差几字节不标）** / **请求完整·响应才截（展示上限只约束响应）** | 56 |

| `backfill_test.py` | `record_finding` 长文本不截断 / payload·response 结构化（请求行·头·状态·正文）/ 命中即落盘 / **没传 response 时自动附最近同 URL 响应** / 完全没响应时如实报缺 / **回填只按 URL 精确匹配（query 不同即不同请求，杜绝把 A 接口的响应挂到 B 漏洞）** / 只填空字段不覆盖 / 老快照端到端回填→报告 / **截断判据（完整正文不得被误标；中文按字节比对）** / **说明冒充响应体→换成真响应** | 48 |
| `export_report_test.py` | **非法 fmt 报错不静默**（列合法值、不写文件）/ fmt 大小写·空格归一 / **`normalize_args` 布尔·数字·枚举字符串归一（"false"→False，undo 不误撤销）** / `[新建]`·`[覆盖]` 标注与实际一致 / **overwrite=false 三格式共用主干（含错位场景）** / notes 会话头不重复累积、哨兵不进交付物 / `plan_reports` 一次定路径 / **set_target 同步 result.target 与导出兜底（报告名不再退化成 `report_*_target`）** | 43 |

合计 **1146 项**。

> 跑全量：`python scripts/run_tests.py`（重定向、超时、汇总由该入口接管）
> （补全测试会调 `msvcrt`，非 TTY 时降级到 `input()`，不重定向 stdin 会挂在
> 等输入上，看起来像"测试卡死"而不是失败。）

**工具脚本：**
- `run_tests.py` —— **全量回归入口**：`python scripts/run_tests.py` 跑完下面 21 个
  `*_test.py`，汇总项数并返回退出码。固定 `< /dev/null` + 单脚本 300s 超时——
  补全测试会读 stdin，漏重定向会挂住，看起来像"卡死"而不是失败。
  支持关键字过滤：`python scripts/run_tests.py throttle`
- `secret_scan.py` —— **提交前扫一遍有没有把密钥写进仓库**
- `_terminal_sim.py` —— **终端模拟器**：补全 / 输入区行为级回归的公共设施。按 cols 折行、右边缘待定折行、写到底行整体上滚，ANSI 上移/下移/右移/擦除/绝对定位
  全按真实语义生效。**为什么不用「断言转义字符串」**：那是自证的——代码拿相对输入区的行号
  去做绝对定位，照样能通过断言。文件名不带 `_test` 后缀，故不被入口脚本收集。

---

## 9. `poc/` —— 33 条 POC YAML

按类别分布：

| 类别 | 条数 | 由谁验证 |
|---|---|---|
| `path_probe` | 6 | `HttpDetector` |
| `cve_probe` | 6 | `HttpDetector` |
| `header_check` | 5 | `HttpDetector._verify_header` |
| `js_logic` | 4 | `JsLogicDetector` |
| `fingerprint` | 4 | `FingerprintDetector` |
| `api_authz` | 3 | `ApiAuthzDetector` |
| `file_op` | 2 | `ExploitProbeDetector` |
| `rce` / `injection` / `file_ext` | 各 1 | `ExploitProbeDetector` |

单条 YAML 结构见 `detectors/poc_loader.py` 的模块文档：`id` / `name` / `category` / `severity` / `request`（paths、params、headers、body）/ `match`（target、op、patterns）。

---

## 10. `data/` —— 运行时数据（已 gitignore）

| 目录 | 内容 |
|---|---|
| `data/sessions/<id>/` | 会话快照（`session.json`）：资产、发现、轮次、对话历史 |
| `data/vector_db/` | POC 索引 `poc_index.json` + 知识库 `knowledge_index.json` |
| `data/intel/` | CVE 情报缓存（cve_list / epss / kev / metadata / nuclei，24h TTL） |
| `data/recon/` | 侦察中间产物 |
| `data/tools.local.yaml` | 自定义外部工具清单 |
| `data/wordlists/` | 内置路径字典 |

## 11. 其他目录

- `_srcs.py` —— **源码读取助手**：`module_source("core.repl")` 对单文件读文件、对包把包内全部模块拼起来。
  拆包之后「源码里有没有 X」这类静态断言不能再按老路径读文件（FileNotFoundError），
  也不能只读门面（只剩装配，会变成**假通过**）——两种形态对调用方是同一个函数。
- `output/` —— 报告与证据（`report_*.md/.html/.json`、`evidence/`、`tool-output/`）
- `reports/` —— 归档报告（已 gitignore）
- `.workbuddy/memory/` —— 跨会话的任务追踪与工作日志（已 gitignore）

---

## 12. 附录：想加一种新的漏洞检测，要动哪些文件

| 步骤 | 改哪里 |
|---|---|
| 1. 写检测规则 | 新增 `poc/<category>__<name>.yaml` |
| 2. 需要新类别 | `core/state/` 的 `Category` 枚举 |
| 3. 需要专用验证逻辑 | `detectors/` 下新增类继承 `Detector`，实现 `verify()` |
| 4. 需要新采集能力 | `collectors/` 下新增采集器 |
| 5. 暴露给 Agent | `core/tools/builtins.py` 加 `BuiltinTool` + `core/tools/runner/` 里按职责选一个 mixin 加 `_h_xxx()`（侦察/检索/验证/台账/取证/导出/文件/外部） |
| 6. 能被检索到 | `kb/indexer.py` 会自动索引新 YAML（跑 `index` 命令重建） |
| 7. 补测试 | `scripts/` 下新增或扩展 |

软 404 抑制、证据留存、报告渲染这些**都不用动**——它们由基类与 output 层统一处理。
