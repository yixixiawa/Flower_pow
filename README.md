# flower_pow

**AI 渗透测试工作台** —— 你给目标和思路，它发真实请求、留证据、串攻击链、出可复现的报告。

> ⚠️ 仅用于**已获得书面授权**的目标。默认 `readonly: true`（拒绝 sqlmap/hydra 这类攻击性工具），
> 文件上传需逐条人工确认。工具**不做授权校验**——这一条由你负责，见 §10。

---

## 目录

| 章节 | 一句话 |
|---|---|
| [1. 它是什么](#1-它是什么) | 渗透搭档：判断归你，跑腿归它 |
| [2. 上手](#2-上手) | 四条命令进到第一个目标 |
| [3. 一次渗透长什么样](#3-一次渗透长什么样) | 六步流程 + 真实回放 + 常用打法速查 |
| [4. 武器库](#4-武器库) | 34 个内置工具 / 18 个命令 / 33 条 POC |
| [5. 攻击链](#5-攻击链从一串漏洞到一条路径) | 上下文变量池 + 显式链路登记 |
| [6. 证据链](#6-证据链报告能不能交付) | Burp 式报文、请求完整响应截断的理由 |
| [7. 降误报](#7-降误报) | 三层防御 + 回源核验 |
| [8. 实战记录](#8-实战记录授权目标) | 一个真实站点跑出来的数据 |
| [9. 高危探针](#9-高危探针与写操作) | SQLi / RCE / 文件读 / 上传的人工闸门 |
| [10. 授权与安全边界](#10-授权与安全边界) | 三道闸门，模型不可绕过 |
| [11. 配置](#11-配置) | 全量配置项与默认值 |
| [12. 目录与规模](#12-目录与规模) | 145 个文件都在哪 |
| [13. 排障](#13-排障) | 三个最常撞的坑 |
| [14. 许可](#14-许可) | MIT + 法律责任声明 |

---

## 1. 它是什么

市面上的工具分两类：**扫描器**（跑规则出清单）和**人**（看响应做判断）。

扫描器的问题是它只能判断"规则匹配了吗"，判断不了"这个 200 到底是不是漏洞"。
人的问题是慢——一个 OpenAPI 文档 507 个操作，一个个点开看鉴权，一天就过去了。

这个项目把两件事分开：

| 环节 | 谁来做 | 为什么 |
|---|---|---|
| 发请求、留原始报文、跑字典、算相似度 | **机器** | 确定性的活，人做既慢又不一致 |
| 这一轮打哪、这个响应说明什么、这条算不算数 | **你 + 模型** | 需要判断力，规则写不出来 |

**它的定位是"替你跑腿并记账"，不是"替你下结论"。**

### 1.1 它擅长什么

| 场景 | 具体能力 |
|---|---|
| **接口面测绘** | OpenAPI/Swagger 全量操作转资产、JS 里的接口与硬编码凭据、子域被动枚举 |
| **鉴权类漏洞** | 未授权访问（不带 Token）、IDOR/越权（换 ID 换角色）、敏感字段出网 |
| **注入与利用** | SQLi（只取版本号即停）、RCE（echo 标记回显）、任意文件读（路径穿越） |
| **前端逻辑** | 前端鉴权绕过、调试后门开关、硬编码密钥、未鉴权接口 |
| **攻击链** | 拿到的 Token / ID 存进变量池，下一步直接复用（§5） |
| **交付** | Burp Repeater 可直接粘贴的请求报文 + 预期/实际命中对照 |

### 1.2 它不做什么

写在前面，省得你试完才发现：

- **不做批量资产扫描**。它是"一个有目标的渗透任务"，不是"扫 10 万个域名找软柿子"。
- **不拖库**。SQLi 探针拿到 `sqlite_version()` 就收手，不 `UNION` 表名、不导数据。
- **不内置爆破 / 社工模块**。hydra 这类工具可以接（装了就认），但它们在 `readonly` 下被直接拒绝——
  要用得自己关只读，那一步是明确的责任交接。
- **不保证零误报**。它给的是"证据 + 判断 + 可复核的操作记录"，不是"金标准"。
- **不替你拿授权**。见 §10。

### 1.3 两种驱动

| | 固定剧本 `--classic` | **AI Agent（默认）** |
|---|---|---|
| 打法 | 第 1 轮必做信息收集，第 3 轮必做鉴权探测 | 看着当前状态决定下一步 |
| 优点 | 稳定、可复现、不烧 token | 不会因为"这站没有登录接口"就死板推进 |
| 代价 | 会做无用功 | 依赖模型质量，故设了多道闸门 |

日常用 Agent；要给别人复现、或者不想花 API 钱，用 `--classic`。

---

## 2. 上手

```bash
# 1) 装（直接依赖只有 7 个，没有 numpy / chromadb 那棵依赖树）
python -m pip install .

# 2) 体检：引擎、采集器、POC 索引、外部工具、模型状态一次看清
flower-pow engines

# 3) 填 Key（首次运行会交互询问并写进 .env；也可直接 export）
export DEEPSEEK_API_KEY=sk-xxx

# 4) 开打
flower-pow chat https://你的授权目标
```

也可以装 wheel（`pip install flower-pow`），内置 POC 规则随包分发，结果仍写当前目录的 `data/` `output/`。

**没 Key 也能用**：扫描、POC 验证、报告模板渲染都不依赖大模型，只有 RAG 重排和误报研判需要。
体检在前、要 Key 在后，就是为了不让"没 Key 就没法用"这种误解发生。

**看工具清单**，确认它手上有多少家伙：

```bash
flower-pow tools       # Agent 能调的两层能力：本机外部 CLI + 34 个内置工具
flower-pow pocs        # 33 条 POC，--detail 看详情
flower-pow proxy       # 本机代理检测结果 + 请求级代理决策
```

---

## 3. 一次渗透长什么样

### 3.1 六步

| # | 步骤 | 你要做的 | 它做的 |
|---|---|---|---|
| 1 | **定范围** | 确认授权书、圈定域名/IP、记下"哪些不能碰" | `/target` 设目标，`readonly` 默认开 |
| 2 | **测绘** | 判断这站是什么类型（后台？开放平台？电商？） | 指纹 → 端口 → JS → OpenAPI → 子域，把接口摊开 |
| 3 | **建模** | 决定测哪些角色、哪些资源 | 找登录端点、还原明文 SVG 验证码、走一遍核心业务流、推权限域 |
| 4 | **打点** | 看它报的东西，决定深挖哪个 | 批量鉴权探测、注入探针、按需手工 `http_request` |
| 5 | **串链** | 判断这条链值多少钱 | 记攻击链、把中间凭证存进变量池（§5） |
| 6 | **交付** | 复核、补写结论、签字 | 导出 Markdown/HTML/JSON + 原始报文（§6） |

### 3.2 真实交互回放

开局直接进提示符，**不做开场白、不自我介绍**（那段话每次措辞都不同，还白烧一轮 token）。

```
› 目标 http://127.0.0.1:8899 ，先做信息收集
  ⚙ set_target(url=http://127.0.0.1:8899)
  ⚙ recon_fingerprint(url=http://127.0.0.1:8899)
  ⚙ recon_openapi(url=http://127.0.0.1:8899)
  ⚙ recon_js(url=http://127.0.0.1:8899)
  ⚙ recon_paths(url=http://127.0.0.1:8899)
  ⚙ http_request(method=GET, url=http://127.0.0.1:8899/actuator/env)

  /actuator/env 未授权可访问，返回 200，泄露 JDBC 连接串。
  13 项资产：5 个接口 / 5 处硬编码凭据 / 3 个内网地址。
  JS 里的 AKIAIOSFODNN7EXAMPLE 是 AWS 文档示例值，大概率假货；
  JWT 签名段是占位符，假；sk-live-… 需验证是否能用。
```

注意最后三行——**它没有把 JS 里的字符串直接报成"高危泄露"**，而是逐条标可信度。
这正是固定剧本做不出来的判断，也是这个工具存在的理由。

### 3.3 会话内命令

25 个，全部 Tab 可补全：

```
/target [URL]    设定或查看目标          /status          当前状态概览
/tools           可用工具清单            /assets [类型]   资产清单
/findings [等级] 发现列表                /model           业务模型（角色/资源/权限域）
/turns           轮次记录                /report [格式]   导出报告
/agent [on|off]  切换 Agent / 剧本       /phase 名称      剧本模式切阶段
/next  /run      推进阶段 / 再跑一轮     /poll            自动跑到穷尽
/backfill        从对话历史回填原始报文   /auto            一键全自动（有警告门）
/resume [id]     载入会话（含对话历史）   /sessions        可恢复会话列表
/reset           彻底重置（砸了换新的）   /clean           删空会话
/key             重设 API Key             /title           改会话标题
/chats           对话历史                 /kickoff         让模型自我介绍一轮
/help            帮助                     /quit            退出（自动保存）
```

**两条硬规矩**：

- `/target` 换成**不同**目标时，上一目标的资产、发现、凭证、对话历史、运行期缓存**整体清空**。报告串线的根源大多在这里。同一目标重复设定不动数据。
- `/reset` 是"砸了换把新的"——丢弃旧会话、换空的、删盘上快照。不做"清对话保留资产"这种半吊子。

### 3.4 断点续跑

```bash
flower-pow chat --resume            # 恢复最近一次
/sessions                           # 看有哪些（按最后更新时间倒序）
/resume 20261011_测 aigc 接口越权    # 精确载入（Tab 可补全）
```

快照存两类东西，恢复时**都会回来**：资产/发现/业务模型/阶段，以及 **Agent 对话历史**。

第二项是关键。没有它，"恢复"只是恢复资产清单——模型看得到有哪些接口，却不知道你上次排除了哪些方向，于是把做完的事又做一遍。

会话目录名 = `日期_第一轮对话标题`：

```
data/sessions/
  20261011_测 aigc 接口越权与 OSS 写权限/session.json
  20261010_juice-shop 全量回归/session.json
```

取**第一轮**而不是最后一轮——第一句才是"这次要测什么"，最后一轮往往是"出报告"。日期在前让字典序等于时间序。目录名一经确定不再改，否则旧路径立刻失效。

**凭证与 Token 不落盘**（快照可能被分享），恢复后需重新取得（Agent 模式下用 `login` 工具）。对话历史写盘前统一脱敏，但**只在写盘时**做——内存里保持原值，否则下一轮 Agent 会拿着 `***` 去干活。

### 3.5 常用打法（照抄即可）

不想每次都组织语言，直接用这些：

**① 只想快速判断"这站有什么值得看"**

```
› 目标 https://target.com，10 分钟内给我一份"哪里可能有洞"的清单，别做深度利用
```

**② 有接口文档，怀疑鉴权没做全**

```
› 目标是 https://target.com/api ，先把 OpenAPI 文档里的接口全拉下来，逐个测未授权访问和 IDOR
```

**③ 怀疑前端把不该给的东西写进了 JS**

```
› 抓 https://target.com 的 JS，找硬编码密钥、内网地址、调试开关，并验证 JS 里提取的接口是否免鉴权
```

**④ 手里有账号，想测水平/垂直越权**

```
› 用 admin/xxx 登录 https://target.com，然后换一个低权限账号，对比同一批接口两边能拿到什么
```

**⑤ 已知一个可疑参数，要验证注入**

```
› 帮我在 https://target.com/api/query?keyword=x 这个参数上验证 SQL 注入，只取版本号
```

**⑥ 子域太多，先筛**

```bash
flower-pow subs subs.txt --root target.com --mode probe   # 只探活 + 指纹
flower-pow chat                                          # 挑一个进会话深挖
```

**⑦ 出报告**

```
› 导出报告，md 和 html 都要
```

导出前先 `/findings` 过一遍，把"设计如此"的排除掉——报告里每一条都会被客户追问。

### 3.6 固定剧本的四轮

`--classic` 不看模型发挥，按这四轮推进（`/next` 或回车推进，`/phase` 直接跳）：

| 轮 | 阶段 | 做什么 |
|---|---|---|
| 1 | 信息收集 | 指纹、端口、JS、**接口文档**（OpenAPI 全部操作转成资产） |
| 2 | 业务建模 | 推导资源/权限域/业务流，并**真的登录走一遍核心流程** |
| 3 | 渗透测试 | 未授权访问、IDOR/越权、敏感字段出网、常规 Web 检测 |
| 4+ | 迭代深挖 | 扩大到全部接口复测、换角色交叉对比 |

`scan` 是这四轮跑一遍就结束；`chat --classic` 是逐轮推进、每轮都真发请求。

---

## 4. 武器库

### 4.1 34 个内置工具

Agent 能直接调，分 8 组。标 **H**（heavy）的耗时较长，比如一次跑几百个请求——赶时间就跳过，或者明确告诉它"先只做指纹"。

**编排（4）**

| 工具 | 作用 |
|---|---|
| `set_target` | 设/切目标。**发任何请求前必须先调**，否则其它网络工具不工作 |
| `session_state` | 读会话：目标、资产统计、发现摘要、已获凭证、业务模型 |
| `extract_variable` | 把响应里的 ID / 工号 / 手机号 / Token / 验证码存进变量池，后续用 `${名}` 引用 |
| `context_get` | 读变量池 |

**侦察（9）**

| 工具 | 作用 |
|---|---|
| `http_request` | 发一个请求看响应。手工验证单个猜测的主力 |
| `recon_fingerprint` | 状态/标题/Server/技术栈——RAG 检索的输入 |
| `recon_ports` | TCP 端口探测（只 connect，不扫 UDP），有 nmap 时优先 `-sV` |
| `recon_paths` **H** | 内置高价值字典：配置泄露、备份、调试端点、管理后台 |
| `recon_js` | 静态分析页面引用的 JS：接口端点、硬编码凭据、内网地址、source map |
| `js_audit` | 前端逻辑审计：权限判断、调试/后门开关、硬编码密钥、未鉴权接口 |
| `recon_openapi` | 解析 OpenAPI/Swagger，把每个操作转成接口资产（含是否需鉴权、是否后台类） |
| `recon_subdomains` | 并发查多个公网被动源（crt.sh / hackertarget / RapidDNS …） |
| `search_assets` **H** | 网络空间测绘检索，按已配置的平台自动路由（FOFA/Quake 等） |

**检索（3）**

| 工具 | 作用 |
|---|---|
| `rag_search` | POC 库混合检索（余弦 + BM25），返回匹配项与匹配原因。**不发任何网络请求** |
| `poc_list` | 列 POC 库，确认库里有/没有什么 |
| `cve_intel` | CVSS / CISA KEV（在野利用）/ EPSS（利用概率）/ 有无公开 PoC |

**业务（1）**

| 工具 | 作用 |
|---|---|
| `login` | 自动定位登录端点与字段名，能还原**纯文本 SVG 验证码**，成功后拿 Token 供后续复用 |

**验证（4）**

| 工具 | 作用 |
|---|---|
| `authz_probe` **H** | 接口鉴权批量探测，三类：未授权访问 / 越权 IDOR / 敏感字段出网 |
| `sqli_probe` **H** | 注入一次性探针，**只取版本号**，拿到即收手。每接口只打一次 |
| `exploit_probe` **H** | RCE / 模板注入（echo 标记回显）、任意文件读、任意文件上传（默认关） |
| `run_pipeline` **H** | 完整流水线：侦察 → RAG 召回 → 重排 → 批量验证 → 降误报 → 出报告 |

**报告（7）**

| 工具 | 作用 |
|---|---|
| `findings` | 列已确认发现，可按严重度过滤 |
| `record_finding` | 登记**手工验证**的漏洞。探针打不中的 payload（特殊闭合语法、null byte）必须登记，否则只存在于对话里 = 等于没测 |
| `record_attack_chain` | 显式记录多步攻击链（见 §5） |
| `dismiss_finding` | 判为误报并排除出报告（可撤销） |
| `check_public_finding` | 回源站根目录核验是否"站点自己公开的东西"（见 §7） |
| `export_report` | 导出 Markdown / HTML / JSON |
| `backfill_evidence` | 从会话历史把**当时真发过的**请求/响应回填到发现上 |

**文件（5）**：`list_files` / `read_file`（含 grep 定位模式）/ `write_file` / `edit_file` / `delete_file`
——只能动 `output/` 目录，扩展名白名单。

**外部工具（1）**：`external_tool` —— 调本机装了的 CLI（nmap / dirsearch / nuclei / curl …），只能用在清单里声明过的那些。

### 4.2 18 个 CLI 命令

| 命令 | 作用 |
|---|---|
| （不带参数） | 体检 + 索要 Key + 进 Agent 会话（推荐入口） |
| `chat <url>` | 交互会话。`--classic` 走剧本 · `--auto N` 跑 N 轮 · `--poll` 跑到穷尽 · `--resume` 续跑 |
| `scan <url>` | 一次性完整扫描。`--no-rag` / `--no-ai` / `--top-k` / `--save-evidence` / `--format md\|html\|all` |
| `exploit <url>` | 一次性高危探针。`--only sqli,rce,fileread,upload` · `--ops-file` 指定接口清单 · `--upload` 开上传 |
| `jsaudit <url>` | 前端 JS 逻辑审计，`--max-endpoints` 控数量 |
| `subs <源>` | 子域批量：文件 / 纯文本 / `-` 读剪贴板 → 并发探活。默认 `--mode probe` 只探活+指纹（不跑 POC，免得几百条低危淹掉真问题），`--mode full` 才逐个跑完整流水线 |
| `ask "<描述>"` | **只做 RAG 检索，不发请求**。调 POC 库时用 |
| `pocs` | 列 POC 库（`--grep` 过滤、`--detail` 详情） |
| `index` | 构建/重建向量索引（改过 `poc/*.yaml` 后跑） |
| `intel <CVE>` | 查外部 CVE 情报（CVSS / KEV / EPSS） |
| `knowledge` | 沉淀知识库（扫描发现回灌），`--ingest` 手工摄入 |
| `findings` | 复核已保存会话的发现 / 排除误报（跨会话生效），`--json` 脚本消费 |
| `sessions` | 历史会话列表，`--clean` 清空 |
| `tools` | Agent 可调的两层能力清单 |
| `discover` | 排查漏登记：列出 PATH 里有但清单不认的可执行文件 |
| `engines` | 引擎、采集器、索引、LLM 状态总览 |
| `models` | 可用模型、当前选型、旧名对照 |
| `proxy` | 本机代理检测 + 请求级代理决策（`--target` 看某目标走不走代理） |
| `init` | 生成 `config.yaml` 与 `.env.example` |

全局选项：`--classic` 跳过 Agent · `--api-key` 直接传 Key · `--save-key/--no-save-key` · `--no-probe` 跳过版本探测。

### 4.3 33 条 POC 规则

按文件前缀分 10 类：

| 类 | 条数 | 内容 |
|---|---:|---|
| `cve_probe` | 6 | fastjson · log4shell · shiro 反序列化 · Spring Cloud Actuator · PHP-CGI 参数注入 · SSTI |
| `path_probe` | 6 | `.env` · `.git/config` · 配置备份 · 调试端点 · 管理后台 · IDOR 接口 |
| `header_check` | 5 | CORS 通配 · 缺 CSP · 缺 HSTS · Cookie 缺 HttpOnly · Server 版本泄露 |
| `fingerprint` | 4 | Web 服务器 / 中间件 / 后端 / 前端 |
| `js_logic` | 4 | 前端鉴权 · 调试开关 · 硬编码凭据 · 未鉴权接口 |
| `api_authz` | 3 | 未授权 · IDOR · 敏感字段出网 |
| `file_op` | 2 | 路径穿越读 · 任意上传 |
| `file_ext` | 1 | 源码泄露 |
| `injection` | 1 | SQL 注入（取版本号） |
| `rce` | 1 | 命令回显 |

严重度分布：critical 8 · high 10 · medium 6 · low 2 · info 7。

**规则只做确定性的部分**：发什么包、匹配什么特征，写在 YAML 里，可复现可审计。
「这个指纹该试哪几条」交给检索，「这个 200 算不算漏洞」交给证据。

### 4.4 为什么不是全库盲扫

33 条规则不算多，但一个目标有 500 个接口时，盲扫 = 16500 个请求，命中率还接近于零。

所以流程是 **指纹 → 检索 → 重排 → 只跑相关的**：

```
指纹（Server / 框架 / 中间件）
   │
   ▼  混合检索：0.35 × 余弦 + 0.65 × BM25，技术栈不匹配降权
候选 POC（top-k，默认 12）→ LLM 重排
   │
   ▼  并上基线 POC（header_check 这类与指纹无关的永远跑）
值得跑的清单
```

**BM25 为什么必需**：向量检索对 "shiro" 这种短专名几乎无感（同义、拼写变体都会漂），
而 BM25 靠词频精确命中。两者互补——纯向量会漏掉精确版本号，纯 BM25 接不住"反序列化"这种描述性查询。

**RAG 的先天盲区**：它只能召回库里有的东西。库里没有某 CVE，检索再准也没用。
所以有一份**基线集**兜底，且 `poc_list` 让你随时确认"库里到底有什么"——不要指望它打穿 0day。

### 4.5 外部工具

装了就认，不用注册（扫 PATH + 自定义清单）：

```bash
flower-pow tools              # 看哪些被认出来了
flower-pow discover           # 看哪些装了但没被认
```

`discover` 专治"明明装了却不被认"——它反过来列 PATH 里存在、但清单不认的可执行文件，
一眼看出是名字对不上还是路径没进 PATH。

`--grep` 过滤、`--limit` 限数、`--all` 连系统目录一起翻。

---

## 5. 攻击链：从"一串漏洞"到"一条路径"

十份扫描报告都是"这里有 SQL 注入 / 这里有越权 / 这里有信息泄露"，客户看完还是不知道**能有多严重**。

真正的风险在链上：信息泄露拿到工号 → 弱口令登进后台 → 后台 IDOR 拿到他人数据 → 一步提权。

### 5.1 上下文变量池

打链最容易断在"记不住上一步拿到了什么"。

```python
# 第一步：从响应里提取
extract_variable(name="jobNumber", value="20243030")
extract_variable(name="authCode", value="eyJhbGciOi...")

# 后续任何工具的参数都能直接引用
http_request(url="https://target/api/user/${jobNumber}", headers={"Auth": "${authCode}"})
context_get()                    # 看池子里有什么
context_get(name="authCode")     # 单个
```

`/reset` 时池子一并清空——上一目标的 Token 绝不能流到下一目标。

### 5.2 显式登记

```python
record_attack_chain(
    chain_id="chain-auth-takeover",
    title="信息泄露 → 任意用户密码重置",
    entry_point="GET /api/auth/info 未授权可访问（F 编号 3）",
    steps=[
        {"action": "GET /api/auth/info?id=1001",
         "evidence": "响应含 passwordHash 明文",
         "result": "拿到他人 passwordHash",
         "finding_id": "api_authz__api-missing-auth"},
        {"action": "POST /api/auth/reset 提交该 hash",
         "evidence": "200，用新密码登录成功",
         "result": "接管他人账号",
         "exploit_payload": "hash=<拿到的 hash>&new=Passw0rd!"},
    ],
    final_impact="任意账号接管",
    severity="critical",
)
```

`steps` 里 `action` / `evidence` / `result` 三个是必填——少了任何一个，这条链在报告里就只是个故事。
`finding_id` 填该步对应的 finding 的 `poc_id`（手工登记的是 `manual_xxx`），链路才能在报告里点回发现详情。

规则：**当一个发现拿到的凭证 / ID / Token 被用于下一个发现时，必须调这个工具**，
不能只把链路写在自然语言回复里——写在回复里等于没写，报告和下一次会话都看不到。

### 5.3 报告里的样子

```
## 攻击链路

> 以下链路只展示 Agent 显式登记的前置条件、动作、证据与结果；未登记的推测不计入最终影响。

### 攻击链 1：信息泄露 → 任意用户密码重置

- 链条 ID：`chain-auth-takeover`
- 整体等级：严重
- 入口点：GET /api/auth/info 未授权可访问
- 最终影响：任意账号接管

| 步骤 | 关联发现 | 动作 | 核心证据 | 结果 |
| --- | --- | --- | --- | --- |
| 1 | `api_authz__api-missing-auth` | GET /api/auth/info?id=1001 | 响应含 passwordHash 明文 | 拿到他人 passwordHash |
| 2 | `manual_reset` | POST /api/auth/reset 提交该 hash | 200，用新密码登录成功 | 接管他人账号 |
```

报告开头那句声明是有意的：**未登记的推测不计入最终影响**。模型可以猜，但猜的东西进不了交付物。

---

## 6. 证据链：报告能不能交付

客户要能**复现**。光有"某接口有 SQL 注入"是不够的——得给出打了什么、预期看到什么、实际看到了什么。

### 6.1 每条发现长什么样

报告里每条漏洞固定三节：**漏洞描述 → PoC → 安全建议**。PoC 节是能否交付的关键：

| 行 | 内容 | 为什么不能省 |
|---|---|---|
| `- 触发 POC：` | POC id + 名称，手工登记的标 `manual_` 前缀 | 对方要知道你跑的是哪条检测 |
| `- 预期返回：` | 把 YAML 的 `match` 规则翻成人话，如「响应体 包含 [SQLite/version]」 | 不给预期，对方看到响应也不知道该看哪 |
| `- 实际命中：` | 真正触发的那条规则 | 判定依据 |
| `- 响应：` | `HTTP 200，312 字节，146ms` | 状态 + 体量 + 耗时，异常值一眼看出 |
| 原始报文块 | `>>> 请求:` 完整请求 ／ `<<< 响应:` 响应 | **可直接粘 Burp Repeater** |

真实渲染出来是这样（请求体省略）：

```text
#### 4.1.2 PoC

- 触发 POC：`manual_sqli_1512`（手工验证：SQL 注入（取版本号））
- 预期返回：响应 data[0].id 回显 SQLite 版本号 3.44.2
- 实际命中：`sqlite_version\(\)` → 3.44.2
- 响应：HTTP 200，312 字节，146ms

  >>> 请求:
  GET /rest/products/search?q=test'))%20UNION%20SELECT%20sqlite_version(),2,3-- HTTP/1.1
  Host: target
  Cookie: token=...
  ...

  <<< 响应:
  HTTP/1.1 200 OK
  Content-Type: application/json
  ...

  {"status":"success","data":[{"id":"3.44.2","name":"2"}]}
```

手工验证的漏洞没有 POC 定义可循，所以 `record_finding` 把 `payload` 设成**必填**——它是对方复现的唯一依据。
自动探针发现的由 `detectors/base.py` 在 `send_request()` 时自动填充。

**只有请求没有响应时会显著警告**，不会让人误以为"响应被省略了"：

> ⚠ 本条只记录了请求，**没有原始响应报文**——对方无法对照复现。

### 6.2 请求完整，响应截断

这是有意的：

| | 报告里 | 为什么 |
|---|---|---|
| **请求** | **完整**：请求行 + 全部请求头 + 请求体，一字不差 | 复现靠它。少一个 Cookie 或路径参数，粘到 Repeater 就是**另一个请求**，等于没给 |
| **响应** | 状态行 + 响应头 + 正文前 6000 字符 | 完整响应可能几百 KB（文件下载 / JSON 导出），全贴报告就没法看了。判漏洞成立看的是「请求 + 命中了什么特征」，不是响应全文 |

请求另有 64KB 防爆上限（我们自己构造的包远小于此，只有 multipart 可能接近）；
证据文件里响应体保留上限同样 64KB（防 SSRF 拉回超大文件撑爆内存）。

**完整报文永远在证据文件里**，报告只负责指路：

```
output/evidence/
  200_040f5c21270f.http   ← 原始请求/响应，可直接粘 Burp Repeater
  index.json              ← 指纹 → 文件名映射（同一个软 404 页面不会存 50 份）
```

落盘是 `scan --save-evidence` 的开关（默认不落，产物体积会翻倍）。

### 6.3 缺响应怎么补

三类事故，都真实踩过：

| 症状 | 根因 | 对策 |
|---|---|---|
| 说明被砍到 500 字、复现步骤丢失 | 登记那一刻就做了 `description[:500]` 硬截断 | 入库即完整保留，报文走结构化字段 |
| `<<< 响应:` 下面是一段中文分析 | 把说明塞进了 `body_excerpt`——**分析文字摆在响应位置比留空更糟，它看起来像证据** | 渲染端判出假响应体并剔除 |
| 只有请求没有响应 | 验证完没把响应交给登记工具 | 自动附最近一次同 URL 的真实响应；仍没有就如实写「没有原始响应报文」 |

老会话用 `/resume`（自动回填）或 `/backfill` 从对话历史把当时的真报文补回来，重导即生效，**不必重跑扫描**。

回填两条纪律：**只补不覆盖**、**只按 URL 精确匹配**（主机 + 路径 + 排序后的 query）。
第二条是踩出来的——早期做了"忽略 query 的同路径匹配"，结果
`/download?file=../proc/self/environ` 被挂上 `?file=../etc/passwd` 的响应，报告里的 PoC 就成了**伪造证据**。宁少不错。

### 6.4 报告结构

```
## 风险概览            ← 等级分布
## 目标指纹
## 侦察资产            ← 端口 / 路径 / 接口端点 / source map / 内网地址 / 硬编码凭据
## 攻击链路            ← §5
## 执行阶段耗时
## 渗透测试结果
   4.1 [严重] 标题
       4.1.1 漏洞描述   ← 编号 / 命中 / 研判 / 说明
       4.1.2 PoC        ← Burp 式报文（>>> 请求 / <<< 响应）
       4.1.3 安全建议
## 已排除的发现        ← 误报复核，带排除理由（反向证据也是证据）
## 执行说明 / 执行日志
## 合规声明
```

**发现详情段永远由模板渲染，不依赖 LLM。** 早先的设计是「AI 正文替换整个详情段」——
AI 一旦输出占位语，所有命中 URL、响应片段、修复建议全部消失，只剩概述。这才是"报告不完整"的真正原因。

---

## 7. 降误报

扫描器最难的部分。四层：

### 第一层：软 404 基线

绝大多数误报来自"所有路径都返回同一个页面"。先探一个随机不存在路径建立基线，
之后任何与基线正文 **Jaccard 相似度 ≥ 0.85** 的命中一律丢弃。
归一化时剥掉时间戳、trace id、随机 nonce，避免同一页面两次请求被判为不同内容。

最阴的一种是**不存在的路径也返回 HTTP 200** + 统一模板页——状态码检查彻底失效。
一个真实目标全站响应一律 200，鉴权失败只体现为业务码 `{"code":401}`：

```
/.git/config            status=200  soft404=False  sim=0.0   ← 真漏洞，保留
/.env                   status=200  soft404=False  sim=0.0   ← 真漏洞，保留
/static/js/main.js.map  status=200  soft404=False  sim=0.0   ← 真漏洞，保留
/nonexist               status=200  soft404=True   sim=1.0   ← 陷阱，丢弃
```

只有正文相似度基线能区分这四条。

### 第二层：声明式规则

`soft_404_markers` / `exclude` 字段让每条 POC 自己声明干扰模式（WAF 页面特征、通用错误页签名）。

### 第三层：回源核验

命中一条后**回源站根目录**判断它是不是"站点自己公开的东西"：

| 取证项 | 判据 |
|---|---|
| 根页面是否自述演示/示例/测试站 | 是 → 误报 |
| 资源是否被站点自己挂了链接 | 是 → 误报 |
| 路径是否在公开目录索引里 | 是 → 误报 |

公开演示站、公开资料目录这类"本来就是给人看"的东西，报成漏洞是浪费时间也消耗信任。
判据分档：证据够强的自动排除，弱的只提示人工确认。开关 `scan.auto_dismiss_public`。

### 第四层：LLM 研判

拿着真实 HTTP 证据逐条判真伪，提示词写死反幻觉约束和正负例——**禁止推测，只认证据**。

典型输出：

> `/actuator/env` 未授权可访问是**已确认的**（有真实 200 + JSON 响应）。
> JS 里的 `AKIAIOSFODNN7EXAMPLE` 是 AWS 官方文档示例值，**大概率假货**。
> `sk-live-…` **需验证是否真能用**。

### 人工排除

排除项按**目标**落盘（`data/exclusions.json`），同一目标重扫自动套用，不用每轮手工删一遍。

```bash
flower-pow findings                      # 列最近会话的有效发现
flower-pow findings 3 -r "公开演示站点"   # 把编号 3 判为误报（理由必填）
flower-pow findings backup --undo        # 按 poc_id 撤销
flower-pow findings 3 --del              # 彻底删除（不留复核痕迹）
flower-pow findings --excluded           # 看已持久化的排除清单
flower-pow findings --auto               # 回源核验，站点自己公开的批量排除
```

被排除的进报告"已排除的发现"章节，**带理由**——反向证据也是证据，客户会问"你们怎么没报这个"。

---

## 8. 实战记录（授权目标）

真实站点 `https://ftitle.studio`，按四轮对话推进：

| 轮次 | 阶段 | 耗时 | 产出 |
|---|---|---:|---|
| 1 | 信息收集 | 79.9s | 515 条资产（含 OpenAPI 507 个操作） |
| 2 | 业务建模 + 登录 | 27.3s | 自动识别 SVG 明文验证码并登录成功 |
| 3 | 渗透测试 | 5.9s | 发现 `passwordHash` 明文出网 |
| 4 | 迭代 | 50.7s | 407 个请求，无新增（收敛） |

**确认的发现**：短信接口无鉴权 · `passwordHash` 明文出网 · SVG 明文验证码 ·
接口文档公开 507 个操作 · 账号维度锁定型 DoS（5 次错密码锁 572 秒）。

**修正的错误判断**：SSRF 白名单实际有效 · 登录限流实际存在（第 8 次触发 429）。

> 一条教训：`/api/auth/info` 这类身份接口一度排在第 81 位、被 `limit=60` 截断，
> 表现为"扫出 0 条"。**工具跑出 0 结果不等于没问题**——
> `detectors/api_authz.py` 的 `_rank()` 因此对身份类接口加权，把它提到前 15。

### 8.1 Agent 模式实测（本地靶场）

同一靶场跑一句"先做信息收集"，8 次工具调用全部成功，模型自主编排的顺序：

```
set_target → recon_fingerprint → http_request → recon_openapi
           → recon_js → recon_paths → http_request(/actuator/env) → http_request(/admin/)
```

拿到的真实证据：13 项资产（5 接口 / 5 处硬编码凭据 / 3 个内网地址）、
`/actuator/env` 未授权 200 且泄露 JDBC 连接串、`/admin/` 返回 401。

它还主动指出指纹矛盾：`Server` 头同时有 `BaseHTTP/0.6 Python` 和 `Apache/2.4.62`，
判定真实运行时是 Python 而页面文案在伪装 Spring Boot。

> 一次坑：靶场进程被 `nohup ... &` 意外回收后，外部工具全部返回 502（代理转发到死进程），
> 模型被这个假象带偏，4 次调用浪费在反复复测上。**排查工具结果异常时，先确认目标还活着**——
> 502 / 超时这类网络层错误，往往不是工具或授权的问题。

---

## 9. 高危探针与写操作

`exploit` 是**一次性**探针，不是批量利用框架。SQLi / RCE / 文件读三类同一套纪律（上传另有闸门，见 §9.1）：

- **每个接口只尝试一次**——命中就停，没命中就跳过，不在同一点反复重打
- **SQL 注入只取版本号**——拿到即收手，不拖库、不读表结构、不写文件
- **出错即跳过**——请求异常/被 WAF 拦就跳过该接口，累计出错达阈值自动跳过该类型

```bash
flower-pow exploit https://target --only sqli,rce,fileread
flower-pow exploit https://target --ops-file ops.txt    # 自定义接口清单（每行 METHOD /path）
flower-pow exploit https://target --upload              # 开上传探测（会往目标写文件）
```

接口清单来源优先级：`--ops-file` > 会话资产（OpenAPI / JS 端点）> 站点根。
**先跑 `scan` 或 `jsaudit` 拿到接口清单，命中率会高得多**——直接对站点根打，基本是空转。

### 9.1 文件上传的闸门

上传是唯一会**改变目标状态**的操作，所以它的闸门不是开关，是**人工审核通道**。
每个接口上传前都会打一段这样的说明等确认：

```
即将向 https://target/api/upload 上传一个探测文件
  文件名：fp_a1b2c3.php（内容为纯文本标记 FP-A1B2C3，不含任何可执行代码）
  目的：验证上传接口是否接受可执行后缀
  影响：会在目标上留下一个文件，需要你手工清理
→ 放行？[y/N]
```

**逐条问，不是一个总开关。**

- **上传的内容永远是不可执行的纯文本标记**——目的是验证"接口接受不接受这个后缀"，不是拿 shell
- 非交互环境（CI、管道、没有确认通道）→ **一个上传请求都不会发**，记为"跳过"而不是"失败"
- 审核通道本身出异常（`approver` 抛错）→ 按**拒绝**处理
- 与 `readonly` 无关：`readonly` 拦的是"悄悄写"，而这里每写一次都要人点确认

---

## 10. 授权与安全边界

**这个工具不做授权校验，可以指向任意目标。这是设计取舍，不是漏洞。**

使用者的责任：拿到书面授权、圈定范围、记下禁区。工具能做的只有这些：

### 10.1 模型不可绕过的闸门

| 闸门 | 拦什么 | 为什么必须有 |
|---|---|---|
| **参数白名单** | 外部工具的选项、文件路径逐项校验 | 模型给的参数可能带 `--output` 写文件 |
| **只读拦截** | 外部工具清单里标 `intrusive` 的（nikto / sqlmap / hydra / masscan）直接拒绝 | 这四类会改业务数据、触发账号锁定、留下攻击痕迹 |
| **无 shell** | `subprocess` 一律 argv 数组 + `shell=False` | 没有 shell 就没有重定向、管道、命令替换 |
| **路径约束** | 外部工具的文件路径必须在项目目录内且存在 | 防 `-o C:\Windows\...` 这类白名单缺口 |

### 10.2 循环检测

目标不可达时模型会无限重试。判定条件：同一工具 + 同一参数连续 3 次，或同一外部工具只换取值连打 4 次，即判无进展。

**软警告管不住固执的模型**，所以有第二道闸：判定死循环的**那个指纹会被记进拒绝集**，
之后再原样重调时**请求根本不发出**，工具结果直接回一段 `[执行被拒绝]`——说清为什么拒、
什么仍然允许（换参数/换路径/换方法/换 UA 都正常）、退路是什么。

拒绝集**只在当轮有效**：下一轮你明确要求重试同一请求是合法的，不能带着上一轮的拒绝状态。

**单轮没有硬性步数上限。** 早先用 `max_steps=12` 硬截断，模型推进任务时被中途切断，
用户看到半截结论还得再敲一句「继续」。现在由"模型不再要求调工具"自然终止。

### 10.3 密钥与产物

- Key 只从环境变量 / `.env` 读，**不写 `config.yaml`**（那是要提交的），`.gitignore` 已排除 `.env`
- 终端回显一律脱敏
- 快照写盘前对对话历史脱敏，但凭证与 Token **根本不落盘**
- 证据文件含完整报文，**交付前自己过一遍**——里面可能有真实 Cookie

### 10.4 全自动的警告门

`/auto` 或 `Alt+Shift` 会先把完整后果打出来（含"上传不再逐条询问"），确认后才跑。
全自动期间的每一次放行**都打印并写进 notes**——"一键"不等于"无法审计"。

---

## 11. 配置

`flower-pow init` 生成 `config.yaml` + `.env.example`。核心项：

```yaml
scan:
  # ── 授权与安全阀 ─────────────────────────────
  readonly: true                    # 拒绝攻击性外部工具（sqlmap/hydra/nikto/masscan）
  auto_dismiss_public: true         # 命中后回源核验"是不是站点自己公开的"
  auto_max_rounds: 12               # /poll 的轮数硬上限（安全阀，不是穷尽判据）
  verify_tls: false                 # 靶场自签证书常需要关

  # ── 侦察 ────────────────────────────────────
  concurrency: 8
  timeout: 12.0
  port_scan_enabled: true
  port_scan_top: 100
  js_analyze_enabled: true          # 纯只读，性价比最高，建议常开
  js_max_files: 120
  js_max_depth: 2                   # 跟进路由懒加载 chunk
  path_scan_enabled: false          # 字典爆破较慢，按需开

  # ── JS 逻辑审计 ─────────────────────────────
  js_logic_enabled: true
  js_logic_probe_api: true          # 对 JS 里的接口打一次免凭证请求
  js_logic_max_endpoints: 60

  # ── 高危探针（每接口每类只试一次）───────────
  sqli_probe_enabled: true          # 只取版本号，拿到即收手
  rce_probe_enabled: true
  file_read_probe_enabled: true
  file_upload_probe_enabled: false  # 上传默认关；开了仍需逐条人工确认
  upload_require_approval: true
  sqli_max_requests: 120
  probe_max_ops: 40                 # 单次最多打多少接口
  probe_error_abort: 6              # 连续出错多少次后跳过该类型
  probe_concurrency: 4              # 刻意低于侦察并发

  # ── 代理 ────────────────────────────────────
  proxy: null                       # 如 http://127.0.0.1:8080
  proxy_autodetect: true            # 探测到本机代理就走（Burp / Clash）
  no_proxy: []                      # 唯一的直连出口，你自己写的声明

rag:
  enabled: true
  top_k: 12                         # 召回多少条 POC 进检测
  min_score: 0.12
  rerank_with_llm: true
  knowledge_enabled: true           # 上次确认的问题回灌，同站复测直接复用

llm:
  base_url: https://api.deepseek.com
  model: deepseek-flash             # 高频机械任务：RAG 重排、误报研判
  deep_model: ''                    # 重型任务单独指定；留空 = 同 model
  temperature: 0.1
  disable_thinking: true            # 结构化抽取不需要思考链

output_dir: ./output
data_dir: ./data
```

环境变量覆盖（优先级高于配置文件）：

```bash
POCS_READONLY=true                    # 或 false —— 改之前先想清楚
POCS_PROXY=http://127.0.0.1:8080      # 显式代理，不再自动探测
POCS_NO_PROXY=corp.internal,10.0.0.0/8
POCS_PROBE_MAX_OPS=40
POCS_FILE_UPLOAD_PROBE=false
FLOWER_POW_PLAIN_INPUT=1              # 终端异常时退回原生 input()
```

证据落盘不是配置项，是 `scan --save-evidence` 的开关（默认不落，因为产物体积会翻倍）。

### 11.1 代理

**配置了代理就全量走代理**，包括内网目标——不再按 Windows 例外表分流。
理由：例外表是给浏览器用的，渗透场景下你想让 Burp 看到每一个包。

```bash
flower-pow proxy                        # 看检测结果
flower-pow proxy --target http://10.0.0.5   # 看某目标走不走
```

**端口扫描也走代理**：TCP connect 不吃系统代理（Clash 只接管 HTTP/HTTPS），
所以内置了 SOCKS5 + HTTP CONNECT 隧道，端口探测优先走隧道。

### 11.2 被 WAF 拦了

dirsearch 那类外部工具撞 WAF 时会返回一堆 403/429。自动降速重试（`-t 1`）后仍失败就跳过，
不硬顶——硬顶只会让 IP 进黑名单，后面所有测试都没得做。

---

## 12. 目录与规模

**145 个 Python 文件 / 33,537 行**（源码 111 个 / 25,089 行，测试与工具脚本 34 个）。

```
flower_pow.py            CLI 入口（typer 注册）
cli/                    18 个子命令
core/
  agent.py              Agent 循环（流式 + 工具调用）
  planner.py            固定剧本四阶段
  scheduler/            一次性扫描流水线（recon → match → verify → report）
  tools/
    builtins.py         34 个内置工具的声明（JSON Schema）
    runner/             执行器：参数白名单 → 只读 → 无 shell → 结果回灌
  state/                Finding / Evidence / Asset / AttackChain 数据模型
  session/              会话快照 + 写盘脱敏
  repl/                 交互终端（25 个命令）
  completer/            prompt_toolkit 输入层
  proxy.py  tunnel.py   代理决策 + SOCKS5/HTTP 隧道
collectors/             端口 / 路径 / OpenAPI / JS / 子域枚举 / 测绘平台
detectors/
  http_detector.py      POC 声明式求值
  api_authz.py          鉴权探测（未授权 / IDOR / 敏感字段）
  js_logic.py           前端逻辑审计
  public_check.py       回源核验
  exploit/              SQLi / RCE / 文件读 / 文件上传
kb/                     向量索引 + BM25 + 检索 + 沉淀
llm/                    OpenAI 兼容客户端 + 提示词
output/                 证据落盘 + MD/HTML/JSON 报告
poc/                    33 条 YAML 规则
scripts/                29 个回归脚本（不用 pytest，`python scripts/run_tests.py` 一把跑完）
```

`doc/auxiliary/FILE_MAP.md` 是每个文件的职责摘要与引用关系（本地生成，不入库）：

```bash
python scripts/gen_file_map.py      # 改完代码重跑一次即可刷新
```

---

## 13. 排障

### 装完跑不起来：`ModuleNotFoundError: No module named 'typer'`

不是没装，是**跑在了错误的解释器上**。Windows 的 `py` 启动器无视已激活的 venv
（激活只改 `PATH`，而 `py` 看 `py.ini` / `PY_PYTHON`）：

```bash
python -c "import sys; print(sys.prefix)"   # .venv 目录  ✅
py -c "import sys; print(sys.prefix)"       # D:\python    ❌
```

最稳的启动方式——完整路径永远指向对的解释器：

```bash
.venv/Scripts/python.exe flower_pow.py engines
```

### 搬过目录之后 exe 启动器全废

Windows venv 不可迁移：`python.exe` 还能用（相对定位找 site-packages），但 `.venv/Scripts/`
下的 exe 启动器绝对路径烧进了 PE 头，报 `Fatal error in launcher`。

用还活着的 `python -m pip` 强制重装即可，**不必重建 venv**：

```bash
.venv/Scripts/python.exe -m pip install --force-reinstall --no-deps pip typer httpx rich
```

### 终端输入乱跳

设 `FLOWER_POW_PLAIN_INPUT=1` 退回原生 `input()`。补全和行编辑会没有，但至少能用。

正常情况下的键位：`←/→` 移光标 · `Home/End` · `Ctrl+←/→` 按词跳 · `Ctrl+A/E` 行首行尾 ·
`Ctrl+U/K` 清空/删到行尾 · `↑/↓` 翻历史 · `Tab` 补全 · `Ctrl+C` 清空当前行（空行时退出）。

---

## 14. 许可

MIT。仅限**授权测试**、CTF 与安全教育。

```
未经授权对他人系统进行渗透测试，在《网络安全法》《刑法》第 285/286 条下可能构成犯罪。
使用本工具即表示你已获得目标所有者的书面授权。
```
