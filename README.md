# flower_pow

**An AI-driven penetration-testing workbench.** You set the target and the strategy; it sends the real requests, keeps the evidence, chains the findings, and hands back a reproducible report.

**AI 渗透测试工作台。** 你给目标和思路，它发真实请求、留证据、串攻击链、出可复现的报告。

> Authorized targets only. `readonly: true` by default; file-upload probes require per-request human approval.
> 仅用于已获得书面授权的目标。默认只读；文件上传探测需逐条人工确认。

---

## English

### Features

#### Division of labor

| Stage | Handled by | Why |
|---|---|---|
| Sending requests, capturing raw traffic, running wordlists, scoring similarity | the machine | deterministic and tedious; doing it by hand is slow and inconsistent |
| Deciding where to strike next, reading a response, judging whether a hit is real | you + the model | requires judgement that rules cannot encode |

It is a **runner and a ledger, not an oracle** — it does not decide on your behalf what counts as a vulnerability.

#### What it is good at

| Area | Capability |
|---|---|
| **Attack-surface mapping** | every OpenAPI/Swagger operation turned into an asset; endpoints and hard-coded credentials mined from JavaScript; passive subdomain enumeration |
| **Authorization flaws** | unauthenticated access (no token), IDOR and privilege escalation (swap the ID or the role), sensitive fields leaving the origin |
| **Injection and exploitation** | SQL injection (version string only, stops on success), RCE (echo marker), arbitrary file read (path traversal) |
| **Front-end logic** | client-side auth bypass, debug backdoors, hard-coded secrets, unauthenticated endpoints |
| **Chaining** | captured IDs, tokens and credentials go into a context pool and are reused by later steps |
| **Delivery** | Burp-Repeater-pasteable raw requests plus expected-vs-actual evidence for every hit |

#### Built-in arsenal

- **37 tools** in eight groups: orchestration, recon, retrieval, business modelling, verification, reporting, file operations, external CLIs. Long-running ones (port sweeps, path brute-force, authz batches, pipelines) can be dispatched to the background and polled with `list_tasks`.
- **33 declarative POC rules** in ten families: CVE probes, path probes, header checks, fingerprinting, JS logic, API authorization, file operations, source exposure, injection, RCE. Rules encode only the deterministic half — what to send and what to match. Whether a `200` is a finding is decided from evidence.
- **Retrieval-driven targeting**: fingerprint → hybrid retrieval (cosine + BM25) → LLM rerank → run only the relevant rules, unioned with an always-on baseline set. A 500-endpoint target is never brute-forced with 16,500 blind requests.
- **18 CLI commands**: interactive chat, one-shot scans, high-risk probes, JS audit, subdomain batches, POC library, knowledge base, sessions, proxy diagnosis, engine status.
- **25 in-session slash commands**, all tab-completable.

#### Attack chains, not a list of bugs

A finding that hands you a token, an ID or a credential can be registered as an explicit chain: entry point → per-step action / evidence / result → final impact. Unregistered speculation never reaches the report, so the client reads only what was actually demonstrated.

#### Evidence you can defend

Every finding carries a description, a PoC section and a recommendation. The PoC section always states: which rule fired, what response was expected, what actually matched, status/size/latency, and the raw request and response in Burp format. Requests are complete; responses are truncated to the first 6,000 characters, with the full traffic kept in `output/evidence/`. A finding that has a request but no response is flagged loudly rather than silently looking complete.

#### Evidence grading, not a coin flip

A raw hit is not a finding. Every hit goes through a **second, independent verification pass** before it counts: completeness check (status line, headers, body, URL, real length) → reverse verification (compare against a random nonexistent path and the site root; a near-identical response is the site's generic page, not evidence) → independent retest (GET/HEAD only — replaying an upload or a delete is a second attack, so non-idempotent hits are recorded as "not retested" instead of replayed) → grading.

Each finding is scored by a standalone `EvidenceQuality` evaluator on six independent dimensions — `response_valid`, `baseline_different`, `signature_specific`, `evidence_complete`, `reproducible`, `impact_proven` — weighted 5/20/25/10/20/20. The resulting status is one of three, and only the first is a vulnerability:

| Status | Meaning | Where it lands |
|---|---|---|
| **Confirmed** | evidence meets the bar | main list, counts, knowledge base |
| **Needs Review** | suspicious, under-evidenced | appendix, **not** counted, not a false positive |
| **Rejected** | generic response / no real evidence | appendix, kept as a review record |

`evidence_score` and `llm_confidence` are **two different numbers**. The latter is the model's self-assessed confidence in its own reading of the evidence — not the probability that the finding is real. It can downgrade a finding, never upgrade one: 0.95 from the model cannot lift a 0.60 evidence score into Confirmed.

The soft-404 baseline, per-rule exclusion markers and the origin check (demo sites, public directories) still run underneath. Exclusions persist per target and are reported with their reason — negative evidence is still evidence.

#### Submission gate: seven fields, or it does not ship

The agent can only *submit* a vulnerability; the report decides what counts. Every `record_finding` call goes through a standalone `FindingValidator` before it becomes a finding. Seven things must be present, specific and checkable:

**vulnerability type · affected URL · trigger condition · raw request · raw response · why it proves the bug · actual impact**

Anything missing, a placeholder ("TBD"), a platitude ("there is a security risk") or unverifiable (no status line, no request line, a "response" that is just the write-up pasted back) is **blocked**, recorded as a **pending lead**, and never reaches the report, the counts, the knowledge base — or even the findings list. The tool returns the exact missing fields and why each one failed; resubmitting the same URL + type with the gaps filled promotes the lead into a finding and closes it automatically.

Leads are a separate lifecycle, not a status: `flower-pow findings --pending`, the in-session `/clues` command and the `list_clues` tool show them, they are persisted in session snapshots, and they are deliberately **absent from the JSON report**. Automatic probes are not subject to this text contract — their evidence chain is graded by the second-pass evaluator above — but the report writers re-run the gate over manually registered findings as a last line of defence, so a session restored from an old snapshot or patched by a script cannot slip an incomplete "confirmed" finding into a deliverable.

#### Two ways to drive it

| | `--classic` script | AI agent (default) |
|---|---|---|
| Plan | fixed rounds: recon → business model → testing → iterate | decides the next step from the current state |
| Strength | reproducible, no token cost | does not stall when the site has no login page |
| Cost | some wasted rounds | depends on model quality, hence the guardrails |

#### Permission control (always on, config cannot turn it off)

Every target-facing request (`http_request` / `external_tool` / `exploit_probe`) passes a ten-rule permission matrix (`policy/api_policy.py::rules_table_markdown()`) before the request is actually sent. Key rules:

| Level | Commands | Condition |
|---|---|---|
| L0 | query detail / list | target + environment + identity bound, read-only |
| L1 | create / update test data | **isolated_test only** |
| L2 | upload test file | **dedicated_test only, per-request approval** |
| L2 | delete test data | test env + per-request approval + ledger verdict |
| L3 | batch delete / SQLi verify / command exec / scheduled task | **always denied, no approval path** |

Hard constraints:

* **Scope**: the request URL must fall inside the bound target — scheme, hostname **and port** are normalized and compared, and a path prefix on the bound target confines the authorized paths. Out-of-scope requests are treated as unbound → denied.
* **No config-level approvals**: `policy.approvals` is ignored. Approval only exists at runtime, **per request, bound to the exact object URL** — changed parameters mean the approval must be obtained again.
* **Ledger**: only objects that were actually created (execution succeeded **and** an object id was extracted from the response) are registered, keyed by target + run + identity + object id. Unknown objects without a per-request approval can never be deleted.
* **Audit is a precondition, not a side-channel**: if the audit JSONL cannot be persisted, write operations and approvals are **refused**; read-only operations proceed with a visible warning.
* **Identity**: credentials are bound as `cred:<header>:<fingerprint>` (+ declared role), so different tokens are distinct identities; unauthenticated requests are explicit `anonymous@<host>`.

#### MCP server

`mcp_server/` exposes the scanner to external AI clients over stdio or HTTP with **10 tools**: `doctor`, `poc_list`, `poc_show`, `kb_search`, `sessions`, `findings`, `scan_start`, `scan_status`, `scan_cancel`, `report`. Scans run as background jobs — `scan_start` returns a `job_id` immediately, `scan_status` polls, `report` exports.

---

### Usage

#### Four entry points

| Entry | Command | When |
|---|---|---|
| **Default** (recommended) | `python flower_pow.py` | daily driver: health check, then straight into chat |
| **Target first** | `python flower_pow.py chat https://target` | you already know where to start |
| **One-shot** | `python flower_pow.py scan https://target` | no interaction, report at the end |
| **Scripted** | any command + `--classic` | reproducible runs, no API spend |

```bash
flower_pow chat https://target --auto 10       # advance 10 rounds automatically
flower_pow chat --poll                         # run until exhausted
flower_pow chat --resume                       # resume, full conversation history included
flower_pow scan https://target --format all    # md + html + json
flower_pow subs subs.txt --root target.com     # subdomain batch discovery
flower_pow exploit https://target --only sqli,rce,fileread
flower_pow ask "shiro deserialization"         # retrieval only, no network traffic
```

#### A session, end to end

| # | Step | What it does |
|---|---|---|
| 1 | **Scope** | `/target` sets the target; `readonly` stays on |
| 2 | **Map** | fingerprint → ports → JS → OpenAPI → subdomains; flatten the endpoint surface |
| 3 | **Model** | find login endpoints, solve plain-text SVG captchas, walk the core flow, infer permission domains |
| 4 | **Strike** | batched authorization probes, injection probes, manual `http_request` when needed |
| 5 | **Chain** | record attack chains; stash intermediate credentials in the context pool |
| 6 | **Deliver** | export Markdown / HTML / JSON with the raw traffic attached |

#### In-session commands

All 26 are tab-completable.

```
/target [URL]     set or show the target      /status          current state
/tools            available tools             /assets [type]   asset list
/findings [sev]   findings                    /clues           pending leads (not vulns)
/model            business model              /report [fmt]    export a report
/turns            turn log
/agent on|off     agent / scripted mode       /phase NAME      jump to a phase
/next  /run       advance / one more round    /poll            run until exhausted
/backfill         backfill raw traffic        /auto            fully automatic
/resume [id]      load a session              /sessions        list resumable sessions (space+Tab for all)
/reset            wipe and start over         /clean           drop empty sessions
/key              reset the API key           /title           rename the session
/chats            conversation history         /kickoff         model introduces itself
/help             help                        /quit            quit (auto-saves)
```

Two rules worth remembering:

- Setting a **different** target clears the previous target's assets, findings, credentials, conversation history and runtime caches. Report cross-contamination almost always comes from here; re-setting the same target leaves data untouched.
- `/reset` discards the old session and deletes its snapshot — there is no half-measure that keeps assets and drops the conversation.

#### Playbooks

```
› Target https://target.com. Give me a "where is it likely vulnerable" list in 10 minutes, no deep exploitation.

› The API docs are at https://target.com/api — pull every OpenAPI operation, then test unauthenticated access and IDOR.

› Grab the JS on https://target.com, find hard-coded keys, internal addresses and debug switches, then check which extracted endpoints need no authentication.

› Log in as admin/xxx, then compare the same endpoints with a low-privilege account.

› Verify SQL injection on /api/query?keyword=x — version string only.

› Export the report as both md and html.
```

#### High-risk probes

`exploit` is a one-shot prober, not an exploitation framework. SQLi, RCE and file-read follow one discipline: **one attempt per endpoint**, stop on a hit, SQL injection reads the version string and nothing else, and repeated errors skip that category.

```bash
flower_pow exploit https://target --only sqli,rce,fileread
flower_pow exploit https://target --ops-file ops.txt    # METHOD /path per line
flower_pow exploit https://target --upload              # enable upload probes
```

Endpoint lists are taken, in priority order, from `--ops-file`, then session assets (OpenAPI / JS endpoints), then the site root. Running `scan` or `jsaudit` first raises the hit rate dramatically.

File upload is the only operation that changes state on the target, so it is gated by **per-request human confirmation**, not a global switch. The uploaded content is always a non-executable plain-text marker; in a non-interactive environment no upload is sent at all and it is recorded as skipped, not failed.

#### Report output

```
output/           Markdown / HTML / JSON reports
output/evidence/  raw .http request/response pairs, pasteable into Burp Repeater
data/             session snapshots, exclusion lists, knowledge base, logs
```

#### MCP, in one command

```bash
flower_pow mcp install     # write the client config and register the trust fingerprint
flower_pow mcp status      # is it registered, does the client accept the fingerprint
flower_pow mcp uninstall   # remove the entry and its trust records (with backup)
flower_pow mcp             # start the stdio server yourself
```

```bash
flower_pow mcp install -c all          # WorkBuddy + Claude Desktop + Cursor
flower_pow mcp install --dry-run       # show what would be written, change nothing
```

The command resolves the interpreter and entry script from the package location (not the current directory), merges into the existing `mcpServers` map without touching other servers, backs up the config first, and computes the trust fingerprint the client expects. WorkBuddy reads `mcp.json` once at start-up, so restart it after installing.

#### Dynamic rule library (Git-driven)

POCs are no longer a static YAML pile — external rules sync through Git with
commit-SHA comparison, so only the YAMLs changed between the last and the
latest remote commit are processed (no full re-download, no full re-scan).

```bash
flower_pow intel check     # fetch remote, compare SHA, report pending (no changes written)
flower_pow intel update    # incremental sync + publish into poc/community
flower_pow intel status    # repos, commits, rule versions, published counts
flower_pow intel rollback  # reset to the previous (or --to) synced commit and re-register
flower_pow intel cve CVE-2021-44228   # external CVE intel (CVSS / KEV / EPSS)
```

Rule version metadata is tracked per rule in `remote_rules/<repo>/manifest.json`:
`rule_id / source / source_url / commit / sha256 / version / status / first_seen / last_updated`.
Flower-schema rules are published into `poc/community/` (picked up by the POC
loader and RAG index automatically); nuclei templates are registered for
reference only. Startup triggers an auto-update **at most once per day**
(`intel:` section in `config.yaml`); first-time clones are left to an explicit
`intel update` so boot never stalls on a big download.

```
intel/updater/         git_sync · yaml_validator · registry · scheduler
data/updater/          state.json · history.json · repositories.json
remote_rules/<repo>/   local clones + manifest.json
poc/builtin/           built-in rules    poc/community/  pulled rules
```

---

## 中文

### 功能介绍

#### 分工

| 环节 | 谁来做 | 为什么 |
|---|---|---|
| 发请求、留原始报文、跑字典、算相似度 | 机器 | 确定性的活，人做既慢又不一致 |
| 这一轮打哪、这个响应说明什么、这条算不算数 | 你 + 模型 | 需要判断力，规则写不出来 |

它的定位是**替你跑腿并记账，不是替你下结论**。

#### 它擅长什么

| 场景 | 具体能力 |
|---|---|
| **接口面测绘** | OpenAPI/Swagger 全量操作转成资产；从 JS 里挖接口与硬编码凭据；子域被动枚举 |
| **鉴权类漏洞** | 未授权访问（不带 Token）、IDOR 与越权（换 ID 换角色）、敏感字段出网 |
| **注入与利用** | SQL 注入（只取版本号，拿到即停）、RCE（echo 标记回显）、任意文件读（路径穿越） |
| **前端逻辑** | 前端鉴权绕过、调试后门、硬编码密钥、未鉴权接口 |
| **攻击链** | 拿到的 ID、Token、凭据存进上下文变量池，后续步骤直接复用 |
| **交付** | 可直接粘进 Burp Repeater 的原始请求 + 预期与实际命中对照 |

#### 内置武器库

- **37 个工具**，分 8 组：编排、侦察、检索、业务建模、验证、报告、文件操作、外部 CLI。耗时长的（端口扫描、路径爆破、鉴权批量、完整流水线）可以甩到后台跑，再用 `list_tasks` 取结果。
- **33 条声明式 POC 规则**，分 10 类：CVE 探针、路径探针、响应头检查、指纹识别、JS 逻辑、API 鉴权、文件操作、源码泄露、注入、RCE。规则只写确定性的那半——发什么包、匹配什么特征；「这个 200 算不算漏洞」由证据决定。
- **检索驱动打击面**：指纹 → 混合检索（余弦 + BM25）→ 模型重排 → 只跑相关的规则，并上永远跑一遍的基线集。500 个接口的目标不会被 16500 个盲目请求犁一遍。
- **18 个 CLI 命令**：交互会话、一次性扫描、高危探针、JS 审计、子域批量、POC 库、知识库、会话、代理诊断、引擎状态。
- **32 个会话内命令**，全部 Tab 可补全；含本地文件（`/read` `/files`）与 Plan/Work 工作流（`/plan` `/approve` `/work` `/reject`）。

#### 攻击链，而不是一串漏洞

一个发现拿到的 Token、ID 或凭据，可以被显式登记成一条链：入口点 → 每步的动作/证据/结果 → 最终影响。**未登记的推测不会进报告**，客户读到的只有真正被演示过的东西。

#### 能交付的证据

每条发现固定三节：漏洞描述、PoC、安全建议。PoC 节一定写清：命中的是哪条规则、预期看到什么、实际命中了什么、状态码/体量/耗时，以及 Burp 格式的原始请求与响应。请求给完整，响应截到前 6000 字符，完整报文留在 `output/evidence/`。只有请求没有响应的，会显著标出来，而不是看起来像齐了。

#### 证据定级，不是抛硬币

**原始命中不等于漏洞。** 每条命中在计入之前都要过一遍**第二次独立验证**：证据完整性检查（状态行、响应头、响应体、URL、实际长度）→ 反向验证（拿随机不存在路径与站点首页做基线，正文几乎一致说明是站点通用页，不是这条路径的证据）→ 独立复测（只对 GET/HEAD 重放；重放上传/删除请求等于再打一次目标，非幂等命中记「未复测」而不是硬发）→ 定级。

每条发现由独立的 `EvidenceQuality` 评估器按六个维度打分：`response_valid`、`baseline_different`、`signature_specific`、`evidence_complete`、`reproducible`、`impact_proven`，权重 5/20/25/10/20/20。定级只有三档，**只有第一档是漏洞**：

| 状态 | 含义 | 去向 |
|---|---|---|
| **Confirmed 已确认漏洞** | 有明确证据，满足判定条件 | 正式列表、数量统计、知识库 |
| **Needs Review 待人工复核** | 有可疑现象但证据不足 | 附录，**不计入**数量，也不是误报 |
| **Rejected 误报或无效命中** | 通用响应 / 证据无效 | 附录，保留复核记录 |

`evidence_score` 与 `llm_confidence` 是**两个不同的数**：后者是模型对「自己这段判断」的信心，不是「这条漏洞为真的概率」。它只能把发现**降级**，不能升级——模型给 0.95，也抬不动 0.60 的证据分。

底层的软 404 基线、规则自带排除特征、回源公开性核验照旧生效；排除项按目标持久化，报告里带理由——反向证据也是证据。

#### 提交闸门：七项信息，缺一不进报告

Agent 只能**提交**漏洞，能不能进报告由闸门定。每次 `record_finding` 都要先过独立的 `FindingValidator`，七项信息必须齐全、具体、可核实：

**漏洞类型 · 受影响 URL · 触发条件 · 原始请求 · 原始响应 · 成立依据 · 实际影响**

缺项、占位（「待补充」）、套话（「存在安全风险」）、无法核实（没有状态行、没有请求行、把说明文字当响应体贴回来）——一律**拦截**，登记成**待验证线索**，不进报告、不计数量、不沉淀知识库，连 `findings` 列表都不进。拦截返回里会点名缺哪几项、每项为什么不达标；用同一 URL + 同一漏洞类型补齐重提，线索自动升级为正式发现并销案。

线索是**独立的生命周期**，不是一个状态档：`flower-pow findings --pending`、会话内 `/clues`、`list_clues` 工具都能看，会话快照里保存，但**刻意不进 JSON 报告**。自动探针不受这套文本契约约束（它的证据链由上面的第二次验证评分把关）；三个报告 writer 会对**手工登记**的发现再复核一遍作为最后防线——从旧快照恢复的会话、或被脚本改过的结果，都不能把一条信息不全的"已确认漏洞"塞进交付物。

#### 两种驱动

| | 固定剧本 `--classic` | AI Agent（默认） |
|---|---|---|
| 打法 | 固定几轮：侦察 → 业务建模 → 测试 → 迭代 | 看着当前状态决定下一步 |
| 优点 | 可复现、不烧 token | 站点没有登录页也不会死板推进 |
| 代价 | 会做无用功 | 依赖模型质量，故设了多道闸门 |

#### 权限控制（恒生效，配置关不掉）

所有面向目标的请求（`http_request` / `external_tool` / `exploit_probe`）在实际发出前过十条规则的权限矩阵（`policy/api_policy.py::rules_table_markdown()`）。要点：

| 等级 | 命令 | 条件 |
|---|---|---|
| L0 | 查询详情 / 查询列表 | 目标 + 环境 + 账号身份已绑定，且只读 |
| L1 | 创建 / 修改测试数据 | **仅隔离测试环境（isolated_test）** |
| L2 | 上传测试文件 | **仅专门测试环境（dedicated_test）+ 逐请求审批** |
| L2 | 删除测试数据 | 测试环境 + 台账（本次创建且取得对象 ID）+ 逐请求审批 |
| L3 | 批量删除 / SQL 注入验证 / 命令执行 / 定时任务执行 | **一律拒绝，审批不设出路** |

硬约束：

* **目标范围**：请求 URL 必须落在绑定目标的授权范围内——scheme、hostname、**端口**规范化比较，绑定目标带路径前缀时请求路径不得越出；出界按"未绑定"拒绝。
* **没有配置级审批**：`policy.approvals` 不再生效。审批只存在于运行期，**逐请求、绑定具体对象 URL**——参数一变就必须重新审批。
* **对象台账**：只有**执行成功并从响应取得对象标识**的创建/上传才会登记，按 目标 + 轮次 + 账号身份 + 对象标识 四元组匹配；未登记的对象**一律删不掉**——审批是第二道门，不能替代对象身份验证。
* **审计是写操作的先决条件**：审计 JSONL 无法持久化时，写操作与审批**拒绝执行**；只读操作放行但状态行可见告警。
* **账号身份**：凭证以 `cred:<头名>:<指纹>`（+ 显式声明的角色）绑定，不同 token 是不同身份；未认证请求显式记为 `anonymous@<host>`。

#### 安全验收：不以"测试全绿"为依据

`pytest/脚本全过`**不等于**安全功能通过——断言被删、被跳过、被放宽，全都还是会绿。所以安全相关的结论单独由验收框架给出：

```bash
python scripts/security_acceptance.py            # 终端看需求表与未过用例
python scripts/security_acceptance.py --json     # 机读结果
python scripts/security_acceptance.py --init-baseline   # 用例增删后重建断言基线
```

* **六级状态**：`UNIT_PASS` / `INTEGRATION_PASS` / `SECURITY_PASS` / `FAIL` / `NOT_TESTED` / `INCONCLUSIVE`。**未测与不确定永不折算成通过**，P0 失败直接整体 `FAIL`，P1 失败不得标完整通过。
* **16 条需求 / 56 个用例**，覆盖 L3 全环境拒绝、UNKNOWN 默认拒绝、EXPORT/AUTH 无授权、fileread 不得映射 L0、所有 HTTP 过统一出口、Runner/Detector/Collector/Scheduler/CLI/MCP/后台任务无旁路、范围外拒绝、重定向逐跳复检、身份三元组绑定、并发不污染、台账、审批、审计，以及本地文件授权与 Plan/Work 闸门。
* **验行为不验返回值**：本地双端口 Mock（A=被测目标、B=外部主机）计数真实到达的请求，证明"被拒的请求没有触网"；httpx 发送级追踪判定"是否经统一出口、有没有未治理的发送"；拒绝事件必须落审计 JSONL。
* **防造 PASS**：预期结果外置在 `catalog.py`（用例代码改不动预期）、断言数基线（删断言即低于基线 → `FAIL`）、完整性检查（删用例 / 删负向用例 / 出现跳过标记 → `FAIL`）。
* 全程只用本地 Mock 与隔离环境，**不打生产目标**。

#### 对话式读文件：Plan → 确认 → Work

你手上有接口文档、源码、导出的表格，想让它"先看懂，再给方案，别急着动手"：

```
› /read ./docs/api.md
› /read ./src/routes/user.ts
› /plan 分析这两份材料里的鉴权问题，先给整改计划，暂时不要改任何文件
   → 输出计划（目标 / 输入文件 sha256 / 分析 / 步骤 / 风险 / 副作用 / 待授权项 / 预期 / 未决问题）
› /approve y      # 确认这份计划（一次性票据）
› /work           # 执行；每步仍过权限矩阵与统一 Gateway
```

**三个阶段，边界是代码画的，不是提示词：**

| 阶段 | 能做什么 | 结构上做不到什么 |
|---|---|---|
| **读** | 只读**你点名的文件**（`/read` 或工具 `read_local_file`） | 没有遍历磁盘的入口；跨会话、路径穿越、符号链接/联接、系统目录一律拒绝；内容按不可信数据处理 |
| **Plan** | 读已授权文件、出结构化计划 | 零工具调用、零请求、零写盘（有测试盯着）；本地写操作与 L3 步骤在**构建期**就被拒 |
| **Work** | 只执行**已确认**的计划 | 未确认/计划被改/文件变了/过期 → 拒绝；每步仍走原闸门：L3 拒、UNKNOWN 拒、生产环境拒、删除查台账；每步落 `work_step` 审计 |

三条容易误解的地方，说清楚：

- **确认 ≠ 放权**。`/approve` 只签"这份计划可以开始跑"，不改变任何 L0–L3 判定。计划里写着"删这个对象"，执行时照样被台账拦下。
- **文件不是全盘可见**。授权粒度是"文件"不是"目录"；同一份文件在另一个会话里读不到。文件内容只作为「工具结果 / 不可信数据」进入对话，**永远不进 system 提示**。
- **解析失败就说失败**。坏 JSON、坏编码、缺 PDF 解析器、压缩炸弹、超时，都会明确标注并保留原文——不会把"没读成"伪装成"读到了空的"。

#### MCP Server

`mcp_server/` 把扫描器通过 stdio 或 HTTP 暴露给外部 AI 客户端，共 **10 个工具**：`doctor`、`poc_list`、`poc_show`、`kb_search`、`sessions`、`findings`、`scan_start`、`scan_status`、`scan_cancel`、`report`。扫描是后台任务——`scan_start` 立刻返回 `job_id`，`scan_status` 轮询，`report` 出报告。

---

### 使用方法

#### 四种启动姿势

| 姿势 | 命令 | 什么时候用 |
|---|---|---|
| **无参入口**（推荐） | `python flower_pow.py` | 日常开工：先体检，再直接进对话 |
| **指定目标进会话** | `python flower_pow.py chat https://目标` | 已经想好打哪 |
| **一次性扫描** | `python flower_pow.py scan https://目标` | 不想交互，跑完出报告 |
| **固定剧本** | 任意命令加 `--classic` | 要复现 / 不想花 API 钱 |

```bash
flower_pow chat https://target --auto 10       # 自动推进 10 轮
flower_pow chat --poll                         # 跑到穷尽
flower_pow chat --resume                       # 断点续跑，连对话历史一起恢复
flower_pow scan https://target --format all    # md + html + json
flower_pow subs subs.txt --root target.com     # 子域批量发现
flower_pow exploit https://target --only sqli,rce,fileread
flower_pow ask "shiro 反序列化"                 # 只做检索，不发请求
```

#### 一次渗透的六步

| # | 步骤 | 它做什么 |
|---|---|---|
| 1 | **定范围** | `/target` 设目标，`readonly` 保持开启 |
| 2 | **测绘** | 指纹 → 端口 → JS → OpenAPI → 子域，把接口面摊开 |
| 3 | **建模** | 找登录端点、还原明文 SVG 验证码、走一遍核心业务流、推权限域 |
| 4 | **打点** | 批量鉴权探测、注入探针，需要时手工 `http_request` |
| 5 | **串链** | 登记攻击链，把中间凭证存进上下文变量池 |
| 6 | **交付** | 导出 Markdown / HTML / JSON，附原始报文 |

#### 会话内命令

32 个，全部 Tab 可补全。

```
/target [URL]    设定或查看目标              /status          当前状态
/tools           可用工具清单                /assets [类型]   资产清单
/findings [等级] 发现列表                    /clues           待验证线索（不算漏洞）
/model           业务模型                    /report [格式]   导出报告
/turns           轮次记录
/agent on|off    切换 Agent / 剧本           /phase 名称      跳到某个阶段
/next  /run      推进 / 再跑一轮             /poll            跑到穷尽
/backfill        从历史回填原始报文           /auto            一键全自动
/resume [id]     载入会话                    /sessions        可恢复会话列表（空格+Tab 出全部会话名）
/read <路径>     授权并读取一个本地文件      /files           已授权文件清单（--drop / --clear）
/plan <目标>     只读分析 → 生成执行计划     /approve y|n     确认这份计划（一次性票据）
/work            执行已确认的计划            /reject          拒绝当前计划（终态）
/reset           彻底重置                    /clean           删空会话
/key             重设 API Key                /title           改会话标题
/chats           对话历史                    /kickoff         让模型自我介绍一轮
/help            帮助                        /quit            退出（自动保存）
```

两条硬规矩：

- `/target` 换成**不同**目标时，上一目标的资产、发现、凭证、对话历史、运行期缓存**整体清空**。报告串线的根源大多在这里；同一目标重复设定不动数据。
- `/reset` 是彻底换一个新的，连盘上快照一起删——不做「清对话保留资产」这种半吊子。

#### 常用打法（照抄即可）

```
› 目标 https://target.com，10 分钟内给我一份"哪里可能有洞"的清单，别做深度利用。

› 目标是 https://target.com/api，先把 OpenAPI 文档里的接口全拉下来，逐个测未授权访问和 IDOR。

› 抓 https://target.com 的 JS，找硬编码密钥、内网地址、调试开关，并验证提取到的接口是否免鉴权。

› 用 admin/xxx 登录 https://target.com，然后换一个低权限账号，对比同一批接口两边能拿到什么。

› 帮我在 https://target.com/api/query?keyword=x 这个参数上验证 SQL 注入，只取版本号。

› 导出报告，md 和 html 都要。
```

#### 高危探针

`exploit` 是一次性探针，不是利用框架。SQLi、RCE、文件读三类同一套纪律：**每个接口只尝试一次**，命中就停；SQL 注入只取版本号，不拖库不读表；连续出错就跳过该类型。

```bash
flower_pow exploit https://target --only sqli,rce,fileread
flower_pow exploit https://target --ops-file ops.txt    # 每行 METHOD /path
flower_pow exploit https://target --upload              # 开上传探测
```

接口清单来源优先级：`--ops-file` > 会话资产（OpenAPI / JS 端点）> 站点根。先跑 `scan` 或 `jsaudit` 拿到接口清单，命中率高得多。

文件上传是唯一会改变目标状态的操作，所以闸门不是开关而是**逐条人工确认**。上传内容永远是纯文本标记，不含可执行代码；非交互环境（CI、管道）一个上传请求都不会发，记为跳过而不是失败。

#### 报告产物

```
output/           Markdown / HTML / JSON 报告
output/evidence/  原始 .http 请求/响应，可直接粘 Burp Repeater
data/             会话快照、排除清单、知识库、日志
```

#### MCP：一条命令接入

```bash
flower_pow mcp install     # 写客户端配置 + 登记信任指纹
flower_pow mcp status      # 看装了没、指纹客户端认不认
flower_pow mcp uninstall   # 删条目与信任记录（带备份）
flower_pow mcp             # 自己起 stdio server
```

```bash
flower_pow mcp install -c all          # WorkBuddy + Claude Desktop + Cursor
flower_pow mcp install --dry-run       # 只看会写什么，不动盘
```

命令按**包所在位置**（不是当前目录）解析解释器和入口脚本，合并进已有的 `mcpServers` 而不动别人的 server，改前自动备份，并算出客户端认的那个信任指纹。WorkBuddy 只在启动时读一次 `mcp.json`，装完记得重启。

#### 动态规则库（Git 驱动）

POC 不再是一堆静态 YAML：外部规则走 Git 同步，本地记录上次同步的 Commit SHA，每次更新只处理新旧 SHA 之间**发生变化的 YAML**——不整仓下载、不整仓重扫。

```bash
flower_pow intel check     # fetch 远程 + SHA 比较，只报告不落盘
flower_pow intel update    # 增量更新，发布到 poc/community
flower_pow intel status    # 仓库 / Commit / 规则版本 / 发布数量
flower_pow intel rollback  # 回退到上一个（或 --to 指定的）已同步 Commit
flower_pow intel cve CVE-2021-44228   # 外部 CVE 情报（CVSS / KEV / EPSS）
```

每条规则的版本元数据落在 `remote_rules/<repo>/manifest.json`，字段固定为
`rule_id / source / source_url / commit / sha256 / version / status / first_seen / last_updated`。
flower Schema 的规则会发布进 `poc/community/`（POC 加载器与 RAG 索引零改动感知）；
nuclei 模板只登记不发布（引擎暂不能直接执行）。启动时**按天**自动检查一次更新
（`config.yaml` 的 `intel:` 段）；首次克隆留给显式 `intel update`，启动路径绝不干等大仓库下载。

```
intel/updater/         git_sync · yaml_validator · registry · scheduler
data/updater/          state.json · history.json · repositories.json
remote_rules/<repo>/   本地克隆 + manifest.json
poc/builtin/           内置规则    poc/community/  外部拉取规则
```
