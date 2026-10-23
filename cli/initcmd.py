"""``init`` —— 生成 ``.env`` 与 ``config.yaml`` 两份配置模板。

两份模板都在这，因为它们都是「给人抄的」东西，放一起才看得出覆盖关系
（同一项在两处都写时，以 ``.env`` 为准）。"""

from __future__ import annotations

from pathlib import Path
import typer
from cli.app import app
from cli.app import console


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="覆盖已存在的配置"),
) -> None:
    """生成 config.yaml 与 .env.example 模板。"""
    p = Path("config.yaml")
    if p.exists() and not force:
        console.print(f"[yellow]config.yaml 已存在，跳过（--force 覆盖）[/yellow]")
    else:
        p.write_text(_TEMPLATE_CONFIG, encoding="utf-8")
        console.print(f"[green]✓[/green] 已生成 {p.resolve()}")
    Path(".env.example").write_text(_TEMPLATE_ENV, encoding="utf-8")
    console.print(f"[green]✓[/green] 已生成 .env.example")



_TEMPLATE_CONFIG = """\
# flower_pow 配置（环境变量优先级高于本文件）
#
# 空字符串的环境变量一律视为「未设置」（保留本文件的值）。
# 类型写错（如 POCS_TIMEOUT=abc）会打印一行警告并回退默认值，不会崩溃。

scan:
  timeout: 12.0
  concurrency: 8
  max_body_capture: 4096
  verify_tls: false          # 靶场/自建证书常为自签
  proxy: null                # 如 http://127.0.0.1:8080
  # 直连例外表：命中的主机不走 proxy（支持域名后缀 / CIDR / 192.168.* 通配）。
  # 唯一的直连出口——你自己写进来的声明。
  # （Windows 注册表的 ProxyOverride 分流表已被忽略：那是浏览器的规则，
  #   拿它当例外表会让扫描内网目标时静默直连、真实 IP 暴露。）
  no_proxy: []
  # 自动探测本机代理（HTTP_PROXY 环境变量 / Windows 系统代理）：
  # 探测到就默认走代理——这解决"挂了 Burp/Clash 却看不到扫描流量"。
  # 端口扫描经 SOCKS5 / HTTP CONNECT 隧道转发，不支持时自动降级直连。
  proxy_autodetect: true
  # 自动"公开性核验"：命中漏洞后回源站根目录取证，判定为站点自己公开的资源
  # （公开演示站 / 公开资料目录 / 站点自己挂了链接）就自动判为误报。
  # 只有证据够强的才自动排除，弱的只提示人工确认。
  auto_dismiss_public: true
  # 允许智能体增删改本地产物文件（只关在 output_dir 内、扩展名白名单）。
  # 与 readonly 无关：readonly 管的是对目标的写操作，导报告本来就要写本地。
  fs_ops_enabled: true
  # 自动轮询（/poll、--poll）的轮数硬上限。安全阀，不是穷尽判据。0 = 不限。
  auto_max_rounds: 12
  readonly: false             # true=跳过攻击性工具；写操作另有人工审核闸门
  port_scan_enabled: true    # TCP connect 端口探测
  port_scan_top: 100
  js_analyze_enabled: true   # JS 静态分析（纯只读，性价比最高，建议常开）
  js_max_files: 120          # 总下载数预算（含 import 追踪到的 chunk）
  js_max_depth: 2            # 0=只看 <script src>；2=跟进路由懒加载 chunk
  js_max_bytes: 2000000      # 单个 JS 抓取上限，别用 max_body_capture 的 4KB 截 bundle
  path_scan_enabled: false   # 字典爆破较慢，按需开启
  path_scan_wordlist: ''     # 留空用内置高价值字典

  # ── JS 逻辑审计 ──────────────────────────────────────────────
  # 抓页面 JS 内容分析前端逻辑：前端权限判断、调试开关、硬编码密钥、
  # 前端算价、后台接口外泄；并对 JS 里提取的接口做一次未鉴权探测。
  js_logic_enabled: true
  js_logic_probe_api: true        # 对 JS 里的接口打一次免凭证请求
  js_logic_max_endpoints: 60      # 最多探测多少个 JS 接口

  # ── 一次性高危探针（每个接口每类只尝试一次）───────────────────
  # 策略：命中即停；没命中就跳过；请求出错/被 WAF 拦截则跳过该接口，
  # 连续出错达 probe_error_abort 次就自动跳过该类型的剩余扫描。
  sqli_probe_enabled: true        # SQL 注入：取到数据库版本号即收手，底线取库名
  rce_probe_enabled: true         # 命令注入 / 模板注入：echo 标记回显
  file_read_probe_enabled: true   # 任意文件读取：路径穿越读 /etc/passwd
  # 任意文件上传：已从「只读禁区」改为开放，但每次发起前都要人工审核。
  # 与 readonly 无关；没有审核通道（非交互环境）时一个请求都不会发。
  file_upload_probe_enabled: false
  upload_require_approval: true   # 每次上传前逐条人工确认（关掉则不再询问）
  sqli_max_requests: 120          # SQL 注入放行全规则后的请求上限
  probe_max_ops: 40               # 单次最多探测多少个接口
  probe_error_abort: 6            # 连续出错多少次后自动跳过该类型
  probe_concurrency: 4            # 探测并发（刻意低于侦察并发）

# RAG 检索：指纹 → 向量召回 → LLM 重排 → 只跑值得跑的 POC
rag:
  enabled: true
  poc_dir: ./poc
  db_dir: ./data/vector_db
  top_k: 12                  # 召回多少条 POC 进检测
  min_score: 0.12            # 相似度下限，低于此值直接丢弃
  rerank_with_llm: true      # 用 LLM 对召回结果重排（更准但多一次调用）
  dim: 2048                  # 向量维度
  boost_terms: 3             # tags/applies_to 在词频上的加权倍数

  # ── 知识库沉淀：把确认过的扫描发现回灌成可检索知识 ──
  # 关闭时 kb 只做 POC 单向检索。开启后，同一个站重复测时，
  # 上次确认过的问题会被召回，不必从头再踩一遍坑。
  knowledge_enabled: true
  knowledge_db: ./data/vector_db/knowledge_index.json   # 独立文件，不与 POC 索引混用
  knowledge_min_severity: medium  # info/low 不入库（是观察不是漏洞）
  knowledge_min_confidence: 0.6    # LLM 研判置信度门槛
  knowledge_max_entries: 2000      # 超容量按最后更新淘汰最旧

# LLM：OpenAI 兼容协议，DeepSeek / OpenAI / vLLM 均可
#
# ⚠ 填注册表以外的模型名不会被拒绝，而是原样发给服务端。厂商对已下线的
#   模型名不报错、只静默换模型，所以启动时会打印警告——看到警告就改配置。
# 用 `python flower_pow.py models` 查看清单并试算名字。
llm:
  enabled: true
  api_key: ''                # 建议改用环境变量 DEEPSEEK_API_KEY
  base_url: 'https://api.deepseek.com'
  model: 'deepseek-flash'    # 主模型：扫描链路默认全用它
  deep_model: ''             # 重型任务单独指定；留空 = 与 model 相同
  temperature: 0.1
  max_tokens: 2048
  timeout: 90.0
  disable_thinking: true     # 结构化抽取不需要思考链，开它只增加延迟与 token
  reasoning_effort: high     # 仅 disable_thinking=false 时生效（low|medium|high）

output_dir: ./output
data_dir: ./data
"""

_TEMPLATE_ENV = """\
# 复制为 .env 并按需修改（不要把 .env 提交到 git）
#
# 规则：空字符串 = 未设置（保留 config.yaml 的值）；
#       类型写错会打印警告并回退默认，不会崩溃。

# ── LLM ───────────────────────────────────────────────────────
DEEPSEEK_API_KEY=sk-your-key-here
DEEPSEEK_MODEL=deepseek-flash
# DEEPSEEK_DEEP_MODEL=deepseek-v4-pro   # 建模/报告走强模型（可选）
DEEPSEEK_BASE_URL=https://api.deepseek.com
POCS_LLM_ENABLED=true

# ── 扫描基础参数 ──────────────────────────────────────────────
POCS_TIMEOUT=12
POCS_CONCURRENCY=8
# 代理：留空则自动探测本机代理（HTTP_PROXY 环境变量 / Windows 系统代理）；
# 探测到就默认走代理——默认**所有目标都走代理**（内网/本机也不例外）。
# POCS_PROXY=http://127.0.0.1:8080
# "直连例外"表（逗号分隔，支持域名后缀 / CIDR / 192.168.* 通配）。
# 唯一的直连出口——你自己写进来的声明。
# POCS_NO_PROXY=internal.corp.com,10.0.0.0/8
# 关掉自动探测（=false 时只认 POCS_PROXY，行为回到旧版）。
POCS_PROXY_AUTODETECT=true
# 自动"公开性核验"：命中漏洞后回源站根目录取证，判定为站点自己公开的资源
# （公开演示站 / 公开资料目录 / 站点自己挂了链接）就自动判为误报。
# 只有证据够强的才自动排除，弱的只提示人工确认。
POCS_AUTO_DISMISS_PUBLIC=true
# 允许智能体增删改本地产物文件（只关在 output_dir 内、扩展名白名单）。
# 与 POCS_READONLY 无关：readonly 管的是对目标的写操作。
POCS_FS_OPS=true
# 自动轮询的轮数硬上限（安全阀，不是穷尽判据）。0 = 不限。
POCS_AUTO_MAX_ROUNDS=12
# 命中漏洞时把完整原始报文（Burp 式请求/响应）落盘到证据目录，
# 报告 PoC 段直接引用。默认 <output_dir>/evidence；=off 关闭落盘
# （报告退回用字段重建，响应体只有 4KB 截断版）。
POCS_EVIDENCE_DIR=
POCS_VERIFY_TLS=false
POCS_READONLY=true
POCS_PORT_SCAN=true
POCS_PATH_SCAN=false
POCS_JS_ANALYZE=true
POCS_OUTPUT_DIR=./output
POCS_DATA_DIR=./data

# ── 探针开关（关掉即不再探测该类漏洞）─────────────────────────
POCS_SQLI_PROBE=true
POCS_RCE_PROBE=true
POCS_FILE_READ_PROBE=true
POCS_FILE_UPLOAD_PROBE=false
POCS_UPLOAD_REQUIRE_APPROVAL=true

# ── JS 逻辑审计 ───────────────────────────────────────────────
POCS_JS_LOGIC=true
POCS_JS_LOGIC_PROBE_API=true

# ── 探针策略 ──────────────────────────────────────────────────
POCS_SQLI_MAX_REQUESTS=120
POCS_PROBE_MAX_OPS=40
POCS_PROBE_ERROR_ABORT=6
POCS_PROBE_CONCURRENCY=4

# ── RAG 检索 ──────────────────────────────────────────────────
POCS_RAG_ENABLED=true
POCS_RAG_TOP_K=12
POCS_POC_DIR=./poc

# ── 知识库沉淀 ────────────────────────────────────────────────
POCS_KNOWLEDGE=true
POCS_KNOWLEDGE_DB=./data/vector_db/knowledge_index.json
POCS_KNOWLEDGE_MIN_SEVERITY=medium
POCS_KNOWLEDGE_MIN_CONFIDENCE=0.6
POCS_KNOWLEDGE_MAX_ENTRIES=2000

# 设为 1 可关闭配置警告（stderr 上的 [config] 行）
# POCS_QUIET_CONFIG=1
"""
