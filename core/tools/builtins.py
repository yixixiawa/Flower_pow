"""内置能力注册表——纯 Python 包装本项目已有模块。

:data:`BUILTINS` 是暴露给模型的**内置**工具声明表，``params`` 是 JSON Schema
片段。模型不该关心某个能力是内置函数还是外部进程，只需要知道"叫什么、要什么
参数、会返回什么"——所以内置与外部（:mod:`core.tools.external`）收敛成同一套
schema 形态，由 :func:`core.tools.args.llm_schemas` 统一产出。

外部工具**不**各生成单独 schema，而是统一走一个 ``external_tool`` 入口
（内部用 ``tool`` 枚举区分）：12 个外部工具各自生成 schema 会白白吃掉几千
token 的上下文，而模型真正需要的信息只是"有哪些工具可用"。
"""


from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.tools.consts import MAX_READ_LINES


# ── 内置能力（纯 Python，包装本项目已有模块）─────────────────────────


@dataclass(frozen=True)
class BuiltinTool:
    """暴露给模型的**内置**能力。``params`` 是 JSON Schema 片段。"""

    name: str
    desc: str
    params: dict[str, Any]
    group: str
    heavy: bool = False
    intrusive: bool = False


def _obj(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required or [],
        "additionalProperties": False,
    }


_S_URL = {"type": "string", "description": "完整 URL，如 https://example.com"}
_S_HOST = {"type": "string", "description": "主机名或 IP（不含协议）"}

BUILTINS: list[BuiltinTool] = [
    BuiltinTool(
        name="set_target",
        group="编排",
        desc=(
            "设定或切换当前测试目标。**发任何请求之前必须先调用它**——"
            "没有会话目标时其它网络类工具无法工作。"
        ),
        params=_obj(
            {"url": {"type": "string", "description": "目标 URL，如 https://example.com"}},
            ["url"],
        ),
    ),
    BuiltinTool(
        name="session_state",
        group="编排",
        desc="读取当前会话状态：目标、资产统计、发现列表摘要、已获凭证、业务模型。",
        params=_obj({}),
    ),
    BuiltinTool(
        name="extract_variable",
        group="编排",
        desc=(
            "把响应或错误里提取到的 ID、工号、手机号、Token、验证码等线索保存到"
            "当前会话的上下文变量池。后续工具参数可以用 ${变量名} 自动替换；"
            "拿到可复用线索后必须立刻调用此工具。"
        ),
        params=_obj(
            {
                "name": {"type": "string", "description": "变量名，如 jobNumber、authCode、tmpToken"},
                "value": {"type": "string", "description": "实际提取到的值"},
                "evidence": {"type": "string", "description": "值出现在哪段响应或哪条事实中"},
                "source": {"type": "string", "description": "来源 URL、工具或接口说明"},
            },
            ["name", "value"],
        ),
    ),
    BuiltinTool(
        name="context_get",
        group="编排",
        desc="读取当前会话上下文变量池；传 name 只读取一个变量，不传则读取全部变量。",
        params=_obj({"name": {"type": "string", "description": "可选变量名"}}),
    ),
    BuiltinTool(
        name="http_request",
        group="侦察",
        desc=(
            "发一个 HTTP 请求并查看响应（状态码、响应头、正文截断）。"
            "用于手工验证某个具体猜测，例如检查未授权访问或某个响应头是否缺失。"
        ),
        params=_obj(
            {
                "url": _S_URL,
                "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"]},
                "headers": {"type": "object", "description": "附加请求头"},
                "body": {"type": "string", "description": "请求体（POST/PUT 时用）"},
            },
            ["url"],
        ),
    ),
    BuiltinTool(
        name="recon_fingerprint",
        group="侦察",
        desc="识别目标指纹：HTTP 状态、标题、Server 头、技术栈。是 RAG 检索的输入。",
        params=_obj({"url": _S_URL}),
    ),
    BuiltinTool(
        name="recon_ports",
        group="侦察",
        desc="TCP 端口探测（只做 connect，不扫 UDP）。有 nmap 时优先用 nmap -sV。",
        params=_obj({"host": _S_HOST, "top": {"type": "integer", "description": "探测端口数，默认 100"}}),
    ),
    BuiltinTool(
        name="recon_paths",
        group="侦察",
        desc="路径探测：用内置高价值字典找配置泄露、备份文件、调试端点、管理后台。",
        params=_obj({"url": _S_URL}),
        heavy=True,
    ),
    BuiltinTool(
        name="recon_js",
        group="侦察",
        desc="静态分析页面引用的 JS 文件：提取接口端点、硬编码凭据、内网地址、source map。",
        params=_obj({"url": _S_URL}),
    ),
    BuiltinTool(
        name="js_audit",
        group="侦察",
        desc=(
            "JS 页面内容审计（找前端逻辑漏洞）：抓页面与 JS 内容，静态分析"
            "前端权限判断、调试/后门开关、硬编码密钥、前端算价、后端接口外泄、"
            "路由守卫缺失；并对 JS 里提取的接口打一次免凭证请求，看是否未鉴权可访问。"
            "**这些漏洞只成立于前端代码里，打接口是测不出来的。**"
        ),
        params=_obj(
            {
                "url": _S_URL,
                "probe_api": {
                    "type": "boolean",
                    "description": "是否对 JS 里提取的接口做未鉴权探测，默认 true",
                },
            }
        ),
    ),
    BuiltinTool(
        name="search_assets",
        group="侦察",
        desc=(
            "从网络空间测绘平台搜索目标相关资产（IP/域名/URL/端口/标题）。"
            "**不需要指定平台**——系统按已配置的凭据自动路由到 Quake/FOFA/"
            "Hunter/ZoomEye 并合并去重。用来扩大攻击面：找主站之外的子域、"
            "历史解析 IP、同 CDN 邻居、被遗忘的测试/后台系统。"
            "检索词用平台语法效果最好（如 domain=\"example.com\"、"
            "app=\"Apache-Tomcat\"），自然语言也会原样传给平台。"
        ),
        params=_obj(
            {
                "query": {
                    "type": "string",
                    "description": (
                        "检索语句。推荐平台语法：domain=\"example.com\" / "
                        "app=\"Apache-Tomcat\" / title=\"后台\"；"
                        "也接受纯关键词。留空则用会话目标域名"
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "最多返回并入库多少条（默认 50，上限 200）",
                },
            },
        ),
        heavy=True,
    ),
    BuiltinTool(
        name="recon_openapi",
        group="侦察",
        desc=(
            "探测并解析 OpenAPI/Swagger 文档，把文档里的每个操作转成接口资产"
            "（含是否需要鉴权、是否后台类、是否高价值）。**这是信息量最大的一步**。"
        ),
        params=_obj({"url": _S_URL}),
    ),
    BuiltinTool(
        name="recon_subdomains",
        group="侦察",
        desc=(
            "子域枚举：并发查多个**公网被动源**（证书透明日志 crt.sh、"
            "hackertarget、RapidDNS、urlscan、OTX 被动 DNS）找出主域下真实"
            "存在过的子域，并可做前缀排列组合扩展候选。任一源挂掉会自动换源，"
            "**被动枚举不发请求给目标**。拿到的清单可以直接喂给子域批量扫描。"
            "给 IP 目标调用会直接返回空。"
        ),
        params=_obj(
            {
                "domain": {
                    "type": "string",
                    "description": "主域或任意目标 URL，如 example.com 或 https://a.example.com",
                },
                "passive_only": {
                    "type": "boolean",
                    "description": "只做被动枚举（多源）。false 时额外做前缀排列组合，默认 true",
                },
            },
            ["domain"],
        ),
    ),
    BuiltinTool(
        name="rag_search",
        group="检索",
        desc="在 POC 知识库里做混合检索（余弦 + BM25），返回最匹配的 POC 及其匹配原因。不发任何网络请求。",
        params=_obj(
            {"query": {"type": "string", "description": "自然语言检索词，如 'spring boot actuator 未授权'"},
             "top_k": {"type": "integer", "description": "返回条数，默认 8"}},
            ["query"],
        ),
    ),
    BuiltinTool(
        name="poc_list",
        group="检索",
        desc="列出 POC 库内容，可按关键词过滤。用来确认库里有/没有什么检测项。",
        params=_obj({"grep": {"type": "string", "description": "按 ID/名称/标签/适用技术过滤"}}),
    ),
    BuiltinTool(
        name="cve_intel",
        group="检索",
        desc="查询外部 CVE 情报：CVSS 评分、是否进 CISA KEV（在野利用）、EPSS 利用概率、是否有公开 PoC。",
        params=_obj({"cve": {"type": "string", "description": "CVE 编号，如 CVE-2021-44228"}}, ["cve"]),
    ),
    BuiltinTool(
        name="login",
        group="业务",
        desc=(
            "用给定账号登录目标，自动定位登录端点、字段名，并能还原纯文本 SVG 验证码，"
            "成功后取得 Token 供后续带凭证测试使用。"
        ),
        params=_obj(
            {"url": _S_URL, "username": {"type": "string"}, "password": {"type": "string"}},
            ["username", "password"],
        ),
    ),
    BuiltinTool(
        name="authz_probe",
        group="验证",
        desc=(
            "接口鉴权批量探测，三类：① 未授权访问（不带 Token 调需鉴权接口）"
            "② 越权/IDOR（带上自己的 Token 换成别人的资源 ID）"
            "③ 敏感字段出网（passwordHash/token/secret 等出现在响应里）。"
        ),
        params=_obj({"url": _S_URL, "limit": {"type": "integer", "description": "每类探测的接口上限，默认 60"}}),
        heavy=True,
    ),
    BuiltinTool(
        name="sqli_probe",
        group="验证",
        desc=(
            "SQL 注入一次性探针：**只取数据库版本号**，拿到即收手，不拖库不读表。"
            "每个接口只打一次，没命中就跳过；请求出错或被 WAF 拦截则跳过该接口，"
            "累计出错过多会自动跳过剩余扫描。覆盖 MySQL/SQLServer/PostgreSQL/Oracle/SQLite。"
        ),
        params=_obj(
            {
                "url": _S_URL,
                "limit": {"type": "integer", "description": "最多探测多少个接口，默认 40"},
            }
        ),
        heavy=True,
    ),
    BuiltinTool(
        name="exploit_probe",
        group="验证",
        desc=(
            "高危漏洞一次性探针：RCE/模板注入（echo 标记回显）、任意文件读取"
            "（路径穿越）、任意文件上传（默认关闭，需 readonly=false）。"
            "**每个接口每类只尝试一次**，没命中就跳过，出错即跳过——与 SQL 注入探针一致。 "
            "先调用 recon_openapi 或 recon_js 拿到接口清单，命中率会高得多。"
        ),
        params=_obj(
            {
                "url": _S_URL,
                "kinds": {
                    "type": "string",
                    "enum": ["rce", "fileread", "upload", "all"],
                    "description": "探测类别，默认 rce,fileread（upload 需显式指定且关闭只读）",
                },
                "limit": {"type": "integer", "description": "最多探测多少个接口，默认 40"},
            }
        ),
        heavy=True,
    ),
    BuiltinTool(
        name="run_pipeline",
        group="验证",
        desc=(
            "跑完整扫描流水线：侦察 → RAG 召回 → LLM 重排 → 批量验证 → LLM 降误报 → 出报告。"
            "耗时最长但覆盖最全，适合作为一轮的收尾。"
        ),
        params=_obj({"url": _S_URL}),
        heavy=True,
    ),
    BuiltinTool(
        name="findings",
        group="报告",
        desc=(
            "列出当前已确认的发现，可按严重度过滤。默认**不列已排除的误报**"
            "（要看已排除的传 include_dismissed=true）。输出里的编号可以直接"
            "喂给 dismiss_finding / record_finding 引用。"
        ),
        params=_obj(
            {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info", "all"]},
                "include_dismissed": {
                    "type": "boolean",
                    "description": "是否一并列出已排除的误报（默认 false）",
                },
            }
        ),
    ),
    BuiltinTool(
        name="dismiss_finding",
        group="报告",
        desc=(
            "把一条发现标记为**误报**并排除出报告（可撤销）。"
            "用于「设计如此、不是漏洞」的情况——最典型的是**公开演示站点**："
            "站点本就建给人看，其中「泄露」的配置、默认账号、接口文档是有意公开的，"
            "属于设计而非漏洞。自动探针判断不了这一点，只能人工排除。"
            "reason 必填且要写清判定依据，它会进入报告的「误报复核」附录。"
            "排除项按**目标**持久化：同一目标重扫不会再把它当有效发现报出来。"
        ),
        params=_obj(
            {
                "ref": {
                    "type": "string",
                    "description": "发现编号（findings 列表里的数字）或 poc_id",
                },
                "reason": {
                    "type": "string",
                    "description": "判定为误报的依据，必填（如「公开演示站点，内容本就公开」）",
                },
                "undo": {
                    "type": "boolean",
                    "description": "撤销排除，让它重新计入有效发现（默认 false）",
                },
                "purge": {
                    "type": "boolean",
                    "description": "彻底删除这条发现（默认 false 只做标记，保留复核痕迹）",
                },
                "scope": {
                    "type": "string",
                    "enum": ["finding", "poc"],
                    "description": (
                        "finding=只排除这一条（默认）；"
                        "poc=该 POC 在本目标上整体排除（某探针在该站永远误报时用）"
                    ),
                },
            },
            ["ref"],
        ),
    ),
    BuiltinTool(
        name="check_public_finding",
        group="报告",
        desc=(
            "**回源站根目录核验**一条命中是不是「站点自己公开的东西」，是则判为误报。"
            "取证三件套：根页面是否自述演示/示例/沙箱站点、站点自己有没有公开列出"
            "这个资源（首页链接 / sitemap.xml）、路径是否落在公开资料目录"
            "（/download//firmware//docs/…）；robots.txt 明确禁止抓取的算反向证据。"
            "**只有证据够强的才自动排除**，弱的只提示人工确认——删掉一条真实漏洞的"
            "代价远大于多留一条误报。ref 传 'all' 可一次核验全部有效发现。"
        ),
        params=_obj(
            {
                "ref": {
                    "type": "string",
                    "description": "发现编号 / poc_id，或 'all' 核验全部有效发现",
                },
                "apply": {
                    "type": "boolean",
                    "description": (
                        "证据够强时是否直接排除（默认 true）。"
                        "传 false 只核验并报告结论，不改动任何发现"
                    ),
                },
            },
            ["ref"],
        ),
    ),
    BuiltinTool(
        name="record_finding",
        group="报告",
        desc=(
            "登记一条**你手工验证**出来的漏洞。自动探针打不中的 payload（"
            "需要特定闭合语法的注入、需要 null byte 的文件读取等）"
            "必须用这个工具登记，否则它只存在于对话里——"
            "报告和 findings 列表都看不到，等于没测。"
            "**report 的 PoC 段直接取自这里登记的原始报文**："
            "把 http_request 的响应整段填进 response、请求填进 payload，"
            "报告里就是一份可直接粘贴复现的 Burp 式报文；"
            "不填 response 时报告那条发现只有请求没有响应，"
            "（会自动尝试附上最近一次同 URL 的 http_request 响应）。"
        ),
        params=_obj(
            {
                "name": {"type": "string", "description": "漏洞名，如「SQL 注入」"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "matched_at": {
                    "type": "string",
                    "description": "漏洞所在的完整 URL 或路径，必须能复现",
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "完整的证据与研判：回显内容、对比结果、攻击链步骤、"
                        "以及为什么判定成立。**不要压缩成一句话**——"
                        "报告里这一栏就是漏洞说明，写得越具体交付方越省事"
                    ),
                },
                "payload": {
                    "type": "string",
                    "description": (
                        "**实际发出的请求**，必填。单行 payload（如"
                        "「GET /rest/products/search?q=test')) UNION SELECT 1--」）"
                        "或整段原始请求（请求行 + 请求头 + 空行 + 请求体）都行；"
                        "给整段时会被拆成结构化字段，报告里就是一份完整请求"
                    ),
                },
                "response": {
                    "type": "string",
                    "description": (
                        "**原始响应报文**（Burp 式：状态行 + 响应头 + 空行 + 响应体），"
                        "把 http_request 的返回整段粘进来即可。"
                        "报告 PoC 段的 <<< 响应: 直接用它——"
                        "**没有它，这条发现的 PoC 只有请求，对方无法比对**"
                    ),
                },
                "expected": {
                    "type": "string",
                    "description": "预期返回特征：判定为成立时应该看到什么",
                },
                "remediation": {"type": "string", "description": "具体修复建议"},
                "category": {
                    "type": "string",
                    "description": "分类：sqli / xss / idor / ssrf / lfi / rce / authz / info_disclosure / other",
                },
                "cve": {"type": "string", "description": "关联 CVE（没有就不传）"},
                "chain_id": {"type": "string", "description": "所属攻击链 ID；独立发现不传"},
                "step_index": {"type": "integer", "description": "该发现位于攻击链第几步，从 0 开始"},
                "exploit_payload": {
                    "type": "string",
                    "description": "实际用于串联下一步的载荷或变量使用方式",
                },
            },
            ["name", "severity", "matched_at", "evidence", "payload"],
        ),
    ),
    BuiltinTool(
        name="record_attack_chain",
        group="报告",
        desc=(
            "显式记录一条由多个漏洞/事实串联的攻击链。必须写清入口、每一步的"
            "前置条件/动作/核心证据/结果，以及最终影响；用 finding_id 关联已有发现。"
            "当一个发现拿到的凭证、ID 或 Token 被用于下一个发现时，必须调用此工具，"
            "不能只把链路写在自然语言回复里。"
        ),
        params=_obj(
            {
                "chain_id": {"type": "string", "description": "可选稳定 ID，如 chain-api-admin"},
                "title": {"type": "string", "description": "攻击链名称"},
                "entry_point": {"type": "string", "description": "入口点或前置条件"},
                "final_impact": {"type": "string", "description": "最终可证明的危害"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "finding_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "已有 Finding 的 poc_id 列表（兼容简化记录）",
                },
                "steps": {
                    "type": "array",
                    "description": "每步包含 action、finding_id、evidence、result，可选 exploit_payload",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string"},
                            "finding_id": {"type": "string"},
                            "evidence": {"type": "string"},
                            "result": {"type": "string"},
                            "exploit_payload": {"type": "string"},
                        },
                        "required": ["action", "evidence", "result"],
                        "additionalProperties": False,
                    },
                },
            },
            ["title", "entry_point", "final_impact"],
        ),
    ),
    BuiltinTool(
        name="export_report",
        group="报告",
        desc=(
            "把当前会话的发现导出为报告文件（Markdown / HTML / JSON）。"
            "**导出前先用 record_finding 登记所有手工验证的漏洞**，"
            "否则报告里只有自动探针登记的那几条。"
            "三种格式收入**同一个文件夹** report_<日期>_<主域名>/"
            "（如 output/report_20261012_ftitle.studio/report_20261012_ftitle.studio.md），"
            "默认**就地覆盖**同名文件，所以反复导出不会堆出一串 _2/_3 副本；"
            "只想改其中一小段时，用 edit_file 就地改，不必整篇重导。"
        ),
        params=_obj(
            {
                "fmt": {"type": "string", "enum": ["md", "html", "json", "all"]},
                "overwrite": {
                    "type": "boolean",
                    "description": "是否覆盖同名报告（默认 true）。false 则另存为新文件",
                },
            }
        ),
    ),
    BuiltinTool(
        name="backfill_evidence",
        group="报告",
        desc=(
            "从会话历史里把**当时真实发过的** http_request 请求/响应回填到"
            "发现上，用于修补「PoC 只有请求、没有响应」的老报告。"
            "（早期 record_finding 把说明文字截断后当成响应体存了，"
            "那些发现导出的报告必然缺少响应。）"
            "回填后重新 export_report 即生效。"
            "只补空字段、只按 URL 精确匹配，绝不覆盖已有记录、不做模糊配对。"
        ),
        params=_obj({}),
    ),
    BuiltinTool(
        name="list_files",
        group="文件",
        desc=(
            "列出产物目录（output/）下的文件与子目录，含大小与修改时间。"
            "改报告前先用它看看已经有哪些文件、哪份是最新的。"
        ),
        params=_obj(
            {"path": {"type": "string", "description": "相对 output 的子目录，留空=根目录"}}
        ),
    ),
    BuiltinTool(
        name="read_file",
        group="文件",
        desc=(
            "读取产物目录里的文本文件。**两种模式**：\n"
            "① 定位模式（推荐）：传 grep='关键字'，一次返回所有命中行 + 上下文，"
            "**不要从头逐页翻**——找函数名/字段名/URL 用这个。\n"
            "② 翻页模式：只传 start_line + max_lines 分段读（最后手段）。\n"
            "**只能读 output/ 之内**——凭据、配置、源码都在外面，读不到。"
        ),
        params=_obj(
            {
                "path": {"type": "string", "description": "相对 output 的文件路径"},
                "grep": {
                    "type": "string",
                    "description": (
                        "按内容定位（正则，忽略大小写）。**分析 JS/HTML/JSON 大文件时优先用这个**，"
                        "例如 grep='postData' 直接找到函数体，不要 start_line 逐页翻。"
                    ),
                },
                "context": {
                    "type": "integer",
                    "description": "grep 命中行前后各显示几行（默认 3）",
                },
                "start_line": {"type": "integer", "description": "翻页模式：从第几行开始（1 起，默认 1）"},
                "max_lines": {
                    "type": "integer",
                    "description": f"翻页模式：最多读几行（默认全部，上限 {MAX_READ_LINES}）",
                },
            },
            ["path"],
        ),
    ),
    BuiltinTool(
        name="write_file",
        group="文件",
        desc=(
            "在产物目录里新建 / 覆盖一个文本文件。"
            "写自定义说明、附录、清单，或整篇重写某个产物时用。"
            "格式受限（md/txt/json/html/csv/xml/svg/log 等报告类产物）——"
            "不允许写脚本或可执行文件。"
        ),
        params=_obj(
            {
                "path": {"type": "string", "description": "相对 output 的文件路径，如 appendix.md"},
                "content": {"type": "string", "description": "完整文件内容"},
                "overwrite": {
                    "type": "boolean",
                    "description": "目标已存在时是否覆盖（默认 true）",
                },
            },
            ["path", "content"],
        ),
    ),
    BuiltinTool(
        name="edit_file",
        group="文件",
        desc=(
            "**就地修改**产物文件里的某个片段（精确替换），不用整篇重写。"
            "改报告优先用这个：一次只动需要改的那段，其余原样保留。"
            "old_text 必须与原文**逐字符一致**（含空白与换行），"
            "且出现次数与 count 相符（默认恰好 1 次），否则拒绝执行——"
            "含糊的替换可能悄悄改掉别处的同一段文字。"
        ),
        params=_obj(
            {
                "path": {"type": "string", "description": "相对 output 的文件路径"},
                "old_text": {"type": "string", "description": "要被替换的原文片段，逐字符照抄"},
                "new_text": {"type": "string", "description": "替换成什么"},
                "count": {
                    "type": "integer",
                    "description": "期望的出现次数（默认 1，必须恰好相符）；传 0 表示全部替换",
                },
            },
            ["path", "old_text", "new_text"],
        ),
    ),
    BuiltinTool(
        name="delete_file",
        group="文件",
        desc=(
            "删除产物目录里的**单个文件**（目录不删）。"
            "删除不可撤销，删之前先用 list_files 确认路径与大小。"
        ),
        params=_obj(
            {"path": {"type": "string", "description": "相对 output 的文件路径"}}, ["path"]
        ),
    ),
    BuiltinTool(
        name="external_tool",
        group="外部工具",
        desc=(
            "调用本机已安装的外部命令行工具（nmap / dirsearch / nuclei 等）。"
            "只能使用列出的工具，参数受白名单限制，且被禁止写文件。"
        ),
        params=_obj(
            {
                "tool": {"type": "string", "description": "工具名，取值见 description 里列出的清单"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "完整参数数组，按正常命令行顺序逐个给出（不要把多个参数合成一个字符串）",
                },
                "purpose": {"type": "string", "description": "本次调用想确认什么，一句话"},
            },
            ["tool", "args"],
        ),
    ),
]
