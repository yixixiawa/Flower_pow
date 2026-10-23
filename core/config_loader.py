"""配置层：环境变量 > config.yaml > 内置默认值。

三类配置
--------
* :class:`ScanConfig` —— 扫描行为（超时、并发、只读、代理）。
* :class:`RAGConfig` —— 检索行为（索引路径、top-k、相似度阈值、重排）。
* :class:`LLMConfig` —— 大模型接入（OpenAI 兼容：DeepSeek / OpenAI / vLLM）。

密钥**只**从环境变量或本地 config.yaml 读取，绝不写入会话快照与报告。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_TIMEOUT = 12.0
DEFAULT_CONCURRENCY = 8
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 POC-Scanner/2.0"
)

BANNER = r"""
 _   _  _____
| | | ||  ___| _ __ _____   _____ _ __
| |_| || |_  | '__/ _ \ \ / / _ \ '__|
|  _  || |_| | | | (_) \ V /|  __/ |
|_| |_||____|_|  \___/ \_/ \_\___|_|
        AI Agent driven vulnerability scanner
"""


class ScanConfig(BaseModel):
    """扫描执行参数。"""

    timeout: float = Field(default=DEFAULT_TIMEOUT)
    concurrency: int = Field(default=DEFAULT_CONCURRENCY)
    user_agent: str = Field(default=DEFAULT_UA)
    max_body_capture: int = Field(default=4096)
    follow_redirects: bool = Field(default=True)
    verify_tls: bool = Field(default=False)
    proxy: str | None = Field(default=None)
    # 代理例外表：命中的主机会**直连**，不走 proxy。
    # 这是唯一的显式例外出口（无论 proxy_local_direct 怎么设都生效）。
    no_proxy: list[str] = Field(default_factory=list)
    # 内网/本机目标是否强制直连。
    # 默认 false = **全部目标都走代理**（挂了 Burp/Clash 就该看到所有流量，
    # 包括内网目标——这才是挂代理的初衷）。
    # 打开则恢复旧行为：内网/本机直连，不经代理。
    proxy_local_direct: bool = Field(default=False)
    # 是否自动探测本机代理（环境变量 / Windows 系统代理）。
    # 探测到就默认走代理——这是"挂了代理却看不到流量"的解药。
    # 关掉则只认 proxy 字段，行为回到旧版。
    proxy_autodetect: bool = Field(default=True)
    # 自动"公开性核验"：命中漏洞后回源站根目录取证，判定为站点自己公开的
    # 资源（公开演示站、公开资料目录、站点自己挂了链接）就自动判为误报。
    # 判定分档，**只有证据够强的才自动排除**，弱的只提示人工确认。
    # 关掉则完全不回源，纯粹交由人工在报告里复核。
    auto_dismiss_public: bool = Field(default=True)
    # 允许智能体增删改**本地产物文件**（只关在 output_dir 内，扩展名白名单，
    # 详见 core/fsops.py）。注意这与 readonly 无关：readonly 管的是"对目标"
    # 的写操作，导出报告本来就要写本地文件。
    fs_ops_enabled: bool = Field(default=True)
    # 自动轮询（/poll、--poll）的轮数硬上限。**这是安全阀，不是穷尽判据**：
    # 真正的停止条件是"连续 2 轮无产出"，上限只防"Agent 每轮都调工具、
    # 每轮都不产出结论"那种永远不判穷尽的烧 token 情况。0 = 不限。
    auto_max_rounds: int = Field(default=12)
    # 只做只读探测（默认 True）。关闭后可能触发写操作，风险自负。
    readonly: bool = Field(default=True)
    # 命中漏洞时把**完整原始报文**（Burp 式：请求行+头+体 / 状态行+响应头+体）
    # 落盘到这个目录，Evidence.artifact 记录路径，报告 PoC 段直接引用。
    # "" = 默认 <output_dir>/evidence；"off" = 关闭落盘（报告退回用
    # Evidence 字段重建，响应体只有 max_body_capture 截断版）。
    evidence_dir: str = Field(default="")
    # 端口扫描（collectors/port_scan）
    port_scan_enabled: bool = Field(default=True)
    port_scan_top: int = Field(default=100)
    # 目录爆破（collectors/path_scan）
    path_scan_enabled: bool = Field(default=False)
    path_scan_wordlist: str = Field(default="")
    # JS 分析（collectors/js_analyze）
    js_analyze_enabled: bool = Field(default=True)
    # 下载多少个 JS 文件上限。**默认给得宽**：现代前端工程一个页面就有
    # 十几个 vendor chunk + 几十个路由 chunk，给 12 只能扫到壳。
    js_max_files: int = Field(default=120)
    # 模块图追踪深度：0=只看 HTML 里 <script src>；1=再看一层 import；
    # 2=继续跟（覆盖「路由 chunk 再懒加载子模块」的常见结构）。
    js_max_depth: int = Field(default=2)
    # 单个 JS 文件的抓取上限（字节）。**必须与 max_body_capture 分开**：
    # 后者 4KB 是给「报告里贴一段响应」用的，拿它截 JS 等于只扫了文件头
    # 的 license 注释——压缩后一个 app.js 动辄几百 KB。
    js_max_bytes: int = Field(default=2_000_000)
    # JS 逻辑审计（detectors/js_logic）：前端鉴权 / 调试开关 / 前端算价 / 未鉴权接口
    js_logic_enabled: bool = Field(default=True)
    js_logic_probe_api: bool = Field(default=True)
    # 一次审计最多探多少个 JS 接口。宽松提取后端点会多出一截，
    # 25 会把真正值钱的后台接口挤掉（排序只保证后台类优先，不保证都覆盖）。
    js_logic_max_endpoints: int = Field(default=60)
    # ── 一次性高危探针（detectors/exploit）────────────────────────
    # 每个接口每类漏洞只尝试一次：命中即停、没命中就跳过、出错则跳过该次扫描。
    sqli_probe_enabled: bool = Field(default=True)
    rce_probe_enabled: bool = Field(default=True)
    file_read_probe_enabled: bool = Field(default=True)
    # 上传会往目标写文件，默认关闭；需显式开启
    file_upload_probe_enabled: bool = Field(default=False)
    # 上传已开放（不再由 readonly 一刀切拦死），但**每次**发起前都要人工审核。
    # 没有审核通道（非交互环境）时不发任何上传请求。
    upload_require_approval: bool = Field(default=True)
    # SQL 注入放行全部规则后的请求上限，防止请求量失控
    sqli_max_requests: int = Field(default=120)
    # 单次扫描最多探测多少个接口（按高价值排序取前 N 个）
    probe_max_ops: int = Field(default=40)
    # 连续 error 达到该阈值即判定目标不可探测，自动跳过该类型剩余接口
    probe_error_abort: int = Field(default=6)
    # 探测并发（远低于侦察并发，避免把目标打挂）
    probe_concurrency: int = Field(default=4)
    # 响应内容硬上限（防止大文件把内存打爆）
    max_download_bytes: int = Field(default=2 * 1024 * 1024)


class RAGConfig(BaseModel):
    """检索增强配置。"""

    enabled: bool = Field(default=True)
    poc_dir: str = Field(default="./poc")
    db_dir: str = Field(default="./data/vector_db")
    # 召回多少条 POC 交给检测器
    top_k: int = Field(default=12)
    # 相似度下限，低于此值直接丢弃（0-1）
    min_score: float = Field(default=0.12)
    # 是否让 LLM 对召回结果重排（更准但更慢）
    rerank_with_llm: bool = Field(default=True)
    # 向量维度（hashing trick，越大越准但越慢）
    dim: int = Field(default=2048)
    # 索引时是否把 tags / applies_to 加权重复，提升技术栈匹配度
    boost_terms: int = Field(default=3)
    # ── 知识库沉淀（把扫描发现回灌成可检索知识）──
    # 关闭时行为与原来完全一致：kb 只做 POC 单向检索，不吸收扫描结果。
    knowledge_enabled: bool = Field(default=True)
    # 沉淀库独立文件，**不与 poc_index.json 混用**——
    # 混在一起会破坏 index_is_stale 基于 YAML mtime 的过期判定。
    knowledge_db: str = Field(default="./data/vector_db/knowledge_index.json")
    # 低于此等级不入库（INFO 是观察不是漏洞，沉淀只会稀释召回）
    knowledge_min_severity: str = Field(default="medium")
    # LLM 研判置信度门槛；0 表示不校验
    knowledge_min_confidence: float = Field(default=0.6)
    # 容量上限，超出按最后更新时间淘汰最旧的
    knowledge_max_entries: int = Field(default=2000)


class LLMConfig(BaseModel):
    """大模型接入配置（OpenAI 兼容协议）。

    模型名以 :mod:`llm.models` 注册表为准，不在这里硬编码字符串——
    厂商改名或下线旧名时只改注册表一处。
    """

    enabled: bool = Field(default=True)
    api_key: str = Field(default="")
    base_url: str = Field(default="https://api.deepseek.com")
    # 主模型：扫描链路默认全用它。官方取值 deepseek-flash / deepseek-v4-pro
    model: str = Field(default="deepseek-flash")
    # 重型任务（业务建模、报告撰写）单独指定模型。留空 = 与 model 相同。
    # 显式填 deepseek-v4-pro 才分流，保持"配一个模型就能跑"的简单性。
    deep_model: str = Field(default="")
    temperature: float = Field(default=0.1)
    max_tokens: int = Field(default=2048)
    timeout: float = Field(default=90.0)
    max_retries: int = Field(default=2)
    # 关闭思考链：扫描链路的任务都是结构化抽取，开思考只增加延迟与 token
    disable_thinking: bool = Field(default=True)
    # 开启思考时的强度（low|medium|high），仅对支持 thinking 的模型生效
    reasoning_effort: str = Field(default="high")

    # 解析后的模型警告（旧名降级 / 未知模型），由 load_config 填充
    model_warnings: list[str] = Field(default_factory=list)


class Config(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    output_dir: str = Field(default="./output")
    data_dir: str = Field(default="./data")


_TRUE = frozenset({"1", "true", "yes", "y", "on"})
_FALSE = frozenset({"0", "false", "no", "n", "off"})


def _env_raw(key: str) -> str | None:
    """取环境变量；**空串一律当没设**。

    这是本文件所有 ``POCS_*`` 的统一入口。修之前这里是两套语义并存的：
    ``if v := e.get(...)`` 那批空串会跳过（保留 yaml 值），而
    :func:`_env_bool` 那批把空串解析成 ``False``——于是
    ``POCS_READONLY=""`` 会把只读**关掉**（危险方向），
    ``POCS_PORT_SCAN=""`` 却什么都不做。同一件事两种行为，
    配置起来只能靠猜。现在统一：空串 = 未设置。
    """
    raw = os.environ.get(key)
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def _warn(msg: str) -> None:
    """配置问题的警告。默认只在 stderr 提示一行，不打断启动。"""
    if os.environ.get("POCS_QUIET_CONFIG"):
        return
    print(f"[config] {msg}", file=sys.stderr)


def _brief(exc: Exception) -> str:
    """把 pydantic 的 ValidationError 压成一行。

    原始消息有 4 行（含"For further information visit …"），
    配置里有几处笔误就刷几屏，用户反而看不见真正要改的那一行。
    """
    lines = [ln.strip() for ln in str(exc).splitlines() if ln.strip()]
    useful = [ln for ln in lines if not ln.startswith("For further information")]
    return " | ".join(useful[:3])[:200]


def _safe_dump(model: BaseModel) -> dict[str, Any]:
    """取字段当前值，**不触发 pydantic 序列化告警**。

    直接 ``model_dump()`` 在字段被塞了非法值时（正是我们要处理的情况）
    会额外打印 UserWarning，噪音盖过我们自己的提示。
    """
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return model.model_dump()
        except Exception:  # noqa: BLE001
            # 极端情况：dump 本身失败，退回字段直读
            return {
                k: getattr(model, k)
                for k in type(model).model_fields
                if not k.startswith("_")
            }


def _env_bool(key: str, default: bool) -> bool:
    """布尔环境变量。空串与无法识别的值都**保留默认**（不猜测）。

    不认识的写法（比如 ``POCS_READONLY=maybe``）以前会被静默当成 False，
    对只读这种"关掉就有风险"的参数，静默取反是最坏的默认。
    """
    raw = _env_raw(key)
    if raw is None:
        return default
    low = raw.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    _warn(f"{key}={raw!r} 不是布尔值（可用 1/true/yes/on 或 0/false/no/off），已保留默认 {default}")
    return default


def _env_int(key: str, default: int) -> int:
    """整数环境变量。解析失败**保留默认并警告**，不抛异常。

    以前是 ``cfg.scan.concurrency = int(v)``——``POCS_CONCURRENCY=abc``
    直接在启动时 ValueError 崩掉，用户看到的是满屏 traceback 而不是
    "你这项配错了"。
    """
    raw = _env_raw(key)
    if raw is None:
        return default
    try:
        return int(float(raw))
    except ValueError:
        _warn(f"{key}={raw!r} 不是整数，已保留默认 {default}")
        return default


def _env_float(key: str, default: float) -> float:
    """浮点环境变量。同样容错，同样保留默认。"""
    raw = _env_raw(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        _warn(f"{key}={raw!r} 不是数字，已保留默认 {default}")
        return default


def _env_str(key: str, default: str, *, allow_empty: bool = False) -> str:
    """字符串环境变量。``allow_empty=False`` 时空串视为未设置。"""
    raw = _env_raw(key)
    return default if raw is None else raw


def _env_list(key: str, default: list[str], *, sep: str = ",") -> list[str]:
    """列表环境变量（逗号或分号分隔）。空串视为未设置，保留默认。

    返回值统一 strip + 去空项，避免 ``"a, ,b"`` 里冒出一个空字符串
    被当成"匹配所有主机"的例外规则（那是真出过的坏事）。
    """
    raw = _env_raw(key)
    if raw is None:
        return default
    items = [x.strip() for x in raw.replace(";", sep).split(sep)]
    return [x for x in items if x]


def _apply_section(cfg: BaseModel, raw: dict[str, Any]) -> None:
    """把 yaml 里的一段写进配置对象，**逐字段走校验**。

    原来直接 ``setattr(cfg, k, v)``：pydantic v2 默认 ``validate_assignment=False``，
    yaml 里写 ``top_k: "abc"`` 会被原样塞进去，直到 ``retriever`` 里
    ``max(top_k, 10)`` 才 TypeError——报错点离根因隔了半个程序。
    现在用 ``model_copy(update=...)`` 触发一次完整校验：配错的行会立刻
    被指出来，且**整行被跳过**（其余配置照常生效），不会因为一处笔误
    让程序带着半截配置跑。
    """
    patch: dict[str, Any] = {}
    for k, v in raw.items():
        if v is None:
            continue
        if not hasattr(cfg, k):
            _warn(f"未知配置项 {type(cfg).__name__}.{k}（已忽略，检查是否拼错）")
            continue
        if callable(getattr(cfg, k, None)):
            continue
        patch[k] = v
    if not patch:
        return
    # 基线：当前**已确定安全**的字段值。
    # 用 model_dump() 会有两个坑：① 它带 serializer warning，配错一行就刷一屏
    # UserWarning；② 它是"整体快照"，一个字段非法会把整段一起否掉。
    baseline = _safe_dump(cfg)
    try:
        type(cfg).model_validate({**baseline, **patch})
    except Exception as exc:  # noqa: BLE001
        # 退化路径：**逐项**应用，坏的那项单独跳过，好的照常生效。
        # 不能靠 cfg.model_dump() 做基线——dump 出来的是所有字段，
        # 拿它整体去 validate 时，前一个坏字段会让后面所有项一起被否掉
        # （实测 min_score=0.2 这种合法值也跟着丢了）。
        # 所以基线只放 **本段已经接受的** 字段。
        _warn(f"配置段 {type(cfg).__name__} 有非法值，改为逐项校验：{_brief(exc)}")
        accepted: dict[str, Any] = {}
        for k, v in patch.items():
            try:
                type(cfg).model_validate({**accepted, k: v})
            except Exception:  # noqa: BLE001
                _warn(f"{type(cfg).__name__}.{k}={v!r} 非法，已保留默认 {getattr(cfg, k)!r}")
                continue
            accepted[k] = v
        patch = accepted
    for k, v in patch.items():
        setattr(cfg, k, v)


def load_config(path: str | Path | None = None) -> Config:
    """加载配置：环境变量 > YAML > 默认值。"""
    cfg = Config()

    # 先把 .env 注入 os.environ（**不覆盖**已存在的真实环境变量），
    # 否则首次运行时用户输入并落盘的 API Key 在下次启动会被彻底忽略——
    # 表现为"明明填过 Key，却一直说未配置"。
    from core.envfile import load_env_file

    load_env_file(Path(".env"))

    cfg_path = Path(path) if path else Path("config.yaml")
    if cfg_path.is_file():
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        _apply_section(cfg.scan, raw.get("scan") or {})
        _apply_section(cfg.rag, raw.get("rag") or {})
        # 兼容旧配置里的 `ai:` 段
        _apply_section(cfg.llm, raw.get("llm") or raw.get("ai") or {})
        for k in ("output_dir", "data_dir"):
            if raw.get(k) is not None:
                setattr(cfg, k, raw[k])

    # ── 环境变量覆盖 ────────────────────────────────────────────
    # 全部走 _env_* 入口：空串=未设置、类型错=保留默认并警告。
    # 以前这里混着 `if v := e.get(...)`（空串跳过）与裸 `float(v)`/`int(v)`
    # （空串解析失败直接崩），同一批参数三种脾气。
    s = cfg.scan
    s.timeout = _env_float("POCS_TIMEOUT", s.timeout)
    s.concurrency = _env_int("POCS_CONCURRENCY", s.concurrency)
    s.proxy = _env_str("POCS_PROXY", s.proxy or "") or None
    s.no_proxy = _env_list("POCS_NO_PROXY", s.no_proxy)
    s.proxy_local_direct = _env_bool("POCS_PROXY_LOCAL_DIRECT", s.proxy_local_direct)
    s.proxy_autodetect = _env_bool("POCS_PROXY_AUTODETECT", s.proxy_autodetect)
    s.auto_dismiss_public = _env_bool("POCS_AUTO_DISMISS_PUBLIC", s.auto_dismiss_public)
    s.fs_ops_enabled = _env_bool("POCS_FS_OPS", s.fs_ops_enabled)
    s.auto_max_rounds = _env_int("POCS_AUTO_MAX_ROUNDS", s.auto_max_rounds)
    s.port_scan_enabled = _env_bool("POCS_PORT_SCAN", s.port_scan_enabled)
    s.path_scan_enabled = _env_bool("POCS_PATH_SCAN", s.path_scan_enabled)
    s.js_analyze_enabled = _env_bool("POCS_JS_ANALYZE", s.js_analyze_enabled)
    s.js_logic_enabled = _env_bool("POCS_JS_LOGIC", s.js_logic_enabled)
    s.js_logic_probe_api = _env_bool("POCS_JS_LOGIC_PROBE_API", s.js_logic_probe_api)
    s.sqli_probe_enabled = _env_bool("POCS_SQLI_PROBE", s.sqli_probe_enabled)
    s.rce_probe_enabled = _env_bool("POCS_RCE_PROBE", s.rce_probe_enabled)
    s.file_read_probe_enabled = _env_bool("POCS_FILE_READ_PROBE", s.file_read_probe_enabled)
    s.file_upload_probe_enabled = _env_bool("POCS_FILE_UPLOAD_PROBE", s.file_upload_probe_enabled)
    s.upload_require_approval = _env_bool("POCS_UPLOAD_REQUIRE_APPROVAL", s.upload_require_approval)
    s.sqli_max_requests = _env_int("POCS_SQLI_MAX_REQUESTS", s.sqli_max_requests)
    s.probe_max_ops = _env_int("POCS_PROBE_MAX_OPS", s.probe_max_ops)
    s.probe_error_abort = _env_int("POCS_PROBE_ERROR_ABORT", s.probe_error_abort)
    s.probe_concurrency = _env_int("POCS_PROBE_CONCURRENCY", s.probe_concurrency)
    s.verify_tls = _env_bool("POCS_VERIFY_TLS", s.verify_tls)
    s.readonly = _env_bool("POCS_READONLY", s.readonly)

    r = cfg.rag
    r.enabled = _env_bool("POCS_RAG_ENABLED", r.enabled)
    r.top_k = _env_int("POCS_RAG_TOP_K", r.top_k)
    r.poc_dir = _env_str("POCS_POC_DIR", r.poc_dir)
    r.knowledge_enabled = _env_bool("POCS_KNOWLEDGE", r.knowledge_enabled)
    r.knowledge_db = _env_str("POCS_KNOWLEDGE_DB", r.knowledge_db)
    r.knowledge_min_severity = _env_str("POCS_KNOWLEDGE_MIN_SEVERITY", r.knowledge_min_severity)
    r.knowledge_min_confidence = _env_float(
        "POCS_KNOWLEDGE_MIN_CONFIDENCE", r.knowledge_min_confidence
    )
    r.knowledge_max_entries = _env_int("POCS_KNOWLEDGE_MAX_ENTRIES", r.knowledge_max_entries)

    m = cfg.llm
    m.enabled = _env_bool("POCS_LLM_ENABLED", m.enabled)
    m.api_key = _env_str("DEEPSEEK_API_KEY", m.api_key)
    m.base_url = _env_str("DEEPSEEK_BASE_URL", m.base_url)
    m.model = _env_str("DEEPSEEK_MODEL", m.model)
    m.deep_model = _env_str("DEEPSEEK_DEEP_MODEL", m.deep_model)
    # 通用 OpenAI 兼容变量（方便切到别家网关）
    m.api_key = _env_str("OPENAI_API_KEY", m.api_key)
    m.base_url = _env_str("OPENAI_BASE_URL", m.base_url)
    m.model = _env_str("OPENAI_MODEL", m.model)

    cfg.output_dir = _env_str("POCS_OUTPUT_DIR", cfg.output_dir)
    cfg.data_dir = _env_str("POCS_DATA_DIR", cfg.data_dir)
    s.evidence_dir = _env_str("POCS_EVIDENCE_DIR", s.evidence_dir)
    # 证据落盘目录的默认值必须等 output_dir 尘埃落定后再填：
    # detector 只拿得到 ScanConfig，够不到顶层的 output_dir。
    # "off" 是显式关闭（报告退回字段重建），其他按给定路径用。
    if not s.evidence_dir:
        s.evidence_dir = str(Path(cfg.output_dir) / "evidence")

    # ── 代理自动探测（"挂了代理却看不到流量"的解药）────────────────
    # 放在最后：此时 proxy 字段已经吃到了 env 覆盖，能正确判断
    # "用户到底显式设了没有"。探测只读本地状态，不发网络请求。
    if s.proxy_autodetect:
        from core.proxy import detect_and_apply  # 局部导入避免循环依赖

        detect_and_apply(s, use_system=True)

    # ── 误报排除清单落点 ─────────────────────────────────────────
    # 跟随 POCS_DATA_DIR。放在这里（而不是让各调用点自己拼路径）是刻意的：
    # 排除清单要在"发现入库"这条公共路径上被查询，那条路径拿不到 cfg。
    # 注意 data_dir 挂在 Config 上、不在 ScanConfig 上（这里是 cfg 不是 s）。
    from core.exclusions import set_store_path  # 局部导入避免循环依赖

    set_store_path(Path(cfg.data_dir) / "exclusions.json")

    _resolve_llm_models(cfg)
    return cfg


def _resolve_llm_models(cfg: Config) -> None:
    """归一化模型名（简写 → 官方名），并收集需要提醒用户的警告。

    这一步不能省：厂商对已下线的模型名**不报错**，只静默换成别的模型
    提供服务。配置层是唯一能在发请求之前发现这件事的地方。

    注意区分两种情况：
    * 空串 / 官方名 / 简写 → 归一化成确定的官方名，静默处理
    * 其他不在注册表里的名字 → **原样保留**（可能是第三方网关的模型，
      也可能只是用户拼错了），但记一条警告让上层打印出来

    规则实现在 :func:`llm.models.normalize`，这里不重复判断。
    """
    from llm.models import normalize

    cfg.llm.model, warn = normalize(cfg.llm.model)
    if warn:
        cfg.llm.model_warnings.append(warn)

    if cfg.llm.deep_model:
        cfg.llm.deep_model, warn2 = normalize(cfg.llm.deep_model)
        if warn2:
            cfg.llm.model_warnings.append(warn2)


def sessions_dir(cfg: Config) -> Path:
    p = Path(cfg.data_dir) / "sessions"
    p.mkdir(parents=True, exist_ok=True)
    return p