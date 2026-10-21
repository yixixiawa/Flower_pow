"""外部漏洞情报源（pocindex.io）—— RAG 的第二知识源。

它是什么
--------
一个公开的 CVE **元数据**索引站（开源项目 0xMarcio/pocindex），提供若干个
可直接下载的 JSON 端点：

===================== ======================================================
端点                   内容
===================== ======================================================
``CVE_list.json``      每个 CVE 的描述 + PoC/Nuclei/Metasploit/ExploitDB 链接
``cve_metadata.json``  NVD 的 CVSS v2/v3/v4 评分、向量字符串、公告链接
``epss.json``          EPSS 利用概率与百分位
``kev.json``           CISA 已知在野利用清单
``nuclei.json``        该 CVE 是否有可运行的 Nuclei 模板及其元数据
===================== ======================================================

**只有元数据，没有任何利用代码**——所以它给RAG 提供的是"这个 CVE 存在吗？
多严重？在野利用了吗？分数多少？"这类**上下文**，而不是可执行的 payload。

在这个项目里它解决什么问题
--------------------------
内置 POC 库是人写的，覆盖有限。pocindex 补的是**情报维度**：
当 RAG 召回一条 CVE 类 POC 时，可以用这个数据源给它补上 CVSS、
KEV 标记、EPSS 概率，让报告里的风险排序有客观依据，而不是只有我们手写的等级。

用法::

    from kb.intel import IntelStore
    intel = IntelStore()
    intel.refresh()                      # 首次会下载并缓存到 data/intel/
    info = intel.lookup("CVE-2021-44228")
    # {'cvss': 10.0, 'severity': 'CRITICAL', 'kev': False, 'epss': 0.97, ...}

降级策略：网络不可用 / 端点变化时静默返回空，**绝不阻塞扫描**。
情报是增强项，不是必需项。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

BASE_URL = "https://pocindex.io"
ENDPOINTS: dict[str, str] = {
    "cve_list": f"{BASE_URL}/CVE_list.json",
    "metadata": f"{BASE_URL}/cve_metadata.json",
    "epss": f"{BASE_URL}/epss.json",
    "kev": f"{BASE_URL}/kev.json",
    "nuclei": f"{BASE_URL}/nuclei.json",
}

# CVE 官方编号格式：``CVE-年份-序号``，序号 4~7 位不定长。
# 各数据源里 ID 字段的形态并不统一——可能是裸 ID，也可能带路径前缀
# （``cves/CVE-2021-44228.md``）或混入多个（``"CVE-2021-44228, CVE-2022-22965"``），
# 所以统一用正则**提取**而不是 startswith 校验。
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def extract_cve_ids(text: str) -> set[str]:
    """从任意文本中提取全部 CVE 编号（统一大写）。

    >>> sorted(extract_cve_ids("cves/CVE-2021-44228.md"))
    ['CVE-2021-44228']
    >>> sorted(extract_cve_ids("CVE-2021-44228, CVE-2022-22965"))
    ['CVE-2021-44228', 'CVE-2022-22965']
    >>> extract_cve_ids("no cve here")
    set()
    """
    return {m.group(0).upper() for m in CVE_RE.finditer(text)}

# 缓存有效期：24 小时。情报更新没那么快，没必要每次扫描都下。
CACHE_TTL = 24 * 3600


@dataclass(slots=True)
class CveIntel:
    """单条 CVE 的情报。"""

    cve: str
    description: str = ""
    cvss: float | None = None
    severity: str = ""
    vector: str = ""
    epss: float | None = None
    kev: bool = False
    has_poc: bool = False
    has_nuclei: bool = False
    references: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        bits: list[str] = []
        if self.cvss is not None:
            bits.append(f"CVSS {self.cvss}")
        if self.severity:
            bits.append(self.severity)
        if self.kev:
            bits.append("CISA KEV 在野利用")
        if self.epss is not None:
            bits.append(f"EPSS {self.epss:.0%}")
        if self.has_nuclei:
            bits.append("有 Nuclei 模板")
        return " | ".join(bits)


class IntelStore:
    """pocindex 情报的本地缓存。"""

    def __init__(self, cache_dir: str | Path = "./data/intel", timeout: float = 20.0) -> None:
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self._cves: dict[str, CveIntel] = {}
        self._loaded = False
        self.errors: list[str] = []

    # ── 缓存读写 ──────────────────────────────────────────────────
    def _cache_path(self, name: str) -> Path:
        return self.cache_dir / f"{name}.json"

    def _read_cache(self, name: str) -> Any | None:
        p = self._cache_path(name)
        if not p.is_file():
            return None
        try:
            if time.time() - p.stat().st_mtime > CACHE_TTL:
                return None
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(self, name: str, data: Any) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_path(name).write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            self.errors.append(f"情报缓存写入失败: {exc}")

    # ── 解析各端点的数据结构 ──────────────────────────────────────
    @staticmethod
    def _parse_cve_list(data: Any) -> dict[str, dict[str, Any]]:
        """``CVE_list.json`` —— 结构随上游演进，因此做多形态兼容。"""
        out: dict[str, dict[str, Any]] = {}
        if isinstance(data, dict):
            for k, v in data.items():
                cid = str(k).upper()
                if not cid.startswith("CVE-"):
                    continue
                out[cid] = v if isinstance(v, dict) else {"description": str(v)}
        elif isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                cid = str(row.get("cve") or row.get("id") or "").upper()
                if cid.startswith("CVE-"):
                    out[cid] = row
        return out

    @staticmethod
    def _parse_metadata(data: Any) -> dict[str, dict[str, Any]]:
        """``cve_metadata.json`` —— 提取最高版本的 CVSS 分数。

        README 说明 CVSS 行形如 ``[version, score, severity, vector, source, type]``，
        所以要按"版本号最大优先"挑，而不是取第一条。
        """
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(data, dict):
            return out
        rows = data.get("cvss") or data.get("assessments") or data
        if not isinstance(rows, dict):
            return out

        for cid, entry in rows.items():
            key = str(cid).upper()
            if not key.startswith("CVE-"):
                continue
            best: dict[str, Any] = {}
            best_ver = -1.0
            candidates: list[Any] = []
            if isinstance(entry, list):
                candidates = entry
            elif isinstance(entry, dict):
                for v in entry.values():
                    if isinstance(v, list):
                        candidates.extend(v)
                    elif isinstance(v, dict):
                        candidates.append(v)
            for c in candidates:
                if not isinstance(c, (list, tuple)) or len(c) < 3:
                    continue
                try:
                    ver = float(str(c[0]).replace("v", "") or 0)
                    score = float(c[1])
                except (TypeError, ValueError):
                    continue
                if ver > best_ver:
                    best_ver = ver
                    best = {
                        "cvss": score,
                        "severity": str(c[2]).upper() if len(c) > 2 else "",
                        "vector": str(c[3]) if len(c) > 3 else "",
                    }
            if best:
                out[key] = best
        return out

    @staticmethod
    def _parse_epss(data: Any) -> dict[str, float]:
        out: dict[str, float] = {}
        if isinstance(data, dict):
            for k, v in data.items():
                # 键是权威来源，不做提取（``CVE-2021-44228`` 本身是干净键名），
                # 但仍需挡住非 CVE 的杂项键
                cid = str(k).upper()
                if not cid.startswith("CVE-"):
                    continue
                val = v
                if isinstance(v, (list, tuple)) and v:
                    val = v[0]
                if isinstance(val, dict):
                    val = val.get("epss") or val.get("score")
                try:
                    out[cid] = float(val)
                except (TypeError, ValueError):
                    continue
        return out

    @staticmethod
    def _parse_kev(data: Any) -> set[str]:
        """``kev.json`` —— 返回 KEV 中的 CVE 集合。"""
        out: set[str] = set()
        if isinstance(data, dict):
            for key in ("vulnerabilities", "kev", "entries", "data"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if isinstance(data, list):
            for row in data:
                if isinstance(row, dict):
                    cid = str(row.get("cveID") or row.get("cve") or "").upper()
                    if cid.startswith("CVE-"):
                        out.add(cid)
                elif isinstance(row, str) and row.upper().startswith("CVE-"):
                    out.add(row.upper())
        elif isinstance(data, dict):
            for k in data:
                if str(k).upper().startswith("CVE-"):
                    out.add(str(k).upper())
        return out

    @staticmethod
    def _parse_nuclei(data: Any) -> set[str]:
        """``nuclei.json`` —— 有可运行 Nuclei 模板的 CVE 集合。"""
        out: set[str] = set()
        if isinstance(data, dict):
            for key in ("nuclei", "templates", "data", "entries"):
                if isinstance(data.get(key), (list, dict)):
                    data = data[key]
                    break
        if isinstance(data, dict):
            for k in data:
                if str(k).upper().startswith("CVE-"):
                    out.add(str(k).upper())
        elif isinstance(data, list):
            for row in data:
                if isinstance(row, dict):
                    # 字段值可能是裸 ID，也可能带路径前缀（``cves/CVE-2021-44228.md``）
                    # 或混入多个 ID（``"CVE-2021-44228, CVE-2022-22965"``），需逐个提取
                    raw = str(
                        row.get("cve") or row.get("id") or row.get("templateID") or ""
                    ).upper()
                    out.update(extract_cve_ids(raw))
                elif isinstance(row, str):
                    out.update(extract_cve_ids(row.upper()))
        return out

    # ── 加载 ──────────────────────────────────────────────────────
    def _load_all(self) -> None:
        """按需加载缓存/网络数据并合成 CveIntel。"""
        if self._loaded:
            return
        self._loaded = True

        cve_list = self._get("cve_list", self._parse_cve_list)
        meta = self._get("metadata", self._parse_metadata)
        epss = self._get("epss", self._parse_epss)
        kev = self._get("kev", self._parse_kev)
        nuclei = self._get("nuclei", self._parse_nuclei)

        for cid, row in cve_list.items():
            refs: list[str] = []
            for key in ("poc", "nuclei", "msf", "edb", "vulhub"):
                v = row.get(key)
                if isinstance(v, str) and v.startswith("http"):
                    refs.append(v)
                elif isinstance(v, list):
                    refs.extend(x for x in v if isinstance(x, str) and x.startswith("http"))
            self._cves[cid] = CveIntel(
                cve=cid,
                description=str(row.get("description") or row.get("desc") or "")[:2000],
                has_poc=bool(row.get("poc")),
                has_nuclei=cid in nuclei or bool(row.get("nuclei")),
                references=refs[:10],
                cvss=(meta.get(cid) or {}).get("cvss"),
                severity=(meta.get(cid) or {}).get("severity", ""),
                vector=(meta.get(cid) or {}).get("vector", ""),
                epss=epss.get(cid),
                kev=cid in kev,
            )

        # 元数据里有但cve_list 没有的（描述缺失）也纳入，至少有 CVSS 可用
        for cid, m in meta.items():
            if cid not in self._cves:
                self._cves[cid] = CveIntel(
                    cve=cid,
                    cvss=m.get("cvss"),
                    severity=m.get("severity", ""),
                    vector=m.get("vector", ""),
                    epss=epss.get(cid),
                    kev=cid in kev,
                )

    def _get(self, name: str, parser: Any) -> dict:
        cached = self._read_cache(name)
        if cached is not None:
            try:
                return parser(cached)
            except Exception:  # noqa: BLE001
                pass

        url = ENDPOINTS[name]
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as c:
                resp = c.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 —— 情报是增强项，失败不阻塞
            self.errors.append(f"[intel] {name} 获取失败: {type(exc).__name__}")
            # 旧缓存不限期过期地兜底
            p = self._cache_path(name)
            if p.is_file():
                try:
                    return parser(json.loads(p.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError):
                    return {}
            return {}
        self._write_cache(name, data)
        try:
            return parser(data)
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"[intel] {name} 解析失败: {type(exc).__name__}")
            return {}

    # ── 对外接口 ──────────────────────────────────────────────────
    def lookup(self, cve: str) -> CveIntel | None:
        """查单条 CVE。"""
        self._load_all()
        return self._cves.get(str(cve).upper())

    def lookup_many(self, cves: list[str]) -> dict[str, CveIntel]:
        self._load_all()
        return {
            c.upper(): self._cves[c.upper()]
            for c in cves
            if c.upper() in self._cves
        }

    def refresh(self, force: bool = False) -> int:
        """强制刷新缓存。返回载入的 CVE 数量。"""
        if force:
            for name in ENDPOINTS:
                p = self._cache_path(name)
                if p.is_file():
                    try:
                        p.unlink()
                    except OSError:
                        pass
            self._loaded = False
            self._cves.clear()
        self._load_all()
        return len(self._cves)

    def enrich(self, cve: str, tags: list[str] | None = None) -> list[str]:
        """把情报转成 Finding 的标签——让报告能展示客观风险指标。"""
        info = self.lookup(cve)
        if not info:
            return []
        out: list[str] = []
        if info.cvss is not None:
            out.append(f"cvss-{info.cvss:g}")
        if info.severity:
            out.append(f"cvss-{info.severity.lower()}")
        if info.kev:
            out.append("cisa-kev")
        if info.epss is not None:
            out.append(f"epss-{info.epss:.0%}")
        if info.has_nuclei:
            out.append("has-nuclei-template")
        if tags:
            out.extend(tags)
        return out

    def __len__(self) -> int:
        self._load_all()
        return len(self._cves)


# 模块级单例——情报数据很大，多份拷贝浪费内存
_default: IntelStore | None = None


def get_intel(cache_dir: str | Path = "./data/intel") -> IntelStore:
    global _default
    if _default is None:
        _default = IntelStore(cache_dir)
    return _default