"""目录/路径爆破采集器。

两种模式
--------
1. **自实现**（默认）——用内置字典并发GET，靠 :class:`HttpDetector` 的
   软 404 基线机制判断"这个路径真的存在"。零外部依赖。
2. **dirsearch**（若PATH 中存在）——字典更大、支持通配符与状态码过滤。

字典策略
--------
默认字典约 120 条，覆盖高价值目标：配置泄露、备份文件、调试端点、
管理后台、API 前缀。**不**内置大规模字典（动辄几万条）——对授权测试
来说，慢且噪音大。要扩就传 ``scan.path_scan_wordlist`` 指向自己的字典。

速率控制：默认并发受 :class:`ScanConfig.concurrency` 限制，
并额外限制为字典长度的最小值，避免瞬间打满。
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from core.config_loader import ScanConfig
from core.state import Asset, Evidence, POC, RequestSpec
from detectors.base import Detector, random_path

# 内置高价值路径字典（不是通用大字典，是"命中率最高的那批"）
DEFAULT_WORDS: list[str] = [
    # 版本控制 / 配置泄露
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/dirstate",
    ".env", ".env.local", ".env.production", ".env.backup", "env.js",
    "config.php.bak", "config.php~", "web.config", "wp-config.php.bak",
    "application.yml", "application.properties", "settings.py",
    "database.yml", "config.inc.php", "configuration.php",
    # 调试 / 监控端点
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "actuator/heapdump", "actuator/beans", "actuator/configprops",
    "server-status", "server-info", "debug", "_debug/",
    "phpinfo.php", "info.php", "test.php", "elmah.axd",
    "metrics", "prometheus/metrics", "health", "healthz", "readyz",
    # 管理后台
    "admin/", "admin/login", "administrator/", "manager/html",
    "wp-admin/", "phpmyadmin/", "adminer.php", "adminer/",
    "console/", "jenkins/", "nacos/", "grafana/", "kibana/",
    "swagger-ui.html", "swagger-ui/", "swagger-ui/index.html",
    "api-docs", "openapi.json", "swagger.json", "doc.html",
    # API 前缀
    "api/", "api/v1/", "api/v2/", "v1/", "v2/", "rest/",
    "graphql", "graphiql", "api/graphql",
    # 备份 / 压缩包
    "backup.zip", "backup.tar.gz", "www.zip", "web.zip", "site.zip",
    "db.sql", "dump.sql", "database.sql", "backup.sql",
    # 常见敏感文件
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    "WEB-INF/web.xml", "META-INF/MANIFEST.MF",
    # 日志 / 临时文件
    "access.log", "error.log", "debug.log", "app.log",
    "test", "test.html", "shell.php", "cmd.php", "upload/",
    # 框架特定
    "favicon.ico", "static/", "assets/", "public/", "dist/",
    # 云存储配置
    ".aws/credentials", ".s3cfg", "ossfs.conf", "config.php.dist",
]


class PathScanner(Detector):
    """路径爆破采集器。"""

    name = "path_scan"

    def __init__(self, cfg: ScanConfig) -> None:
        super().__init__(cfg)
        self.use_dirsearch = shutil.which("dirsearch") is not None
        self.words: list[str] = list(DEFAULT_WORDS)
        #: 最近一次 dirsearch 的完整过程（结果 / 是否降速 / 拦截理由），
        #: 供上层写进报告。None = 没跑过
        self.last_dirsearch = None
        #: 最近一次 dirsearch 的事件流（start/done/throttle/timeout/error）
        self.dirsearch_events: list[dict] = []

    def load_words(self, wordlist_path: str = "") -> None:
        """加载自定义字典。用户未指定时用内置字典。"""
        if not wordlist_path:
            return
        p = Path(wordlist_path)
        if not p.is_file():
            return
        try:
            words = [
                ln.strip()
                for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
            if words:
                self.words = words
        except OSError:
            pass

    # ── dirsearch（可选）─────────────────────────────────────────
    async def run_dirsearch(self, base_url: str, timeout: int = 300) -> list[Asset]:
        """调用 dirsearch 做深度爆破；被拦截时自动降速到 ``-t 1`` 重试。

        拦截判定与降速重试逻辑在 :mod:`collectors.dirsearch_runner`，
        与子域批量爆破共用——两处此前各拼一次 argv，行为不一致。
        """
        from collectors.dirsearch_runner import run_with_throttle_retry, to_assets

        events: list[dict] = []
        outcome = await run_with_throttle_retry(
            shutil.which("dirsearch") or "dirsearch",
            targets=[base_url],
            wordlist=None,  # 用 dirsearch 自带大字典
            dictionary_size=0,  # 自带字典长度未知，不参与零命中判据
            threads=max(10, self.cfg.concurrency),
            timeout=timeout,
            on_event=lambda kind, payload: events.append({"kind": kind, **payload}),
        )
        self.last_dirsearch = outcome
        self.dirsearch_events = events
        if outcome.throttled:
            reason = outcome.block_reasons[0] if outcome.block_reasons else "未知"
            print(f"[collect] dirsearch 被拦截（{reason}），已降速到单线程重试")
        return to_assets(outcome)

    # ── 自实现路径探测 ───────────────────────────────────────────
    async def run_builtin(self, base_url: str, verbose: bool = False) -> list[Asset]:
        """用内置字典并发探测，靠软 404 基线过滤噪音。"""
        base = base_url.rstrip("/") + "/"
        await self.probe_soft404(base)  # 建立基线——这一步是降误报的关键

        sem = asyncio.Semaphore(max(4, self.cfg.concurrency))
        assets: list[Asset] = []

        async def one(word: str) -> Asset | None:
            async with sem:
                url = self.build_url(base, self._probe_poc(word), word)
                ev = await self.send_request(url)
                if ev.error or ev.status_code is None:
                    return None
                if ev.status_code >= 400 and ev.status_code not in {401, 403}:
                    return None
                if self.is_soft404(ev):
                    return None
                return Asset(
                    kind="path",
                    value=word,
                    meta={"url": ev.url, "status": ev.status_code,
                          "size": ev.body_size, "title": self._title(ev)},
                    source="path_scan",
                )

        if verbose:
            print(f"[collect] 路径爆破：{len(self.words)} 条字典")
        results = await asyncio.gather(
            *(one(w) for w in self.words), return_exceptions=True
        )
        for r in results:
            if isinstance(r, Asset):
                assets.append(r)
        return assets

    @staticmethod
    def _title(ev: Evidence) -> str:
        import re

        if m := re.search(r"<title[^>]*>(.*?)</title>", ev.body_excerpt, re.IGNORECASE):
            return re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        return ""

    @staticmethod
    def _probe_poc(word: str) -> POC:
        """把一个路径包成最小 POC 以复用 :meth:`build_url`。"""
        from core.state import Category, Severity

        return POC(
            id="probe",
            name="probe",
            category=Category.PATH_PROBE,
            severity=Severity.INFO,
            request=RequestSpec(paths=[word], expect_status=[200, 401, 403]),
        )

    # ── 对外入口 ──────────────────────────────────────────────────
    async def run(self, base_url: str, verbose: bool = False) -> list[Asset]:
        if not self.cfg.path_scan_enabled:
            return []
        self.load_words(self.cfg.path_scan_wordlist)

        if self.use_dirsearch:
            if verbose:
                print("[collect] 路径爆破：dirsearch")
            assets = await self.run_dirsearch(base_url)
            if assets:
                return assets
            if verbose:
                print("[collect] dirsearch 无结果，回退内置字典")

        return await self.run_builtin(base_url, verbose)

    async def verify(self, poc: POC, base_url: str, rag_score: float = 0.0) -> list:
        """采集器不做漏洞判定，:meth:`verify` 留空。"""
        return []


# 让路径扫描器可复用随机路径工具（软 404 基线）
__all__ = ["PathScanner", "DEFAULT_WORDS", "random_path"]