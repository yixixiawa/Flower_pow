"""命名：slugify / 主域名裁剪 / 时间戳后缀。

原 ``report.py`` 的命名段。**被 paths / json / markdown / html 几乎都用到**，
所以先定在这一块——它不依赖本包任何其他模块，依赖链的根。"""

from __future__ import annotations

import time
import ipaddress
import re as _re
from datetime import datetime
from urllib.parse import urlparse
from core.state import safe_name


_UNSAFE = _re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def slugify(target: str, limit: int = 60) -> str:
    """把目标 URL 转成安全文件名片段。

    Windows 下``:`` ``/`` ``?`` ``*`` 非法，不清洗会生成半截文件名，
    结果报告写成 0 字节。
    """
    return safe_name(target, limit)


def _split_host(target: str) -> tuple[str, int | None]:
    """从目标里取出 ``(主机名, 端口)``。解析不出来时主机名为空。"""
    raw = (target or "").strip()
    if not raw:
        return "", None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlparse(raw)
        return (u.hostname or "").strip(), u.port
    except ValueError:
        return "", None


def target_host(target: str) -> str:
    """完整主机名（含端口），用于报告正文与需要区分端口的场景。

    报告名不用它——见 :func:`target_domain`。
    端口保留（``host:8443`` 与 ``host`` 是两台不同的服务），
    冒号会被 safe_name 换成下划线。
    """
    host, port = _split_host(target)
    if not host:
        return safe_name((target or "").strip() or "target", 60)
    if port:
        host = f"{host}_{port}"
    return safe_name(host, 60)


# 常见"两级公共后缀"：这些后缀下要保留三段（``example.co.uk`` 而不是 ``co.uk``）。
# 这是个**启发式**，不是完整 PSL——真正的 PSL 有上万条且每月更新，为一个文件名
# 引入那份依赖不值得。宁可少裁一段（``a.b.co.uk`` → ``b.co.uk``）也不能多裁
# （把 ``co.uk`` 当成主域名，两个不相干的站会撞同一个文件名）。
_TWO_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "org.hk", "edu.hk", "gov.hk", "net.hk",
        "com.tw", "org.tw", "edu.tw", "gov.tw",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "co.nz", "co.za", "co.in", "net.in", "org.in",
        "com.sg", "com.my", "com.br", "com.mx", "com.ar", "com.tr",
        "com.vn", "com.pk", "com.ua", "com.ru", "com.pl", "com.es",
    }
)


def registrable_domain(host: str) -> str:
    """从主机名取**可注册主域名**：``www.ftitle.studio`` → ``ftitle.studio``。

    IP 地址原样返回（IPv4/IPv6 都没有"子域"可裁）。单段主机名（``localhost``、
    内网机器名）也原样返回。
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def target_domain(target: str) -> str:
    """报告文件名里的「主域名」：**去掉子域**，取可注册域名。

    为什么用主域名而不是完整主机：``report_20261012_ftitle.studio.md``
    一眼能认出"哪一天、测的哪个站"，而 ``report_20261012_www.ftitle.studio.md``
    多出来的 ``www.`` 不带信息量。同一主域下的 ``www`` / ``api`` / ``m.``
    本来就是同一个站点，散成三份报告反而更难找。

    **代价与对策**：同一主域的不同子站会撞同一个文件名。所以 :func:`_report_stem`
    在写入前会读一下同名文件里记录的目标，发现是**另一个目标**就自动加子域后缀
    （``..._api.md``）区分开——不静默把两份报告合并成一份。

    端口保留：``host:8443`` 与 ``host`` 是两个不同的服务。
    """
    host, port = _split_host(target)
    if not host:
        return safe_name((target or "").strip() or "target", 60)
    d = registrable_domain(host)
    if port:
        d = f"{d}_{port}"
    return safe_name(d, 60)


def _stamp(epoch: float) -> str:
    """文件名里的日期：``20261011``。

    用紧凑日期而非时间戳：既是"日期"（用户要的），又保证字典序 == 时间序，
    同一天跑多次也不会互相覆盖（撞名时由 :func:`_unique_path` 加序号）。
    """
    try:
        return datetime.fromtimestamp(epoch or time.time()).strftime("%Y%m%d")
    except (OSError, OverflowError, ValueError):
        return datetime.now().strftime("%Y%m%d")
