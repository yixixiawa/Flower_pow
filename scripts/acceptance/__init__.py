"""安全验收框架（不是"pytest 全绿"那种通过）。

设计前提：**测试代码不能自己宣布通过**。用例只负责采集事实
（决策、是否发请求、打到哪个主机、审计写了什么），判定由
:mod:`scripts.acceptance.harness` 对照 :mod:`scripts.acceptance.catalog`
里的**结构化预期**完成。改测试代码、删断言、放宽预期都不会变成 PASS：
断言数低于基线判 FAIL，观测与预期不符判 FAIL，用例没跑判 NOT_TESTED。

对外入口是 ``scripts/security_acceptance.py``。
"""

from __future__ import annotations

__all__ = ["model", "mocknet", "gateway", "harness", "catalog", "report"]
