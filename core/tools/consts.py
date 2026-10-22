"""工具层共享常量。

放在独立模块（而不是某个 handler 里）是因为声明层（``builtins.py`` 的
schema 描述）与执行层（``runner/files.py`` 的 handler）都要引用它——
描述里的"上限 400"和实现里的 ``min(..., 400)`` 必须是**同一个数**，
否则文档会悄悄漂移（模型按文档传 500，被实现截到 400，它还不知道为什么）。
"""

from __future__ import annotations

# read_file 翻页模式单次最多读多少行。
# 调整这个值只需改这里：builtins.py 的 schema 描述是 f-string 引用，
# runner/files.py 的截断同样引用——三处（含描述）永远不会漂移。
MAX_READ_LINES = 400
