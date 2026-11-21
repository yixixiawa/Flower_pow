"""产物查询 handler：``artifact_query``。

工具输出超长时会被落成 artifact（``output/tool-output/xxx.txt``）。模型要
其中某一段，不该用 ``read_file`` 一页页翻——那是拿上下文换"顺序"。
这个 handler 提供三个维度的**定点查询**，并在同一 artifact + 同一条件下
命中缓存（不重复读盘、不重复回灌同样内容）。

安全边界与 ``read_file`` 同源：只允许产物目录内的相对路径，绝对路径/
盘符/``..``/符号链接逃逸一律拒绝（见 :mod:`core.artifact`）。
"""

from __future__ import annotations


class ArtifactMixin:
    """见模块说明。"""

    def _artifact_store(self):
        """同一 runner 共用一个 store——缓存必须跨调用存活才有意义。

        每次 new 一个 ``ArtifactStore``，``_cache`` 就是新的空字典，
        "同 artifact 同查询命中缓存"永远不可能成立（这条真踩过）。
        """
        from core.artifact import ArtifactStore

        out = getattr(self.cfg, "output_dir", ".") or "."
        cached = getattr(self, "_artifact_cache", None)
        if cached is None or cached[0] != out:
            cached = (out, ArtifactStore(out))
            self._artifact_cache = cached
        return cached[1]

    async def _h_artifact_query(
        self,
        session,
        path: str = "",
        keyword: str = "",
        start_line: int = 0,
        end_line: int = 0,
        jsonpath: str = "",
        context: int = 3,
        max_chars: int = 0,
    ) -> str:
        from core.artifact import MAX_QUERY_CHARS, ArtifactError

        if not (path or "").strip():
            return "【参数不合法】artifact_query 需要 path（如 tool-output/xxx.txt）"
        store = self._artifact_store()
        limit = int(max_chars or 0) or MAX_QUERY_CHARS
        try:
            res = store.query(
                path,
                keyword=keyword or "",
                start_line=int(start_line or 0),
                end_line=int(end_line or 0),
                jsonpath=jsonpath or "",
                context=int(context or 0),
                max_chars=limit,
            )
        except ArtifactError as exc:
            return f"【已拒绝】{exc}"
        except OSError as exc:
            return f"【执行失败】读取 artifact 失败：{type(exc).__name__}: {exc}"
        return res.render()


__all__ = ["ArtifactMixin"]
