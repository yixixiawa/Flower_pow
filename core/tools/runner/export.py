"""报告导出：把会话结果落成 Markdown / HTML / JSON 三份产物。

``fmt`` 校验必须在参数归一之后做——``normalize_args`` 会把 ``"MD"``、
``"md "`` 归一成 ``md``，而枚举外的值（如 ``markdown``）会原样传下来。
"""

from __future__ import annotations

from pathlib import Path


class ExportMixin:
    """见模块说明。"""

    async def _h_export_report(
        self, session, fmt: str = "all", overwrite: bool = True
    ) -> str:
        from output.report import (
            plan_reports,
            write_html,
            write_json,
            write_markdown,
        )

        # fmt 必须在归一之后校验：normalize_args 已把 "MD"、"md " 归一成 "md"，
        # 但 "markdown" 这类不在枚举里的值会原样传下来。以前这里三个
        # `if fmt in (...)` 全落空时照样返回"报告已导出："——一个文件都没写
        # 却报了成功，模型会以为报告已经产出，用户等半天什么都找不到。
        # 静默失败是最坏的一种失败，必须当场报错并列出合法值。
        fmt = str(fmt or "all").strip().lower()
        if fmt not in ("md", "html", "json", "all"):
            return (
                f"【参数不合法】fmt={fmt!r} 无法识别，一个文件都没有导出。"
                f"合法值：md / html / json / all（默认 all）。"
            )

        s = session
        # 兜底同步：报告命名读的是 result.target，不是 session.target。
        # 正常路径（repl /target、set_target 工具）两处都已同步，但只要
        # 将来新增一条只改 session.target 的赋值路径，这里就是最后防线——
        # 否则文件名退化成 report_<日期>_target，主域名形同虚设。
        if s.target and s.result.target != s.target:
            s.result.target = s.target
        # notes 是**追加**的，反复导出会在里面堆出一串一模一样的会话头。
        # 与 /report（core/repl.py）同一条约定：自己产生的条目带哨兵前缀，
        # 重写前先清掉旧的；哨兵在报告输出前由 _dedupe_notes 剥掉。
        s.result.notes[:] = [
            n for n in s.result.notes if not n.startswith("\x00report:")
        ]
        s.result.notes.insert(0, f"\x00report:交互式会话 {s.session_id}，共 {len(s.turns)} 轮")
        if s.model.resources:
            s.result.notes.insert(1, f"\x00report:业务模型：{s.model.summary()}")
        outdir = Path(self.cfg.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        # **一次性**决定这次要写的所有路径：overwrite=False 时如果让三个
        # writer 各自找空位，先写的 json 占掉 _2 后 md 会跳到 _3，三格式
        # 主干错位，报告与 JSON 快照对不上号。plan_reports 保证共用主干。
        # 先查实际目标路径是否存在：覆盖必须是**可见的**，不能静默盖掉上一份。
        formats = ("json", "md", "html") if fmt == "all" else (fmt,)
        planned = plan_reports(s.result, outdir, overwrite=overwrite, formats=formats)
        before = {ext: p.exists() for ext, p in planned.items()}
        writers = {"json": write_json, "md": write_markdown, "html": write_html}
        paths: list[Path] = []
        try:
            for ext in ("json", "md", "html"):
                if ext in planned:
                    paths.append(
                        writers[ext](s.result, outdir, "", path=planned[ext])
                    )
        except Exception as exc:  # noqa: BLE001
            return f"报告导出失败：{type(exc).__name__}: {exc}"

        overwritten = [p for ext, p in planned.items() if before.get(ext, False)]
        lines = ["报告已导出："]
        for p in paths:
            mark = "覆盖" if p in overwritten else "新建"
            size = p.stat().st_size if p.exists() else 0
            lines.append(f"  [{mark}] {p}（{size} 字节）")
        lines.append(
            "  三种格式已收入同一文件夹（report_<日期>_<主域名>/），"
            "共用同一个文件名主干，反复导出不会堆出 _2/_3 副本。"
            f"{'' if overwrite else '（本次 overwrite=false，同名时会另存新文件）'}"
        )
        if overwritten and overwrite:
            # 这条必须说出来：导报告是**整篇重新生成**，之前用 edit_file
            # 打的补丁会被这次的内容盖掉。不说的话，模型会以为"改完再导一次"
            # 是安全的，用户的修改就这么静默丢了。
            lines.append(
                "  ⚠ 覆盖是整篇重新生成：之前用 edit_file 做的局部改动已被替换掉。"
                "\n     要保留手工改动就别再导出；要长期保留某段内容，"
                "先把它记进发现（record_finding）或另存一份说明文件。"
            )
        return "\n".join(lines)
