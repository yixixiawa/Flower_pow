"""文件操作工具：列目录、读、写、改、删。

沙箱与闸门在 :mod:`core.fsops`（路径穿行、扩展名白名单、重解析点检查），
这里只负责把工具参数翻译成沙箱调用并把结果讲给模型听。
"""

from __future__ import annotations

import time

from core.tools.consts import MAX_READ_LINES


class FileMixin:
    """见模块说明。"""

    # ── 文件操作（沙箱与闸门在 core/fsops.py）─────────────────────

    def _sandbox(self):
        from core.fsops import sandbox_for

        return sandbox_for(self.cfg)

    async def _h_list_files(self, session, path: str = "") -> str:
        from core.fsops import FileOpDenied

        try:
            sb = self._sandbox()
            items = sb.list_dir(path)
        except FileOpDenied as exc:
            return f"【已拒绝】{exc}"
        except Exception as exc:  # noqa: BLE001
            return f"列出失败：{type(exc).__name__}: {exc}"
        where = f"{sb.root}/{path.strip('/')}" if (path or "").strip() else str(sb.root)
        if not items:
            return f"{where} 下没有文件"
        lines = [f"{where} 共 {len(items)} 项："]
        for it in items:
            if it["dir"]:
                lines.append(f"  [目录] {it['path']}/")
            else:
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(it["mtime"]))
                lines.append(f"  [文件] {it['path']}  {it['size']} 字节  {ts}")
        lines.append("  修改报告前先用 read_file 看清原文，再用 edit_file 就地改。")
        return "\n".join(lines)

    async def _h_read_file(
        self,
        session,
        path: str = "",
        start_line: int = 1,
        max_lines: int = 400,
        grep: str = "",
        context: int = 3,
    ) -> str:
        from core.fsops import FileOpDenied

        try:
            sb = self._sandbox()
            text = sb.read(path)
        except FileOpDenied as exc:
            return f"【已拒绝】{exc}"
        except Exception as exc:  # noqa: BLE001
            return f"读取失败：{type(exc).__name__}: {exc}"

        all_lines = text.splitlines()

        # ── grep 模式：按内容定位，不翻页 ──────────────────────────
        # 这是治"Agent 通读 JS 文件"的主药：给它一次定位到目标函数的能力，
        # 而不是只能 start_line 一页页翻。267 行 JS 找 postData 从 7 次 → 1 次。
        if (grep or "").strip():
            import re as _re

            try:
                pat = _re.compile(grep, _re.I)
            except _re.error as exc:
                return f"grep 正则无效：{exc}"
            # context=0 是合法值（只要命中行本身）——不能用 `context or 3`，
            # 0 是假值会被吞成默认 3（测试抓出来的真 bug）。
            ctx = 3 if context in (None, "") else max(0, min(int(context), 20))
            hits = [(i, ln) for i, ln in enumerate(all_lines, 1) if pat.search(ln)]
            if not hits:
                return f"{path}（共 {len(all_lines)} 行）中未找到 {grep!r}"
            out = [f"{path}（共 {len(all_lines)} 行，{len(hits)} 处命中 {grep!r}）："]
            for i, ln in hits[:20]:  # 最多 20 处，防命中太多刷屏
                lo, hi = max(1, i - ctx), min(len(all_lines), i + ctx)
                out.append(f"--- 第 {i} 行命中 ---")
                out.extend(f"{n:>5}  {all_lines[n-1]}" for n in range(lo, hi + 1))
            if len(hits) > 20:
                out.append(f"…（另有 {len(hits)-20} 处命中，收窄 grep 或加 context）")
            return "\n".join(out)

        # ── 原有翻页模式不变 ──────────────────────────────────────
        start = max(1, int(start_line or 1))
        take = max(1, min(int(max_lines or MAX_READ_LINES), MAX_READ_LINES))
        chunk = all_lines[start - 1 : start - 1 + take]
        head = (
            f"{path}（共 {len(all_lines)} 行，显示第 {start}–"
            f"{start + len(chunk) - 1} 行）："
        )
        tail = "" if start - 1 + len(chunk) >= len(all_lines) else (
            "…（还有更多。**不要逐页翻**——用 grep=\"你要找的函数名/关键字\" 一次定位；"
            "确实要通读再调 start_line 继续。）"
        )
        return "\n".join([head, *chunk, tail] if tail else [head, *chunk])

    async def _h_write_file(
        self, session, path: str = "", content: str = "", overwrite: bool = True
    ) -> str:
        from core.fsops import FileOpDenied

        try:
            sb = self._sandbox()
            existed = sb.resolve(path).exists()
            f = sb.write(path, content, overwrite=overwrite)
        except FileOpDenied as exc:
            return f"【已拒绝】{exc}"
        except Exception as exc:  # noqa: BLE001
            return f"写入失败：{type(exc).__name__}: {exc}"
        size = f.stat().st_size
        act = "覆盖" if existed else "新建"
        return (
            f"已{act}：{sb.rel(f)}（{size} 字节）\n"
            f"  完整路径：{f}\n"
            f"  同一目录现有文件可用 list_files 查看；\n"
            f"  **只想改其中一段时用 edit_file，不要整篇重写**——"
            f"整篇重写会把别处的内容也一起换掉。"
        )

    async def _h_edit_file(
        self,
        session,
        path: str = "",
        old_text: str = "",
        new_text: str = "",
        count: int = 1,
    ) -> str:
        from core.fsops import FileOpDenied

        try:
            sb = self._sandbox()
            f, done = sb.edit(path, old_text, new_text, count=int(count))
        except FileOpDenied as exc:
            # 拒绝是**正常返回值**：模型据此改 prompt 重试，别当异常
            return f"【已拒绝】{exc}"
        except Exception as exc:  # noqa: BLE001
            return f"修改失败：{type(exc).__name__}: {exc}"
        return (
            f"已就地修改：{sb.rel(f)}（替换 {done} 处，{f.stat().st_size} 字节）\n"
            f"  原文件被原子替换，其余内容一字未动。"
        )

    async def _h_delete_file(self, session, path: str = "") -> str:
        from core.fsops import FileOpDenied

        try:
            sb = self._sandbox()
            f, size = sb.delete(path)
        except FileOpDenied as exc:
            return f"【已拒绝】{exc}"
        except Exception as exc:  # noqa: BLE001
            return f"删除失败：{type(exc).__name__}: {exc}"
        # 删除不可撤销，必须在会话里留痕（会进报告的「执行说明」）
        session.result.notes.append(f"删除产物文件：{sb.rel(f)}（{size} 字节）")
        return (
            f"已删除：{sb.rel(f)}（原 {size} 字节）\n"
            f"  删除不可撤销。要重新生成报告用 export_report。"
        )
