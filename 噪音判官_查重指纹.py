# -*- coding: utf-8 -*-
"""噪音判官 溯源指纹 检测工具

用法：
    python 噪音判官_查重指纹.py <待检测的.html> [更多文件...]
    python 噪音判官_查重指纹.py            # 不带参数则检测官方版自身

判定：
    官方版   -> 命中且指纹匹配
    非官方拷贝 -> 命中但指纹不匹配（说明被改动过指纹）
    无指纹   -> 未命中（可能整页复制时指纹被清洗，或来自更早版本）
"""
from pathlib import Path
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import qz_fingerprint as F


def check(path):
    try:
        html = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"[读取失败] {type(e).__name__}: {e}"
    hits = F.detect(html)
    if not hits:
        return ("无指纹", "未命中任何指纹标记（可能已被清洗，或来自 v7 之前的版本）")
    matched = [h for h in hits if h[2]]
    lines = ["命中 %d 处标记：" % len(hits)]
    for name, code, ok in hits:
        lines.append("   - %-14s %s  %s" % (name, code, "✓匹配" if ok else "✗不匹配"))
    if matched:
        verdict = "官方版" if len(matched) == len(hits) else "官方版（含改动）"
        lines.append("结论：%s —— 指纹与官方一致" % verdict)
    else:
        lines.append("结论：非官方拷贝 —— 命中标记但指纹已被篡改/替换")
    return None, "\n".join(lines)


def main():
    args = sys.argv[1:]
    if not args:
        args = [str(Path(__file__).resolve().parent / "噪音判官_原型.html")]
        print("（未指定文件，默认检测官方版：噪音判官_原型.html）\n")
    for a in args:
        print("=" * 60)
        print("文件：", a)
        err, msg = check(a)
        print(err if err else msg)
        print()
    print("官方指纹短码：", F.SIG_SHORT)
    print("官方签名串  ：", F.SIG_TEXT)
    print("官方仓库    ：https://github.com/W17607728505/noise-judge")


if __name__ == "__main__":
    main()
