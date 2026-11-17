# -*- coding: utf-8 -*-
"""噪音判官 溯源指纹：注入/移除/检测（不使用额外 script/style 标签）。"""
import hashlib, re

SIG_TEXT = "noise-judge|W17607728505|v7"
SIG_SHORT = hashlib.sha256(SIG_TEXT.encode("utf-8")).hexdigest()[:12]
ZW = {"0": "\u200b", "1": "\u200c"}
ZW_ALL = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060")
BLOCK = "<!--qz-fingerprint-->"
BLOCK_END = "<!--/qz-fingerprint-->"


def encode(text):
    bits = "".join(format(int(c, 16), "04b") for c in text)
    return "".join(ZW[b] for b in bits)


def zw_segments(text):
    segs, cur = [], []
    for ch in text:
        if ch in ZW_ALL:
            cur.append(ch)
        else:
            if cur:
                segs.append("".join(cur)); cur = []
    if cur:
        segs.append("".join(cur))
    return segs


def decode(zw_text):
    bits = []
    for ch in zw_text:
        if ch == ZW["0"]:
            bits.append("0")
        elif ch == ZW["1"]:
            bits.append("1")
        elif ch in ("\u200d", "\ufeff", "\u2060"):
            pass
        else:
            return None
    if len(bits) < 8 or len(bits) % 4:
        return None
    try:
        return "".join(format(int("".join(bits[i:i+4]), 2), "x") for i in range(0, len(bits), 4))
    except ValueError:
        return None


def strip_zw(s):
    for ch in ZW_ALL:
        s = s.replace(ch, "")
    return s


def strip_fingerprint(html):
    html = re.sub(re.escape(BLOCK) + r".*?" + re.escape(BLOCK_END), "", html, flags=re.S)
    html = re.sub(r"<title>(.*?)</title>",
                  lambda m: "<title>" + strip_zw(m.group(1)) + "</title>", html, flags=re.S)
    html = re.sub(r'<meta name="qz-sig"[^>]*>', "", html)
    html = re.sub(r'<meta name="author"[^>]*>', "", html)
    html = re.sub(r'<span id="qz-sig"[^>]*>.*?</span>', "", html, flags=re.S)
    html = re.sub(r'\s*--qz-sig:[^;]*;', "", html)
    html = re.sub(r"const QZ_SIGNATURE\s*=\s*'[^']*';", "", html)
    html = re.sub(r"const QZ_SIG_SHORT\s*=\s*'[^']*';", "", html)
    html = re.sub(r"qz-fingerprint\s+[0-9a-f]+\s+[^\s<]+", "", html)
    return html


def inject(html):
    html = strip_fingerprint(html)
    zw = encode(SIG_SHORT)
    block = f"""{BLOCK}
<meta name="qz-sig" content="{SIG_SHORT}">
<meta name="author" content="W17607728505">
<!-- qz-fingerprint {SIG_SHORT} {SIG_TEXT} -->
<span id="qz-sig" hidden data-sig="{SIG_SHORT}" data-qz-signature="{SIG_TEXT}" aria-hidden="true">{zw}</span>
{BLOCK_END}"""
    html = html.replace("</head>", block + "\n</head>", 1)
    html = re.sub(r"<title>(.*?)</title>",
                  lambda m: "<title>" + m.group(1) + zw + "</title>", html, count=1, flags=re.S)
    return html


def detect(html):
    hits = []
    for m in re.finditer(r"<title>(.*?)</title>", html, flags=re.S):
        for seg in zw_segments(m.group(1)):
            code = decode(seg)
            if code:
                hits.append(("title零宽指纹", code, code == SIG_SHORT))
    for seg in zw_segments(html):
        code = decode(seg)
        if code:
            hits.append(("正文零宽指纹", code, code == SIG_SHORT))
    for m in re.finditer(r'data-sig="([0-9a-f]+)"', html):
        hits.append(("隐藏元素", m.group(1), m.group(1) == SIG_SHORT))
    for m in re.finditer(r'<meta name="qz-sig" content="([0-9a-f]+)"', html):
        hits.append(("meta标签", m.group(1), m.group(1) == SIG_SHORT))
    for m in re.finditer(r"qz-fingerprint\s+([0-9a-f]+)\s+([^\s<]+)", html):
        hits.append(("注释签名", m.group(2), m.group(1) == SIG_SHORT))
    for m in re.finditer(r'data-qz-signature="([^"]+)"', html):
        hits.append(("隐藏签名串", m.group(1), m.group(1) == SIG_TEXT))
    for m in re.finditer(r"--qz-sig:([0-9a-f]+)", html):
        hits.append(("CSS属性", m.group(1), m.group(1) == SIG_SHORT))
    for m in re.finditer(r"QZ_SIG_SHORT\s*=\s*'([0-9a-f]+)'", html):
        hits.append(("JS常量", m.group(1), m.group(1) == SIG_SHORT))
    seen, uniq = set(), []
    for h in hits:
        k = (h[0], h[1])
        if k not in seen:
            seen.add(k); uniq.append(h)
    return uniq


if __name__ == "__main__":
    print("SIG_TEXT  =", SIG_TEXT)
    print("SIG_SHORT =", SIG_SHORT)
