#!/usr/bin/env python3
"""Build bundled payload corpus text files.

Sources:
  - PortSwigger XSS cheat-sheet vectors (portswigger.net/web-security/cross-site-scripting/cheat-sheet)
  - HexBrain / PayloadsAllTheThings XSS Injection passages (hexbrainai.com/payloads/XSS%20Injection,
    derived from swisskyrepo/PayloadsAllTheThings, MIT)
  - Hand-curated context/WAF vectors in tools/curated.txt

Usage (offline regeneration is optional; the .txt files are committed):
  python3 tools/build_corpus.py --ps /path/portswigger.html --patt /path/patt.md
"""
import argparse
import html
import os
import re
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "corpus")

EVENT_RE = re.compile(r"\bon[a-z]+\s*=", re.I)
TAG_RE = re.compile(r"<[a-z!/]", re.I)


def clean_lines(items):
    out = []
    seen = set()
    for v in items:
        v = v.replace("\x00", "").strip()
        if not v or v in seen:
            continue
        # the loader is line-oriented: flatten embedded newlines so one payload
        # never splits into several bogus entries.
        if "\n" in v or "\r" in v:
            v = re.sub(r"[\r\n]+", " ", v).strip()
        if not v or v in seen:
            continue
        if len(v) > 1500:
            continue
        seen.add(v)
        out.append(v)
    return out


def from_portswigger(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    urls = re.findall(r"xss\.php\?x=([^\"&\s]+)", raw)
    vals = []
    for u in urls:
        try:
            vals.append(urllib.parse.unquote(html.unescape(u)))
        except Exception:
            pass
    out = []
    seen = set()

    def add(v, depth=0):
        v = v.strip()
        if not v or v in seen or depth > 2:
            return
        seen.add(v)
        if "xss.php?x=" in v and v.count("<") <= 2:
            m = re.search(r"xss\.php\?x=(.*?)([\"']|\s|$)", v, re.S)
            if m:
                try:
                    add(urllib.parse.unquote(html.unescape(m.group(1))), depth + 1)
                except Exception:
                    pass
        if (TAG_RE.search(v) or "javascript:" in v.lower()
                or v.lower().startswith("data:text/html")
                or "<script" in v.lower() or "<svg" in v.lower()
                or "<img" in v.lower() or "<iframe" in v.lower()
                or "<math" in v.lower() or "<object" in v.lower()
                or "<embed" in v.lower() or "<body" in v.lower()):
            out.append(v)
        elif v.lower().startswith("javascript:"):
            out.append(v)

    for v in vals:
        add(v)
    return clean_lines(out)


def from_patt(path):
    md = open(path, encoding="utf-8", errors="replace").read()
    blocks = re.findall(r"```[a-zA-Z0-9+]*\n(.*?)```", md, re.S)
    cands = []
    for b in blocks:
        for line in b.splitlines():
            line = line.strip()
            if not line or len(line) < 8 or len(line) > 1200:
                continue
            if line.startswith(("//", "#", "$", "echo", "BOM", "Unicode", "ASCII",
                                "Hex", "Escape", "javascript2", "javascript3",
                                "javascript4", "javascript5", "javascript6",
                                "javascript7", "javascript8", "javascript9",
                                "javascript10", "javascript11", "javascript12",
                                "javascript13", "javascript14", "javascript15",
                                "javascript16", "javascript17", "javascript20",
                                "htmlCopy", "javascriptCopy", "svgCopy", "ps1Copy",
                                "ps13", "psCopy")):
                continue
            low = line.lower()
            if ("<script" in low or "onerror" in low or "onload" in low
                    or "javascript:" in low or line.startswith("<")
                    or "alert(" in low or "prompt(" in low or "confirm(" in low
                    or "<svg" in low or "eval(" in low or "constructor(" in low
                    or "data:text/html" in low or "<img" in low or "<iframe" in low):
                if line in ("<script>", "</script>", "<script>alert(1)</script>"):
                    continue
                cands.append(line)
    return clean_lines(cands)


def from_html_code(path):
    """Extract payload-looking strings from a saved HTML page (HexBrain etc.)."""
    raw = open(path, "rb").read().decode("utf-8", "replace")
    cands = []
    for m in re.finditer(r"<code[^>]*>(.*?)</code>", raw, re.S | re.I):
        text = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
        if text and len(text) < 1200:
            cands.append(text)
    for m in re.finditer(r"<pre[^>]*>(.*?)</pre>", raw, re.S | re.I):
        text = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
        for line in text.splitlines():
            line = line.strip()
            if line and len(line) < 1200:
                cands.append(line)
    keep = []
    for c in cands:
        low = c.lower()
        if any(t in low for t in ("<script", "<svg", "<img", "<iframe", "javascript:",
                                  "onerror", "onload", "alert(", "data:text/html",
                                  "constructor(", "eval(")):
            keep.append(c)
    return clean_lines(keep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ps", help="saved PortSwigger cheat-sheet HTML")
    ap.add_argument("--patt", help="saved PayloadsAllTheThings XSS README.md")
    ap.add_argument("--hexbrain-html", help="saved HexBrain XSS payload page")
    ap.add_argument("--no-merge", action="store_true",
                    help="replace instead of merging with the bundled lists")
    a = ap.parse_args()
    os.makedirs(CORPUS, exist_ok=True)

    def write(name, rows):
        path = os.path.join(CORPUS, name)
        existing = []
        if not a.no_merge and os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                existing = [ln.rstrip("\n") for ln in f if ln.strip()]
        merged = clean_lines(existing + rows)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(merged) + "\n")
        print("%s: %d (existing %d, new %d)" % (name, len(merged),
                                                len(clean_lines(existing)), len(rows)))

    if a.ps:
        write("portswigger.txt", from_portswigger(a.ps))
    if a.patt:
        write("hexbrain.txt", from_patt(a.patt))
    if a.hexbrain_html:
        write("hexbrain.txt", from_html_code(a.hexbrain_html))


if __name__ == "__main__":
    main()
