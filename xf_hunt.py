"""Methodology layer: turn recon signals into a prioritized XSS hunt plan.

This module embeds the practical part of the XSS hunting methodology into the
scanner: identify high-value surfaces first (sanitizer version, postMessage,
OAuth redirects, stored/admin content, markdown editors, SVG upload, RSC/LLM
output), then tell the operator which generic xssforge flags cover them.

It is deliberately read-only: no exploit chains are executed here. It only
classifies observed HTML/JS/header facts so `--full` can spend effort where a
real-world finding is most likely.
"""
import re

import xf_csp
import xf_libscan

SINK_PATTERNS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "document.write": re.compile(r"document\.write(?:ln)?\s*\("),
    "eval/Function": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    "dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML"),
    "v-html": re.compile(r"\bv-html\s*="),
    "bypassSecurityTrust": re.compile(r"bypassSecurityTrust"),
    "setTimeout-string": re.compile(r"setTimeout\s*\(\s*['\"`]"),
}

OAUTH_PARAMS = ("redirect_uri", "returnTo", "return_to", "state", "RelayState",
                "post_logout_redirect_uri")
EDITOR_MARKERS = ("trix", "ckeditor", "tinymce", "quill", "slate", "lexical",
                  "markdown-it", "markdown-to-jsx", "marked", "remark",
                  "prosemirror")
LLM_MARKERS = ("chatbot", "assistant", "llm", "prompt", "openai", "anthropic",
               "message.content", "choices[0]")
RSC_MARKERS = ("__NEXT_DATA__", "_next/static", "Server-Action",
               "react-server-dom")
PROTO_MARKERS = ("__proto__[", "constructor[prototype][", "_.merge(",
                 "$.extend(true")

POSTMSG_RE = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"](.{0,1200}?)\}\s*\)", re.S)


def _has(patterns, text):
    low = (text or "").lower()
    return [p for p in patterns if p.lower() in low]


def analyze(html, headers=None, js_bodies=None, url=""):
    html = html or ""
    headers = headers or {}
    js = "\n".join(js_bodies or [])
    combined = html + "\n" + js
    low = combined.lower()

    libs = {}
    try:
        libs = xf_libscan.detect_from_text(combined)
    except Exception:
        pass
    csp = {}
    try:
        csp = xf_csp.analyze(dict(headers), html)
    except Exception:
        pass

    sinks = [name for name, rx in SINK_PATTERNS.items()
             if rx.search(combined)]
    postmsg = list(POSTMSG_RE.finditer(combined))
    risky_origin = bool(re.search(r"\.includes\s*\(|\.endsWith\s*\(|!==\s*['\"]https?://",
                                  " ".join(m.group(1) for m in postmsg), re.I)) or \
        bool(postmsg) and not re.search(r"\.origin\s*===|\.origin\s*==", combined)

    dompurify_ver = next((v for k, v in libs.items() if k.lower() == "dompurify"), "")
    dompurify_old = False
    if dompurify_ver:
        try:
            dompurify_old = bool(xf_libscan.vulnerable("DOMPurify", dompurify_ver))
        except Exception:
            pass

    oauth = _has(OAUTH_PARAMS, combined)
    editors = _has(EDITOR_MARKERS, combined)
    llm = _has(LLM_MARKERS, combined)
    rsc = _has(RSC_MARKERS, combined)
    proto = _has(PROTO_MARKERS, combined)
    upload = bool(re.search(r'type=["\']file["\']|multipart/form-data', low))
    svg = "svg" in low and upload

    targets = []
    def add(name, why, flags, priority=2):
        targets.append({"name": name, "why": why, "flags": flags,
                        "priority": priority})

    if dompurify_old:
        add("dompurify-mxss",
            "DOMPurify %s has a known mXSS bypass family" % dompurify_ver,
            "--dom --mxss-family --browser --only-poc", 1)
    if postmsg and (risky_origin or sinks):
        add("postmessage",
            "postMessage handler with weak origin check or HTML sink",
            "--dom-fuzz --fragment --browser --only-poc", 1)
    if oauth:
        add("oauth-reflection",
            "OAuth redirect parameter present (%s)" % ", ".join(oauth[:3]),
            "-p %s --auto --browser --only-poc" % oauth[0], 1)
    if upload or svg:
        add("stored-upload",
            "file upload surface; test content and filename, then render URL",
            "--sxss-url <RENDER_URL> --browser --only-poc", 1)
    if editors:
        add("editor-markdown",
            "rich-text/markdown renderer detected (%s)" % ", ".join(editors[:3]),
            "--corpus html,mxss --auto --browser --only-poc", 2)
    if rsc:
        add("rsc-react",
            "React Server Components / Server Actions surface",
            "--dom --auto --browser --only-poc", 2)
    if llm:
        add("llm-output",
            "chat/LLM output surface; check innerHTML rendering",
            "--dom --browser --only-poc", 2)
    if proto:
        add("prototype-pollution",
            "prototype-pollution sources/gadgets visible",
            "--dom --browser --only-poc", 2)
    if csp.get("present"):
        add("csp-tt",
            "CSP present (%s); use base/object/DOM gadgets" %
            ", ".join(csp.get("gadgets") or []) or "policy present",
            "--dom --auto --browser --only-poc", 2)
    if sinks:
        add("dom-sinks",
            "dangerous JS sinks: %s" % ", ".join(sinks[:4]),
            "--dom --dom-fuzz --fragment --browser --only-poc", 2)
    add("generic-reflected",
        "standard reflected/stored sweep across discovered points",
        "--full --authorized", 3)
    targets.sort(key=lambda t: t["priority"])

    return {
        "url": url,
        "libs": libs,
        "csp": csp,
        "signals": {
            "dompurify": dompurify_ver,
            "dompurify_outdated": dompurify_old,
            "postmessage_handlers": len(postmsg),
            "risky_postmessage_origin": risky_origin,
            "sinks": sinks,
            "oauth_params": oauth,
            "editors": editors,
            "llm_surface": llm,
            "rsc": rsc,
            "prototype_sources": proto,
            "upload": upload,
            "svg_upload": svg,
        },
        "targets": targets,
    }


def format_report(facts):
    lines = ["=" * 68, "[HUNT PLAN] methodology-driven priorities"]
    sig = facts.get("signals") or {}
    if facts.get("libs"):
        lines.append("  stack    : %s" % ", ".join(
            "%s %s" % (k, v) for k, v in sorted(facts["libs"].items())))
    interesting = [k for k, v in sig.items() if v]
    lines.append("  signals  : %s" % (", ".join(interesting) or "none"))
    for t in facts.get("targets") or []:
        lines.append("  P%d %-20s %s" %
                     (t["priority"], t["name"], t["why"]))
        lines.append("       -> %s" % t["flags"])
    lines.append("=" * 68)
    return "\n".join(lines)
