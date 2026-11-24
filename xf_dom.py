"""Static DOM-XSS taint analysis: sources -> sinks across inline and external JS."""
import re
from urllib.parse import urljoin

import xf_ast

SOURCES = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie", "localStorage", "sessionStorage",
    "event.data", "e.data", "evt.data", "msg.data", "message.data",
    "document.location", "window.location", "location.assign", "location.replace",
    "URLSearchParams", "searchParams", "websocket", "WebSocket",
    "indexedDB", "IndexedDB", "history.state",
    "document.currentScript", "document.currentScript.src", "FileReader",
    "navigator.clipboard", "clipboardData", "window.opener",
]

SINKS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=\s*([^;\n]+)")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=\s*([^;\n]+)")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]+)\)")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(\s*([^)]+)\)")),
    ("eval", re.compile(r"\beval\s*\(\s*([^)]+)\)")),
    ("Function", re.compile(r"\bFunction\s*\(\s*([^)]+)\)")),
    ("setTimeout", re.compile(r"\bsetTimeout\s*\(\s*(['\"`][^'\"`]*['\"`])\s*,")),
    ("setInterval", re.compile(r"\bsetInterval\s*\(\s*(['\"`][^'\"`]*['\"`])\s*,")),
    ("jQuery.html", re.compile(r"\.\s*(?:html|append|prepend|after|before)\s*\(\s*([^)]+)\)")),
    ("setAttribute", re.compile(r"setAttribute\s*\(\s*['\"](?:on\w+|href|src|srcdoc)['\"]\s*,\s*([^)]+)\)")),
    ("script.src", re.compile(r"\.src\s*=\s*([^;\n]+)")),
    ("location", re.compile(r"(?:location(?:\.href)?)\s*=\s*([^;\n]+)")),
    ("srcdoc", re.compile(r"\.srcdoc\s*=\s*([^;\n]+)")),
    ("document.domain", re.compile(r"document\.domain\s*=\s*([^;\n]+)")),
    ("jQuery.globalEval", re.compile(r"(?:jQuery|\$)\.globalEval\s*\(\s*([^)]+)\)")),
    ("jQuery.parseHTML", re.compile(r"(?:\$|jQuery)\.parseHTML\s*\(\s*([^)]+)\)")),
    ("React.dangerouslySetInnerHTML",
     re.compile(r"dangerouslySetInnerHTML\s*=\s*\{[^}]*__html\s*:\s*([^}]+)")),
    ("Angular.bypassSecurityTrust",
     re.compile(r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(([^)]+)")),
    ("window.open", re.compile(r"window\.open\s*\(\s*([^)]+)")),
    ("location.assign/replace",
     re.compile(r"location\.(?:assign|replace)\s*\(\s*([^)]+)\)")),
    ("href/src assign", re.compile(r"\.(?:href|src|action|formAction)\s*=\s*([^;\n]+)")),
    ("DOMParser.parseFromString", re.compile(r"parseFromString\s*\(\s*([^,]+),")),
    ("execScript", re.compile(r"execScript\s*\(\s*([^)]+)")),
    ("FileReader.readAsText", re.compile(r"\.readAs(?:Text|DataURL)\s*\(\s*([^)]+)")),
    ("clipboard.readText", re.compile(r"navigator\.clipboard\.readText\s*\(\s*([^)]*)")),
    ("clipboard.writeText", re.compile(r"navigator\.clipboard\.writeText\s*\(\s*([^)]+)")),
    ("document.currentScript", re.compile(r"document\.currentScript(\.src|\.innerHTML)?")),
    ("DOM clobber named property",
     re.compile(r"document\.(forms|images|anchors|embeds|plugins)\s*\[")),
]

FRAMEWORK_SINKS = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML", re.I),
     "React raw HTML escape hatch"),
    ("v-html", re.compile(r"\bv-html\s*=", re.I), "Vue raw HTML escape hatch"),
    ("[innerHTML]", re.compile(r"\[innerHTML\]", re.I), "Angular raw HTML binding"),
    ("{@html}", re.compile(r"\{@html", re.I), "Svelte raw HTML escape hatch"),
    ("bypassSecurityTrust", re.compile(r"bypassSecurityTrust", re.I),
     "Angular sanitizer bypass"),
    ("template interpolation", re.compile(r"\{\{[^}\n]{0,200}\}\}"),
     "client-side template interpolation (CSTI candidate)"),
]

ASSIGN_RE = re.compile(
    r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
POSTMSG_RE = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"](.{0,800}?)\}\s*\)", re.S)

JS_INCLUDE_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)


def _fetch_js(url, fetcher):
    try:
        return fetcher(url) or ""
    except Exception:
        return ""


def analyze_page(html, page_url, fetcher):
    findings = []
    scripts = []
    for m in INLINE_SCRIPT_RE.finditer(html or ""):
        scripts.append((page_url, m.group(1)))
    for m in JS_INCLUDE_RE.finditer(html or ""):
        url = urljoin(page_url, m.group(1))
        js = _fetch_js(url, fetcher)
        if js:
            scripts.append((url, js))
    for url, js in scripts:
        findings.extend(_analyze_script(url, js))
    findings.extend(_analyze_html(html or "", page_url))
    return _dedupe(findings)


def _analyze_html(html, page_url):
    """Flag framework/template raw-HTML escape hatches visible in markup."""
    out = []
    for name, rx, note in FRAMEWORK_SINKS:
        m = rx.search(html)
        if not m:
            continue
        snippet = " ".join(html[max(0, m.start() - 80):m.start() + 160].split())
        out.append({
            "type": "dom-xss-candidate",
            "sink": name,
            "source": "framework template / markup",
            "variable": "",
            "argument": m.group(0)[:200],
            "snippet": snippet[:320],
            "script": page_url,
            "severity": "high" if name != "template interpolation" else "medium",
            "note": note,
        })
    return out



def _analyze_script(url, js):
    out = []
    tainted = {}
    # direct source in sink
    for sink, rx in SINKS:
        for m in rx.finditer(js):
            arg = m.group(1)
            if _contains_source(arg):
                out.append(_finding(url, sink, _which_source(arg), "", arg, js, m.start()))
    # taint variables (a few propagation passes)
    for _ in range(3):
        for m in ASSIGN_RE.finditer(js):
            var, rhs = m.group(1), m.group(2)
            if var in tainted:
                continue
            src = _which_source(rhs)
            if src:
                tainted[var] = src
            else:
                for tv, ts in list(tainted.items()):
                    if re.search(r"\b%s\b" % re.escape(tv), rhs):
                        tainted[var] = ts
                        break
    for var, src in tainted.items():
        for sink, rx in SINKS:
            for m in rx.finditer(js):
                arg = m.group(1)
                if re.search(r"\b%s\b" % re.escape(var), arg):
                    out.append(_finding(url, sink, src, var, arg, js, m.start()))
    # postMessage handlers
    for m in POSTMSG_RE.finditer(js):
        body = m.group(1)
        if not re.search(r"\.data\b", body):
            continue
        for sink, rx in SINKS:
            sm = rx.search(body)
            if sm:
                out.append(_finding(url, sink, "postMessage event.data", "", sm.group(1), body, m.start()))
                break
    # Structural pass: tokenizer/scope-aware (class fields, getters, params,
    # destructuring, module exports, jQuery attr/prop/wrap, currentScript.src).
    try:
        out.extend(xf_ast.analyze(js, url))
    except Exception:
        pass
    return out


def _contains_source(text):
    low = text.lower()
    return any(s.lower() in low for s in SOURCES)


def _which_source(text):
    low = text.lower()
    for s in SOURCES:
        if s.lower() in low:
            return s
    return ""


def _finding(url, sink, source, var, arg, js, pos):
    snippet = " ".join(js[max(0, pos - 80):pos + 160].split())
    return {
        "type": "dom-xss-candidate",
        "sink": sink,
        "source": source,
        "variable": var,
        "argument": arg.strip()[:200],
        "snippet": snippet[:320],
        "script": url,
        "line": js[:pos].count("\n") + 1,
        "column": pos - js.rfind("\n", 0, pos),
        "flow": " -> ".join([s for s in (source, var, sink) if s]),
        "analysis": "static-source-to-sink",
        "severity": "high" if sink in (
            "innerHTML", "outerHTML", "document.write", "eval", "Function",
            "insertAdjacentHTML", "jQuery.html", "jQuery.globalEval",
            "jQuery.parseHTML", "React.dangerouslySetInnerHTML",
            "Angular.bypassSecurityTrust", "DOMParser.parseFromString",
            "srcdoc", "execScript") else "medium",
    }


def _dedupe(items):
    seen = set()
    out = []
    for it in items:
        key = (it["script"], it["sink"], it["source"], it["argument"])
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
