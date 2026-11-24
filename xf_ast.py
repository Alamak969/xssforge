"""Lightweight structural JavaScript analysis (tokenizer + scope-aware taint).

This is not a full ECMAScript parser, but it is deliberately more than regex:
it tokenizes strings/comments/templates so sources inside comments or data
strings never count, then reasons about declarations, class fields, getters,
function parameters with defaults, destructuring and module exports before
matching source->sink dataflow.

Public API:
    analyze(js, url) -> list of finding dicts (same shape as xf_dom)
    mask(js)         -> source with comments/strings blanked (same length)
"""
import re

SRC_PATTERNS = [
    (r"location\.(?:hash|search|href|pathname)", "location.*"),
    (r"document\.(?:URL|documentURI|referrer|cookie|location|currentScript)", "document.*"),
    (r"window\.(?:name|location|opener)", "window.*"),
    (r"localStorage|sessionStorage", "web storage"),
    (r"event\.data|\be\.data\b|\bmsg\.data\b", "postMessage data"),
    (r"URLSearchParams|searchParams", "URLSearchParams"),
    (r"history\.state", "history.state"),
    (r"navigator\.clipboard", "clipboard"),
    (r"FileReader", "FileReader"),
    (r"indexedDB|IndexedDB", "indexedDB"),
]

# (sink name, regex, capture group) - regexes run on masked JS.
SINKS = [
    ("innerHTML", r"\.innerHTML\s*=\s*", 0),
    ("outerHTML", r"\.outerHTML\s*=\s*", 0),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\(\s*[^,]+,\s*", 1),
    ("document.write", r"document\.write(?:ln)?\s*\(\s*", 1),
    ("eval", r"\beval\s*\(\s*", 1),
    ("Function", r"\bFunction\s*\(\s*", 1),
    ("setTimeout", r"\bsetTimeout\s*\(\s*", 1),
    ("setInterval", r"\bsetInterval\s*\(\s*", 1),
    ("execScript", r"\bexecScript\s*\(\s*", 1),
    ("jQuery.html", r"\.\s*(?:html|append|prepend|after|before|replaceWith)\s*\(\s*", 1),
    ("jQuery.wrap", r"\.\s*(?:wrap|wrapAll|wrapInner)\s*\(\s*", 1),
    ("jQuery.attr", r"\.\s*attr\s*\(\s*['\"][^'\"]*['\"]\s*,\s*", 1),
    ("jQuery.prop", r"\.\s*prop\s*\(\s*['\"][^'\"]*['\"]\s*,\s*", 1),
    ("jQuery.globalEval", r"(?:jQuery|\$)\.globalEval\s*\(\s*", 1),
    ("jQuery.parseHTML", r"(?:\$|jQuery)\.parseHTML\s*\(\s*", 1),
    ("setAttribute", r"setAttribute\s*\(\s*['\"](?:on\w+|href|src|srcdoc|formaction)['\"]\s*,\s*", 1),
    ("script.src", r"\.src\s*=\s*", 0),
    ("srcdoc", r"\.srcdoc\s*=\s*", 0),
    ("href/src assign", r"\.(?:href|action|formAction)\s*=\s*", 0),
    ("location", r"\blocation(?:\.href)?\s*=\s*", 0),
    ("location.assign/replace", r"location\.(?:assign|replace)\s*\(\s*", 1),
    ("window.open", r"window\.open\s*\(\s*", 1),
    ("document.domain", r"document\.domain\s*=\s*", 0),
    ("React.dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*=\s*\{[^}]*__html\s*:\s*", 1),
    ("Angular.bypassSecurityTrust", r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(\s*", 1),
    ("DOMParser.parseFromString", r"parseFromString\s*\(\s*", 1),
    ("currentScript.src", r"document\.currentScript\.src\b", 0),
    ("clobber named property", r"document\.(?:forms|images|anchors|embeds|plugins)\s*\[", 0),
]

DECL_RE = re.compile(
    r"(?:^|[;{}\(\)\]])\s*(?:export\s+)?(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=(?!=)")
SIMPLE_ASSIGN_RE = re.compile(
    r"(?:^|[;{}\(\)\]])\s*([A-Za-z_$][\w$]*)\s*=(?!=)")
THIS_ASSIGN_RE = re.compile(r"\bthis\.([A-Za-z_$][\w$]*)\s*=(?!=)")
CALLBACK_ASSIGN_RE = re.compile(
    r"(?:^|[;{}\(\)\]])\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=(?!=)")
DESTRUCT_RE = re.compile(
    r"(?:var|let|const)?\s*[\{\[]\s*([^\}\]]{1,400})[\}\]]\s*=(?!=)")
FUNCTION_RE = re.compile(
    r"\bfunction\s*[A-Za-z_$\w]*\s*\(([^)]{0,400})\)")
ARROW_RE = re.compile(r"\(([^()]{0,400})\)\s*=>")
GETTER_RE = re.compile(
    r"\bget\s+([A-Za-z_$][\w$]*)\s*\(\)\s*\{([^{}]{0,600})\}")
EXPORTS_RE = re.compile(r"\bexports\.([A-Za-z_$][\w$]*)\s*=(?!=)")

IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


class Token(tuple):
    __slots__ = ()

    def __new__(cls, kind, value, start, end, quote=""):
        return tuple.__new__(cls, (kind, value, start, end, quote))

    kind = property(lambda s: s[0])
    value = property(lambda s: s[1])
    start = property(lambda s: s[2])
    end = property(lambda s: s[3])
    quote = property(lambda s: s[4])


def tokenize(js):
    """Yield tokens, dropping comments. Strings/templates become one token."""
    out = []
    i, n = 0, len(js)
    while i < n:
        ch = js[i]
        if ch in " \t\r\n\f\v":
            i += 1
            continue
        if js.startswith("//", i):
            j = js.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if js.startswith("/*", i):
            j = js.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch in "\"'`":
            quote = ch
            j = i + 1
            while j < n:
                if js[j] == "\\":
                    j += 2
                    continue
                if js[j] == quote:
                    break
                j += 1
            end = min(j + 1, n)
            out.append(Token("str", js[i + 1:j], i, end, quote))
            i = end
            continue
        if ch.isalpha() or ch in "_$":
            j = i + 1
            while j < n and (js[j].isalnum() or js[j] in "_$"):
                j += 1
            out.append(Token("id", js[i:j], i, j))
            i = j
            continue
        if ch.isdigit():
            j = i + 1
            while j < n and (js[j].isalnum() or js[j] in "._"):
                j += 1
            out.append(Token("num", js[i:j], i, j))
            i = j
            continue
        out.append(Token("punct", ch, i, i + 1))
        i += 1
    return out


def mask(js):
    """Blank comments and string/template bodies, preserving offsets."""
    chars = list(js)
    for tok in tokenize(js):
        if tok.kind == "str":
            for k in range(tok.start + 1, tok.end - 1):
                if chars[k] not in "\r\n":
                    chars[k] = " "
    # comments are absent from tokenize output; blank them separately
    for m in re.finditer(r"//[^\n]*|/\*.*?\*/", js, re.S):
        for k in range(m.start(), m.end()):
            if chars[k] not in "\r\n":
                chars[k] = " "
    # Regex literals: blank bodies so /location.hash/ is not read as code.
    # Division (a / b) is left alone because the previous token is an operand.
    i, n = 0, len(js)
    while i < n:
        if js[i] != "/" or chars[i] != "/":
            i += 1
            continue
        if i + 1 < n and js[i + 1] in "/*":
            i += 2
            continue
        j = i - 1
        while j >= 0 and chars[j] in " \t\r\n":
            j -= 1
        prev = chars[j] if j >= 0 else ""
        if prev and (prev.isalnum() or prev in "_$)]}."):
            i += 1
            continue
        k, in_class, closed = i + 1, False, False
        while k < n:
            c = js[k]
            if c == "\\":
                k += 2
                continue
            if c == "\n":
                break
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                closed = True
                break
            k += 1
        if not closed:
            i += 1
            continue
        for t in range(i, k + 1):
            if chars[t] not in "\r\n":
                chars[t] = " "
        i = k + 1
    return "".join(chars)


def _statement_rhs(masked, pos, limit=400):
    i, depth = pos, 0
    n = len(masked)
    while i < n and i - pos < limit:
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            break
        elif ch == "\n" and depth == 0:
            break
        i += 1
    return masked[pos:i]


def _bare_location(text):
    if re.fullmatch(r"\s*(?:window\.|document\.)?location\s*", text or ""):
        return "location"
    return ""


def which_source(text):
    for pat, label in SRC_PATTERNS:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return ""


def _template_source(text):
    for m in re.finditer(r"\$\{([^{}]{1,300})\}", text or ""):
        src = which_source(m.group(1))
        if src:
            return src
    return ""


def _template_has_source(js, start, end):
    seg = js[start:end]
    return which_source(seg)


def _collect_tainted(js, masked):
    tainted = {}
    templates = [t for t in tokenize(js)
                 if t.kind == "str" and t.quote == "`"]

    def mark(name, rhs, pos=0):
        if not name or name in tainted:
            return
        src = which_source(rhs) or _bare_location(rhs)
        if not src:
            for tv, ts in tainted.items():
                if re.search(r"(?<![\w$])%s(?![\w$])" % re.escape(tv), rhs):
                    src = ts
                    break
        if not src:
            # template literal interpolation e.g. `${location.hash}`
            for tok in templates:
                if tok.start >= pos and tok.start <= pos + len(rhs) + 1:
                    src = _template_has_source(js, tok.start, tok.end)
                    if src:
                        break
        if src:
            tainted[name] = src

    for _ in range(3):
        for rx in (DECL_RE, THIS_ASSIGN_RE, CALLBACK_ASSIGN_RE, SIMPLE_ASSIGN_RE):
            for m in rx.finditer(masked):
                name = m.group(1)
                rhs = _statement_rhs(masked, m.end())
                mark(name, rhs, m.start())
        for m in DESTRUCT_RE.finditer(masked):
            rhs = _statement_rhs(masked, m.end())
            if not which_source(rhs) and not _bare_location(rhs) and not any(
                    re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(v), rhs)
                    for v in tainted):
                continue
            for ident in IDENT_RE.findall(m.group(1)):
                if ident not in ("var", "let", "const"):
                    mark(ident, rhs, m.start())
        for rx in (FUNCTION_RE, ARROW_RE):
            for m in rx.finditer(masked):
                for param in m.group(1).split(","):
                    pm = re.match(r"\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$", param, re.S)
                    if pm:
                        mark(pm.group(1), pm.group(2), m.start())
        for m in GETTER_RE.finditer(masked):
            src = which_source(m.group(2))
            if src:
                tainted[m.group(1)] = src
                tainted["this." + m.group(1)] = src
        for m in EXPORTS_RE.finditer(masked):
            rhs = _statement_rhs(masked, m.end())
            mark(m.group(1), rhs, m.start())
    return tainted


def analyze(js, url):
    if len(js) > 1000000:
        js = js[:1000000]
    masked = mask(js)
    tainted = _collect_tainted(js, masked)
    findings = []
    seen = set()
    for sink, pat, use_rhs in SINKS:
        rx = re.compile(pat)
        for m in rx.finditer(masked):
            start = m.end() if use_rhs else m.end()
            arg = _statement_rhs(masked, start, limit=300)
            original = _statement_rhs(js, start, limit=300)
            src = which_source(arg) or _template_source(original)
            var = ""
            if not src:
                for name, s in tainted.items():
                    if re.search(r"(?<![\w$])%s(?![\w$])" % re.escape(name), arg):
                        src, var = s, name
                        break
            if not src:
                continue
            key = (url, sink, src, var, original[:120])
            if key in seen:
                continue
            seen.add(key)
            pos = m.start()
            findings.append({
                "type": "dom-xss-candidate",
                "sink": sink,
                "source": src,
                "variable": var,
                "argument": (original or arg).strip()[:200],
                "snippet": " ".join(js[max(0, pos - 80):pos + 160].split())[:320],
                "script": url,
                "severity": "high" if sink in (
                    "innerHTML", "outerHTML", "document.write", "eval", "Function",
                    "insertAdjacentHTML", "jQuery.html", "jQuery.globalEval",
                    "jQuery.parseHTML", "React.dangerouslySetInnerHTML",
                    "Angular.bypassSecurityTrust", "DOMParser.parseFromString",
                    "srcdoc", "execScript", "jQuery.wrap", "currentScript.src") else "medium",
                "engine": "ast",
            })
            if len(findings) >= 200:
                return findings
    return findings
