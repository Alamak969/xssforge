"""Seed selection for --deep-bypass.

Before generating new payloads, pick the most relevant payloads from the
web-derived corpus (or optionally refresh them from public sources), matched to
the attack type, injection context and the filter profile.
"""
import re

import payloads as P
import xf_csp
import xf_filter

WEB_SOURCES = (
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md",
)

# attack type -> corpus categories (most specific first)
ATTACK_CATEGORIES = {
    "reflected": ("html", "attr_dq", "attr_sq", "attr_unquoted", "script",
                  "script_string", "polyglot", "waf", "firewall", "encoding"),
    "stored": ("html", "svg", "markdown", "file", "mxss", "polyglot", "waf"),
    "dom": ("dom", "hash", "postmessage", "angular", "vue", "prototype",
            "jsonp", "polyglot", "html"),
    "blind": ("dom", "file", "svg", "html", "waf"),
    "header": ("html", "url", "waf", "polyglot"),
}

CONTEXT_HINT = {
    "html": ("html", "polyglot", "waf"),
    "attr_dq": ("attr_dq", "polyglot", "waf"),
    "attr_sq": ("attr_sq", "polyglot", "waf"),
    "attr_unquoted": ("attr_unquoted", "polyglot", "waf"),
    "script": ("script", "script_string", "encoding"),
    "script_string": ("script_string", "script", "encoding"),
    "url": ("url", "jsonp", "dom"),
    "svg": ("svg", "file", "mxss"),
    "comment": ("comment", "html", "polyglot"),
    "css": ("css", "html"),
    "rcdata": ("rcdata", "html", "mxss"),
    "dom": ("dom", "polyglot", "html"),
}

TOKENS = dict(xf_filter.PROBES)
_BLOCK_KEYS = ("angle-open", "angle-close", "slash", "single-quote",
               "double-quote", "paren-open", "paren-close", "equal", "space")


def profile_from_facts(observed):
    """Convert a passive web probe into a filter-style profile."""
    observed = observed or {}
    profile = {
        "blocked": [], "removed": [], "escaped": {},
        "waf": list(observed.get("waf") or []),
        "login": bool(observed.get("login")),
        "csp": bool(observed.get("csp")),
        "csp_info": observed.get("csp_info") or {},
        "dom_sinks": list(observed.get("dom_sinks") or []),
        "challenge": observed.get("challenge", ""),
        "reflected": bool(observed.get("reflected")),
    }
    if observed.get("login"):
        profile["verdict"] = "login required"
    elif observed.get("csp"):
        profile["verdict"] = (observed.get("csp_info") or {}).get("verdict") or \
            "CSP protected — use gadget/CSP payload sets"
    elif observed.get("dom_sinks"):
        profile["verdict"] = "DOM/JS sinks observed — client-side payloads viable"
    elif observed.get("reflected"):
        profile["verdict"] = "reflection confirmed — server-side payloads viable"
    return profile


def attack_from_facts(observed, url=""):
    observed = observed or {}
    if observed.get("challenge"):
        return "challenge"
    if observed.get("dom_sinks") or (url and "#" in url):
        return "dom"
    if observed.get("login"):
        return "login"
    if observed.get("forms"):
        return "stored"
    return "reflected"


def attack_type(point, opts):
    loc = (getattr(point, "location", "") or "").lower()
    if getattr(opts, "dom_form", ""):
        return "dom"
    if getattr(opts, "stored_url", ""):
        return "stored"
    if loc in ("fragment", "dom", "path"):
        return "dom"
    if getattr(opts, "blind", "") or getattr(opts, "interactsh", ""):
        return "blind"
    if loc in ("header", "cookie"):
        return "header"
    return "reflected"


def _blocked_tokens(profile):
    bad = set()
    for key in _BLOCK_KEYS:
        if key in (profile.get("blocked") or []) or key in (profile.get("removed") or []):
            tok = TOKENS.get(key)
            if tok:
                bad.add(tok)
    return bad


def candidate_seeds(attack, ctx, profile, limit=20):
    """Return the best corpus payloads for this attack/context/profile."""
    ctx_name = (ctx or {}).get("context") or "html"
    cats = list(CONTEXT_HINT.get(ctx_name, ()))
    csp = (profile or {}).get("csp_info") or {}
    if csp.get("present"):
        cats = xf_csp.adapt_categories(cats, csp)
    for c in ATTACK_CATEGORIES.get(attack, ()):
        if c not in cats:
            cats.append(c)
    for c in ("html", "polyglot", "waf", "encoding"):
        if c not in cats:
            cats.append(c)
    blocked = _blocked_tokens(profile or {})
    ranked = []
    seen = set()
    for rank, cat in enumerate(cats):
        for _name, payload in P.PAYLOADS.get(cat, []):
            if payload in seen:
                continue
            seen.add(payload)
            score = 100 - rank * 4
            if "__M__" in payload:
                score += 12
            if P.looks_executable(payload):
                score += 10
            if blocked and any(t in payload for t in blocked):
                score -= 25
            if len(payload) > 240:
                score -= 10
            if csp.get("present"):
                score += xf_csp.payload_score(payload, csp)
            ranked.append((score, payload))
    ranked.sort(key=lambda x: -x[0])
    return [p for _s, p in ranked[:max(1, limit)]]


def web_seeds(limit=40, timeout=20):
    """Fetch current public payload sources and extract usable payload lines."""
    import requests
    out, seen = [], set()
    for url in WEB_SOURCES:
        try:
            text = requests.get(url, timeout=timeout, verify=False).text
        except Exception:
            continue
        for block in re.findall(r"```[a-z]*\n(.*?)```", text, re.S):
            for line in block.splitlines():
                line = line.strip()
                if not (6 < len(line) < 240):
                    continue
                if "<" not in line and "javascript:" not in line.lower() \
                        and "data:" not in line.lower():
                    continue
                if any(b in line.lower() for b in (
                        "http://", "https://", "attacker", "[", "example.com")):
                    continue
                line = re.sub(r"alert\s*\(\s*['\"]XSS['\"]\s*\)", "alert('__M__')",
                              line, flags=re.I)
                line = re.sub(r"alert\s*\(\s*1\s*\)", "alert('__M__')", line, flags=re.I)
                if line not in seen:
                    seen.add(line)
                    out.append(line)
                if len(out) >= limit:
                    return out
    return out
