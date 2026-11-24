"""Lightweight WAF fingerprinting and block detection."""
import re

SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"]),
    ("Akamai", ["akamai", "ak_bmsc", "bm_sz", "akamai-ghost"]),
    ("Imperva/Incapsula", ["incap_ses", "visid_incap", "incapsula", "_incap_"]),
    ("F5 BIG-IP", ["bigip", "ts_", "f5-", "x-wa-info"]),
    ("AWS WAF", ["awswaf", "x-amzn-waf", "aws-waf"]),
    ("Sucuri", ["x-sucuri", "sucuri"]),
    ("ModSecurity", ["mod_security", "modsecurity", "nyob", "not acceptable"]),
    ("Barracuda", ["barra", "barracuda"]),
    ("FortiWeb", ["fortiweb", "fortigate"]),
    ("Wallarm", ["wallarm"]),
    ("Azure Front Door", ["x-azure-ref", "azurefd"]),
    ("Google Cloud Armor", ["cloud armor", "google cloud armor", "x-goog-", "gclb"]),
    ("Wordfence", ["wordfence"]),
    ("DDoS-Guard", ["ddos-guard"]),
    ("Fastly", ["fastly", "x-fastly"]),
]

BLOCK_PHRASES = [
    "access denied", "request blocked", "blocked by", "web application firewall",
    "not acceptable", "security policy", "suspicious activity", "forbidden",
    "attention required", "bot detection",
]

# Interstitial / JS-challenge pages that echo the REQUESTED URL (including our
# canary) into their body. A naive scanner sees the canary and reports a false
# "reflected" hit. These must be treated as blocked, never as reflections.
CHALLENGE_TITLES = (
    "one moment, please", "just a moment", "checking your browser",
    "attention required", "verify you are human", "checking browser",
    "cf-please-wait", "ddos protection by",
)
CHALLENGE_MARKERS = (
    "enable javascript and cookies to continue",
    "checking your browser before accessing",
    "this process is automatic",
    "ddos protection by",
    "cf-browser-verification",
    "cf-challenge-running",
    "cf-please-wait",
)


def is_challenge(body, status=200):
    """Return True if body looks like a WAF/bot interstitital page rather than
    the real application response. Such pages reflect the request URL (and the
    canary in it) but are NOT genuine injection points."""
    if not body:
        return False
    low = body[:12000].lower()
    m = re.search(r"<title[^>]*>([^<]*)", low)
    title = m.group(1).strip() if m else ""
    if any(t in title for t in CHALLENGE_TITLES):
        return True
    return any(mk in low for mk in CHALLENGE_MARKERS)


STRONG_NEEDLES = {
    "cf-ray", "cf-cache-status", "__cf_bm", "ak_bmsc", "bm_sz", "incap_ses",
    "visid_incap", "x-sucuri", "x-amzn-waf", "awswaf", "x-azure-ref",
    "x-wa-info", "bigip", "x-fastly",
}


def fingerprint(headers, body, status):
    hay = " ".join("%s:%s" % (k, v) for k, v in headers.items()).lower()
    bl = (body or "")[:20000].lower()
    header_hits, body_hits, strong = [], [], False
    for name, needles in SIGNATURES:
        h = any(nd in hay for nd in needles)
        b = (not h) and any(nd in bl for nd in needles)
        if h:
            header_hits.append(name)
            if any(nd in hay for nd in needles if nd in STRONG_NEEDLES):
                strong = True
        elif b:
            body_hits.append(name)
    names = sorted(set(header_hits + body_hits))
    if not names:
        confidence = 0
    else:
        confidence = 45 + 18 * len(header_hits) + 8 * len(body_hits)
        if strong:
            confidence += 25
        confidence = max(0, min(97, confidence))
    challenge = is_challenge(body, status)
    blocked = (status in (403, 406, 429, 503)
               or any(p in bl for p in BLOCK_PHRASES) or challenge)
    return {
        "waf": names,
        "confidence": confidence,
        "confidence_reason": ("strong header signature" if strong else
                             ("header signature" if header_hits else
                              ("body fingerprint only" if body_hits else "no signature"))),
        "blocked": blocked,
        "status": status,
        "challenge": challenge or status == 429,
    }


def suggest_encoders(waf):
    names = [str(w).lower() for w in (waf or [])]
    enc = []
    if any("cloudflare" in n for n in names):
        enc += ["html-mixed", "comment", "zwsp", "html-hex"]
    if any("imperva" in n or "incapsula" in n for n in names):
        enc += ["utf7", "js-unicode", "b64-eval"]
    if any("akamai" in n for n in names):
        enc += ["newline", "html-mixed", "fullwidth"]
    if any("modsecurity" in n for n in names):
        enc += ["comment", "call-concat", "call-atob", "js-unicode"]
    if any("f5" in n or "big-ip" in n for n in names):
        enc += ["utf7", "utf16le", "utf16be", "html-hex"]
    if any("aws" in n for n in names):
        enc += ["url2", "html-named", "tab"]
    seen, out = set(), []
    for name in enc:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def bypass_hint(waf):
    waf = [w.lower() for w in waf]
    hints = []
    if any("cloudflare" in w for w in waf):
        hints.append("cloudflare: try svg/onload, entity-encoded handlers, html comments in tags")
    if any("imperva" in w or "incapsula" in w for w in waf):
        hints.append("imperva: try alternate charsets, data: URIs, JS octal/unicode escapes")
    if any("akamai" in w for w in waf):
        hints.append("akamai: try newline/NUL inside attributes, case mixing")
    if any("modsecurity" in w for w in waf):
        hints.append("modsecurity: try split keywords, comments, backticks, eval()")
    if any("f5" in w or "big-ip" in w for w in waf):
        hints.append("f5: try charset overrides and overlong UTF-8")
    if any("aws" in w for w in waf):
        hints.append("aws waf: try JSON/body placement and whitespace obfuscation")
    if not hints:
        hints.append("generic: run with --encode all and the polyglot/waf payload sets")
    return hints
