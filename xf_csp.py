"""CSP parsing, Trusted Types classification and adaptive payload guidance."""
import html
import re

META_RE = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*['\"]?content-security-policy['\"]?[^>]*>", re.I)
CONTENT_RE = re.compile(r"content\s*=\s*(['\"])(.*?)\1", re.I | re.S)
POLICY_RE = re.compile(r"createPolicy\s*\(\s*(['\"])([^'\"]+)\1\s*,\s*(\{.*?\})\s*\)",
                       re.I | re.S)

HTML_SINKS = {
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "srcdoc", "jQuery.html", "jQuery.parseHTML", "jQuery.globalEval",
    "React.dangerouslySetInnerHTML", "Angular.bypassSecurityTrust",
    "DOMParser.parseFromString", "execScript",
}

_SCHEMA_KEYS = ("script-src", "default-src", "base-uri", "object-src",
                "require-trusted-types-for")


def parse_policy(value):
    directives = {}
    for part in str(value or "").split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        key = tokens[0].lower()
        directives.setdefault(key, [])
        directives[key].extend(tokens[1:])
    return directives


def collect(headers=None, body=""):
    policies = []
    for key, value in (headers or {}).items():
        name = str(key).lower()
        if name not in ("content-security-policy", "content-security-policy-report-only"):
            continue
        policies.append({
            "source": "header",
            "enforce": name == "content-security-policy",
            "raw": str(value or ""),
            "directives": parse_policy(value),
        })
    for m in META_RE.finditer(body or ""):
        cm = CONTENT_RE.search(m.group(0))
        if not cm:
            continue
        value = html.unescape(cm.group(2))
        policies.append({
            "source": "meta",
            "enforce": True,
            "raw": value,
            "directives": parse_policy(value),
        })
    return policies


def _merged(policies):
    out = {}
    for pol in policies:
        for key, values in pol["directives"].items():
            out.setdefault(key, [])
            for value in values:
                if value not in out[key]:
                    out[key].append(value)
    return out


def _is_host(token):
    low = token.lower()
    return ("//" in low or low.startswith(("http:", "https:", "wss:", "ws:")))


def trusted_types_state(body="", policies=None):
    enforced = any("'script'" in p.get("directives", {}).get(
        "require-trusted-types-for", []) for p in (policies or []) if p.get("enforce"))
    policies_found = []
    permissive_default = False
    for m in POLICY_RE.finditer(body or ""):
        name, callback = m.group(2), m.group(3)
        policies_found.append(name)
        if name == "default":
            low = callback.lower()
            if not any(k in low for k in ("dompurify", "sanitize", "escape", "textcontent")):
                permissive_default = True
    protected = bool(enforced and not permissive_default)
    if enforced and permissive_default:
        reason = "enforced, but default policy is a no-op (createHTML: x => x)"
    elif enforced:
        reason = "enforced with a strict or absent default policy"
    elif permissive_default:
        reason = "default policy is permissive but require-trusted-types-for is missing"
    else:
        reason = "not enforced"
    return {
        "enforced": enforced,
        "policies": policies_found,
        "permissive_default": permissive_default,
        "protected": protected,
        "reason": reason,
    }


def analyze(headers=None, body=""):
    policies = collect(headers, body)
    enforced = [p for p in policies if p["enforce"]]
    directives = _merged(enforced)
    script = list(directives.get("script-src") or directives.get("default-src") or [])
    low_script = [v.lower() for v in script]
    nonce = ""
    hashes = []
    hosts = []
    for token in script:
        t = token.lower()
        if t.startswith("'nonce-"):
            nonce = token.strip("'").split("nonce-", 1)[-1]
        elif t.startswith("'sha"):
            hashes.append(token)
        elif _is_host(token):
            hosts.append(token)
    base_uri = directives.get("base-uri", [])
    object_src = directives.get("object-src", [])
    allows_data = any(t in ("data:", "'data:'") for t in low_script)
    allows_blob = any(t in ("blob:", "'blob:'") for t in low_script)
    strict_dynamic = "'strict-dynamic'" in low_script
    unsafe_inline = "'unsafe-inline'" in low_script
    unsafe_eval = "'unsafe-eval'" in low_script
    tt = trusted_types_state(body, policies)
    gadgets = []
    if not base_uri:
        gadgets.append("base-hijack")
    if not object_src:
        gadgets.append("object-embed")
    if allows_data or allows_blob:
        gadgets.append("data-blob")
    if strict_dynamic:
        gadgets.append("strict-dynamic")
    if nonce and strict_dynamic:
        gadgets.append("nonce-reuse")
    if hashes and strict_dynamic:
        gadgets.append("hash-reuse")
    if hosts:
        gadgets.append("jsonp-gadget")
    hardened = bool(enforced and not (unsafe_inline or unsafe_eval or gadgets))
    if unsafe_inline:
        verdict = "CSP allows unsafe-inline — inline vectors viable"
    elif hardened:
        verdict = "CSP hardened (nonce/hash only) — script vectors unlikely; try base/object/DOM gadgets"
    elif gadgets:
        verdict = "CSP weak spots: %s" % ", ".join(gadgets)
    else:
        verdict = "CSP present"
    return {
        "present": bool(policies),
        "enforced": bool(enforced),
        "report_only": bool(policies) and not enforced,
        "policies": policies,
        "directives": directives,
        "script_src": script,
        "nonce": nonce,
        "hashes": hashes,
        "hosts": hosts,
        "base_uri_missing": not base_uri,
        "object_src_missing": not object_src,
        "allows_data": allows_data,
        "allows_blob": allows_blob,
        "strict_dynamic": strict_dynamic,
        "unsafe_inline": unsafe_inline,
        "unsafe_eval": unsafe_eval,
        "trusted_types": tt,
        "gadgets": gadgets,
        "hardened": hardened,
        "verdict": verdict,
    }


def adapt_categories(categories, info):
    cats = list(categories or [])
    if not info or not info.get("present"):
        return cats
    if info.get("gadgets") or info.get("unsafe_inline"):
        if "csp" not in cats:
            cats.insert(0, "csp")
    if info.get("hosts") and "jsonp" not in cats:
        cats.insert(0, "jsonp")
    return cats


def payload_score(payload, info):
    if not info or not info.get("present"):
        return 0
    low = (payload or "").lower()
    score = 0
    if info.get("base_uri_missing") and "<base" in low:
        score += 25
    if info.get("object_src_missing") and ("<object" in low or "<embed" in low):
        score += 25
    if (info.get("allows_data") or info.get("allows_blob")) and \
            ("data:" in low or "blob:" in low):
        score += 20
    if (info.get("strict_dynamic") or info.get("nonce")) and \
            ("nonce=" in low or "createelement" in low or "document.write" in low):
        score += 18
    if info.get("nonce") and "nonce=" in low:
        score += 10
    if any(host.split("//")[-1].rstrip("/") in low for host in info.get("hosts", [])):
        score += 15
    if info.get("unsafe_inline"):
        score += 5
    if info.get("hardened"):
        if "<script" in low or "javascript:" in low:
            score -= 30
        elif re.search(r"\bon[a-z]{3,20}\s*=", low):
            score -= 10
    return score


def filter_dom_findings(findings, info):
    tt = (info or {}).get("trusted_types") or {}
    if not tt.get("protected"):
        return list(findings or []), []
    kept, suppressed = [], []
    for finding in findings or []:
        if finding.get("sink") in HTML_SINKS:
            suppressed.append(dict(finding, note="suppressed: %s" % tt["reason"]))
        else:
            kept.append(finding)
    return kept, suppressed


def describe(info):
    if not info or not info.get("present"):
        return ""
    parts = ["CSP %s" % ("enforced" if info["enforced"] else "report-only")]
    if info.get("gadgets"):
        parts.append("gadgets=%s" % ",".join(info["gadgets"]))
    if info.get("trusted_types", {}).get("protected"):
        parts.append("Trusted Types protected")
    return " | ".join(parts)
