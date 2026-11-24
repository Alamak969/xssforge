"""Automatic input-filter fingerprinting.

Sends small probe tokens instead of full payloads to learn what the target
allows, removes, escapes or blocks. The resulting profile drives encoder and
canary-style selection so the payload phase starts with vectors that can
actually survive the filter.
"""
import html
import urllib.parse

import xf_points
import xf_waf

PROBES = [
    ("angle-open", "<"),
    ("angle-close", ">"),
    ("slash", "/"),
    ("single-quote", "'"),
    ("double-quote", '"'),
    ("paren-open", "("),
    ("paren-close", ")"),
    ("equal", "="),
    ("space", " "),
    ("tab", "\t"),
    ("word-alert", "alert"),
    ("word-script", "script"),
    ("word-onerror", "onerror"),
    ("word-javascript", "javascript:"),
    ("word-eval", "eval"),
    ("word-prompt", "prompt"),
    ("word-confirm", "confirm"),
    ("word-print", "print"),
    ("word-console", "console.log"),
    ("word-title", "document.title"),
    ("word-fetch", "fetch"),
    ("tag-script", "<script>"),
    ("tag-svg", "<svg"),
    ("comment-open", "<!--"),
    ("percent", "%"),
    ("ampersand", "&"),
]

BLOCK_STATUS = (401, 403, 406, 429, 501, 503)


def _transformed(body, probe):
    """Return the transformation name if a recognisable escaped form exists."""
    variants = {
        "html-escape": html.escape(probe, quote=True),
        "html-entity-dec": "".join("&#%d;" % ord(c) for c in probe),
        "html-entity-dec-pad": "".join("&#%03d;" % ord(c) for c in probe),
        "html-entity-hex": "".join("&#x%x;" % ord(c) for c in probe),
        "html-entity-hex-pad": "".join("&#x%04x;" % ord(c) for c in probe),
        "apos": probe.replace("'", "&apos;"),
        "quot": probe.replace('"', "&quot;"),
        "url-encode": urllib.parse.quote(probe, safe=""),
        "backslash": "".join("\\" + c for c in probe),
        "double-backslash": "".join("\\\\" + c for c in probe),
    }
    for name, v in variants.items():
        if v and v in body:
            return name
    return None


def _classify(resp, probe, baseline_len):
    body = resp.text or ""
    status = getattr(resp, "status_code", 0)
    fp = xf_waf.fingerprint(dict(getattr(resp, "headers", {}) or {}), body, status)
    if status in BLOCK_STATUS or fp.get("blocked") or fp.get("challenge"):
        return "BLOCKED", ""
    if probe in body:
        # A raw probe can still be present while every occurrence is escaped
        # (e.g. PHP addslashes turns ' into \' inside reflected SQL errors).
        if probe in ("'", '"') and ("\\" + probe) in body:
            return "ESCAPED", "backslash"
        return "ALLOWED", ""
    tr = _transformed(body, probe)
    if tr:
        return "ESCAPED", tr
    return "REMOVED", ""


def parse_probe_chars(spec):
    r"""Parse a comma-separated probe list, with \t / \n / \s / \0 escapes."""
    if not spec:
        return None
    mapping = {"\\t": "\t", "\\n": "\n", "\\r": "\r", "\\s": " ", "\\0": "\x00"}
    out = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        out.append((item, mapping.get(item, item)))
    return out or None


def probe_points(opts, factory, limiter, points, state, max_points=3,
                 max_probes=0, probes=None):
    """Return a filter profile built from a handful of injection points."""
    profile = {
        "points": [], "blocked": [], "removed": [], "escaped": {}, "allowed": [],
        "reflected": False, "verdict": "", "encoders": [], "canary_style": "quoted",
        "waf": [], "auth_required": False, "waf_challenge": False, "matrix": {},
    }
    login_markers = ('id="loginform"', 'action="/user/login"', 'action="/login"',
                     'type="password"', 'name="password"')
    if not points:
        profile["verdict"] = "no injection points found"
        return profile
    token = "flt" + __import__("secrets").token_hex(4)
    checks = probes or PROBES
    if max_probes and not probes:
        critical = {"tag-script", "tag-svg", "comment-open", "word-script",
                    "word-onerror", "word-alert"}
        ordered = ([p for p in checks if p[0] in critical] +
                   [p for p in checks if p[0] not in critical])
        checks = ordered[:max_probes]
    elif max_probes:
        checks = checks[:max_probes]
    seen = set()

    for point in points[:max_points]:
        kwargs, _ = xf_points.build_request(point, token, opts)
        try:
            limiter.wait()
            base = factory.get().request(**kwargs)
        except Exception:
            continue
        base_body = base.text or ""
        low = base_body.lower()
        from urllib.parse import urlparse as _urlparse
        target_path = _urlparse(getattr(opts, "url", "") or "").path
        point_path = _urlparse(getattr(point, "url", "") or "").path
        primary = (not target_path) or (point_path == target_path)
        normal_point = getattr(point, "location", "") in (
            "query", "form", "json", "graphql", "xml", "multipart",
            "multipart-filename", "path", "fragment")
        if primary and normal_point and any(m in low for m in login_markers):
            profile["auth_required"] = True
        reflected = token in base_body
        profile["reflected"] = profile["reflected"] or reflected
        fp = xf_waf.fingerprint(dict(getattr(base, "headers", {}) or {}), base_body,
                                getattr(base, "status_code", 0))
        if fp.get("waf"):
            profile["waf"] = sorted(set(profile["waf"] + fp["waf"]))
        if fp.get("challenge"):
            profile["waf_challenge"] = True
        point_res = {"point": point.label, "reflected": reflected, "probes": [],
                     "matrix": {}}
        for name, probe in checks:
            kwargs, _ = xf_points.build_request(point, probe, opts)
            try:
                limiter.wait()
                resp = factory.get().request(**kwargs)
            except Exception:
                continue
            if getattr(resp, "status_code", 0) == 429 and hasattr(limiter, "penalize"):
                limiter.penalize()
            verdict, how = _classify(resp, probe, len(base_body))
            point_res["probes"].append((name, probe, verdict, how))
            if len(probe) == 1:
                point_res["matrix"][probe] = verdict
                profile.setdefault("matrix", {})[probe] = verdict
            if verdict == "BLOCKED" and name not in seen:
                seen.add(name)
                profile["blocked"].append(name)
            elif verdict == "REMOVED" and name not in seen:
                seen.add(name)
                profile["removed"].append(name)
            elif verdict == "ESCAPED":
                profile["escaped"][name] = how
            elif verdict == "ALLOWED" and name not in seen:
                seen.add(name)
                profile["allowed"].append(name)
        profile["points"].append(point_res)

    profile["encoders"] = recommend_encoders(profile)
    quote_bad = ({"single-quote", "double-quote"} &
                 (set(profile["escaped"]) | set(profile["blocked"]) | set(profile["removed"])))
    if quote_bad:
        # A transformed quote outside a script attribute (e.g. inside <script>)
        # breaks alert('TOKEN'). Quote-less canaries survive both cases.
        profile["canary_style"] = "regex"
    if profile["auth_required"]:
        profile["verdict"] = ("login/register page returned — an authenticated "
                              "session is required; use -c or --cookie-file")
    elif profile["waf_challenge"]:
        profile["verdict"] = ("WAF/bot challenge page returned — reflection is "
                              "an interstitial echo, not application output")
    elif not profile["reflected"]:
        profile["verdict"] = ("input not reflected on any tested point — "
                              "no reflected/stored XSS reachable here")
    elif profile["blocked"] or profile["removed"] or profile["escaped"]:
        profile["verdict"] = "filter detected — payloads adapted to the profile"
    else:
        profile["verdict"] = "no input filter detected — run the normal corpus"
    return profile


def recommend_encoders(profile):
    enc = []
    blocked = set(profile["blocked"]) | set(profile["removed"])
    escaped = set(profile["escaped"])
    if {"angle-open", "tag-script"} & (blocked | escaped):
        enc += ["html-dec", "html-hex", "html-entity", "url", "url2"]
    if "slash" in blocked or "slash" in escaped:
        enc += ["html-hex", "html-dec", "js-unicode", "b64"]
    if "single-quote" in (blocked | escaped) or "double-quote" in (blocked | escaped):
        enc += ["noquote-regex", "noquote-ident", "js-unicode", "fromcharcode"]
    if "word-alert" in blocked or "word-alert" in escaped:
        # Detection-mechanism ladder: stop relying on the alert identifier.
        enc += ["alt-prompt", "alt-confirm", "alt-print", "alt-console",
                "call-template", "call-concat", "call-atob", "call-constructor",
                "call-unicode", "call-throw", "call-title"]
    if "word-eval" in blocked:
        enc += ["js-unicode", "fromcharcode", "b64-eval", "atob-eval"]
    if "word-script" in blocked or "tag-script" in blocked:
        enc += ["html-mixed", "comment", "zwsp", "fullwidth", "utf7"]
    if "word-javascript" in blocked:
        enc += ["url", "html-dec", "html-hex", "utf7", "fullwidth"]
    if "ampersand" in blocked or "percent" in blocked:
        enc += ["js-unicode", "base64", "fromcharcode"]
    enc += xf_waf.suggest_encoders(profile.get("waf") or [])
    if "space" in blocked or "tab" in blocked:
        enc += ["tab", "newline", "cr", "formfeed", "comment"]
    if not enc:
        enc = ["url", "html-dec", "js-unicode"]
    seen, out = set(), []
    for e in enc:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def blocked_chars(profile):
    names = set(profile.get("blocked") or []) | set(profile.get("removed") or [])
    tokens = dict(PROBES)
    out = set()
    for name, verdict in (profile.get("matrix") or {}).items():
        if verdict in ("BLOCKED", "REMOVED"):
            token = tokens.get(name, "")
            out.add(token if len(token) == 1 else name)
    for name in names:
        token = tokens.get(name, "")
        if len(token) == 1:
            out.add(token)
    return out


def format_matrix(profile):
    parts = []
    for ch, verdict in sorted((profile.get("matrix") or {}).items()):
        label = {'"': 'dq', "'": 'sq', "<": "lt", ">": "gt"}.get(ch, repr(ch))
        parts.append("%s=%s" % (label, verdict[:4]))
    return " ".join(parts)


def format_report(profile):
    lines = ["=" * 68, "[FILTER PROFILE]"]
    lines.append("  verdict : %s" % profile["verdict"])
    if profile["waf"]:
        lines.append("  waf     : %s" % ", ".join(profile["waf"]))
    lines.append("  reflect : %s" % ("yes" if profile["reflected"] else "no"))
    if profile["auth_required"]:
        lines.append("  AUTH    : login page returned — session cookie missing/invalid")
    if profile.get("waf_challenge"):
        lines.append("  CHALLENGE: WAF/bot interstitial — echoed canary is not a real reflection")
    lines.append("  blocked : %s" % (", ".join(profile["blocked"]) or "none"))
    lines.append("  removed : %s" % (", ".join(profile["removed"]) or "none"))
    if profile["escaped"]:
        lines.append("  escaped : %s" % ", ".join(
            "%s(%s)" % (k, v) for k, v in profile["escaped"].items()))
    if profile.get("matrix"):
        lines.append("  matrix  : %s" % format_matrix(profile))
    lines.append("  encoders: %s" % ", ".join(profile["encoders"]))
    lines.append("  canary  : %s" % profile["canary_style"])
    for p in profile["points"]:
        lines.append("  point   : %s reflected=%s" %
                     (p["point"], "yes" if p["reflected"] else "no"))
        if p.get("matrix"):
            lines.append("      matrix: %s" % format_matrix(p))
        for name, probe, verdict, how in p["probes"]:
            lines.append("      %-16s %-10s %s" %
                         (name, verdict, how or repr(probe)[:24]))
    lines.append("=" * 68)
    return "\n".join(lines)
