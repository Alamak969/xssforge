"""Usage advisor: suggest the right xssforge command for a given target."""
from urllib.parse import urlparse, parse_qs

CHALLENGE_HINTS = (
    ("alf.nu/alert1", "--browser --dom-form '#inp'"),
    ("xss-game.appspot.com/level2", "--browser --dom-form '#post-content'"),
    ("xss-game.appspot.com/level3", "--browser --dom --dom-fuzz --fragment --first-hit"),
    ("xss-game.appspot.com/level6", "--browser --dom --dom-fuzz --fragment --first-hit"),
)


def _with_url(flags):
    return "python3 xssforge.py -u '<URL>' " + flags


def probe(url, opts=None):
    """One-request passive baseline check. Returns observed target facts."""
    import secrets
    import requests
    import xf_csp
    import xf_waf

    out = {"ok": False, "status": 0, "waf": [], "login": False, "forms": [],
           "dom_sinks": [], "reflected": False, "csp": False, "title": "",
           "challenge": "", "error": "", "csp_info": {}}
    try:
        ua = getattr(opts, "user_agent", "Mozilla/5.0") if opts else "Mozilla/5.0"
        proxy = getattr(opts, "proxy", "") if opts else ""
        timeout = getattr(opts, "timeout", 12) if opts else 12
        parse = urlparse(url or "")
        q = parse_qs(parse.query)
        canary = "zq" + secrets.token_hex(4)
        test_url = url
        if q:
            key = next(iter(q))
            q[key] = [canary]
            from urllib.parse import urlencode, urlunparse
            test_url = urlunparse(parse._replace(query=urlencode(q, doseq=True)))
        session = requests.Session()
        session.headers.update({"User-Agent": ua,
                                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        cookie_header = getattr(opts, "cookie", "") if opts else ""
        if not cookie_header and getattr(opts, "cookie_file", "") and opts:
            try:
                pairs = []
                for line in open(opts.cookie_file, encoding="utf-8", errors="replace"):
                    if not line.strip() or line.startswith("#"):
                        continue
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 7:
                        pairs.append("%s=%s" % (parts[5], parts[6]))
                cookie_header = "; ".join(pairs)
            except Exception:
                cookie_header = ""
        if cookie_header:
            session.headers["Cookie"] = cookie_header
        kwargs = {"timeout": timeout, "verify": not getattr(opts, "insecure", True)}
        r = session.get(test_url, **kwargs)
        body = r.text or ""
        csp_info = xf_csp.analyze(dict(r.headers), body)
        out.update({"ok": True, "status": r.status_code,
                    "csp": csp_info["present"],
                    "csp_info": csp_info,
                    "title": (body.split("<title>", 1)[1].split("</title>", 1)[0]
                              if "<title>" in body else "")})
        out["waf"] = xf_waf.fingerprint(dict(r.headers), body, r.status_code).get("waf", [])
        out["reflected"] = canary in body
        low = body.lower()
        out["login"] = any(m in low for m in (
            'id="loginform"', 'action="/user/login"', 'action="/login"',
            'type="password"', 'name="password"'))
        out["forms"] = [
            {"action": m.group(1)[:160], "method": (m.group(2) or "GET").upper()}
            for m in __import__("re").finditer(
                r"<form[^>]*action=['\"]([^'\"]+)['\"][^>]*method=['\"]([^'\"]+)['\"]",
                body, __import__("re").I)
        ][:5]
        sinks = ("innerhtml", "location.hash", "document.write", "eval(",
                 "postmessage", "location.href", "outerhtml")
        out["dom_sinks"] = [s for s in sinks if s in low]
        for hint, flags in CHALLENGE_HINTS:
            if hint in (url or ""):
                out["challenge"] = flags
                break
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


def advise(url="", opts=None, points=None, baseline=None, results_summary=None,
           observed=None):
    lines = []
    p = urlparse(url or "")
    params = list(parse_qs(p.query).keys())
    frag = bool(p.fragment)
    host = p.netloc.lower()
    observed = observed or {}
    if observed and ("status" in observed or "ok" in observed):
        lines.append("[TARGET PROBE] status=%s waf=%s reflected=%s login=%s "
                     "dom_sinks=%s csp=%s" %
                     (observed.get("status"), ",".join(observed.get("waf") or []) or "none",
                      observed.get("reflected"), observed.get("login"),
                      ",".join(observed.get("dom_sinks") or []) or "none",
                      observed.get("csp")))
        if observed.get("title"):
            lines.append("  title: %s" % observed["title"][:90])
        if observed.get("error"):
            lines.append("  probe error: %s" % observed["error"])

    # known challenge sites
    for hint, flags in CHALLENGE_HINTS:
        if hint in host or hint in (url or ""):
            lines.append("Detected a known XSS challenge target.")
            lines.append("  " + _with_url("--authorized " + flags))
            return lines

    if frag:
        lines.append("URL has a fragment — test DOM sinks:")
        lines.append("  " + _with_url("--authorized --browser --dom --dom-fuzz --fragment --first-hit"))

    if params:
        lines.append("URL has query parameters (%s) — standard reflected workflow:" %
                     ", ".join(params[:5]))
        lines.append("  " + _with_url("--authorized --browser --auto --first-hit"))
        lines.append("Full corpus + WAF bypass:")
        lines.append("  " + _with_url("--authorized --browser --auto --deep-bypass "
                                    "--bypass-max 300 --bypass-time 600"))
    else:
        lines.append("No query parameters — discover injection points first:")
        lines.append("  " + _with_url("--authorized --crawl --crawl-depth 2 --browser --auto"))
        lines.append("Or target the DOM directly:")
        lines.append("  " + _with_url("--authorized --browser --dom --dom-fuzz --fragment"))

    lines.append("Stored XSS (form/POST):")
    lines.append("  python3 xssforge.py -u '<FORM_URL>' -d 'field=x' -X POST \\")
    lines.append("    --stored-url '<RENDER_URL>' --authorized --browser --first-hit")

    waf = (observed.get("waf") or (baseline or {}).get("waf") or [])
    if waf:
        lines.append("WAF detected (%s) — slow down or rotate:" % ", ".join(waf))
        lines.append("  " + _with_url("--authorized --threads 2 --delay 0.5 "
                                    "--max-blocks 5 --proxy-file proxies.txt"))

    if observed.get("login"):
        lines.append("Login page returned — supply a session cookie:")
        lines.append("  " + _with_url("--authorized -c 'SESSION=...' --browser --auto"))

    if observed.get("dom_sinks"):
        lines.append("Client-side sinks seen (%s) — test DOM:" %
                     ", ".join(observed["dom_sinks"][:4]))
        lines.append("  " + _with_url("--authorized --browser --dom --dom-fuzz --fragment --first-hit"))
        lines.append("  " + _with_url("--authorized --browser --dom-form '<INPUT_CSS_SELECTOR>'"))

    if observed.get("forms"):
        lines.append("Forms found: %s" % ", ".join(
            "%s %s" % (f["method"], f["action"][:50]) for f in observed["forms"][:3]))
        lines.append("  " + _with_url("--authorized --crawl --browser --auto --first-hit"))

    if observed.get("csp"):
        info = observed.get("csp_info") or {}
        lines.append("CSP detected: %s" %
                     (info.get("verdict") or "header/meta policy present"))
        if info.get("gadgets"):
            lines.append("  exploitable shapes: %s" % ", ".join(info["gadgets"]))
        if (info.get("trusted_types") or {}).get("protected"):
            lines.append("  Trusted Types enforced — pure DOM HTML sinks are blocked; "
                         "focus on reflected/stored vectors")
        lines.append("  " + _with_url("--authorized --browser --auto --encode all --deep-bypass"))

    if observed.get("reflected"):
        lines.append("Canary reflected in response — reflected workflow confirmed as viable:")
        lines.append("  " + _with_url("--authorized --browser --auto --first-hit"))

    if results_summary is not None and not (results_summary.get("confirmed") or
                                            results_summary.get("likely")):
        lines.append("No findings yet — next steps:")
        lines.append("  --encode all --bypass-variants 12   (filter evasion)")
        lines.append("  --crawl                            (more injection points)")
        lines.append("  --deep-bypass --web-refresh        (fresh public payloads + generation)")
        lines.append("  --dom-form '<CSS_SELECTOR>'        (client-side/localStorage sinks)")
    return lines


def quick_tip(url="", opts=None):
    """One-line tip for minimal invocations."""
    p = urlparse(url or "")
    if p.fragment:
        return "tip: DOM fragment target — add --browser --dom --dom-fuzz --fragment --first-hit"
    if parse_qs(p.query):
        return "tip: add --authorized --browser --auto --first-hit for context-aware browser proof (run --recommend for full advice)"
    return "tip: no query params — add --crawl or --dom --dom-fuzz; run --recommend for tailored commands"
