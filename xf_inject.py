import os
import re
import urllib.parse

import requests

import xf_points

STANDARD_HEADERS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Forwarded-Prefix", "X-Host", "X-Forwarded-Server", "X-Real-IP",
    "Referer", "Origin", "Accept-Language", "X-Requested-With",
    "X-HTTP-Method-Override", "X-Forwarded-Proto",
]

NAME_PATTERNS = [
    re.compile(r"""\bname\s*=\s*["']([A-Za-z_][\w.-]{1,64})["']""", re.I),
    re.compile(r"""\bid\s*=\s*["']([A-Za-z_][\w.-]{1,64})["']""", re.I),
    re.compile(r"""\bwindow\.([A-Za-z_$][\w$]{1,64})\b"""),
    re.compile(r"""\b(?:var|let|const)\s+([A-Za-z_$][\w$]{1,64})\s*="""),
    re.compile(r"""get(?:Parameter|QueryString)\s*\(\s*["']([^"']{1,64})["']""", re.I),
    re.compile(r"""params(?:\.|\[["'])([A-Za-z_$][\w$]{1,64})""", re.I),
]

SKIP_NAMES = {
    "username", "password", "email", "submit", "button", "csrf", "token",
    "session", "id", "name", "action", "method", "class", "style",
}


def _dedupe(items):
    out = []
    seen = set()
    for item in items:
        key = item.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def sweep_headers(opts):
    names = list(STANDARD_HEADERS)
    names.extend(opts.headers.keys())
    names.extend(opts.inject_headers or [])
    return _dedupe([n for n in names if n.lower() not in ("host", "content-length")])


def _parse_cookie_file(path, with_values=False):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    out.append((parts[5], parts[6]) if with_values else parts[5])
    except Exception:
        pass
    return out


def cookie_map(opts):
    out = {}
    for part in (opts.cookie or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    if opts.cookie_file:
        for k, v in _parse_cookie_file(opts.cookie_file, with_values=True):
            out[k.strip()] = v.strip()
    return out


SESSION_COOKIES = {
    "phpsessid", "jsessionid", "sessionid", "sid", "connect.sid",
    "asp.net_sessionid", "aspnet_sessionid", "laravel_session", "ci_session",
    "cakephp", "kcfinder_session", "zde_debug", "xsrf-token", "csrftoken",
}


def sweep_cookies(opts):
    names = []
    for part in (opts.cookie or "").split(";"):
        if "=" in part:
            names.append(part.split("=", 1)[0].strip())
    if opts.cookie_file:
        names.extend(_parse_cookie_file(opts.cookie_file))
    names.extend(opts.inject_cookies or [])
    # Injecting into the auth cookie logs the scanner out mid-run, which makes
    # every later point look "not reflected" and kills stored/DOM proof.
    names = [n for n in names
             if n.lower() not in SESSION_COOKIES
             and not n.lower().startswith("wordpress_logged_in")]
    return _dedupe(names)


def load_wordlist(source, timeout=10.0, insecure=False):
    if not source:
        return []
    try:
        if source.startswith(("http://", "https://")):
            r = requests.get(source, timeout=timeout, verify=not insecure)
            text = r.text or ""
        else:
            with open(source, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except Exception:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split("=", 1)[0].split(":", 1)[0].strip()
        if re.match(r"^[A-Za-z_][\w.-]{1,64}$", name):
            out.append(name)
    return _dedupe(out)


def mine_names(html_text, extra=()):
    found = []
    text = html_text or ""
    for pattern in NAME_PATTERNS:
        found.extend(pattern.findall(text))
    for name in extra or ():
        found.append(name)
    return _dedupe([n for n in found if n.lower() not in SKIP_NAMES])


def _url_with_param(url, name):
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    keys = {k for k, _ in pairs}
    if name in keys:
        return url
    pairs.append((name, "xssforge"))
    query = urllib.parse.urlencode(pairs)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def mine_points(url, html_text, names, only_params=None):
    pts = []
    for name in names:
        if only_params and name not in only_params:
            continue
        target = _url_with_param(url, name)
        found = xf_points.points_from_url(target, [name])
        for p in found:
            p.label = "mined:%s" % name
            p.meta["mined"] = True
            pts.append(p)
    return pts
