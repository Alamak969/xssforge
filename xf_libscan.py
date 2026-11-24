"""Outdated / vulnerable JavaScript library detection for xssforge.

Detects JS libraries and their versions from:
  1. script src URLs (CDN paths and versioned filenames)
  2. JS file content banners (/*! jQuery v3.4.0 */, AngularJS v1.7.7, ...)
  3. browser global version properties (jQuery.fn.jquery, angular.version.full, ...)

Compares detected versions against a bundled DB of XSS-relevant advisories,
similar in spirit to XSStrike's retireJS integration / retire.js.

Usage: enabled with --libscan (or automatically with --all).
"""
import re
from urllib.parse import urlparse

# (library, detected-from pattern on URL or file content) -> version extraction
# order matters: first match per library wins.
SIGNATURES = [
    ("jQuery", [
        r'jquery[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'/jquery[@/](\d+\.\d+(?:\.\d+)?)',
        r'jQuery\s+v?(\d+\.\d+(?:\.\d+)?)',
        r'jQuery JavaScript Library v?(\d+\.\d+(?:\.\d+)?)',
    ]),
    ("AngularJS", [
        r'angular[./_-]v?(\d+)-(\d+)(?:-(\d+))',  # hyphen version angular_1-7-7
        r'angular[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'angularjs[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'AngularJS v?(\d+\.\d+(?:\.\d+)?)',
        r'angular\.version\.full\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("Angular", [
        r'@angular/core[@/](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("lodash", [
        r'lodash[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'lodash[@/](\d+\.\d+(?:\.\d+)?)',
        r'lodash\.VERSION\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("underscore", [
        r'underscore[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'_\.VERSION\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("DOMPurify", [
        r'dompurify[@/](\d+\.\d+(?:\.\d+)?)',
        r'DOMPurify\s+v?(\d+\.\d+(?:\.\d+)?)',
        r'DOMPurify\.version\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("Vue", [
        r'vue[@./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'Vue\.version\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("React", [
        r'react(?:dom)?[@./_-](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("Bootstrap", [
        r'bootstrap[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'Bootstrap v?(\d+\.\d+(?:\.\d+)?)',
    ]),
    ("Handlebars", [
        r'handlebars[./_-]v?(\d+\.\d+(?:\.\d+)?)',
        r'Handlebars\.VERSION\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)',
    ]),
    ("moment.js", [
        r'moment[./_-]v?(\d+\.\d+(?:\.\d+)?)',
    ]),
    ("prototype", [
        r'prototype[./_-]v?(\d+\.\d+(?:\.\d+)?)',
    ]),
    ("swfobject", [
        r'swfobject[./_-]v?(\d+\.\d+(?:\.\d+)?)',
    ]),
]

# Browser-side global expression probes for version detection.
BROWSER_GLOBALS = [
    ("jQuery", "window.jQuery && jQuery.fn && jQuery.fn.jquery"),
    ("AngularJS", "window.angular && angular.version && angular.version.full"),
    ("lodash", "window._ && _.VERSION"),
    ("underscore", "window._ && _.VERSION"),
    ("DOMPurify", "window.DOMPurify && DOMPurify.version"),
    ("Vue", "window.Vue && Vue.version"),
    ("React", "window.React && React.version"),
    ("Handlebars", "window.Handlebars && Handlebars.VERSION"),
    ("moment.js", "window.moment && moment.version"),
]

# Bundled vulnerable-version ranges (XSS-relevant where applicable).
# Each entry: (library, upper_bound_inclusive_or_None, summary, refs)
VULNS = [
    ("jQuery", "3.4.1", "XSS via jQuery.html()/append() (CVE-2020-11022/11023)", "GHSA-jpcq-cgw6-v4j6"),
    ("jQuery", "1.12.4", "Multiple XSS / prototype pollution in legacy jQuery", "CVE-2020-11023"),
    ("AngularJS", "1.8.4", "AngularJS XSS / sandbox escape / sanitizer bypass (multiple advisories)", "GHSA-prc3-vjfx-vhm9"),
    ("Angular", "18.2.15", "Angular template/i18n XSS and namespace bypass", "GHSA-692r-grfm-v8x7"),
    ("lodash", "4.17.20", "Prototype pollution / command injection (CVE-2021-23337)", "CVE-2021-23337"),
    ("DOMPurify", "2.4.9", "DOMPurify mXSS / nesting bypass (CVE-2024-47875 family, <2.5.0)", "GHSA-gx9m-whjm-85jf"),
    ("DOMPurify", "3.1.2", "DOMPurify mXSS re-contextualization bypass (<3.1.3)", "GHSA-h8r8-wccr-v5f2"),
    ("Handlebars", "4.7.7", "Handlebars template injection / prototype pollution XSS", "CVE-2021-23369"),
    ("Bootstrap", "4.6.2", "Bootstrap XSS in tooltip/popover data-* attributes", "CVE-2019-8331"),
    ("prototype", "1.7.3", "Prototype.js legacy XSS", "CVE-2020-27522"),
    ("swfobject", "2.2", "SWFObject flash XSS", "CVE-2019-19514"),
    ("moment.js", "2.29.3", "moment.js ReDoS / XSS in locale", "CVE-2022-24785"),
]


def _parse_ver(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _cmp(a, b):
    return (a > b) - (a < b)


def vulnerable(library, version):
    """Return a list of advisories for a library/version, or []."""
    v = _parse_ver(version)
    if not v:
        return []
    out = []
    for lib, upper, summary, ref in VULNS:
        if lib.lower() != library.lower():
            continue
        uv = _parse_ver(upper)
        if uv and _cmp(v, uv) <= 0:
            out.append({"library": library, "version": version,
                        "upper": upper, "summary": summary, "ref": ref})
    return out


def detect_from_text(text):
    """Detect (library, version) pairs from a blob of HTML / JS text."""
    found = {}
    for lib, pats in SIGNATURES:
        for pat in pats:
            m = re.search(pat, text, re.I)
            if m:
                grp = [g for g in m.groups() if g]
                ver = ".".join(grp) if len(grp) > 1 else m.group(1)
                found.setdefault(lib, ver)
                break
    return found


def scan_scripts(session, base_url, html, timeout=10, insecure=False,
                 max_scripts=40, fetch_content=True):
    """Given an HTML body, find script src URLs, fetch their content and
    detect libraries. Returns a list of {library,version,url,vulns} dicts."""
    results = []
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html or "", re.I)
    seen = set()
    for src in srcs[:max_scripts]:
        # resolve relative URL
        if src.startswith("//"):
            scheme = urlparse(base_url).scheme or "https"
            url = scheme + ":" + src
        elif src.startswith("/"):
            p = urlparse(base_url)
            url = "%s://%s%s" % (p.scheme, p.netloc, src)
        elif src.startswith("http"):
            url = src
        else:
            p = urlparse(base_url)
            url = "%s://%s/%s" % (p.scheme, p.netloc, src.lstrip("./"))
        if url in seen:
            continue
        seen.add(url)
        detected = detect_from_text(src)  # from filename/CDN path
        body = ""
        if fetch_content and not detected:
            try:
                r = session.get(url, timeout=timeout, verify=not insecure)
                body = r.text or ""
                detected = detect_from_text(body)
            except Exception:
                pass
        for lib, ver in detected.items():
            results.append({"library": lib, "version": ver, "url": url,
                            "vulns": vulnerable(lib, ver)})
    return results


def browser_probe(driver):
    """Detect library versions from live browser globals. driver is a Selenium
    WebDriver positioned on the target page. Returns list of result dicts."""
    results = []
    for lib, expr in BROWSER_GLOBALS:
        try:
            ver = driver.execute_script("try{return (%s)||''}catch(e){return ''}" % expr)
        except Exception:
            ver = ""
        if ver and re.match(r"\d+\.\d+", str(ver)):
            results.append({"library": lib, "version": str(ver), "url": "browser-global",
                            "vulns": vulnerable(lib, str(ver))})
    return results
