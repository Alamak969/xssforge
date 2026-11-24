"""HTML/JS context tokenizer for xssforge.

Classifies the exact parsing context at a marker occurrence by walking a small
HTML5-flavoured state machine from the start of the document. This is much more
accurate than regex look-behind heuristics for nested tags, SVG, RCDATA and
JavaScript strings.
"""
from html import unescape

RAW_TEXT_TAGS = {"script", "style", "textarea", "title", "xmp", "iframe",
                 "noembed", "noframes", "plaintext"}
RCDATA_TAGS = {"textarea", "title", "xmp", "noembed", "noframes", "plaintext"}
URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "codebase",
             "cite", "background", "longdesc", "usemap", "xlink:href", "ping",
             "manifest", "profile", "icon", "content"}
CSS_ATTRS = {"style"}
EVENT_PREFIX = "on"
HTML_ATTRS = {"srcdoc"}


def reflection_offsets(body, token):
    out = []
    start = 0
    while True:
        i = body.find(token, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def _is_alpha(c):
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def _is_space(c):
    return c in " \t\n\r\f"


def classify_at(text, idx):
    """Return a context dict for the character position idx in text."""
    n = min(idx, len(text))
    i = 0
    state = "data"
    tag = ""
    attr = ""
    quote = ""
    buf = ""
    stack = []
    in_svg = False
    js = "code"
    js_quote = ""
    # comment / declaration states
    while i < n:
        c = text[i]
        if state == "data":
            if c == "<":
                if text.startswith("<!--", i):
                    state = "comment"
                    i += 4
                    continue
                if text.startswith("<![CDATA[", i):
                    state = "cdata"
                    i += 9
                    continue
                if text.startswith("<!", i) or text.startswith("<?", i):
                    state = "decl"
                    i += 2
                    continue
                if text.startswith("</", i):
                    state = "end_tag"
                    buf = ""
                    i += 2
                    continue
                if i + 1 < len(text) and (_is_alpha(text[i + 1]) or text[i + 1] in "!?"):
                    state = "tag_name"
                    buf = ""
                    i += 1
                    continue
                i += 1
                continue
            i += 1
            continue

        if state == "comment":
            j = text.find("-->", i)
            if j < 0 or j >= n:
                return _ctx("comment", tag, attr, quote, in_svg, js)
            i = j + 3
            state = "data"
            continue

        if state == "cdata":
            j = text.find("]]>", i)
            if j < 0 or j >= n:
                return _ctx("html", tag, attr, quote, in_svg, js)
            i = j + 3
            state = "data"
            continue

        if state == "decl":
            j = text.find(">", i)
            if j < 0 or j >= n:
                return _ctx("html", tag, attr, quote, in_svg, js)
            i = j + 1
            state = "data"
            continue

        if state in ("tag_name", "end_tag"):
            if _is_alpha(c) or c in "!-":
                buf += c
                i += 1
                continue
            tag = buf.lower().strip("!")
            if state == "end_tag":
                if tag in RAW_TEXT_TAGS or tag == "svg":
                    if stack:
                        # pop until matching tag
                        for k in range(len(stack) - 1, -1, -1):
                            if stack[k] == tag:
                                del stack[k:]
                                break
                    in_svg = "svg" in stack
                    state = "data"
                    if c == ">":
                        i += 1
                    continue
                if stack:
                    for k in range(len(stack) - 1, -1, -1):
                        if stack[k] == tag:
                            del stack[k:]
                            break
                in_svg = "svg" in stack
                state = "data"
                if c == ">":
                    i += 1
                continue
            if tag in RAW_TEXT_TAGS:
                stack.append(tag)
                if tag == "svg":
                    in_svg = True
                if c == ">":
                    state = "raw" if tag in RCDATA_TAGS or tag != "script" else "raw"
                    js = "code"
                    i += 1
                    continue
                state = "before_attr"
                i += 1
                continue
            if tag == "svg":
                stack.append(tag)
                in_svg = True
                state = "before_attr"
                i += 1
                continue
            if c == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 1
                continue
            if c == "/" and i + 1 < len(text) and text[i + 1] == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 2
                continue
            state = "before_attr"
            i += 1
            continue

        if state == "raw":
            close = "</" + tag
            j = text.lower().find(close, i)
            if j < 0 or j >= n:
                # token is inside raw text for sure
                if tag == "script":
                    js = _js_state(text, i, n)
                    jsq = _js_quote(text, i, n)
                    if js == "string":
                        return _ctx("script_string", tag, attr, jsq, in_svg, "string")
                    if js == "comment":
                        return _ctx("script", tag, attr, quote, in_svg, "comment")
                    return _ctx("script", tag, attr, quote, in_svg, "code")
                if tag in ("style",):
                    return _ctx("css", tag, attr, quote, in_svg, js)
                return _ctx("rcdata", tag, attr, quote, in_svg, js)
            # token might be inside the close prefix
            if j < n:
                # if token lies within the detected close tag name, treat as tag
                i = j
                state = "end_tag"
                buf = ""
                i += 2
                continue
            i = j
            continue

        if state == "before_attr":
            if _is_space(c):
                i += 1
                continue
            if c == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 1
                continue
            if c == "/" and i + 1 < len(text) and text[i + 1] == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 2
                continue
            state = "attr_name"
            buf = c
            i += 1
            continue

        if state == "attr_name":
            if _is_space(c) or c == "=" or c == ">":
                attr = buf.lower()
                if c == "=":
                    state = "before_attr_value"
                    i += 1
                elif c == ">":
                    stack.append(tag)
                    in_svg = "svg" in stack
                    state = "data"
                    i += 1
                else:
                    state = "after_attr_name"
                    i += 1
                continue
            if c == "/" and i + 1 < len(text) and text[i + 1] == ">":
                attr = buf.lower()
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 2
                continue
            buf += c
            i += 1
            continue

        if state == "after_attr_name":
            if _is_space(c):
                i += 1
                continue
            if c == "=":
                state = "before_attr_value"
                i += 1
                continue
            if c == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 1
                continue
            state = "before_attr"
            continue

        if state == "before_attr_value":
            if _is_space(c):
                i += 1
                continue
            if c == '"':
                state = "attr_dq"
                quote = '"'
                i += 1
                continue
            if c == "'":
                state = "attr_sq"
                quote = "'"
                i += 1
                continue
            if c == ">":
                stack.append(tag)
                in_svg = "svg" in stack
                state = "data"
                i += 1
                continue
            state = "attr_uq"
            quote = ""
            i += 1
            continue

        if state in ("attr_dq", "attr_sq", "attr_uq"):
            end = '"' if state == "attr_dq" else ("'" if state == "attr_sq" else None)
            if end is None:
                if _is_space(c) or c == ">":
                    ctx = _attr_context(tag, attr, "", in_svg)
                    if c == ">":
                        stack.append(tag)
                        in_svg = "svg" in stack
                        state = "data"
                    else:
                        state = "before_attr"
                    i += 1
                    continue
            elif c == end:
                ctx = _attr_context(tag, attr, quote, in_svg)
                state = "before_attr"
                i += 1
                continue
            i += 1
            continue

        i += 1
    # Fell off the end of the prefix: we are in the last seen state
    if state == "attr_dq":
        return _attr_context(tag, attr, '"', in_svg)
    if state == "attr_sq":
        return _attr_context(tag, attr, "'", in_svg)
    if state == "attr_uq":
        return _attr_context(tag, attr, "", in_svg)
    if state in ("before_attr_value", "attr_name", "before_attr"):
        if state == "before_attr_value":
            return _attr_context(tag, attr, "", in_svg)
        return _ctx("attr_name", tag, attr, quote, in_svg, js)
    if state == "comment":
        return _ctx("comment", tag, attr, quote, in_svg, js)
    if state == "raw":
        if tag == "script":
            return _ctx("script", tag, attr, quote, in_svg, "code")
        if tag == "style":
            return _ctx("css", tag, attr, quote, in_svg, js)
        return _ctx("rcdata", tag, attr, quote, in_svg, js)
    if state in ("tag_name", "end_tag"):
        return _ctx("attr_name", tag, attr, quote, in_svg, js)
    return _ctx("html", tag, attr, quote, in_svg, js)


def _attr_context(tag, attr, quote, in_svg):
    if attr.startswith(EVENT_PREFIX):
        return _ctx("script", tag, attr, quote, in_svg, "code", attr_event=True)
    if attr in URL_ATTRS or attr.endswith(":href"):
        return _ctx("url", tag, attr, quote, in_svg, "code")
    if attr in CSS_ATTRS:
        return _ctx("css", tag, attr, quote, in_svg, "css")
    if attr in HTML_ATTRS:
        return _ctx("html", tag, attr, quote, in_svg, "html")
    ctx = "attr_dq" if quote == '"' else ("attr_sq" if quote == "'" else "attr_unquoted")
    return _ctx(ctx, tag, attr, quote, in_svg, "text")


def _ctx(context, tag="", attr="", quote="", in_svg=False, js="code", attr_event=False):
    return {
        "context": context,
        "tag": tag,
        "attr": attr,
        "quote": quote,
        "in_svg": in_svg,
        "js": js,
        "attr_event": attr_event,
    }


def _js_state(text, start, end):
    i = start
    state = "code"
    quote = ""
    while i < end:
        c = text[i]
        if state == "code":
            if c == "'":
                state, quote = "string", "'"
            elif c == '"':
                state, quote = "string", '"'
            elif c == "`":
                state, quote = "string", "`"
            elif c == "/" and i + 1 < end and text[i + 1] == "/":
                state = "line"
                i += 1
            elif c == "/" and i + 1 < end and text[i + 1] == "*":
                state = "block"
                i += 1
            i += 1
            continue
        if state == "string":
            if c == "\\":
                i += 2
                continue
            if c == quote:
                state = "code"
            i += 1
            continue
        if state == "line":
            if c == "\n":
                state = "code"
            i += 1
            continue
        if state == "block":
            if c == "*" and i + 1 < end and text[i + 1] == "/":
                state = "code"
                i += 2
                continue
            i += 1
            continue
    return "string" if state == "string" else ("comment" if state in ("line", "block") else "code")


def _js_quote(text, start, end):
    i = start
    state = "code"
    quote = ""
    while i < end:
        c = text[i]
        if state == "code":
            if c in "'\"`":
                state, quote = "string", c
            elif c == "/" and i + 1 < end and text[i + 1] == "/":
                state = "comment"
                i += 1
            elif c == "/" and i + 1 < end and text[i + 1] == "*":
                state = "block"
                i += 1
            i += 1
            continue
        if state == "string":
            if c == "\\":
                i += 2
                continue
            if c == quote:
                state = "code"
                quote = ""
            i += 1
            continue
        if state == "comment":
            if c == "\n":
                state = "code"
            i += 1
            continue
        if state == "block":
            if c == "*" and i + 1 < end and text[i + 1] == "/":
                state = "code"
                i += 2
                continue
            i += 1
            continue
    return quote


def classify(body, token):
    """Classify the first occurrence of token; return (context_dict, index)."""
    for idx in reflection_offsets(body, token):
        return classify_at(body, idx), idx
    return None, -1


def response_encoding_hint(body, payload, token):
    """Detect how the server transformed the payload around the reflection."""
    if payload and payload in body:
        return "raw"
    if token not in body:
        return "absent"
    esc = unescape(payload)
    if esc in body:
        return "html-encoded-then-decoded"
    # common escaping: payload's angle brackets/entities encoded
    no_lt = payload.replace("<", "&lt;").replace(">", "&gt;")
    if no_lt in body:
        return "html-entity-escaped"
    if payload.replace("<", "").replace(">", "") in body:
        return "tag-stripped"
    return "mutated"
