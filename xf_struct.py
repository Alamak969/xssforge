import copy
import json
import re

HPP_MARKER = "__HPP__"


def _clone(point, meta_updates=None):
    p = copy.copy(point)
    p.meta = dict(point.meta or {})
    if meta_updates:
        p.meta.update(meta_updates)
    return p


def hpp_pairs(name, value, parts=3):
    parts = max(2, int(parts or 3))
    if HPP_MARKER in value:
        expanded = value.replace(HPP_MARKER, name)
        out = []
        for chunk in expanded.split("&"):
            if not chunk:
                continue
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                out.append((k, v))
            else:
                out.append((name, chunk))
        return out or [(name, value)]
    chunks = _split_balanced(value, parts)
    while len(chunks) < parts:
        longest = max(range(len(chunks)), key=lambda i: len(chunks[i]))
        chunk = chunks[longest]
        if len(chunk) < 2:
            break
        mid = len(chunk) // 2
        chunks[longest:longest + 1] = [chunk[:mid], chunk[mid:]]
    return [(name, chunk) for chunk in chunks]


def _split_balanced(value, parts):
    chunks = []
    cur = []
    depth = 0
    quote = None
    i = 0
    while i < len(value):
        ch = value[i]
        cur.append(ch)
        if quote:
            if ch == quote and (i == 0 or value[i - 1] != "\\"):
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch in ";&" and depth == 0 and len(chunks) < parts - 1:
            chunks.append("".join(cur))
            cur = []
        i += 1
    tail = "".join(cur)
    if tail or not chunks:
        chunks.append(tail)
    return chunks


def duplicate_json_body(obj, path, value):
    key = path[-1] if path else "inject"
    marker = "__XF_DUPJSON_%s__" % key
    tmp = copy.deepcopy(obj)
    if not isinstance(tmp, dict):
        tmp = {"inject": value}
    try:
        import xf_points
        xf_points.set_path(tmp, path, marker)
    except Exception:
        tmp[key] = marker
    encoded = json.dumps(tmp)
    replacement = "%s,%s:%s" % (
        json.dumps(value), json.dumps(str(key)), json.dumps(value))
    return encoded.replace(json.dumps(marker), replacement)


def attr_decode_mutations(value):
    out = []
    for name, repl in (
            ("struct:entity-angle", (
                ("<", "&lt;"), (">", "&gt;"))),
            ("struct:entity-quotes", (
                ("'", "&#39;"), ('"', "&quot;"))),
            ("struct:mixed-angle", (
                ("<", "&#x3c;"), (">", "&#x3e;")))):
        mutated = value
        for old, new in repl:
            mutated = mutated.replace(old, new)
        if mutated != value:
            out.append((name, mutated))
    return out


def size_window(value, pad=2048):
    return ("A" * max(0, int(pad or 0))) + value


def variants(point, value, opts):
    out = []
    use_hpp = bool(getattr(opts, "hpp", False) or HPP_MARKER in value)
    if use_hpp:
        pairs = hpp_pairs(point.name, value, getattr(opts, "hpp_parts", 3))
        if point.location in ("query", "form"):
            p = _clone(point, {"struct": "hpp-pairs"})
            p.data = pairs
            out.append(("hpp:repeat", p, value))
        elif point.location == "json":
            p = _clone(point, {"struct": "dupjson"})
            out.append(("hpp:dupjson", p, value))
        elif point.location in ("multipart", "multipart-filename"):
            p = _clone(point, {"struct": "mp-dupname"})
            out.append(("hpp:multipart", p, value))
    if not getattr(opts, "structural", False):
        return out
    for name, mutated in attr_decode_mutations(value):
        out.append((name, point, mutated))
    pad = getattr(opts, "structural_pad", 2048)
    out.append(("struct:size-window", point, size_window(value, pad)))
    if point.location == "json":
        out.append(("struct:dupjson", _clone(point, {"struct": "dupjson"}), value))
    if point.location in ("multipart", "multipart-filename"):
        out.append(("struct:mp-confusion",
                    _clone(point, {"struct": "mp-confusion"}), value))
    if point.location == "header":
        out.append(("struct:header-fold", point, value + ";\tX-XSS=1"))
    if point.location == "cookie":
        out.append(("struct:cookie-fold", point, value + "; X-XSS=1"))
    return out


def _dedupe(out):
    seen = set()
    result = []
    for name, point, value in out:
        key = (point.location, point.name, value, tuple(sorted((point.meta or {}).items())))
        if key in seen:
            continue
        seen.add(key)
        result.append((name, point, value))
    return result


def all_variants(point, value, opts):
    return _dedupe(variants(point, value, opts))
