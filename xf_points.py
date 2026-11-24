"""Injection-point model and request construction for xssforge."""
import copy
import http.client
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote

import requests

DEFAULT_METHOD = "GET"


@dataclass
class Point:
    label: str
    method: str
    url: str
    location: str
    name: str
    data: object = None
    path: tuple = ()
    template: str = ""
    meta: dict = field(default_factory=dict)

    def signature(self):
        return (self.location, self.method, self.url, self.name, self.path, self.template)


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def flatten_json(obj, prefix=()):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(flatten_json(v, prefix + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(flatten_json(v, prefix + (i,)))
    else:
        out.append((prefix, obj))
    return out


def get_path(obj, path):
    cur = obj
    for k in path:
        cur = cur[k]
    return cur


def set_path(obj, path, value):
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _query_pairs(url):
    parsed = urlparse(url)
    return parsed, parse_qsl(parsed.query, keep_blank_values=True)


def points_from_url(url, only_params=None):
    parsed, qsl = _query_pairs(url)
    if not qsl:
        return []
    clean = urlunparse(parsed._replace(query=""))
    base = {}
    for k, v in qsl:
        base.setdefault(k, v)
    pts = []
    for k, _ in qsl:
        if only_params and k not in only_params:
            continue
        if any(p.name == k for p in pts):
            continue
        pts.append(Point(label="query:%s" % k, method="GET", url=clean,
                         location="query", name=k, data=dict(base)))
    return pts


def points_from_path(url, segment=-1):
    p = urlparse(url)
    segs = p.path.split("/")
    idx = len(segs) - 1
    while idx > 0 and segs[idx] == "":
        idx -= 1
    if segment < 0:
        idx = max(1, len(segs) + segment)
    if idx <= 0 or idx >= len(segs):
        return []
    template = list(segs)
    template[idx] = "{inject}"
    tmpl_url = urlunparse((p.scheme, p.netloc, "/".join(template), "", p.query, ""))
    return [Point(label="path:%d" % idx, method="GET", url=url,
                  location="path", name="path", template=tmpl_url)]


def points_from_fragment(url, only_params=None):
    parsed = urlparse(url)
    if not parsed.fragment:
        return []
    base = urlunparse(parsed._replace(fragment=""))
    return [Point(label="fragment", method="GET", url=base,
                  location="fragment", name="fragment", data={})]


def points_from_data(url, data_str, method="POST", only_params=None,
                     content_type=""):
    stripped = data_str.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            obj = json.loads(stripped)
        except Exception:
            return []
        if not isinstance(obj, (dict, list)):
            return []
        gql = _points_from_graphql(url, obj, method or "POST", only_params)
        if gql:
            return gql
        pts = []
        for path, val in flatten_json(obj):
            if isinstance(val, (dict, list)):
                continue
            if only_params and path[-1] not in only_params and ".".join(
                    str(x) for x in path) not in only_params:
                continue
            pts.append(Point(label="json:%s" % _pstr(path), method=method or "POST",
                             url=url, location="json", name=_pstr(path),
                             data=obj, path=path))
        return pts
    if content_type.startswith("multipart/"):
        return _points_from_multipart(url, stripped, method or "POST", only_params)
    if ("xml" in content_type.lower() or stripped.startswith("<?xml")
            or re.match(r"<[A-Za-z][\w:-]*[ />]", stripped)):
        xml_pts = _points_from_xml(url, stripped, method or "POST", only_params)
        if xml_pts:
            return xml_pts
    qsl = parse_qsl(stripped, keep_blank_values=True)
    if not qsl:
        return [Point(label="body", method=method or "POST", url=url,
                      location="form", name="", data={"": stripped})]
    base = {}
    for k, v in qsl:
        base.setdefault(k, v)
    method = (method or "POST").upper()
    if method == "GET":
        parsed = urlparse(url)
        target = urlunparse(parsed._replace(query=urlencode(list(base.items()))))
        pts = points_from_url(target, only_params)
        for pt in pts:
            pt.label = "form:GET:%s" % pt.name
        return pts
    pts = []
    for k, _ in qsl:
        if only_params and k not in only_params:
            continue
        if any(p.name == k for p in pts):
            continue
        pts.append(Point(label="body:%s" % k, method=method, url=url,
                         location="form", name=k, data=dict(base)))
    return pts


def _points_from_graphql(url, obj, method, only_params):
    """GraphQL bodies: inject into every scalar under `variables`."""
    if not isinstance(obj, dict) or not isinstance(obj.get("query"), str):
        return []
    q = obj["query"].lstrip()
    if not re.match(r"(?:query|mutation|subscription|fragment)\b|\{", q):
        return []
    variables = obj.get("variables")
    if not isinstance(variables, dict) or not variables:
        return []
    pts = []
    for path, val in flatten_json(variables):
        if isinstance(val, (dict, list)):
            continue
        name = "variables." + _pstr(path)
        if only_params and name not in only_params and path[-1] not in only_params:
            continue
        pts.append(Point(label="graphql:%s" % name, method=method,
                         url=url, location="graphql", name=name,
                         data=obj, path=("variables",) + path,
                         meta={"graphql": True}))
    return pts


_XML_TEXT_RE = re.compile(r">\s*([^<]{1,4000}?)\s*<", re.S)
_XML_ATTR_RE = re.compile(r"([A-Za-z_:][\w:.-]*)\s*=\s*(\"([^\"]*)\"|'([^']*)')")


def _points_from_xml(url, body, method, only_params):
    """XML/SOAP bodies: inject into text nodes and quoted attribute values."""
    spans = []
    for m in _XML_TEXT_RE.finditer(body):
        if m.group(1).strip():
            spans.append((m.start(1), m.end(1), "text"))
    for m in _XML_ATTR_RE.finditer(body):
        if m.group(3) is not None:
            spans.append((m.start(3), m.end(3), "attr:%s" % m.group(1)))
        elif m.group(4) is not None:
            spans.append((m.start(4), m.end(4), "attr:%s" % m.group(1)))
    if not spans:
        return []
    spans.sort()
    pts = []
    for idx, (start, end, kind) in enumerate(spans):
        if only_params and kind not in only_params and "xml" not in only_params:
            continue
        pts.append(Point(label="xml:%d:%s" % (idx, kind), method=method,
                         url=url, location="xml", name=kind,
                         data={"xml": body}, path=(idx,),
                         meta={"spans": spans}))
    return pts


def _points_from_multipart(url, body, method, only_params):
    boundary = ""
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("--") and len(line) > 2:
            boundary = line[2:]
            break
    if not boundary:
        return []
    fields = []
    parts_meta = {}
    for part in body.split("--" + boundary):
        if "Content-Disposition" not in part:
            continue
        head, sep, val = part.partition("\r\n\r\n")
        if not sep:
            head, sep, val = part.partition("\n\n")
        try:
            name = re.search(r'name="([^"]+)"', head).group(1)
        except Exception:
            continue
        fname_m = re.search(r'filename="([^"]*)"', head)
        filename = fname_m.group(1) if fname_m else None
        ctype_m = re.search(r'Content-Type:\s*([^\r\n]+)', head, re.I)
        ctype = ctype_m.group(1).strip() if ctype_m else None
        fields.append((name, val.rstrip("\r\n")))
        parts_meta[name] = {"filename": filename, "ctype": ctype,
                            "head": head.strip()}
    base = {}
    for k, v in fields:
        base.setdefault(k, v)
    pts = []
    for name, _ in fields:
        if only_params and name not in only_params:
            continue
        pts.append(Point(label="multipart:%s" % name, method=method or "POST",
                         url=url, location="multipart", name=name,
                         data=dict(base), meta={"boundary": boundary,
                                                "parts_meta": parts_meta}))
        # File-upload fields: also inject into the filename attribute so
        # filename-based XSS is tested automatically (no manual editing).
        pm = parts_meta.get(name) or {}
        if pm.get("filename") is not None:
            pts.append(Point(
                label="multipart:%s:filename" % name, method=method or "POST",
                url=url, location="multipart-filename", name=name,
                data=dict(base), meta={"boundary": boundary,
                                       "parts_meta": parts_meta}))
    return pts


def _find_header(body):
    return "application/x-www-form-urlencoded"


def _pstr(path):
    s = ""
    for k in path:
        if isinstance(k, int):
            s += "[%d]" % k
        elif s:
            s += "." + str(k)
        else:
            s = str(k)
    return s


def points_from_headers(url, header_names):
    pts = []
    for h in header_names:
        pts.append(Point(label="header:%s" % h, method="GET", url=url,
                         location="header", name=h, data={}))
    return pts


def points_from_cookies(url, cookie_names):
    pts = []
    for c in cookie_names:
        pts.append(Point(label="cookie:%s" % c, method="GET", url=url,
                         location="cookie", name=c, data={}))
    return pts


def points_from_headers_all(url, header_values):
    """header_values: list of (name, value)."""
    pts = []
    for name, value in header_values:
        pts.append(Point(label="header:%s" % name, method="GET", url=url,
                         location="header", name=name, data={"value": value}))
    return pts


# ---------------------------------------------------------------------------
# Raw HTTP request (Burp-style)
# ---------------------------------------------------------------------------

def parse_raw_request(raw_text, scheme="https", base_host=""):
    lines = raw_text.replace("\r\n", "\n").split("\n")
    if not lines:
        return None, None, None
    first = lines[0].split()
    if len(first) < 2:
        return None, None, None
    method = first[0].upper()
    target = first[1]
    headers = []
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers.append((k.strip(), v.strip()))
        i += 1
    body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else ""
    hmap = {k.lower(): v for k, v in headers}
    host = base_host or hmap.get("host", "")
    path = target
    url = target
    if "://" not in target:
        url = "%s://%s%s" % (scheme, host, target)
    content_type = hmap.get("content-type", "")
    return {
        "method": method,
        "url": url,
        "path": path,
        "headers": headers,
        "host": host,
        "body": body,
        "content_type": content_type,
    }, headers, body


def points_from_raw_request(parsed, only_params=None):
    pts = []
    url = parsed["url"]
    pts.extend(points_from_url(url, only_params))
    body = parsed["body"]
    if body:
        pts.extend(points_from_data(url, body, parsed["method"], only_params,
                                    parsed["content_type"]))
    return pts


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def raw_request(kwargs, user_agent="", timeout=15.0, max_body=4000000):
    """Send a request with literal URL bytes (no requests/Chrome requoting).

    Returns a requests.Response so callers can keep using .text/.content.
    """
    url = kwargs["url"]
    parts = urlparse(url)
    scheme = (parts.scheme or "https").lower()
    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = cls(host, port, timeout=timeout)
    headers = dict(kwargs.get("headers") or {})
    headers.setdefault("User-Agent", user_agent or "Mozilla/5.0")
    headers.setdefault("Host", host)
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Connection", "close")
    method = (kwargs.get("method") or "GET").upper()
    body = kwargs.get("data")
    if isinstance(body, (dict, list, tuple)):
        body = urlencode(body)
    if body is not None and not isinstance(body, bytes):
        body = str(body).encode("utf-8", "replace")
    if body is not None:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        headers["Content-Length"] = str(len(body))
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        content = resp.read()
        if len(content) > max_body:
            content = content[:max_body]
        r = requests.Response()
        r.status_code = resp.status
        r.headers = requests.structures.CaseInsensitiveDict(dict(resp.getheaders()))
        r._content = content
        r.url = url
        r.encoding = "utf-8"
        return r
    finally:
        conn.close()


def build_request(point, value, opts):
    """Return (kwargs, display_url) for requests.request."""
    url = point.url
    method = point.method or DEFAULT_METHOD
    kwargs = {"method": method, "url": url, "timeout": opts.timeout,
              "verify": not opts.insecure, "allow_redirects": True}
    imported_headers = dict(point.meta.get("headers") or {})
    if imported_headers:
        kwargs["headers"] = imported_headers
    display = url

    if point.location == "query":
        parsed = urlparse(url)
        if point.meta.get("struct") == "hpp-pairs":
            pairs = list(point.data)
        elif isinstance(point.data, list):
            pairs = [(k, value if k == point.name else v)
                     for k, v in point.data]
        else:
            pairs = [(k, value if k == point.name else v)
                     for k, v in point.data.items()]
        if getattr(opts, "raw_inject", False):
            q = "&".join("%s=%s" % (k, v) for k, v in pairs)
        else:
            q = urlencode(pairs)
        kwargs["url"] = urlunparse(parsed._replace(query=q))
        display = kwargs["url"]
    elif point.location == "form":
        if point.meta.get("struct") == "hpp-pairs":
            fields = list(point.data)
        else:
            fields = dict(point.data)
            if point.name:
                fields[point.name] = value
            else:
                fields = {"": value}
        kwargs["data"] = fields
        display = url + "?" + urlencode(fields)
    elif point.location in ("json", "graphql"):
        obj = copy.deepcopy(point.data)
        set_path(obj, point.path, _json_value(obj, point.path, value))
        if point.meta.get("struct") == "dupjson":
            import xf_struct
            body = xf_struct.duplicate_json_body(point.data, point.path, value)
            kwargs["data"] = body
            kwargs["headers"] = dict(kwargs.get("headers") or {})
            kwargs["headers"]["Content-Type"] = "application/json"
            display = url + "  JSON=" + body
        else:
            kwargs["json"] = obj
            display = url + "  JSON=" + json.dumps(obj)
    elif point.location == "xml":
        xml_text = (point.data or {}).get("xml", "")
        spans = point.meta.get("spans") or []
        idx = point.path[0] if point.path else 0
        if 0 <= idx < len(spans):
            start, end = spans[idx][0], spans[idx][1]
            body = xml_text[:start] + value + xml_text[end:]
        else:
            body = xml_text
        kwargs["data"] = body
        kwargs["headers"] = dict(kwargs.get("headers") or {})
        kwargs["headers"].setdefault("Content-Type", "application/xml")
        display = url + "  XML=" + body[:400]
    elif point.location in ("multipart", "multipart-filename"):
        boundary = point.meta.get("boundary") or "----xssforgeBoundary"
        fields = dict(point.data) if isinstance(point.data, dict) else {}
        parts_meta = point.meta.get("parts_meta") or {}
        inject_filename = point.location == "multipart-filename"
        if not inject_filename:
            fields[point.name] = value
        parts = []
        for name, val in fields.items():
            pm = parts_meta.get(name) or {}
            head = pm.get("head")
            if head:
                head = head.strip()
                if inject_filename and name == point.name:
                    if pm.get("filename") is not None:
                        head = re.sub(r'filename="[^"]*"',
                                      'filename="%s"' % value.replace('"', '\\"'), head)
                    else:
                        head += '; filename="%s"' % value.replace('"', '\\"')
            else:
                head = 'Content-Disposition: form-data; name="%s"' % name
                if inject_filename and name == point.name:
                    head += '; filename="%s"' % value.replace('"', '\\"')
            struct = point.meta.get("struct") or ""
            if struct == "mp-confusion":
                head += '\r\nContent-Disposition: form-data; name="__skip__"'
            elif struct == "mp-dupname" and name == point.name:
                head += '\r\nContent-Disposition: form-data; name="%s"' % name
            parts.append("--%s\r\n%s\r\n\r\n%s\r\n" % (boundary, head, val))
        parts.append("--%s--\r\n" % boundary)
        body = "".join(parts)
        kwargs["data"] = body
        kwargs["headers"] = dict(kwargs.get("headers") or {})
        kwargs["headers"]["Content-Type"] = "multipart/form-data; boundary=" + boundary
        display = url + "  MULTIPART" + (":filename" if inject_filename else "")
    elif point.location == "header":
        kwargs.setdefault("headers", {})[point.name] = value
        display = url + "  [%s: %s]" % (point.name, value)
    elif point.location == "cookie":
        cookie = dict(point.meta.get("cookies") or {})
        cookie[point.name] = value
        kwargs.setdefault("headers", {})["Cookie"] = "; ".join(
            "%s=%s" % (k, v) for k, v in cookie.items())
        display = url + "  [Cookie %s]" % point.name
    elif point.location == "path":
        kwargs["url"] = point.template.replace("{inject}", quote(value, safe=""))
        display = kwargs["url"]
    elif point.location == "fragment":
        parsed = urlparse(url)
        frag = value[1:] if value.startswith("#") else value
        kwargs["url"] = urlunparse(parsed._replace(fragment=frag))
        display = kwargs["url"]
    return kwargs, display


def _json_value(obj, path, value):
    try:
        orig = get_path(obj, path)
    except Exception:
        return value
    if isinstance(orig, bool):
        return True
    if isinstance(orig, (int, float)) and not isinstance(orig, bool):
        try:
            return type(orig)(value)
        except Exception:
            return value
    return value


def curl_repro(point, value, opts):
    kwargs, _ = build_request(point, value, opts)
    pieces = ["curl", "-sk", "-X", kwargs["method"]]
    for k, v in (kwargs.get("headers") or {}).items():
        pieces += ["-H", "%s: %s" % (k, v)]
    if kwargs.get("data"):
        pieces += ["--data-binary", str(kwargs["data"])]
    if kwargs.get("json") is not None:
        pieces += ["-H", "Content-Type: application/json",
                   "--data-raw", json.dumps(kwargs["json"])]
    pieces.append(shell_quote(kwargs["url"]))
    return " ".join(pieces)


def shell_quote(s):
    if not s:
        return "''"
    if all(ch.isalnum() or ch in "-_./:?=&%@" for ch in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"
