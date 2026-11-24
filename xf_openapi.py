"""OpenAPI / Swagger ingestion for xssforge.

Turns an OpenAPI 2.0/3.x document into injection points: query params, path
segments, headers, cookies and JSON request bodies. This closes a gap that
URL-only scanners miss on documented APIs.

Usage from the CLI: ``--openapi https://target/openapi.json`` or ``--openapi spec.yaml``.
"""
import json
import os
from urllib.parse import urlparse, urlunparse

import requests

import xf_points


def load_spec(source, timeout=15, insecure=False):
    """Load a spec from a URL, file path or raw JSON/YAML string."""
    text = ""
    if source.startswith("http://") or source.startswith("https://"):
        r = requests.get(source, timeout=timeout, verify=not insecure)
        r.raise_for_status()
        text = r.text
    elif os.path.exists(source):
        with open(source, encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = source
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        return None


def _resolve(doc, node, depth=0):
    if depth > 8 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not ref or not ref.startswith("#/"):
        return node
    cur = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or part not in cur:
            return node
        cur = cur[part]
    return _resolve(doc, cur, depth + 1)


def _example(schema, doc, depth=0):
    schema = _resolve(doc, schema or {})
    if depth > 6 or not isinstance(schema, dict):
        return "x"
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        out = {}
        for k, v in (schema.get("properties") or {}).items():
            out[k] = _example(v, doc, depth + 1)
        return out
    if t == "array":
        return [_example(schema.get("items") or {}, doc, depth + 1)]
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    return "x"


def _join(base, path):
    return base.rstrip("/") + "/" + path.lstrip("/")


def points_from_spec(doc, base_url="", only_params=None):
    if not isinstance(doc, dict):
        return []
    base = base_url
    if not base:
        if doc.get("servers"):
            base = (doc["servers"][0] or {}).get("url", "")
        elif doc.get("host"):
            scheme = (doc.get("schemes") or ["https"])[0]
            base = "%s://%s%s" % (scheme, doc["host"], doc.get("basePath", ""))
    if not base:
        return []
    if base.startswith("/"):
        return []
    pts = []
    seen = set()

    def add(p):
        sig = p.signature()
        if sig not in seen:
            seen.add(sig)
            pts.append(p)

    for path, item in (doc.get("paths") or {}).items():
        item = _resolve(doc, item)
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method in ("get", "post", "put", "patch", "delete"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(shared) + list(op.get("parameters") or [])
            params = [_resolve(doc, p) for p in params]
            query = {}
            path_vals = {}
            header_names = []
            cookie_names = []
            for prm in params:
                if not isinstance(prm, dict):
                    continue
                name = prm.get("name")
                where = prm.get("in")
                if not name:
                    continue
                val = _example(prm.get("schema") or prm, doc)
                if where == "query":
                    query[name] = val
                elif where == "path":
                    path_vals[name] = val
                elif where == "header":
                    header_names.append(name)
                elif where == "cookie":
                    cookie_names.append(name)
            url_path = path
            for name, val in path_vals.items():
                url_path = url_path.replace("{%s}" % name, str(val))
            url = _join(base, url_path)
            if query:
                from urllib.parse import urlencode
                url = url + "?" + urlencode(query)
            for p in xf_points.points_from_url(url, only_params or None):
                add(p)
            # each {placeholder} path segment is its own injection point
            segs = url_path.split("/")
            tmpl_segs = path.split("/")
            for i, seg in enumerate(tmpl_segs):
                if not seg or "{" not in seg:
                    continue
                tmpl = list(segs)
                tmpl[i] = "{inject}"
                tmpl_url = urlunparse((urlparse(base).scheme, urlparse(base).netloc,
                                       "/".join(tmpl), "", "", ""))
                add(xf_points.Point(label="openapi:path:%s" % seg, method=method.upper(),
                                    url=_join(base, url_path), location="path",
                                    name=seg, template=tmpl_url))
            if header_names:
                for p in xf_points.points_from_headers(url, header_names):
                    add(p)
            if cookie_names:
                for p in xf_points.points_from_cookies(url, cookie_names):
                    add(p)
            body = op.get("requestBody")
            if isinstance(body, dict):
                body = _resolve(doc, body)
                content = body.get("content") or {}
                chosen = None
                for ctype in ("application/json", "application/*+json"):
                    if ctype in content:
                        chosen = content[ctype]
                        break
                if chosen is None and content:
                    chosen = list(content.values())[0]
                if chosen:
                    ex = _example((chosen or {}).get("schema") or {}, doc)
                    try:
                        data = json.dumps(ex)
                    except Exception:
                        data = "{}"
                    for p in xf_points.points_from_data(url, data, method.upper(),
                                                        only_params or None):
                        p.label = "openapi:" + p.label
                        add(p)
            elif isinstance(op.get("parameters"), list):
                # Swagger 2 body parameter
                for prm in op.get("parameters"):
                    prm = _resolve(doc, prm)
                    if isinstance(prm, dict) and prm.get("in") == "body":
                        ex = _example(prm.get("schema") or {}, doc)
                        try:
                            data = json.dumps(ex)
                        except Exception:
                            data = "{}"
                        for p in xf_points.points_from_data(url, data, method.upper(),
                                                            only_params or None):
                            p.label = "openapi:" + p.label
                            add(p)
    return pts
