import json
import urllib.parse

import requests

import xf_points


def load_json(source, timeout=10.0, insecure=False):
    if not source:
        return None
    try:
        if source.startswith(("http://", "https://")):
            r = requests.get(source, timeout=timeout, verify=not insecure)
            return r.json()
        with open(source, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _header_map(headers):
    out = {}
    if isinstance(headers, dict):
        items = headers.items()
    else:
        items = ((h.get("key", ""), h.get("value", "")) for h in headers or []
                 if isinstance(h, dict))
    for k, v in items:
        if k:
            out[str(k)] = str(v)
    return out


def _body_and_type(request):
    body = request.get("body") or {}
    mode = body.get("mode")
    if mode == "raw":
        return str(body.get("raw") or ""), str(body.get("options", {}).get("raw", {}).get("language") or "")
    if mode == "urlencoded":
        pairs = []
        for item in body.get("urlencoded") or []:
            if isinstance(item, dict) and "key" in item:
                pairs.append((item["key"], item.get("value", "")))
        return urllib.parse.urlencode(pairs), "application/x-www-form-urlencoded"
    if mode == "formdata":
        return "", "multipart/form-data"
    return "", ""


def _request_points(method, url, headers, body, content_type, only_params=None):
    pts = []
    method = (method or "GET").upper()
    if url:
        pts.extend(xf_points.points_from_url(url, only_params))
    if body:
        pts.extend(xf_points.points_from_data(url, body, method, only_params,
                                              content_type))
    meta = {"headers": headers}
    for p in pts:
        p.method = method
        p.meta.update(meta)
        p.label = "import:%s" % p.label
    return pts


def _walk_postman(items, only_params=None):
    pts = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "item" in item:
            pts.extend(_walk_postman(item["item"], only_params))
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        url = request.get("url")
        if isinstance(url, dict):
            url = url.get("raw", "")
        headers = _header_map(request.get("header"))
        body, ctype = _body_and_type(request)
        if body or ctype != "multipart/form-data":
            pts.extend(_request_points(request.get("method"), url or "",
                                       headers, body, ctype, only_params))
    return pts


def postman_points(collection, only_params=None):
    if not isinstance(collection, dict):
        return []
    return _walk_postman(collection.get("item"), only_params)


def _har_request(entry, only_params=None):
    request = entry.get("request") or {}
    url = request.get("url") or ""
    headers = _header_map(request.get("headers"))
    post = request.get("postData") or {}
    body = post.get("text") or ""
    ctype = post.get("mimeType") or ""
    if not body and post.get("params"):
        pairs = [(p.get("name", ""), p.get("value", "")) for p in post["params"]]
        body = urllib.parse.urlencode(pairs)
        ctype = "application/x-www-form-urlencoded"
    return _request_points(request.get("method"), url, headers, body,
                           ctype, only_params)


def har_points(har, only_params=None):
    if not isinstance(har, dict):
        return []
    pts = []
    for entry in (har.get("log") or {}).get("entries") or []:
        if isinstance(entry, dict):
            pts.extend(_har_request(entry, only_params))
    return pts
