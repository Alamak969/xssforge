"""Report writers for xssforge (console/JSON/HTML/Markdown)."""
import base64
import html as _html
import json
import os
import re
import time

import xf_evidence

SEV_COLOR = {"CONFIRMED": "#1a7f37", "LIKELY": "#9a6700", "REFLECTED": "#0969da",
             "NO": "#6e7781", "BLIND": "#8250df"}


def summary(results, meta=None):
    confirmed = [r for r in results if r.get("confirmed")]
    blind = [r for r in results if r.get("blind_confirmed")]
    likely = [r for r in results if r.get("candidates") and not r.get("confirmed")]
    dom = [r for r in results if r.get("dom_findings")]
    return {
        "points": len(results),
        "confirmed": len(confirmed),
        "blind_confirmed": len(blind),
        "likely": len(likely),
        "dom_candidates": sum(len(r.get("dom_findings") or []) for r in results),
        "findings": len(confirmed) + len(blind),
        "tiers": xf_evidence.counts(results),
        "meta": meta or {},
    }


def filter_low_confidence(results, level="low"):
    if level != "high":
        return 0
    dropped = 0
    for r in results:
        kept = []
        for cand in r.get("candidates") or []:
            if cand.get("status") in ("CONFIRMED", "BLIND") or \
                    int(cand.get("confidence") or 0) >= 80:
                kept.append(cand)
            else:
                dropped += 1
        r["candidates"] = kept
    return dropped


def write_json(path, target, results, meta):
    data = {"tool": "xssforge", "target": target, "generated": time.time(),
            "meta": meta, "summary": summary(results, meta), "results": results}
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def write_jsonl(path, target, results, meta):
    """One JSON object per line: a meta record followed by one record/candidate."""
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"type": "meta", "tool": "xssforge", "target": target,
                            "generated": time.time(), "meta": meta,
                            "summary": summary(results, meta)},
                           default=str) + "\n")
        for r in results:
            base = {k: v for k, v in r.items() if k != "candidates"}
            if not (r.get("candidates") or []) and r.get("blind_confirmed"):
                rec = dict(base)
                rec["type"] = "blind"
                rec["tier"] = "V"
                rec["detection_method"] = "oob"
                f.write(json.dumps(rec, default=str) + "\n")
            for cand in r.get("candidates") or []:
                rec = dict(base)
                rec.update(cand)
                rec["type"] = "finding"
                f.write(json.dumps(rec, default=str) + "\n")
            for d in r.get("dom_findings") or []:
                rec = dict(base)
                rec.update(d)
                rec["type"] = "dom"
                f.write(json.dumps(rec, default=str) + "\n")
    return path


def _toml_key(k):
    k = str(k)
    if re.match(r"^[A-Za-z0-9_-]+$", k):
        return k
    return json.dumps(k)


def _toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        if all(isinstance(x, (str, int, float, bool)) for x in v):
            return "[" + ", ".join(_toml_value(x) for x in v) + "]"
        return json.dumps(v, default=str)
    return json.dumps(v, default=str)


def _toml_emit(obj, prefix, lines):
    simple, tables = {}, []
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, dict):
            tables.append(("dict", k, v))
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            tables.append(("array", k, v))
        else:
            simple[k] = v
    for k, v in simple.items():
        lines.append("%s = %s" % (_toml_key(k), _toml_value(v)))
    for kind, k, v in tables:
        name = (_toml_key(k) if not prefix else prefix + "." + _toml_key(k))
        if kind == "dict":
            lines.append("")
            lines.append("[%s]" % name)
            _toml_emit(v, name, lines)
        else:
            for item in v:
                lines.append("")
                lines.append("[[%s]]" % name)
                _toml_emit(item, name, lines)


def write_toml(path, target, results, meta):
    data = {"tool": "xssforge", "target": target, "generated": time.time(),
            "meta": meta, "summary": summary(results, meta), "results": results}
    lines = []
    _toml_emit(data, "", lines)
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def write_sarif(path, target, results, meta):
    """Write SARIF 2.1.0 for GitHub code scanning / CI integration."""
    rules = []
    rule_index = {}
    findings = []
    for r in results:
        for c in (r.get("candidates") or []):
            status = (c.get("status") or "").upper()
            if status not in ("CONFIRMED", "LIKELY", "BLIND"):
                continue
            name = "xss/confirmed" if status == "CONFIRMED" else "xss/likely"
            if name not in rule_index:
                rule_index[name] = len(rules)
                rules.append({
                    "id": name,
                    "name": name.replace("/", "-"),
                    "shortDescription": {"text": "Cross-Site Scripting (%s)" %
                                                  status.title()},
                    "fullDescription": {"text": "Reflected/stored/DOM XSS detected "
                                                "by xssforge with %s evidence" % status},
                    "helpUri": "https://owasp.org/www-community/attacks/xss/",
                    "properties": {"tags": ["security", "xss"],
                                   "security-severity": "9.8" if status == "CONFIRMED" else "6.5"},
                })
            msg = (c.get("detail") or c.get("name") or "XSS candidate")[:200]
            loc = {"physicalLocation": {
                "artifactLocation": {"uri": str(c.get("url") or r.get("url") or target)},
                "region": {"startLine": 1},
            }}
            findings.append({
                "ruleId": name,
                "ruleIndex": rule_index[name],
                "level": "error" if status == "CONFIRMED" else "warning",
                "message": {"text": msg},
                "locations": [loc],
                "properties": {"payload": c.get("payload") or "",
                               "context": c.get("context") or "",
                               "confidence": c.get("confidence") or 0,
                               "tier": c.get("tier") or "",
                               "detection_method": c.get("detection_method") or "",
                               "confidence_reason": c.get("confidence_reason") or ""},
            })
    data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "xssforge",
                "informationUri": "https://github.com/",
                "version": "1.0",
                "rules": rules,
            }},
            "results": findings,
            "properties": {"target": target, "summary": summary(results, meta)},
        }],
    }
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def _candidates(results):
    for r in results:
        for c in r.get("candidates") or []:
            yield r, c


def _shot_tag(shot, base_dir, embed=False):
    if not shot:
        return ""
    link = '<a href="%s">open</a>' % _html.escape(_rel(shot, base_dir))
    if not embed or not os.path.isfile(shot):
        return link
    try:
        with open(shot, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        ext = os.path.splitext(shot)[1].lower().lstrip(".") or "png"
        return ('<a href="%s"><img class="shot" src="data:image/%s;base64,%s" '
                'alt="execution screenshot"></a>') % (
                    _html.escape(_rel(shot, base_dir)),
                    "jpeg" if ext in ("jpg", "jpeg") else ext, data)
    except Exception:
        return link


def _safe_http_url(url):
    u = str(url or "").strip()
    return u if u.lower().startswith(("http://", "https://")) else ""


def _html_url(url, label=None):
    u = _safe_http_url(url)
    text = _html.escape(str(label or u or "-"))
    if not u:
        return text
    return '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (
        _html.escape(u, quote=True), text)


def _md_url(url, label=None):
    u = _safe_http_url(url)
    if not u:
        return "`%s`" % str(label or url or "-")
    text = str(label or u).replace("[", "\\[").replace("]", "\\]")
    return "[%s](<%s>)" % (text, u.replace(">", "%3E"))


def write_html(path, target, results, meta, embed_shots=False):
    s = summary(results, meta)
    base_dir = os.path.dirname(os.path.abspath(path))
    rows = []
    shots = []
    for r, c in _candidates(results):
        status = c.get("status", "LIKELY")
        color = SEV_COLOR.get(status, "#6e7781")
        proof = ""
        if c.get("screenshot"):
            embed = embed_shots and status == "CONFIRMED"
            proof = _shot_tag(c["screenshot"], base_dir, embed)
            shots.append((status, c, _shot_tag(c["screenshot"], base_dir, True)))
        if c.get("evidence"):
            proof += ' <a href="%s">response</a>' % _html.escape(_rel(c["evidence"], base_dir))
        rows.append(
            "<tr><td><span class='tag' style='background:%s'>%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='ctx'>%s</td>"
            "<td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>"
            % (color, _html.escape(status),
               _html.escape(str(c.get("verification") or "-")),
               _html.escape(c.get("tier") or "-"),
                _html.escape(str(r.get("param"))),
                "%s %s" % (_html.escape(str(r.get("method"))),
                           _html_url(c.get("url") or r.get("url"))),
                _html.escape(str(r.get("context"))), _html.escape(str(c.get("payload"))),
               _html.escape(str(c.get("detail") or c.get("notes") or "")), proof))
    blind_rows = []
    for r in results:
        if not r.get("blind_confirmed"):
            continue
        ev = r.get("callback_evidence") or {}
        hits = ev.get("hits") or []
        detail = "; ".join(
            " ".join(str(v) for k, v in sorted(h.items())
                     if k in ("time", "method", "path", "client", "full-id"))
            for h in hits[:5])[:300]
        blind_rows.append(
            "<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td>"
            "<td>%d</td><td><code>%s</code></td></tr>"
            % (_html.escape(str(r.get("param") or "-")),
               _html.escape(str(ev.get("provider") or r.get("oob_provider") or "external")),
               _html.escape(str(ev.get("token") or r.get("oob_token") or "")),
               int(ev.get("hit_count") or len(r.get("blind_hits") or [])),
               _html.escape(detail)))
    dom_rows = []
    for r in results:
        for d in r.get("dom_findings") or []:
            dom_rows.append(
                "<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td>"
                "<td>%s</td><td><code>%s</code></td></tr>"
                % (_html.escape(d.get("sink", "")), _html.escape(d.get("source", "")),
                   _html.escape(d.get("variable", "")), _html_url(d.get("script")),
                   _html.escape(d.get("snippet", ""))))
    waf = ", ".join((meta or {}).get("waf") or []) or "none detected"
    doc = """<!doctype html><html><head><meta charset="utf-8">
<title>xssforge report - %(target)s</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1f2328;background:#fff}
h1{font-size:22px}h2{margin-top:32px;border-bottom:1px solid #d0d7de;padding-bottom:6px}
table{border-collapse:collapse;width:100%%;font-size:13px}
th,td{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f6f8fa}code{font-size:12px;word-break:break-all}
.tag{color:#fff;border-radius:10px;padding:1px 8px;font-size:11px}
.k{display:inline-block;margin-right:24px}.k b{font-size:20px}
.muted{color:#6e7781}
.shot{max-width:320px;max-height:200px;border:1px solid #d0d7de;border-radius:4px;display:block;margin:4px 0}
</style></head><body>
<h1>xssforge report</h1>
<p class="muted">target: %(target)s &middot; generated: %(when)s</p>
<p class="muted">Scope: authorized=%(authorized)s. Only assets you own or have
explicit written permission to test.</p>
<div><span class="k">confirmed <b>%(confirmed)d</b></span>
<span class="k">blind <b>%(blind)d</b></span>
<span class="k">likely <b>%(likely)d</b></span>
<span class="k">points <b>%(points)d</b></span>
<span class="k">DOM candidates <b>%(dom)d</b></span></div>
<p>WAF: <b>%(waf)s</b> &middot; HTTP blocks: <b>%(blocks)d</b>%(blocknote)s</p>
<p>Browser verifier: <b>%(browser_state)s</b>%(browser_reason)s</p>
<p class="muted">Verification states: CONFIRMED requires isolated-browser canary
proof; NOT_VERIFIED means execution was not established. CALLBACK_OBSERVED is
out-of-band evidence only, not browser confirmation.</p>
<h2>Executed / likely findings</h2>
<table><tr><th>Status</th><th>Verification</th><th>Tier</th><th>Param</th><th>Endpoint</th><th>Context</th>
<th>Payload</th><th>Detail</th><th>Proof</th></tr>%(rows)s</table>
<h2>Blind-XSS callbacks</h2>
<table><tr><th>Param</th><th>Provider</th><th>Token</th><th>Hits</th><th>Callback evidence</th></tr>%(blindrows)s</table>
<p class="muted">Callback evidence proves an out-of-band interaction only; it is
never browser-confirmed execution.</p>
<h2>DOM-XSS static candidates</h2>
<table><tr><th>Sink</th><th>Source</th><th>Variable</th><th>Script</th><th>Snippet</th></tr>%(domrows)s</table>
<h2>Execution screenshots</h2>
%(shots)s
<p class="muted">Screenshots are captured by the browser oracle for confirmed
reflected, DOM/fragment and stored executions. Static DOM source-to-sink
findings are code-level only and have no screenshot. Validate every finding
manually before reporting.</p>
</body></html>""" % {
        "target": _html.escape(target), "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "confirmed": s["confirmed"], "blind": s["blind_confirmed"],
        "likely": s["likely"], "points": s["points"], "dom": s["dom_candidates"],
        "waf": _html.escape(waf), "rows": "".join(rows) or "<tr><td colspan=9>none</td></tr>",
        "authorized": _html.escape(str(bool((meta or {}).get("scope", {}).get("authorized")))),
        "browser_state": _html.escape(str((meta or {}).get("browser", {}).get("state") or "DISABLED")),
        "browser_reason": (" — " + _html.escape(str((meta or {}).get("browser", {}).get("reason") or ""))
                           if (meta or {}).get("browser", {}).get("reason") else ""),
        "blocks": int((meta or {}).get("http_blocks") or 0),
        "blocknote": (" — results incomplete (IP/WAF block)" if (meta or {}).get("http_blocks") else ""),
        "blindrows": "".join(blind_rows) or
                     '<tr><td colspan=5>none</td></tr>',
        "domrows": "".join(dom_rows) or "<tr><td colspan=5>none</td></tr>",
        "shots": "".join(
            "<div><b>%s</b> %s <code>%s</code></div>" %
            (_html.escape(st), tag, _html.escape(str(c.get("payload") or "")[:160]))
            for st, c, tag in shots) or '<p class="muted">no browser screenshots</p>',
    }
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


def write_markdown(path, target, results, meta):
    s = summary(results, meta)
    lines = ["# xssforge report", "", "- target: `%s`" % target,
             "- generated: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
             "- scope: authorized=%s — only assets you own or have explicit written permission to test"
             % bool((meta or {}).get("scope", {}).get("authorized")),
             "- confirmed: %d, blind: %d, likely: %d, points: %d"
             % (s["confirmed"], s["blind_confirmed"], s["likely"], s["points"]),
             "- browser verifier: %s%s" % (
                 (meta or {}).get("browser", {}).get("state") or "DISABLED",
                 " — %s" % (meta or {}).get("browser", {}).get("reason")
                 if (meta or {}).get("browser", {}).get("reason") else ""),
             "- verification states: CONFIRMED = isolated-browser canary proof; "
             "NOT_VERIFIED = execution not established; "
             "CALLBACK_OBSERVED = out-of-band evidence only", ""]
    lines += ["## Findings", ""]
    for r, c in _candidates(results):
        lines += ["### %s [%s] `%s` (%s)" % (c.get("status"), c.get("tier") or "-",
                                            r.get("param"), r.get("context")),
                  "", "- endpoint: %s %s" % (
                      r.get("method"), _md_url(c.get("url") or r.get("url"))),
                   "- tier: %s / %s — %s" % (c.get("tier") or "-",
                                             c.get("detection_method") or "-",
                                             c.get("confidence_reason") or "-"),
                   "- verification: %s — %s" % (
                       c.get("verification") or "NOT_VERIFIED",
                       c.get("verification_reason") or "not recorded"),
                   "- payload: `%s`" % c.get("payload"), ""]
        if c.get("detail"):
            lines += ["- detail: %s" % c["detail"]]
        if c.get("browser_evidence"):
            lines += ["- browser evidence: `%s`" %
                      json.dumps(c["browser_evidence"], default=str)]
        if c.get("curl"):
            lines += ["", "```bash", c["curl"], "```"]
        if c.get("screenshot"):
            lines += ["- screenshot: `%(path)s`" % {"path": c["screenshot"]},
                      "![screenshot](%s)" % _rel(c["screenshot"], os.path.dirname(os.path.abspath(path)))]
        lines.append("")
    blind = [r for r in results if r.get("blind_confirmed")]
    if blind:
        lines += ["## Blind-XSS callbacks", ""]
        for r in blind:
            ev = r.get("callback_evidence") or {}
            lines += ["### `%s` (%s)" % (r.get("param") or "-",
                                         ev.get("provider") or r.get("oob_provider") or "external"),
                      "", "- endpoint: %s %s" % (
                          r.get("method"), _md_url(r.get("url"))),
                      "- token: `%s`, hits: %d" % (
                          ev.get("token") or r.get("oob_token") or "",
                          int(ev.get("hit_count") or len(r.get("blind_hits") or []))),
                      "- note: callbacks are out-of-band evidence, not browser-confirmed execution",
                      ""]
            for h in (ev.get("hits") or [])[:10]:
                lines += ["  - `%s`" % json.dumps(h, default=str)]
            lines.append("")
    dom = [(r, d) for r in results for d in (r.get("dom_findings") or [])]
    if dom:
        lines += ["## DOM-XSS static candidates", ""]
        for r, d in dom:
            lines += ["- `%s` from `%s` in %s" % (
                d.get("sink"), d.get("source"), _md_url(d.get("script"))),
                      "  - `%s`" % d.get("snippet", "")[:200]]
        lines.append("")
    _ensure(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def _rel(target, base_dir):
    try:
        return os.path.relpath(os.path.abspath(target), base_dir)
    except Exception:
        return target


def _ensure(path):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
