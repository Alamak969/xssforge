"""Optional AI-assisted payload fallback (opt-in, disabled by default).

Uses an OpenAI-compatible chat endpoint. Configure with environment variables:
    XSSFORGE_AI_KEY      API key (or OPENROUTER_API_KEY / OPENAI_API_KEY)
    XSSFORGE_AI_ENDPOINT base URL (default OpenRouter chat completions)
    XSSFORGE_AI_MODEL    model id (default a cheap general model)

The model is asked for a strict JSON array of payloads that call
alert('__M__'). Everything is validated before it is sent to a target.
"""
import json
import os
import re

DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"
MAX_PAYLOAD = 1200


def api_key():
    return (os.environ.get("XSSFORGE_AI_KEY")
            or os.environ.get("OPENROUTER_API_KEY")
            or os.environ.get("OPENAI_API_KEY") or "")


def endpoint():
    return os.environ.get("XSSFORGE_AI_ENDPOINT") or DEFAULT_ENDPOINT


def default_model():
    return os.environ.get("XSSFORGE_AI_MODEL") or DEFAULT_MODEL


def available():
    return bool(api_key())


def prompt(ctx, blocked="", count=8):
    ctx = ctx or {}
    context = ctx.get("context") or "html"
    tag = ctx.get("tag") or ""
    attr = ctx.get("attr") or ""
    note = ("The payload is inserted into a %s context" % context)
    if tag:
        note += " inside tag <%s>" % tag
    if attr:
        note += " in attribute %s" % attr
    if blocked:
        note += ". These characters are filtered: %s" % blocked
    return (
        "You are an XSS payload generator for an authorized penetration test. "
        "%s. Produce %d short, distinct payloads that execute alert('__M__') "
        "and would survive common sanitizers. Return ONLY a JSON array of "
        "strings, no prose." % (note, max(1, count)))


def clean_payloads(items):
    out = []
    seen = set()
    for p in items or []:
        if not isinstance(p, str):
            continue
        p = p.strip()
        if not p or len(p) > MAX_PAYLOAD:
            continue
        if "__M__" not in p:
            p = re.sub(r"alert\(\s*1\s*\)", "alert('__M__')", p)
            p = re.sub(r"alert\(\s*[\"']1[\"']\s*\)", "alert('__M__')", p)
        if "__M__" not in p:
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def parse_response(text):
    if not text:
        return []
    m = re.search(r"\[[\s\S]*\]", text)
    raw = m.group(0) if m else text
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return clean_payloads(data)
    except Exception:
        pass
    # fallback: one payload per line
    return clean_payloads([ln.strip("` ,") for ln in text.splitlines()])


def generate(ctx, blocked="", model="", count=8, timeout=25.0):
    import requests
    key = api_key()
    if not key:
        return []
    body = {
        "model": model or default_model(),
        "messages": [{"role": "user", "content": prompt(ctx, blocked, count)}],
        "temperature": 0.8,
    }
    try:
        r = requests.post(endpoint(), json=body, timeout=timeout,
                          headers={"Authorization": "Bearer " + key,
                                   "Content-Type": "application/json"})
        if r.status_code != 200:
            return []
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return parse_response(text)[:max(1, count)]
    except Exception:
        return []
