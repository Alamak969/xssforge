"""Explicit verification states for findings and the browser oracle.

Finding states describe the evidence behind one candidate:
  REFLECTION        input echoed in the response; no injection evidence
  CANDIDATE         context/payload analysis suggests possible injection
  LIKELY            stronger context evidence, execution not established
  CONFIRMED         harmless canary demonstrably executed in an isolated browser
  CALLBACK_OBSERVED out-of-band callback only; NOT browser-confirmed
  NOT_VERIFIED      verification could not be performed or produced no proof

Browser-oracle states describe the verifier for the whole scan:
  DISABLED, UNAVAILABLE, READY, COMPLETED, TIMED_OUT, FAILED
"""
import time
from datetime import datetime, timezone

FINDING_REFLECTION = "REFLECTION"
FINDING_CANDIDATE = "CANDIDATE"
FINDING_LIKELY = "LIKELY"
FINDING_CONFIRMED = "CONFIRMED"
FINDING_CALLBACK = "CALLBACK_OBSERVED"
FINDING_NOT_VERIFIED = "NOT_VERIFIED"

VERIFIER_DISABLED = "DISABLED"
VERIFIER_UNAVAILABLE = "UNAVAILABLE"
VERIFIER_READY = "READY"
VERIFIER_COMPLETED = "COMPLETED"
VERIFIER_TIMED_OUT = "TIMED_OUT"
VERIFIER_FAILED = "FAILED"

VERIFIER_STATES = (VERIFIER_DISABLED, VERIFIER_UNAVAILABLE, VERIFIER_READY,
                   VERIFIER_COMPLETED, VERIFIER_TIMED_OUT, VERIFIER_FAILED)
FINDING_STATES = (FINDING_REFLECTION, FINDING_CANDIDATE, FINDING_LIKELY,
                  FINDING_CONFIRMED, FINDING_CALLBACK, FINDING_NOT_VERIFIED)


def _now():
    return datetime.now(timezone.utc).isoformat()


def automation_version():
    try:
        from importlib.metadata import version
        return version("selenium")
    except Exception:
        return "unknown"


def verifier_status(browser=None, requested=False):
    """Describe browser-oracle state without requiring selenium to be present."""
    if not requested:
        state, reason = VERIFIER_DISABLED, "--browser was not requested"
    elif browser is None:
        state, reason = VERIFIER_UNAVAILABLE, "browser oracle was not started"
    elif not getattr(browser, "available", False):
        state = VERIFIER_UNAVAILABLE
        reason = str(getattr(browser, "error", None) or "browser oracle unavailable")
    else:
        state, reason = VERIFIER_READY, ""
    return {
        "state": state,
        "reason": reason,
        "available": bool(requested and browser is not None
                          and getattr(browser, "available", False)),
        "automation": "selenium",
        "automation_version": automation_version(),
        "browser_version": getattr(browser, "browser_version", "") or "",
        "requested": bool(requested),
        "counts": {},
        "updated": _now(),
    }


def finding(state, reason="", evidence=None):
    """Return the verification fields attached to a candidate."""
    if state not in FINDING_STATES:
        state = FINDING_NOT_VERIFIED
    out = {"verification": state, "verification_reason": str(reason or "")[:300]}
    if evidence:
        out["browser_evidence"] = dict(evidence)
    return out


def _iso(ts):
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except Exception:
        return ""


def callback_evidence(result):
    """Normalize raw OOB hits into one evidence block for a blind finding.

    Only callback metadata is recorded. It proves an out-of-band interaction,
    never browser-confirmed script execution.
    """
    hits = result.get("blind_hits") or []
    items = []
    for h in hits:
        if not isinstance(h, dict):
            items.append({"raw": str(h)[:240]})
            continue
        item = {}
        when = _iso(h.get("time") or h.get("_seen_at") or h.get("timestamp"))
        if when:
            item["time"] = when
        for key in ("method", "path", "full-id", "unique-id", "client",
                    "remote-ip", "source-ip"):
            if h.get(key):
                item[key] = str(h[key])[:200]
        if not item:
            item["raw"] = str(h)[:240]
        items.append(item)
    return {
        "type": "out-of-band-callback",
        "provider": str(result.get("oob_provider") or "external"),
        "token": str(result.get("oob_token") or ""),
        "observed_at": _now(),
        "hit_count": len(hits),
        "note": "callback proves out-of-band interaction, not browser-confirmed execution",
        "hits": items[:20],
    }


def _default_reason(cand, verifier):
    status = str(cand.get("status") or "").upper()
    if status == "BLIND" or cand.get("blind_confirmed"):
        return ("out-of-band callback observed; browser execution not established"
                if status == "BLIND" else "")
    verifier = verifier or {}
    vstate = verifier.get("state")
    if vstate == VERIFIER_DISABLED:
        return "browser verification disabled (--browser not requested)"
    if vstate == VERIFIER_UNAVAILABLE:
        return "browser verification unavailable: %s" % verifier.get("reason", "")
    if vstate in (VERIFIER_FAILED, VERIFIER_TIMED_OUT):
        return "browser verifier %s: %s" % (vstate.lower(), verifier.get("last_detail", ""))
    return str(cand.get("detail") or "no canary execution observed")[:300]


def annotate(results, verifier=None):
    """Ensure every candidate carries an honest verification state. Idempotent."""
    summary = {s: 0 for s in FINDING_STATES}
    for r in results or []:
        for cand in r.get("candidates") or []:
            status = str(cand.get("status") or "").upper()
            if status == "CONFIRMED" and cand.get("browser_evidence"):
                cand.setdefault("verification", FINDING_CONFIRMED)
                cand.setdefault("verification_reason", "browser canary execution proof")
            elif status == "BLIND":
                cand.setdefault("verification", FINDING_CALLBACK)
                cand.setdefault("verification_reason", _default_reason(cand, verifier))
                cand.setdefault("callback_evidence", callback_evidence(r))
            else:
                cand.setdefault("verification", FINDING_NOT_VERIFIED)
                cand.setdefault("verification_reason", _default_reason(cand, verifier))
            summary[cand["verification"]] = summary.get(cand["verification"], 0) + 1
        for d in r.get("dom_findings") or []:
            if not d.get("browser_evidence"):
                d.setdefault("verification", FINDING_NOT_VERIFIED)
                d.setdefault("verification_reason", _default_reason(d, verifier))
            else:
                d.setdefault("verification", FINDING_CONFIRMED)
                d.setdefault("verification_reason", "browser canary execution proof")
            summary[d["verification"]] = summary.get(d["verification"], 0) + 1
        if r.get("blind_confirmed"):
            r.setdefault("verification", FINDING_CALLBACK)
            r.setdefault("callback_evidence", callback_evidence(r))
    return summary


def summarize(results):
    out = {s: 0 for s in FINDING_STATES}
    for r in results or []:
        for cand in r.get("candidates") or []:
            key = cand.get("verification") or FINDING_NOT_VERIFIED
            out[key] = out.get(key, 0) + 1
    return out


def elapsed(started):
    try:
        return round(max(0.0, time.time() - float(started)), 3)
    except Exception:
        return None
