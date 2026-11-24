"""Evidence grading for findings (Dalfox-style tier + detection method).

Tiers:
  V = verified execution (browser dialog / DOM execution ack)
  A = actionable (strong reflection with executable context, or OOB callback,
      or outdated vulnerable library)
  R = reflection only (echo observed, execution not proven)
  I = informational (static candidate, low confidence)
"""

TIER_RANK = {"V": 3, "A": 2, "R": 1, "I": 0}
TIER_LABEL = {"V": "verified", "A": "actionable", "R": "reflection",
              "I": "informational"}


def detection_method(result, cand):
    status = (cand.get("status") or "").upper()
    loc = (result.get("location") or "").lower()
    name = str(cand.get("name") or "")
    if result.get("blind_confirmed") or status == "BLIND":
        return "oob"
    if loc == "libscan":
        return "library"
    if status == "CONFIRMED":
        if loc in ("fragment", "dom", "stored") or name.startswith(
                ("dom:", "fragment:")):
            return "dom-verification"
        if cand.get("screenshot"):
            return "browser"
        return "browser"
    if "csti" in name or (cand.get("context") or "").lower() == "csti":
        return "csti"
    refl = cand.get("reflection") or {}
    enc = str(refl.get("encoding") or "").lower()
    if name.startswith(("enc:", "firsthit:")) or enc in (
            "encoded", "url", "html", "js", "unicode", "fullwidth"):
        return "encoded-reflection"
    if loc in ("dom", "fragment"):
        return "ast"
    return "reflection"


def grade(result, cand):
    status = (cand.get("status") or "").upper()
    method = detection_method(result, cand)
    conf = int(cand.get("confidence") or 0)
    loc = (result.get("location") or "").lower()
    if status in ("CONFIRMED", "BLIND") or conf >= 90:
        tier = "V"
        reason = ("browser execution confirmed (alert/dialog observed)"
                  if status == "CONFIRMED" else
                  "out-of-band callback confirmed payload execution")
    elif loc == "libscan":
        tier = "A"
        reason = "outdated JS library with a known XSS advisory"
    elif status == "LIKELY" and conf >= 70:
        tier = "A"
        reason = "executable reflection context (unproven browser execution)"
    elif method == "csti":
        tier = "A"
        reason = "client-side template injection candidate"
    elif status in ("LIKELY", "REFLECTED"):
        tier = "R"
        reason = "canary reflected but execution not proven"
    else:
        tier = "I"
        reason = "static/low-confidence candidate"
    return tier, method, reason


def annotate(results):
    """Attach tier/detection_method/confidence_reason to every candidate and
    the best grade to each result. Idempotent."""
    for r in results:
        best = None
        best_rank = -1
        for cand in r.get("candidates") or []:
            tier, method, reason = grade(r, cand)
            cand["tier"] = tier
            cand["detection_method"] = method
            cand["confidence_reason"] = reason
            rank = TIER_RANK.get(tier, 0)
            if rank > best_rank:
                best_rank, best = rank, cand
        if best is not None:
            r["tier"] = best["tier"]
            r["detection_method"] = best["detection_method"]
        elif r.get("blind_confirmed"):
            r["tier"] = "V"
            r["detection_method"] = "oob"
        for d in r.get("dom_findings") or []:
            d.setdefault("tier", "I")
            d.setdefault("detection_method", "ast")
            d.setdefault("confidence_reason", "static source-to-sink dataflow")
    return results


def only_poc(results):
    """Keep only verified/actionable execution evidence (PoC-grade)."""
    dropped = 0
    for r in results:
        kept = []
        for cand in r.get("candidates") or []:
            if cand.get("tier") in ("V", "A"):
                kept.append(cand)
            else:
                dropped += 1
        r["candidates"] = kept
    return dropped


def counts(results):
    out = {"V": 0, "A": 0, "R": 0, "I": 0}
    for r in results:
        for c in r.get("candidates") or []:
            out[c.get("tier", "I")] = out.get(c.get("tier", "I"), 0) + 1
        for _ in r.get("dom_findings") or []:
            out["I"] += 1
    return out
