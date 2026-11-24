import json
import os
import subprocess
import sys
import time
import urllib.parse

import requests

import xf_waf

LOGIN_MARKERS = ('id="loginform"', 'action="/user/login"',
                 'action="/login"', 'type="password"', 'name="password"')

MASS_FLAGS = {
    "--mass", "--mass-state", "--resume", "--baseline", "--dry-run",
    "--mass-limit",
}


def read_targets(path):
    out = []
    seen = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key = normalize_url(line)
                if key in seen:
                    continue
                seen.add(key)
                out.append(line)
    except Exception as exc:
        raise SystemExit("could not read --mass file: %s" % exc)
    return out


def normalize_url(url):
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(
        parts.query, keep_blank_values=True)))
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/") or "/",
         query, ""))


def load_state(path, resume=False):
    if resume:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                data.setdefault("done", {})
                data.setdefault("results", {})
                return data
        except Exception:
            pass
    return {"done": {}, "results": {}}


def save_state(path, state):
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True, default=str)
    except Exception as exc:
        print("mass: state write failed: %s" % exc, file=sys.stderr)


def baseline(url, opts):
    info = {"status": 0, "length": 0, "waf": [], "blocked": False,
            "session_loss": False}
    try:
        r = requests.get(url, timeout=opts.timeout, verify=not opts.insecure,
                         headers={"User-Agent": opts.user_agent},
                         cookies=dict(parse_cookie(opts.cookie)))
        body = r.text or ""
        fp = xf_waf.fingerprint(dict(r.headers), body, r.status_code)
        info["status"] = r.status_code
        info["length"] = len(body)
        info["waf"] = fp.get("waf") or []
        info["blocked"] = bool(fp.get("blocked") or fp.get("challenge") or
                               xf_waf.is_challenge(body, r.status_code))
        low = body.lower()
        info["session_loss"] = any(m in low for m in LOGIN_MARKERS)
    except Exception as exc:
        info["error"] = str(exc)[:200]
    return info


def parse_cookie(cookie):
    out = {}
    for part in (cookie or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def strip_mass_args(argv):
    out = []
    i = 0
    skip_next = False
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--mass=") or arg.startswith("--mass-state=") or \
                arg.startswith("--mass-limit="):
            i += 1
            continue
        if arg in MASS_FLAGS:
            i += 2 if i + 1 < len(argv) and not argv[i + 1].startswith("-") else 1
            continue
        if arg in ("-u", "--url"):
            i += 2 if i + 1 < len(argv) else 1
            continue
        if arg.startswith("--url="):
            i += 1
            continue
        out.append(arg)
        i += 1
    if "--authorized" not in out:
        out.insert(0, "--authorized")
    return out


def _outdir(base, url):
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "target").replace(".", "_")
    suffix = abs(hash(normalize_url(url))) % 100000
    return os.path.join(base, "%s-%d" % (host, suffix))


def run(opts, argv=None):
    targets = read_targets(opts.mass_file)
    state = load_state(opts.mass_state, opts.mass_resume)
    targets = [t for t in targets if normalize_url(t) not in state["done"]]
    if opts.mass_limit:
        targets = targets[:max(1, opts.mass_limit)]
    print("mass: %d target(s) pending, %d already done" %
          (len(targets), len(state["done"])))
    if opts.mass_dry_run:
        for url in targets:
            print("  " + url)
        return 0
    base_args = strip_mass_args(list(argv if argv is not None else sys.argv[1:]))
    script = os.path.abspath(sys.argv[0])
    outdir_base = os.path.join(opts.output_dir, "mass")
    os.makedirs(outdir_base, exist_ok=True)
    scanned = 0
    skipped = 0
    for url in targets:
        key = normalize_url(url)
        if opts.mass_baseline:
            info = baseline(url, opts)
            state["done"][key] = info
            if info.get("blocked") or info.get("session_loss") or not info.get("status"):
                state["results"][key] = {"skipped": True, "reason": info}
                skipped += 1
                save_state(opts.mass_state, state)
                print("mass: SKIP %s (%s)" % (
                    url, "blocked" if info.get("blocked") else
                    ("session loss" if info.get("session_loss") else "unreachable")))
                continue
        cmd = [sys.executable, script] + base_args + [
            "-u", url, "--output-dir", _outdir(outdir_base, url)]
        print("mass: scan %s" % url)
        try:
            proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
            output = proc.stdout or ""
        except Exception as exc:
            output = str(exc)
            proc = None
        tail = "\n".join(output.strip().splitlines()[-20:])
        print(tail)
        state["done"][key] = {"status": getattr(proc, "returncode", -1),
                              "time": time.time()}
        state["results"][key] = {"url": url, "returncode": getattr(proc, "returncode", -1),
                                 "output_tail": tail}
        scanned += 1
        save_state(opts.mass_state, state)
        if opts.mass_baseline:
            after = baseline(url, opts)
            if after.get("session_loss"):
                state["results"][key]["session_loss"] = True
                save_state(opts.mass_state, state)
                print("mass: session lost after %s — stop mass scan" % url)
                break
    print("mass: done scanned=%d skipped=%d state=%s" %
          (scanned, skipped, opts.mass_state))
    return 0
