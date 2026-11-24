"""Mid-scan authentication/session-loss detection.

A scanner that silently loses its session will report "not reflected" for every
point. This module fingerprints the authenticated page and watches it during the
scan; when the login page reappears (or a 401/403 replaces a 200) the scan is
marked unreliable.
"""
import threading
import time

LOGIN_MARKERS = (
    'type="password"', "type='password'", 'name="password"', "name='password'",
    'id="login"', "sign in", "log in", "login form",
)
AUTHED_MARKERS = (
    "logout", "log out", "sign out", "my account", "dashboard", "profile",
    "settings", "welcome back",
)


def fingerprint(status, body, url=""):
    low = (body or "")[:200000].lower()
    return {
        "status": int(status or 0),
        "length": len(body or ""),
        "login": any(m in low for m in LOGIN_MARKERS),
        "authed": any(m in low for m in AUTHED_MARKERS),
        "url": url,
    }


def detect_loss(before, after):
    """Return a human reason if the session appears to have been lost."""
    if not before or not after:
        return ""
    if after.get("status") in (401, 403) and before.get("status") == 200:
        return "HTTP %s (was 200)" % after.get("status")
    if before.get("authed") and not after.get("authed") and after.get("login"):
        return "login form reappeared"
    if before.get("login") is False and after.get("login") and \
            not after.get("authed"):
        return "session redirected to login"
    return ""


class SessionWatch(threading.Thread):
    """Background watchdog sampling the authenticated page during a scan."""

    def __init__(self, factory, url, state, opts, interval=12.0):
        super().__init__(daemon=True)
        self.factory = factory
        self.url = url
        self.state = state
        self.opts = opts
        self.interval = interval
        self.holder = state.setdefault("session", {"lost": False, "reason": ""})
        self._halt = threading.Event()

    def baseline(self):
        try:
            r = self.factory.get().get(self.url, timeout=self.opts.timeout,
                                       verify=not self.opts.insecure)
            self.holder["baseline"] = fingerprint(r.status_code, r.text or "", self.url)
        except Exception as e:
            self.holder["error"] = str(e)[:160]
        return self.holder.get("baseline")

    def sample(self):
        try:
            r = self.factory.get().get(self.url, timeout=self.opts.timeout,
                                       verify=not self.opts.insecure)
            after = fingerprint(r.status_code, r.text or "", self.url)
            reason = detect_loss(self.holder.get("baseline"), after)
            if reason:
                self.holder["lost"] = True
                self.holder["reason"] = reason
                self.holder["after"] = after
            return after
        except Exception:
            return None

    def run(self):
        while not self._halt.wait(self.interval):
            if self.holder.get("lost"):
                return
            self.sample()

    def stop(self):
        self._halt.set()
