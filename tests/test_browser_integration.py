"""Local-lab browser-oracle integration tests.

These tests start the bundled deliberately-vulnerable lab on an ephemeral
loopback port. They are skipped when selenium/chromium/chromedriver are not
available; they never contact third-party systems.
"""
import glob
import importlib.metadata
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import quote
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import xf_browser
import xf_dom
import xf_points
import xf_verify
import xssforge as X

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")


def browser_deps():
    missing = []
    try:
        importlib.metadata.version("selenium")
    except Exception:
        missing.append("selenium")
    if not shutil.which("chromedriver"):
        missing.append("chromedriver")
    if not any(shutil.which(b) for b in BROWSERS):
        missing.append("chromium/chrome")
    return missing


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BrowserIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = browser_deps()
        if missing:
            raise unittest.SkipTest("browser deps missing: %s" % ", ".join(missing))
        cls.port = free_port()
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "lab.py"), str(cls.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            try:
                urlopen(cls.base + "/", timeout=0.5).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            cls.proc.terminate()
            raise unittest.SkipTest("local lab did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()

    def setUp(self):
        opts = X.Options(browser=True, timeout=8, browser_wait=1.0,
                         insecure=True, browser_pool=1)
        self.pool = xf_browser.BrowserPool(opts, 1)
        if not self.pool.available:
            self.skipTest("browser pool unavailable: %s" % self.pool.error)
        self.addCleanup(self.pool.close)

    def point(self, route, value):
        url = "%s%s?q=%s" % (self.base, route, quote(value, safe=""))
        return xf_points.Point(label="query:q", method="GET", url=url,
                               location="query", name="q", data={"q": value})

    def verify(self, route, value, token):
        return self.pool.verify(self.point(route, value), value, token, "")

    def test_benchmark_dataset_matches_lab(self):
        with open(os.path.join(ROOT, "benchmark", "cases.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["version"], 1)
        self.assertTrue(data["cases"])
        for case in data["cases"]:
            for key in ("id", "route", "param", "context", "expected", "rationale"):
                self.assertIn(key, case)
            self.assertIn(case["expected"], xf_verify.FINDING_STATES)
            token = "zq" + secrets.token_hex(4)
            url = "%s%s?%s=%s" % (self.base, case["route"], case["param"], token)
            body = urlopen(url, timeout=3).read().decode("utf-8", "replace")
            self.assertIn(token, body, case["id"])

    def test_known_executing_reflected_fixture(self):
        token = "zq" + secrets.token_hex(6)
        payload = "<script>alert('%s')</script>" % token
        vr = self.verify("/reflected", payload, token)
        self.assertTrue(vr["hit"], vr.get("detail"))
        self.assertEqual(vr["state"], xf_verify.VERIFIER_COMPLETED)
        self.assertEqual(vr["evidence"]["type"], "canary-execution")
        self.assertTrue(vr["evidence"]["test_id"].startswith("xf-"))
        self.assertTrue(vr["evidence"]["browser"])

    def test_known_executing_onfocus_fixture(self):
        token = "zq" + secrets.token_hex(6)
        payload = "\" autofocus onfocus=alert('%s') x=\"" % token
        vr = self.verify("/attr", payload, token)
        self.assertTrue(vr["hit"], vr.get("detail"))
        entry = X.set_verification({}, vr)
        self.assertEqual(entry["verification"], xf_verify.FINDING_CONFIRMED)

    def test_dom_hash_source_to_sink_is_confirmed(self):
        url = self.base + "/domhash"
        html = urlopen(url, timeout=3).read().decode("utf-8", "replace")
        findings = xf_dom.analyze_page(html, url, lambda u: "")
        self.assertTrue(any(f.get("sink") == "innerHTML" and
                            f.get("source") == "location.hash" for f in findings))
        state = {"browser": self.pool,
                 "browser_verifier": xf_verify.verifier_status(self.pool, requested=True),
                 "bcount": [0]}
        X.verify_dom_findings(X.Options(browser=True, timeout=8, browser_wait=1.0,
                                        insecure=True), state, findings, url)
        dom = next(f for f in findings if f.get("sink") == "innerHTML")
        self.assertEqual(dom["verification"], xf_verify.FINDING_CONFIRMED)
        self.assertIn("flow", dom)
        self.assertTrue(dom["browser_evidence"]["test_id"].startswith("xf-"))

    def test_cli_dom_scan_confirms_hash_sink(self):
        out = tempfile.mkdtemp()
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "xssforge.py"),
             "-u", self.base + "/domhash", "--authorized", "--browser", "--dom",
             "--quiet", "--output-dir", out],
            capture_output=True, text=True, timeout=120)
        reports = sorted(glob.glob(os.path.join(out, "report-*.json")))
        self.assertTrue(reports, proc.stdout + proc.stderr)
        with open(reports[-1], encoding="utf-8") as f:
            data = json.load(f)
        findings = [d for r in data["results"] for d in r.get("dom_findings") or []]
        self.assertTrue(any(d.get("source") == "location.hash" and
                            d.get("verification") == xf_verify.FINDING_CONFIRMED
                            and d.get("browser_evidence") for d in findings),
                        proc.stdout + proc.stderr)

    def test_escaped_fixture_is_never_confirmed(self):
        token = "zq" + secrets.token_hex(6)
        vr = self.verify("/escaped", "<script>alert('%s')</script>" % token, token)
        self.assertFalse(vr["hit"], vr.get("detail"))
        entry = X.set_verification({}, vr)
        self.assertEqual(entry["verification"], xf_verify.FINDING_NOT_VERIFIED)

    def test_plain_text_fixture_is_never_confirmed(self):
        token = "zq" + secrets.token_hex(6)
        vr = self.verify("/plain", "<script>alert('%s')</script>" % token, token)
        self.assertFalse(vr["hit"], vr.get("detail"))
        entry = X.set_verification({}, vr)
        self.assertEqual(entry["verification"], xf_verify.FINDING_NOT_VERIFIED)


if __name__ == "__main__":
    unittest.main()
