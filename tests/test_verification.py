"""Unit tests for explicit verification states and NOT_VERIFIED behaviour."""
import concurrent.futures
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import payloads as P
import xf_browser
import xf_dom
import xf_context
import xf_evidence
import xf_points
import xf_report
import xf_verify
import xssforge as X


class FakeResp:
    def __init__(self, body, status=200, url="http://x.test/?q=1"):
        self.text = body
        self.content = body.encode("utf-8")
        self.status_code = status
        self.url = url


class FakeSession:
    def __init__(self, resp):
        self.resp = resp

    def request(self, **kw):
        return self.resp


class FakeFactory:
    def __init__(self, resp):
        self.resp = resp

    def get(self):
        return FakeSession(self.resp)


class FakeLimiter:
    def __init__(self):
        self.local = type("L", (), {"good": 0})()

    def wait(self):
        pass

    def penalize(self):
        pass

    def relax(self):
        pass


class StateTests(unittest.TestCase):
    def test_states_are_explicit(self):
        self.assertEqual(len(set(xf_verify.VERIFIER_STATES)), 6)
        self.assertIn(xf_verify.FINDING_NOT_VERIFIED, xf_verify.FINDING_STATES)

    def test_disabled_and_unavailable_status(self):
        disabled = xf_verify.verifier_status(None)
        self.assertEqual(disabled["state"], xf_verify.VERIFIER_DISABLED)
        unavailable = xf_verify.verifier_status(None, requested=True)
        self.assertEqual(unavailable["state"], xf_verify.VERIFIER_UNAVAILABLE)
        self.assertFalse(unavailable["available"])

    def test_ready_status(self):
        browser = type("B", (), {"available": True, "error": None,
                                 "browser_version": "150.0"})()
        status = xf_verify.verifier_status(browser, requested=True)
        self.assertEqual(status["state"], xf_verify.VERIFIER_READY)
        self.assertEqual(status["browser_version"], "150.0")


class VerifyCallTests(unittest.TestCase):
    def setUp(self):
        self.state = {"browser_verifier": xf_verify.verifier_status(None, requested=True)}

    def test_missing_browser_never_crashes(self):
        opts = X.Options(browser=True)
        vr = X.browser_verify("point", "value", "tok", "", opts, self.state)
        self.assertEqual(vr["state"], xf_verify.VERIFIER_UNAVAILABLE)
        self.assertFalse(vr["hit"])
        self.assertEqual(self.state["browser_verifier"]["counts"]["UNAVAILABLE"], 1)

    def test_disabled_browser(self):
        vr = X.browser_verify("point", "value", "tok", "", X.Options(), self.state)
        self.assertEqual(vr["state"], xf_verify.VERIFIER_DISABLED)

    def test_verifier_exception_becomes_failed(self):
        browser = type("B", (), {
            "available": True, "error": None,
            "verify": lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        })()
        self.state["browser"] = browser
        vr = X.browser_verify("point", "value", "tok", "", X.Options(browser=True), self.state)
        self.assertEqual(vr["state"], xf_verify.VERIFIER_FAILED)
        self.assertIn("boom", vr["detail"])

    def test_concurrent_calls_preserve_counts(self):
        state = {"browser_verifier": xf_verify.verifier_status(None, requested=True)}
        opts = X.Options(browser=True)

        def call(_i):
            return X.browser_verify("point", "value", "tok", "", opts, state)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(call, range(50)))
        self.assertEqual(state["browser_verifier"]["counts"]["UNAVAILABLE"], 50)

    def test_browser_evidence_metadata(self):
        pool = object.__new__(xf_browser.BrowserPool)
        pool.browser_version = "150.0.7871.181"
        pool.automation_version = "4.24.0"
        vr = pool._annotate({"hit": True, "detail": "execution: alert:zqabc"})
        self.assertEqual(vr["state"], xf_verify.VERIFIER_COMPLETED)
        self.assertEqual(vr["evidence"]["type"], "canary-execution")
        self.assertTrue(vr["evidence"]["test_id"].startswith("xf-"))
        self.assertIn("timestamp", vr["evidence"])
        self.assertEqual(vr["evidence"]["browser"], "150.0.7871.181")
        self.assertEqual(vr["evidence"]["automation_version"], "4.24.0")


class FindingStateTests(unittest.TestCase):
    def test_annotate_never_labels_unproven_as_confirmed(self):
        results = [{"candidates": [
            {"status": "CONFIRMED", "confidence": 95, "detail": "raw reflection"},
            {"status": "LIKELY", "confidence": 80},
            {"status": "BLIND"},
        ]}]
        summary = xf_verify.annotate(results, xf_verify.verifier_status(None, requested=True))
        self.assertEqual(results[0]["candidates"][0]["verification"],
                         xf_verify.FINDING_NOT_VERIFIED)
        self.assertEqual(results[0]["candidates"][2]["verification"],
                         xf_verify.FINDING_CALLBACK)
        self.assertGreater(summary[xf_verify.FINDING_NOT_VERIFIED], 0)

    def test_dom_findings_count_in_verification_summary(self):
        results = [{"dom_findings": [{
            "status": "CONFIRMED", "browser_evidence": {"type": "canary-execution"}}]}]
        summary = xf_verify.annotate(results)
        self.assertEqual(summary[xf_verify.FINDING_CONFIRMED], 1)
        self.assertEqual(results[0]["dom_findings"][0]["verification"],
                         xf_verify.FINDING_CONFIRMED)

    def test_unproven_dom_finding_is_not_confirmed(self):
        results = [{"dom_findings": [{"status": "CONFIRMED", "sink": "innerHTML"}]}]
        xf_verify.annotate(results)
        self.assertEqual(results[0]["dom_findings"][0]["verification"],
                         xf_verify.FINDING_NOT_VERIFIED)

    def test_blind_callback_evidence_is_normalized(self):
        results = [{"blind_confirmed": True, "oob_provider": "collaborator",
                    "oob_token": "b123", "blind_hits": [{
                        "time": 1700000000, "method": "GET", "path": "/b123",
                        "client": "1.2.3.4"}]}]
        xf_verify.annotate(results)
        ev = results[0]["callback_evidence"]
        self.assertEqual(ev["type"], "out-of-band-callback")
        self.assertEqual(ev["hit_count"], 1)
        self.assertEqual(ev["hits"][0]["path"], "/b123")
        self.assertTrue(ev["hits"][0]["time"].startswith("2023"))
        self.assertEqual(results[0]["verification"], xf_verify.FINDING_CALLBACK)

    def test_reports_link_repro_url_and_payload(self):
        url = "http://x.test/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        payload = "<script>alert('__M__')</script>"
        results = [{"point": "query:q", "url": url, "method": "GET",
                    "param": "q", "context": "html", "candidates": [{
                        "status": "CONFIRMED", "tier": "V",
                        "verification": xf_verify.FINDING_CONFIRMED,
                        "url": url, "payload": payload,
                        "detail": "execution: alert:zqabc"}],
                    "dom_findings": []}]
        with tempfile.TemporaryDirectory() as d:
            md = os.path.join(d, "r.md")
            html = os.path.join(d, "r.html")
            xf_report.write_markdown(md, "http://x.test/", results, {})
            xf_report.write_html(html, "http://x.test/", results, {})
            with open(html, encoding="utf-8") as f:
                out = f.read()
            self.assertIn('href="%s"' % url, out)
            self.assertIn("&lt;script&gt;alert(&#x27;__M__&#x27;)&lt;/script&gt;", out)
            with open(md, encoding="utf-8") as f:
                out = f.read()
            self.assertIn("[%s](<%s>)" % (url, url), out)
            self.assertIn("`%s`" % payload, out)

    def test_unsafe_url_is_not_linked(self):
        self.assertNotIn("href", xf_report._html_url("javascript:alert(1)"))
        self.assertNotIn("](", xf_report._md_url("javascript:alert(1)"))

    def test_reports_show_blind_callback_evidence(self):
        results = [{"point": "blind", "url": "http://x/?q=1", "method": "GET",
                    "param": "q", "blind_confirmed": True,
                    "oob_provider": "collaborator", "oob_token": "b123",
                    "blind_hits": [{"time": 1700000000, "path": "/b123",
                                    "client": "1.2.3.4"}],
                    "candidates": [], "dom_findings": []}]
        xf_verify.annotate(results)
        with tempfile.TemporaryDirectory() as d:
            md = os.path.join(d, "r.md")
            html = os.path.join(d, "r.html")
            xf_report.write_markdown(md, "http://x/", results, {})
            xf_report.write_html(html, "http://x/", results, {})
            with open(md, encoding="utf-8") as f:
                self.assertIn("b123", f.read())
            with open(html, encoding="utf-8") as f:
                self.assertIn("b123", f.read())

    def test_confirmed_requires_evidence(self):
        results = [{"candidates": [{
            "status": "CONFIRMED", "confidence": 95,
            "browser_evidence": {"type": "canary-execution"},
        }]}]
        xf_verify.annotate(results)
        self.assertEqual(results[0]["candidates"][0]["verification"],
                         xf_verify.FINDING_CONFIRMED)

    def test_confirmed_without_any_proof_is_not_tier_v(self):
        tier, _method, reason = xf_evidence.grade(
            {"location": "query"}, {"status": "CONFIRMED", "confidence": 95})
        self.assertEqual(tier, "A")
        self.assertIn("no browser evidence", reason)

    def test_screenshot_without_browser_evidence_is_not_tier_v(self):
        tier, _method, reason = xf_evidence.grade(
            {"location": "query"}, {"status": "CONFIRMED", "confidence": 95,
                                    "screenshot": "s.png"})
        self.assertEqual(tier, "A")
        self.assertIn("no browser evidence", reason)

    def test_high_confidence_reflection_is_not_tier_v(self):
        tier, _method, _reason = xf_evidence.grade(
            {"location": "query"}, {"status": "LIKELY", "confidence": 95})
        self.assertEqual(tier, "A")


class DomEvidenceTests(unittest.TestCase):
    def test_finding_has_source_to_sink_trace(self):
        js = "// c\nvar x = location.hash; el.innerHTML = x;"
        f = xf_dom._finding("http://x/", "innerHTML", "location.hash", "x", "x", js, js.index("innerHTML"))
        self.assertEqual(f["flow"], "location.hash -> x -> innerHTML")
        self.assertEqual(f["line"], 2)
        self.assertGreaterEqual(f["column"], 1)
        self.assertEqual(f["analysis"], "static-source-to-sink")

    def test_unsupported_source_stays_not_verified(self):
        opts = X.Options(browser=True)
        fake = type("B", (), {"available": True, "error": None})()
        state = {"browser": fake,
                 "browser_verifier": xf_verify.verifier_status(None, requested=True)}
        findings = [{"source": "document.cookie", "sink": "innerHTML"}]
        X.verify_dom_findings(opts, state, findings, "http://x/?q=1")
        self.assertEqual(findings[0]["verification"], xf_verify.FINDING_NOT_VERIFIED)
        self.assertIn("not browser-testable", findings[0]["verification_reason"])


class StoredCleanupTests(unittest.TestCase):
    def test_cleanup_is_explicit_and_recorded(self):
        class Factory:
            def __init__(self):
                self.urls = []

            def get(self, url=None, **kw):
                if url is None:
                    return self
                self.urls.append(url)
                return FakeResp("ok", 200)

        factory = Factory()
        opts = X.Options(stored_cleanup_url="http://x/clear", timeout=2, insecure=True)
        state = {"factory": factory}
        results = [{"notes": [], "cleanup": {"status": "not_configured"}}]
        X._cleanup_stored(opts, state, results)
        self.assertEqual(factory.urls, ["http://x/clear"])
        self.assertEqual(results[0]["cleanup"]["status"], "ok")
        self.assertTrue(any("cleanup" in n for n in results[0]["notes"]))

    def test_no_cleanup_without_operator_url(self):
        results = [{"notes": []}]
        X._cleanup_stored(X.Options(), {"factory": None}, results)
        self.assertNotIn("cleanup", results[0])


class NoBrowserScanTests(unittest.TestCase):
    def test_payload_without_browser_key_is_not_verified(self):
        token = "zq123456"
        body = "<html><body><div>%s</div></body></html>" % token
        opts = X.Options(browser=True, evidence_max=0)
        point = xf_points.Point(label="query:q", method="GET",
                                url="http://x.test/?q=1", location="query",
                                name="q", data={"q": "1"})
        state = {
            "factory": FakeFactory(FakeResp(body)), "limiter": FakeLimiter(),
            "token": token, "bcount": [0], "ecount": [0], "blocked": [0],
            "stop": threading.Event(),
            "browser_verifier": xf_verify.verifier_status(None, requested=True),
        }
        ctx, _ = xf_context.classify(body, token)
        out = X.test_payload(ctx, point, "unit", "<script>alert('__M__')</script>",
                             opts, state)
        self.assertIsNotNone(out)
        entry, confirmed = out
        self.assertFalse(confirmed)
        self.assertNotEqual(entry["status"], "CONFIRMED")
        self.assertEqual(entry["verification"], xf_verify.FINDING_NOT_VERIFIED)
        self.assertIn("unavailable", entry["verification_reason"])
        self.assertNotIn("browser", state)

    def test_canaryized_payload_keeps_token(self):
        self.assertIn("tok", P.canaryize("<script>alert('__M__')</script>", "tok"))


if __name__ == "__main__":
    unittest.main()
