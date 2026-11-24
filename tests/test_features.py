"""Offline tests for 2026 feature additions (AST, grading, GraphQL/XML,
gadgets, session loss, AI parsing, JSONL/TOML)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import payloads as P
import xf_ai
import xf_ast
import xf_dom
import xf_evidence
import xf_gadget
import xf_hunt
import xf_points
import xf_report
import xf_session
import xf_waf


class Opt:
    timeout = 5.0
    insecure = True


class AstTests(unittest.TestCase):
    def test_class_this_flow(self):
        js = "class A { c(){ this.x = location.hash; document.body.innerHTML = this.x; } }"
        found = xf_ast.analyze(js, "inline.js")
        self.assertTrue(any(f["sink"] == "innerHTML" and f["source"] == "location.hash"
                            for f in found), found)

    def test_getter_flow(self):
        js = "class A { get y(){ return document.referrer; } } el.innerHTML = this.y;"
        found = xf_ast.analyze(js, "inline.js")
        self.assertTrue(any(f["source"] == "document.referrer" for f in found), found)

    def test_param_default_flow(self):
        js = "function f(p = location.search){ el.innerHTML = p; }"
        found = xf_ast.analyze(js, "inline.js")
        self.assertTrue(any(f["sink"] == "innerHTML" for f in found), found)

    def test_destructuring_flow(self):
        js = "const {hash} = location; document.write(hash);"
        found = xf_ast.analyze(js, "inline.js")
        self.assertTrue(any(f["sink"] == "document.write" for f in found), found)

    def test_jquery_attr_and_currentscript(self):
        js = ("jQuery('#a').attr('href', location.hash);"
              "var s = document.currentScript.src; q.src = s;")
        found = xf_ast.analyze(js, "inline.js")
        sinks = {f["sink"] for f in found}
        self.assertIn("jQuery.attr", sinks)
        self.assertIn("script.src", sinks)

    def test_comment_and_string_not_sources(self):
        js = "// location.hash\neval('location.hash'); el.innerHTML = 'location.search';"
        found = xf_ast.analyze(js, "inline.js")
        self.assertFalse(found, found)

    def test_template_literal_sink(self):
        js = "el.innerHTML = `<p>${location.hash}</p>`;"
        found = xf_ast.analyze(js, "inline.js")
        self.assertTrue(any(f["sink"] == "innerHTML" and f["source"] == "location.hash"
                            for f in found), found)

    def test_regex_literal_not_code(self):
        js = "var re = /location.hash/; el.innerHTML = re;"
        found = xf_ast.analyze(js, "inline.js")
        self.assertFalse(found, found)

    def test_dom_module_uses_ast_engine(self):
        html = "<script>const {hash} = location; document.write(hash);</script>"
        found = xf_dom.analyze_page(html, "https://x/", lambda u: "")
        self.assertTrue(any(f.get("engine") == "ast" for f in found), found)


class PointTests(unittest.TestCase):
    def test_graphql_variables(self):
        body = json.dumps({"query": "query($q:String){x(q:$q)}",
                           "variables": {"q": "hi", "n": {"z": "deep"}}})
        pts = xf_points.points_from_data("https://x/api", body, "POST",
                                         content_type="application/json")
        self.assertTrue(pts)
        self.assertTrue(all(p.location == "graphql" for p in pts))
        self.assertEqual(pts[0].path, ("variables", "q"))
        kwargs, _ = xf_points.build_request(pts[0], "<svg onload=x>", Opt)
        self.assertEqual(kwargs["json"]["variables"]["q"], "<svg onload=x>")

    def test_xml_text_and_attr(self):
        xml = '<?xml version="1.0"?><r a="v"><q>hello</q></r>'
        pts = xf_points.points_from_data("https://x/soap", xml, "POST",
                                         content_type="text/xml")
        self.assertTrue(any(p.name == "text" for p in pts))
        self.assertTrue(any(p.name.startswith("attr:") for p in pts))
        text_pt = [p for p in pts if p.name == "text"][0]
        kwargs, _ = xf_points.build_request(text_pt, "<pwn>", Opt)
        self.assertIn("<q><pwn></q>", kwargs["data"])
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/xml")

    def test_plain_form_unchanged(self):
        pts = xf_points.points_from_data("https://x/", "a=1&b=2", "POST")
        self.assertTrue(all(p.location == "form" for p in pts))


class EvidenceTests(unittest.TestCase):
    def result(self, **kw):
        base = {"location": "query", "candidates": []}
        base.update(kw)
        return base

    def test_tiers(self):
        results = [
            self.result(candidates=[{"status": "CONFIRMED", "confidence": 95,
                                     "screenshot": "s.png", "name": "x"}]),
            self.result(location="libscan",
                        candidates=[{"status": "LIKELY", "confidence": 70, "name": "lib"}]),
            self.result(candidates=[{"status": "REFLECTED", "confidence": 45,
                                     "name": "x"}]),
        ]
        xf_evidence.annotate(results)
        tiers = [c["tier"] for r in results for c in r["candidates"]]
        self.assertEqual(tiers, ["V", "A", "R"])
        methods = [c["detection_method"] for r in results for c in r["candidates"]]
        self.assertEqual(methods, ["browser", "library", "reflection"])

    def test_blind_graded_without_candidates(self):
        results = [{"location": "query", "candidates": [], "blind_confirmed": True}]
        xf_evidence.annotate(results)
        self.assertEqual(results[0]["tier"], "V")
        self.assertEqual(results[0]["detection_method"], "oob")

    def test_only_poc(self):
        results = [self.result(candidates=[
            {"status": "CONFIRMED", "confidence": 95, "name": "v"},
            {"status": "REFLECTED", "confidence": 45, "name": "r"}])]
        xf_evidence.annotate(results)
        self.assertEqual(xf_evidence.only_poc(results), 1)
        self.assertEqual(len(results[0]["candidates"]), 1)


class WafTests(unittest.TestCase):
    def test_confident_header_signature(self):
        fp = xf_waf.fingerprint({"cf-ray": "1"}, "", 200)
        self.assertEqual(fp["waf"], ["Cloudflare"])
        self.assertGreaterEqual(fp["confidence"], 80)

    def test_body_only_lower_confidence(self):
        fp = xf_waf.fingerprint({}, "cloudflare", 200)
        self.assertLess(fp["confidence"], 80)

    def test_no_signature(self):
        self.assertEqual(xf_waf.fingerprint({}, "hello", 200)["confidence"], 0)

    def test_google_word_is_not_a_waf(self):
        fp = xf_waf.fingerprint({}, "google analytics google fonts", 200)
        self.assertNotIn("Google Cloud Armor", fp["waf"])
        self.assertEqual(fp["confidence"], 0)

    def test_normal_page_words_are_not_a_challenge(self):
        body = ('<html><head><title>loader</title></head><body>please wait, '
                'this page has a challenge and a captcha; '
                'window.location.reload()</body></html>')
        self.assertFalse(xf_waf.is_challenge(body, 200))
        fp = xf_waf.fingerprint({}, body, 200)
        self.assertFalse(fp["challenge"])
        self.assertFalse(fp["blocked"])

    def test_real_interstitial_is_a_challenge(self):
        body = ('<html><head><title>Just a moment...</title></head><body>'
                'Checking your browser before accessing the site. '
                'Enable JavaScript and cookies to continue.</body></html>')
        self.assertTrue(xf_waf.is_challenge(body, 200))
        self.assertTrue(xf_waf.fingerprint({}, body, 200)["challenge"])

    def test_cloud_armor_header_is_a_waf(self):
        fp = xf_waf.fingerprint({"x-goog-cloud-armor": "1"}, "", 200)
        self.assertIn("Google Cloud Armor", fp["waf"])

    def _blocked(self, body, status=200):
        import xssforge
        return xssforge._looks_blocked(
            type("R", (), {"text": body, "status_code": status})())

    def test_captcha_menu_link_is_not_a_block(self):
        body = ('<nav><a href="/vulnerabilities/captcha/">Insecure CAPTCHA'
                '</a></nav><pre>Hello world</pre>')
        self.assertFalse(self._blocked(body))

    def test_captcha_challenge_phrase_is_a_block(self):
        body = "Please solve the captcha to continue."
        self.assertTrue(self._blocked(body))

    def test_403_status_is_a_block(self):
        self.assertTrue(self._blocked("nope", 403))

    def test_quote_mangling_is_detected(self):
        import xssforge
        self.assertTrue(xssforge._quote_mangled(
            "<svg onload=alert(\\'zqabc1234\\')>", "zqabc1234"))
        self.assertTrue(xssforge._quote_mangled(
            "alert(&#39;zqabc1234&#39;)", "zqabc1234"))
        self.assertFalse(xssforge._quote_mangled(
            "alert('zqabc1234')", "zqabc1234"))


class FilterProfileTests(unittest.TestCase):
    class Resp:
        def __init__(self, body, status=200):
            self.text = body
            self.status_code = status
            self.headers = {}

    class Session:
        def __init__(self, body):
            self.body = body
        def request(self, **kw):
            return FilterProfileTests.Resp(self.body)

    class Factory:
        def __init__(self, body):
            self.body = body
        def get(self):
            return FilterProfileTests.Session(self.body)

    def profile(self, body):
        import xf_filter, xf_points
        opts = Opt()
        pt = xf_points.Point(label="q", method="GET",
                             url="https://x/?q=1", location="query",
                             name="q", data={"q": "1"})
        wait = type("L", (), {"wait": lambda self: None,
                              "penalize": lambda self: None})()
        return xf_filter.probe_points(opts, self.Factory(body), wait, [pt], {},
                                      max_points=1, max_probes=4)

    def test_login_page_marks_auth_required(self):
        prof = self.profile('<form action="/login"><input type="password"></form>')
        self.assertTrue(prof["auth_required"])
        self.assertIn("authenticated session", prof["verdict"])

    def test_header_login_widget_does_not_mark_auth_required(self):
        prof = self.profile(
            '<html><nav><input type="password" name="login"></nav>'
            '<pre>hello</pre></html>')
        self.assertFalse(prof["auth_required"])

    def test_normal_page_does_not_mark_challenge(self):
        prof = self.profile('<title>loader</title> please wait challenge captcha q')
        self.assertFalse(prof["waf_challenge"])

    def test_challenge_page_marks_waf_challenge(self):
        import xf_filter
        body = ("Just a moment... enable javascript and cookies to continue " +
                " ".join(tok for _, tok in xf_filter.PROBES))
        prof = self.profile(body)
        self.assertTrue(prof["waf_challenge"])
        self.assertIn("challenge", prof["verdict"])


class GadgetTests(unittest.TestCase):
    def test_version_gate(self):
        old = xf_gadget.gadgets_for("<html>jquery ng-app angular</html>",
                                    {"jQuery": "3.4.0", "AngularJS": "1.7.7"})
        names = {n.split(":")[1] for n, _ in old}
        self.assertIn("jquery-html-script", names)
        self.assertIn("angularjs-sandbox-escape", names)
        new = xf_gadget.gadgets_for("<html>jquery</html>", {"jQuery": "3.7.1"})
        self.assertFalse(any("jquery-html-script" in n for n, _ in new))

    def test_need_gate(self):
        out = xf_gadget.gadgets_for("<html>nothing here</html>",
                                    {"AngularJS": "1.6.0"})
        self.assertFalse(any("angularjs" in n for n, _ in out))


class FilterProbeOrderTests(unittest.TestCase):
    def test_critical_probes_survive_small_probe_budget(self):
        import xf_filter, xf_points
        class Opt:
            timeout = 5
            insecure = True
            url = "https://x/?q=1"
        class Resp:
            text = "<html>q</html>"
            status_code = 200
            headers = {}
        class Sess:
            def request(self, **kw): return Resp()
        class Factory:
            def get(self): return Sess()
        class L:
            def wait(self): pass
            def penalize(self): pass
        pt = xf_points.Point(label="q", method="GET", url="https://x/?q=1",
                             location="query", name="q", data={"q": "1"})
        prof = xf_filter.probe_points(Opt(), Factory(), L(), [pt], {},
                                      max_points=1, max_probes=6)
        names = {n for n, _ in (xf_filter.PROBES[:6])}
        self.assertIn("tag-script", prof["probes"][0] if False else
                      {p[0] for p in prof["points"][0]["probes"]})


class CrawlerTests(unittest.TestCase):
    def test_logout_link_is_not_crawled(self):
        import xf_crawl
        class Opt:
            url = "http://x/"
            crawl_subdomains = False
        c = xf_crawl.Crawler(None, Opt())
        c._add_url("http://x/page.php?q=1")
        c._add_url("http://x/logout.php")
        c._add_url("http://x/index.php?action=logout")
        self.assertEqual(c.urls, ["http://x/page.php?q=1"])


class CookieSweepTests(unittest.TestCase):
    def test_session_cookies_are_not_swept(self):
        import xf_inject
        class Opt:
            cookie = "PHPSESSID=abc; theme=dark"
            cookie_file = ""
            inject_cookies = ["JSESSIONID", "X-Custom"]
        names = xf_inject.sweep_cookies(Opt())
        self.assertNotIn("PHPSESSID", names)
        self.assertNotIn("JSESSIONID", names)
        self.assertIn("theme", names)
        self.assertIn("X-Custom", names)


class CsrfRefreshTests(unittest.TestCase):
    def test_dvwa_user_token_is_refreshed(self):
        import xssforge
        class Resp:
            text = '<form><input type="hidden" name="user_token" value="ABC123"></form>'
            cookies = []
        class Sess:
            def get(self, *a, **k): return Resp()
        class Factory:
            def get(self): return Sess()
        class Opt:
            timeout = 5
            insecure = True
        import xf_points
        pt = xf_points.Point(label="x", method="POST", url="http://x/",
                             location="form", name="name",
                             data={"txtName": "x", "user_token": "OLD"})
        xssforge._refresh_csrf_for_point(pt, "http://x/", Opt(), {"factory": Factory()})
        self.assertEqual(pt.data["user_token"], "ABC123")


class CookieFileTests(unittest.TestCase):
    def test_ip_domain_cookies_are_normalised(self):
        import os, tempfile, requests, xssforge
        d = tempfile.mkdtemp()
        path = os.path.join(d, "cookies.txt")
        with open(path, "w") as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("127.0.0.1\tFALSE\t/\tFALSE\t0\tPHPSESSID\tabc123\n")
        sess = requests.Session()
        xssforge._load_netscape_into(sess, path)
        self.assertTrue(any(c.domain == ".127.0.0.1" for c in sess.cookies))


class HuntPlanTests(unittest.TestCase):
    def test_signals_and_priorities(self):
        html = (
            '<script>DOMPurify v3.1.2</script>'
            '<script>addEventListener("message", function(e){'
            ' if(e.origin.includes("trusted")) x.innerHTML=e.data.html; });</script>'
            '<form enctype="multipart/form-data"><input type="file" name="f"></form>'
            '<a href="/oauth?redirect_uri=x">oauth</a>'
            '<div dangerouslySetInnerHTML={{__html:data}}></div>'
        )
        facts = xf_hunt.analyze(html, {"Content-Security-Policy": "default-src 'self'"},
                                [], "https://x/")
        sig = facts["signals"]
        self.assertTrue(sig["dompurify_outdated"])
        self.assertGreaterEqual(sig["postmessage_handlers"], 1)
        self.assertTrue(sig["upload"])
        self.assertIn("redirect_uri", sig["oauth_params"])
        names = {t["name"] for t in facts["targets"]}
        self.assertTrue({"dompurify-mxss", "postmessage", "oauth-reflection",
                         "stored-upload"} <= names)
        self.assertIn("HUNT PLAN", xf_hunt.format_report(facts))

    def test_clean_page_has_generic_target(self):
        facts = xf_hunt.analyze("<html><body>hello</body></html>", {}, [], "https://x/")
        self.assertEqual([t["name"] for t in facts["targets"]], ["generic-reflected"])


class SendRetryTests(unittest.TestCase):
    def test_transient_errors_are_retried(self):
        import requests, xf_points, xssforge
        class Resp:
            content = b"<html>ok</html>"
            status_code = 200
            text = "<html>ok</html>"
            headers = {}
        class Session:
            def __init__(self, fail):
                self.fail = fail
                self.calls = 0
            def request(self, **kw):
                self.calls += 1
                if self.calls <= self.fail:
                    raise requests.ConnectionError("connection reset by peer")
                return Resp()
        class Factory:
            def __init__(self, fail): self.s = Session(fail)
            def get(self): return self.s
        class Limiter:
            local = type("L", (), {"good": 0})()
            def wait(self): pass
            def penalize(self): pass
            def relax(self): pass
        opts = xssforge.Options()
        opts.retries = 3
        opts.timeout = 5
        opts.follow = True
        factory = Factory(2)
        pt = xf_points.Point(label="q", method="GET", url="https://x/?q=1",
                             location="query", name="q", data={"q": "1"})
        r = xssforge.send(factory, Limiter(), pt, "1", opts)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(factory.s.calls, 3)


class BrowserProofTests(unittest.TestCase):
    def test_alert_log_is_proof(self):
        import xf_browser
        self.assertEqual(xf_browser._exec_logs(["alert:zq123"], "zq123"),
                         ["alert:zq123"])

    def test_reference_error_is_not_proof(self):
        import xf_browser
        logs = ["error:Uncaught ReferenceError: zq123 is not defined"]
        self.assertFalse(xf_browser._exec_logs(logs, "zq123"))

    def test_dvwa_captcha_word_is_not_a_block(self):
        import xf_browser
        class Driver:
            title = "Damn Vulnerable Web Application"
            current_url = "http://127.0.0.1/DVWA/vulnerabilities/xss_r/"
            def execute_script(self, script):
                return "XSS Reflected ... CAPTCHA ..."
            def find_elements(self, *a, **k):
                return []
        self.assertIsNone(xf_browser._block_reason(Driver()))

    def test_analytics_echo_is_not_proof(self):
        import xf_browser
        logs = ["fetch:https://www.google-analytics.com/g/collect?zq123"]
        self.assertFalse(xf_browser._exec_logs(logs, "zq123"))


class SessionTests(unittest.TestCase):
    def test_login_reappeared(self):
        before = {"status": 200, "authed": True, "login": False}
        after = {"status": 200, "authed": False, "login": True}
        self.assertTrue(xf_session.detect_loss(before, after))

    def test_stable_session(self):
        fp = {"status": 200, "authed": True, "login": False}
        self.assertFalse(xf_session.detect_loss(fp, dict(fp)))

    def test_401_loss(self):
        self.assertTrue(xf_session.detect_loss(
            {"status": 200}, {"status": 401}))

    def test_watch_thread_stops_cleanly(self):
        holder = {"session": {"lost": False, "reason": ""}}
        w = xf_session.SessionWatch(None, "http://x/", holder, Opt, interval=999)
        w.stop()
        w.start()
        w.join(2)
        self.assertFalse(w.is_alive())


class AiTests(unittest.TestCase):
    def test_parse_and_normalize(self):
        out = xf_ai.parse_response(
            '["<svg onload=alert(1)>", "nope", "<img src=x onerror=alert(\'__M__\')>"]')
        self.assertTrue(all("__M__" in p for p in out))
        self.assertEqual(len(out), 2)

    def test_prompt_mentions_context(self):
        p = xf_ai.prompt({"context": "attr_dq", "tag": "a", "attr": "href"}, "'")
        self.assertIn("attr_dq", p)
        self.assertIn("<a>", p)
        self.assertIn("__M__", p)


class OutputTests(unittest.TestCase):
    def sample(self):
        return [{"location": "query", "param": "q",
                 "candidates": [{"status": "CONFIRMED", "confidence": 95,
                                 "tier": "V", "detection_method": "browser",
                                 "name": "x", "payload": "<svg>"}],
                 "dom_findings": []}]

    def test_jsonl(self):
        d = tempfile.mkdtemp()
        path = xf_report.write_jsonl(os.path.join(d, "r.jsonl"), "t",
                                     self.sample(), {"a": 1})
        with open(path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f]
        self.assertEqual(lines[0]["type"], "meta")
        self.assertEqual(lines[1]["type"], "finding")

    def test_toml(self):
        try:
            import tomllib
        except Exception:
            self.skipTest("tomllib unavailable")
        d = tempfile.mkdtemp()
        path = xf_report.write_toml(os.path.join(d, "r.toml"), "t",
                                    self.sample(), {"m": {"x": [1, 2]}})
        with open(path, "rb") as f:
            data = tomllib.load(f)
        self.assertEqual(data["target"], "t")
        self.assertEqual(data["meta"]["m"]["x"], [1, 2])
        self.assertEqual(data["results"][0]["candidates"][0]["tier"], "V")


class GatherTests(unittest.TestCase):
    def test_custom_payloads_survive_corpus_duplicates(self):
        import os, tempfile, xssforge
        d = tempfile.mkdtemp()
        path = os.path.join(d, "mine.txt")
        with open(path, "w") as f:
            f.write("<script>alert('__M__')</script>\n")
        opts = xssforge.Options()
        opts.payload_files = [path]
        opts.payload_limit = 1
        names = [n for n, _ in xssforge.gather_payloads({"context": "html"}, opts)]
        self.assertIn("custom:0", names)

    def test_blocked_chars_maps_matrix_names_to_tokens(self):
        import xf_filter
        self.assertEqual(xf_filter.blocked_chars(
            {"matrix": {"angle-open": "BLOCKED", "space": "REMOVED"}}), {"<", " "})

    def test_gadgets_respect_blocked_chars(self):
        import xssforge
        opts = xssforge.Options()
        opts.libraries = {"jQuery": "3.4.0"}
        opts.filter_profile = {"matrix": {"angle-open": "BLOCKED"}}
        opts.payload_limit = 40
        items = xssforge.gather_payloads({"context": "html"}, opts)
        gadget = [p for n, p in items if n.startswith("gadget:")]
        self.assertFalse(any("<" in p for p in gadget), gadget)


class PayloadFamilyTests(unittest.TestCase):
    def test_new_families_present(self):
        families = P._gen_gap_families()
        names = {n for items in families.values() for n, _ in items}
        for needle in ("gap:jsexec-expr", "gap:upload-svg-script",
                       "gap:clobber-module-export"):
            self.assertIn(needle, names)


if __name__ == "__main__":
    unittest.main()
