"""Offline unit tests for xssforge (no network, no browser required)."""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import payloads as P
import xf_context
import xf_mutate
import xf_openapi
import xf_points


class CorpusTests(unittest.TestCase):
    def test_corpus_size_over_1500(self):
        self.assertGreaterEqual(P.corpus_size(), 1500)

    def test_every_category_has_300(self):
        for cat, items in P.PAYLOADS.items():
            self.assertGreaterEqual(len(items), 300, "category %s has %d" % (cat, len(items)))

    def test_every_payload_has_bypass(self):
        missing = []
        for cat, items in P.PAYLOADS.items():
            for name, payload in items:
                if not P.bypass_variants(payload, limit=1):
                    missing.append((cat, name, payload))
                    if len(missing) >= 5:
                        break
            if len(missing) >= 5:
                break
        self.assertFalse(missing, "no bypass for: %r" % (missing,))

    def test_bypass_preserves_placeholders(self):
        phs = ("__M__", "__B64__", "__B64DOC__", "__FCC__", "__CB__")
        checked = 0
        for cat, items in P.PAYLOADS.items():
            for name, payload in items[:40]:
                for _, got in P.bypass_variants(payload, limit=6):
                    for ph in phs:
                        if ph in payload:
                            self.assertIn(ph, got, (cat, name, ph, got))
                    checked += 1
        self.assertGreater(checked, 0)

    def test_encoder_decoder_breadth(self):
        self.assertGreaterEqual(len(P.ENCODERS), 30)
        self.assertGreaterEqual(len(P.DECODERS), 10)
        enc = P.ENCODERS["url"]("<script>alert('__M__')</script>")
        dec = dict(P.decode_all(enc))
        self.assertIn("<script>", dec.get("url", ""))

    def test_canaryize_keeps_token(self):
        out = P.canaryize("<script>alert('__M__')</script>", "abc123")
        self.assertIn("abc123", out)
        self.assertIn("<script", out)

    def test_canaryize_rewrites_existing_call(self):
        out = P.canaryize("<svg onload=alert(1)>", "tok9")
        self.assertIn("tok9", out)

    def test_encoders_roundtrip_url(self):
        val = P.ENCODERS["url"]("<img src=x onerror=alert('__M__')>")
        self.assertIn("%3C", val)


class ContextTests(unittest.TestCase):
    def test_html_context(self):
        ctx, idx = xf_context.classify("<html><body><div>TOKEN</div></body></html>", "TOKEN")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.get("context"), "html")

    def test_attribute_context(self):
        ctx, _ = xf_context.classify('<input value="TOKEN">', "TOKEN")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.get("context"), "attr_dq")

    def test_script_string_context(self):
        ctx, _ = xf_context.classify("<script>var a='TOKEN';</script>", "TOKEN")
        self.assertIsNotNone(ctx)
        self.assertIn("script", ctx.get("context"))

    def test_encoding_hint_quote_escaped_is_entity_escaped(self):
        import html
        payload = "<script>alert('TOKEN')</script>"
        body = "<pre>Hello %s</pre>" % html.escape(payload, quote=True)
        self.assertEqual(
            xf_context.response_encoding_hint(body, payload, "TOKEN"),
            "html-entity-escaped")

    def test_encoding_hint_angle_only_still_entity_escaped(self):
        payload = "<script>alert('TOKEN')</script>"
        body = payload.replace("<", "&lt;").replace(">", "&gt;")
        self.assertEqual(
            xf_context.response_encoding_hint(body, payload, "TOKEN"),
            "html-entity-escaped")

    def test_encoding_hint_raw_reflection(self):
        payload = "<svg onload=alert('TOKEN')>"
        self.assertEqual(
            xf_context.response_encoding_hint(payload, payload, "TOKEN"), "raw")

    def test_canaryize_noquote_survives_quote_escaping(self):
        self.assertEqual(
            P.canaryize_noquote("alert('zqabc1234')", "zqabc1234", "regex"),
            "alert(/zqabc1234/)")
        self.assertEqual(
            P.canaryize_noquote("alert('zqabc1234')", "zqabc1234", "template"),
            "alert(`zqabc1234`)")


class MutationTests(unittest.TestCase):
    def test_mutations_preserve_marker(self):
        out = xf_mutate.mutate("<img src=x onerror=alert('__M__')>", "html", 10)
        self.assertTrue(out)
        for _, payload in out:
            self.assertIn("__M__", payload)

    def test_mutations_are_unique(self):
        out = xf_mutate.mutate("<svg onload=alert('__M__')>", "attr_dq", 40)
        self.assertEqual(len({p for _, p in out}), len(out))


class PointTests(unittest.TestCase):
    def test_query_point_request(self):
        pts = xf_points.points_from_url("http://x.test/?a=1&b=2")
        self.assertEqual(len(pts), 2)
        class O:
            timeout = 5
            insecure = True
        kwargs, _ = xf_points.build_request(pts[0], "PAY", O())
        self.assertIn("a=PAY", kwargs["url"])

    def test_json_point_request(self):
        pts = xf_points.points_from_data("http://x.test/api", '{"q":"v","n":{"x":1}}')
        self.assertEqual(len(pts), 2)
        class O:
            timeout = 5
            insecure = True
        kwargs, _ = xf_points.build_request(pts[0], "PAY", O())
        self.assertIn("PAY", json.dumps(kwargs["json"]))


class OpenAPITests(unittest.TestCase):
    def test_spec_to_points(self):
        spec = {
            "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "servers": [{"url": "http://api.test"}],
            "paths": {
                "/search": {"get": {"parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}}]}},
                "/user/{name}": {"get": {"parameters": [
                    {"name": "name", "in": "path", "schema": {"type": "string"}}]}},
                "/data": {"post": {"requestBody": {"content": {
                    "application/json": {"schema": {"type": "object", "properties": {
                        "msg": {"type": "string"}}}}}}}},
            },
        }
        pts = xf_openapi.points_from_spec(spec)
        labels = [p.label for p in pts]
        self.assertTrue(any(p.location == "query" for p in pts))
        self.assertTrue(any(p.location == "path" for p in pts))
        self.assertTrue(any(p.location == "json" for p in pts), labels)


class InteractshCryptoTests(unittest.TestCase):
    def test_decrypt_ctr_roundtrip(self):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception:
            self.skipTest("cryptography not installed")
        import secrets
        import xf_interactsh
        obj = xf_interactsh.Interactsh.__new__(xf_interactsh.Interactsh)
        obj._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        payload = json.dumps({"protocol": "http", "full-id": "abc123.oast.fun"}).encode()
        enc = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
        ct = enc.update(payload) + enc.finalize()
        wrapped = obj._key.public_key().encrypt(
            aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                  algorithm=hashes.SHA256(), label=None))
        got = obj._decrypt(base64.b64encode(wrapped).decode(),
                           base64.b64encode(iv + ct).decode())
        self.assertEqual(got["protocol"], "http")


class ArgvTests(unittest.TestCase):
    def setUp(self):
        import xssforge
        self.xssforge = xssforge
        self.ap = xssforge.build_argparser()

    def test_combined_flags_are_split(self):
        argv = ["-u", "https://example.com/?q=x",
                "--authorized-browser--auto", "--first-hit"]
        got = self.xssforge.normalize_argv(argv, self.ap)
        self.assertEqual(got, ["-u", "https://example.com/?q=x",
                               "--authorized", "--browser", "--auto", "--first-hit"])

    def test_unknown_and_value_options_are_untouched(self):
        argv = ["--encode", "url--html-dec", "--data", "a--b", "--totally-unknown"]
        self.assertEqual(self.xssforge.normalize_argv(argv, self.ap), argv)

    def test_parsed_combined_flags_enable_all_switches(self):
        argv = self.xssforge.normalize_argv(
            ["-u", "https://example.com/?q=x",
             "--authorized-browser--auto", "--first-hit"], self.ap)
        a = self.ap.parse_args(argv)
        self.assertTrue(a.authorized)
        self.assertTrue(a.browser)
        self.assertTrue(a.auto)
        self.assertTrue(a.first_hit)

    def test_raw_inject_keeps_literal_bytes(self):
        import xf_points
        opts = self.xssforge.Options(raw_inject=True)
        pt = xf_points.Point("query:id", "GET", "https://example.com/p?id=1",
                             "query", "id", {"id": "1"})
        kwargs, _ = xf_points.build_request(pt, '"><script>alert(1)</script>', opts)
        self.assertIn('id="><script>alert(1)</script>', kwargs["url"])

    def test_normal_mode_url_encodes(self):
        import xf_points
        opts = self.xssforge.Options()
        pt = xf_points.Point("query:id", "GET", "https://example.com/p?id=1",
                             "query", "id", {"id": "1"})
        kwargs, _ = xf_points.build_request(pt, '"><script>alert(1)</script>', opts)
        self.assertIn("id=%22%3E%3Cscript%3E", kwargs["url"])

    def test_no_switches_keep_defaults(self):
        a = self.ap.parse_args(["-u", "https://example.com/?q=x", "--auto",
                                "--no-browser", "--no-first-hit"])
        self.assertTrue(a.no_browser)
        self.assertTrue(a.no_first_hit)


class GapPayloadTests(unittest.TestCase):
    def test_new_encoders(self):
        self.assertIn("url4", P.ENCODERS)
        self.assertTrue(P.ENCODERS["url4"]("<").startswith("%25"))

    def test_gap_families_present(self):
        names = {cat: {n for n, _ in items} for cat, items in P.PAYLOADS.items()}
        self.assertIn("gap:poly-svg", names["waf"])
        self.assertIn("gap:hpp-concat", names["waf"])
        self.assertIn("gap:split-eval", names["script"])
        self.assertIn("gap:clobber-action", names["dom"])
        self.assertIn("gap:tt-policy", names["csp"])


class StructuralTests(unittest.TestCase):
    def test_hpp_repeats_param(self):
        import xf_struct
        pairs = xf_struct.hpp_pairs(
            "q", "1'&__HPP__=alert('__M__')&'2", 3)
        self.assertEqual([k for k, _ in pairs], ["q", "q", "q"])

        class O:
            hpp = True
            hpp_parts = 3
            structural = False
            structural_pad = 8
            timeout = 5
            insecure = True
            raw_inject = False

        pt = xf_points.Point("query:q", "GET", "http://x.test/?q=1",
                             "query", "q", data={"q": "1"})
        variants = xf_struct.all_variants(pt, "PAY", O())
        self.assertTrue(any(name == "hpp:repeat" for name, _, _ in variants))
        variant = next(v for v in variants if v[0] == "hpp:repeat")
        kwargs, _ = xf_points.build_request(variant[1], variant[2], O())
        self.assertGreaterEqual(kwargs["url"].count("q="), 3)

    def test_duplicate_json_keys(self):
        import xf_struct
        body = xf_struct.duplicate_json_body({"q": "safe"}, ("q",), "PAY")
        self.assertEqual(body.count('"q"'), 2)
        self.assertIn('"PAY"', body)


class CstiTests(unittest.TestCase):
    def test_escaped_angular_reflection(self):
        import xf_csti
        body = ('<script src="/angular.min.js"></script>'
                '<div>{{ &lt;img src=x onerror=alert(1)&gt; zqabc }}</div>')
        findings = xf_csti.detect(body, "zqabc")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["context"], "csti")
        self.assertGreaterEqual(findings[0]["confidence"], 60)


class ImportTests(unittest.TestCase):
    def test_postman_import(self):
        import xf_import
        collection = {"item": [{"request": {
            "method": "POST",
            "url": {"raw": "http://x.test/?a=1"},
            "header": [{"key": "X-Test", "value": "1"}],
            "body": {"mode": "raw", "raw": "q=v"},
        }}]}
        pts = xf_import.postman_points(collection)
        self.assertTrue(any(p.location == "query" for p in pts))
        self.assertTrue(any(p.location == "form" for p in pts))
        self.assertTrue(all(p.meta["headers"]["X-Test"] == "1" for p in pts))

    def test_har_import(self):
        import xf_import
        har = {"log": {"entries": [{"request": {
            "method": "GET", "url": "http://x.test/?b=2", "headers": [],
        }}]}}
        pts = xf_import.har_points(har)
        self.assertTrue(pts)
        self.assertEqual(pts[0].method, "GET")


class InjectionTests(unittest.TestCase):
    def test_mine_names(self):
        import xf_inject
        html = ('<input name="search" id="q">'
                '<script>var debug = 1; window.cfg = {};</script>')
        names = xf_inject.mine_names(html)
        self.assertIn("search", names)
        self.assertIn("debug", names)
        self.assertIn("q", xf_inject.mine_names('<input name="q">'))
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("x\nlongname\n")
            path = fh.name
        try:
            self.assertEqual(xf_inject.load_wordlist(path), ["x", "longname"])
        finally:
            os.unlink(path)

    def test_sweep_headers_cookies(self):
        import types
        import xf_inject
        opts = types.SimpleNamespace(
            headers={"X-A": "1"}, inject_headers=[],
            cookie="a=1; b=2", cookie_file="", inject_cookies=[])
        self.assertIn("X-Forwarded-For", xf_inject.sweep_headers(opts))
        self.assertIn("a", xf_inject.sweep_cookies(opts))
        self.assertEqual(xf_inject.cookie_map(opts), {"a": "1", "b": "2"})


class MassTests(unittest.TestCase):
    def test_normalize_and_strip(self):
        import xf_mass
        self.assertEqual(
            xf_mass.normalize_url("http://X.test/a/?b=2&a=1"),
            "http://x.test/a?a=1&b=2")
        argv = ["--mass", "urls.txt", "-u", "http://old.test", "--authorized",
                "--hpp"]
        out = xf_mass.strip_mass_args(argv)
        self.assertNotIn("--mass", out)
        self.assertNotIn("-u", out)
        self.assertIn("--authorized", out)
        self.assertIn("--hpp", out)


class DomSinkTests(unittest.TestCase):
    def test_expanded_sinks(self):
        import xf_dom
        names = {name for name, _ in xf_dom.SINKS}
        self.assertIn("FileReader.readAsText", names)
        self.assertIn("clipboard.readText", names)
        self.assertIn("document.currentScript", names)


class ReportFilterTests(unittest.TestCase):
    def test_high_confidence_filter(self):
        import xf_report
        results = [{"candidates": [
            {"status": "REFLECTED", "confidence": 45},
            {"status": "LIKELY", "confidence": 70},
            {"status": "LIKELY", "confidence": 95},
        ]}]
        dropped = xf_report.filter_low_confidence(results, "high")
        self.assertEqual(dropped, 2)
        self.assertEqual(len(results[0]["candidates"]), 1)


class RealWorldVectorTests(unittest.TestCase):
    def test_realworld_block_merged(self):
        for cat, items in P.REALWORLD_2026.items():
            self.assertTrue(items, cat)
            corpus = {p for _, p in P.PAYLOADS.get(cat, [])}
            for name, payload in items:
                self.assertIn(payload, corpus, (cat, name))

    def test_realworld_placeholders_and_canary(self):
        for cat, items in P.REALWORLD_2026.items():
            for name, payload in items:
                self.assertIn("__M__", payload, (cat, name))
                got = P.fill(payload, "tok123")
                self.assertNotIn("__M__", got)
                self.assertIn("tok123", got)

    def test_dompurify_recontext_vectors(self):
        ps = dict((n, p) for n, p in P.REALWORLD_2026["mxss"])
        for wrapper in ("xmp", "noscript", "textarea", "iframe", "noembed", "noframes"):
            self.assertIn("</" + wrapper, ps["dp-%s-recontext" % wrapper])
            self.assertIn("onerror=alert", ps["dp-%s-recontext" % wrapper])

    def test_firewall_mirrors_waf(self):
        self.assertEqual(len(P.PAYLOADS["firewall"]), len(P.PAYLOADS["waf"]))
        self.assertEqual(P.PAYLOADS["firewall"], P.PAYLOADS["waf"])


if __name__ == "__main__":
    unittest.main()
