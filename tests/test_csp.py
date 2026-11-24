"""Tests for CSP adaptation, Trusted Types and reflection-matrix guidance."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import payloads as P
import xf_csp
import xf_filter
import xssforge


class CspParseTests(unittest.TestCase):
    def test_parse_and_collect_meta(self):
        directives = xf_csp.parse_policy("default-src 'self'; script-src 'nonce-abc'")
        self.assertEqual(directives["script-src"], ["'nonce-abc'"])
        body = '<meta http-equiv="Content-Security-Policy" content="base-uri \'none\'">'
        policies = xf_csp.collect({}, body)
        self.assertEqual(len(policies), 1)
        self.assertIn("base-uri", policies[0]["directives"])

    def test_report_only_is_not_enforced(self):
        info = xf_csp.analyze({"Content-Security-Policy-Report-Only": "script-src 'self'"})
        self.assertTrue(info["present"])
        self.assertFalse(info["enforced"])
        self.assertTrue(info["report_only"])

    def test_weak_csp_gadgets(self):
        info = xf_csp.analyze({
            "Content-Security-Policy":
                "script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'"
        })
        self.assertEqual(info["nonce"], "abc")
        self.assertTrue(info["strict_dynamic"])
        self.assertIn("strict-dynamic", info["gadgets"])
        self.assertIn("base-hijack", info["gadgets"])
        self.assertNotIn("object-embed", info["gadgets"])
        self.assertFalse(info["hardened"])

    def test_hardened_csp(self):
        info = xf_csp.analyze({
            "Content-Security-Policy":
                "default-src 'none'; script-src 'nonce-abc'; base-uri 'none'; object-src 'none'"
        })
        self.assertTrue(info["hardened"])


class TrustedTypesTests(unittest.TestCase):
    def test_noop_default_policy_is_permissive(self):
        body = "trustedTypes.createPolicy('default', {createHTML: s => s});"
        tt = xf_csp.trusted_types_state(body)
        self.assertTrue(tt["permissive_default"])
        self.assertFalse(tt["protected"])

    def test_enforced_strict_policy_protects_html_sinks(self):
        body = "trustedTypes.createPolicy('default', {createHTML: s => DOMPurify.sanitize(s)});"
        info = xf_csp.analyze({
            "Content-Security-Policy": "require-trusted-types-for 'script'"
        }, body)
        self.assertTrue(info["trusted_types"]["protected"])
        findings = [{"sink": "innerHTML", "source": "location.hash"},
                    {"sink": "eval", "source": "location.hash"}]
        kept, suppressed = xf_csp.filter_dom_findings(findings, info)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["sink"], "eval")
        self.assertEqual(len(suppressed), 1)


class PayloadGuidanceTests(unittest.TestCase):
    def test_score_prioritises_gadget_payloads(self):
        info = xf_csp.analyze({
            "Content-Security-Policy":
                "default-src 'none'; script-src 'nonce-abc'; base-uri 'none'; object-src 'none'"
        })
        weak = xf_csp.analyze({"Content-Security-Policy": "script-src 'self'"})
        self.assertGreater(xf_csp.payload_score('<base href="//x/">', weak), 0)
        self.assertLess(xf_csp.payload_score("<script>alert(1)</script>", info), 0)
        self.assertEqual(xf_csp.payload_score("<svg onload=alert(1)>", {}), 0)

    def test_adapt_categories_adds_csp(self):
        info = xf_csp.analyze({"Content-Security-Policy": "script-src 'self'"})
        cats = xf_csp.adapt_categories(["html", "polyglot"], info)
        self.assertIn("csp", cats)

    def test_gather_payloads_uses_csp_and_matrix(self):
        info = xf_csp.analyze({
            "Content-Security-Policy": "script-src 'nonce-abc'; base-uri 'none'"
        })
        opts = xssforge.Options(payload_limit=8, filter_profile={
            "matrix": {"%": "BLOCKED"}, "blocked": ["percent"]})
        ctx = {"context": "html"}
        names = [n for n, _ in xssforge.gather_payloads(ctx, opts, info)]
        self.assertTrue(names)
        self.assertTrue(any(n.startswith("csp:") or n.startswith("jsonp:")
                            for n in names), names)

    def test_nonce_placeholder_is_filled(self):
        P.set_nonce("abc123")
        try:
            out = P.fill("<script nonce=\"__NONCE__\">alert('__M__')</script>", "tok")
            self.assertIn('nonce="abc123"', out)
            self.assertNotIn("__NONCE__", out)
        finally:
            P.set_nonce("")

    def test_modern_families_present(self):
        names = {cat: {n for n, _ in items} for cat, items in P.PAYLOADS.items()}
        self.assertIn("gap:mxss-foreignobject", names["mxss"])
        self.assertIn("gap:clobber-currentscript", names["dom"])
        self.assertIn("gap:strict-dynamic", names["csp"])
        self.assertIn("gap:blob-js", names["csp"])


class MatrixTests(unittest.TestCase):
    def test_blocked_chars_from_matrix(self):
        profile = {"matrix": {"<": "BLOCKED", ">": "ALLOWED", "'": "REMOVED"},
                   "blocked": ["word-alert"]}
        self.assertEqual(xf_filter.blocked_chars(profile), {"<", "'"})

    def test_rate_limiter_backoff(self):
        limiter = xssforge.RateLimiter(0.01)
        limiter.penalize()
        self.assertGreaterEqual(limiter.penalty, 0.02)
        for _ in range(8):
            limiter.penalize()
        self.assertLessEqual(limiter.penalty, 30.0)
        limiter.relax()
        self.assertLess(limiter.penalty, 30.0)


if __name__ == "__main__":
    unittest.main()
