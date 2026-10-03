"""Tests for the enhanced subdomain takeover check."""
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from scanner.checks.takeover import TakeoverCheck, TAKEOVER_SIGNATURES
from scanner.utils import create_dirs


class TestFingerprintDatabase(unittest.TestCase):
    def test_coverage(self):
        self.assertGreaterEqual(len(TAKEOVER_SIGNATURES), 40,
                                "Must cover at least 40 services")

    def test_entries_well_formed(self):
        for sig in TAKEOVER_SIGNATURES:
            self.assertIn("service", sig)
            self.assertIn("cnames", sig)
            self.assertIn("fingerprint", sig)
            self.assertIn("severity", sig)
            self.assertTrue(sig["cnames"])
            self.assertTrue(sig["fingerprint"])
            self.assertIn(sig["severity"], ("info", "low", "medium", "high", "critical"))

    def test_core_services_present(self):
        services = {s["service"] for s in TAKEOVER_SIGNATURES}
        for required in ["GitHub Pages", "AWS S3", "Heroku", "Shopify",
                          "Fastly", "Azure Websites", "Netlify", "Vercel"]:
            self.assertIn(required, services)


class TestTakeoverVerification(unittest.TestCase):
    def _check(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return TakeoverCheck(target="example.com", dirs=dirs,
                             live_hosts=[], threads=2)

    def test_match_fingerprint_github(self):
        c = self._check()
        chain = ["abandoned.example.com", "example.github.io"]
        body = ("<html>404 - There isn't a GitHub Pages site here. "
                "If you're trying to publish one, read the full documentation.</html>")
        match = c._match_fingerprint(body, 404, chain)
        self.assertIsNotNone(match)
        self.assertEqual(match["service"], "GitHub Pages")

    def test_match_fingerprint_s3(self):
        c = self._check()
        chain = ["img.example.com", "s3.amazonaws.com"]
        body = "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code></Error>"
        match = c._match_fingerprint(body, 404, chain)
        self.assertIsNotNone(match)
        self.assertEqual(match["service"], "AWS S3")

    def test_no_fingerprint_match(self):
        c = self._check()
        chain = ["x.example.com"]
        body = "<html>Welcome to our site</html>"
        self.assertIsNone(c._match_fingerprint(body, 200, chain))

    def test_cname_vulnerable_service(self):
        c = self._check()
        self.assertIsNotNone(
            c._is_cname_vulnerable_service(["x.example.com", "foo.github.io"])
        )
        self.assertIsNone(
            c._is_cname_vulnerable_service(["x.example.com", "cdn.random.net"])
        )

    def test_verify_requires_strong_evidence(self):
        """Verification must require HTTP fingerprint OR dangling + nxdomain_also."""
        c = self._check()
        with patch.object(c, "_cname_chain", return_value=["x.example.com", "random.net"]), \
             patch.object(c, "_nxdomain", return_value=False), \
             patch.object(c, "_fetch_body", return_value=(200, "<html>normal</html>")):
            self.assertIsNone(c._verify_subdomain("x.example.com"))

    def test_verify_confirms_github(self):
        """CNAME + fingerprint match + double-confirmed body -> finding."""
        c = self._check()
        gh_body = ("<html>There isn't a GitHub Pages site here. "
                   "If you're trying to publish one, read the full documentation.</html>")
        with patch.object(c, "_cname_chain",
                           return_value=["x.example.com", "example.github.io"]), \
             patch.object(c, "_nxdomain", return_value=False), \
             patch.object(c, "_fetch_body", return_value=(404, gh_body)), \
             patch("scanner.checks.takeover.time.sleep", lambda *_a, **_k: None):
            result = c._verify_subdomain("x.example.com")
            self.assertIsNotNone(result)
            self.assertEqual(result["service"], "GitHub Pages")
            self.assertEqual(result["http_status"], 404)
            self.assertEqual(len(result["confirmed_stages"]), 2)

    def test_verify_rejects_on_double_check_mismatch(self):
        """If the second fetch doesn't match the fingerprint, treat as flake."""
        c = self._check()
        bodies = iter([
            (404, "There isn't a GitHub Pages site here"),
            (200, "<html>page actually works now</html>"),
        ])
        with patch.object(c, "_cname_chain",
                           return_value=["x.example.com", "example.github.io"]), \
             patch.object(c, "_nxdomain", return_value=False), \
             patch.object(c, "_fetch_body", side_effect=lambda *a, **kw: next(bodies)), \
             patch("scanner.checks.takeover.time.sleep", lambda *_a, **_k: None):
            self.assertIsNone(c._verify_subdomain("x.example.com"))


class TestTakeoverIntegration(unittest.TestCase):
    def test_execute_without_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            c = TakeoverCheck(target="example.com", dirs=dirs,
                              live_hosts=[], threads=1)
            self.assertEqual(c.execute(), [])

    def test_dual_detector_elevates_severity(self):
        """A manual-confirmed finding whose subdomain also appears in
        subjack output must escalate severity above medium."""
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            Path(f"{dirs['subdomains']}/all_subdomains.txt").write_text(
                "x.example.com\n"
            )
            c = TakeoverCheck(target="example.com", dirs=dirs,
                              live_hosts=[], threads=1)
            manual_result = {
                "service": "GitHub Pages",
                "severity": "high",
                "cname_chain": "x.example.com -> example.github.io",
                "matched_fingerprint": "There isn't a GitHub Pages site here",
                "http_status": 404,
                "confirmed_stages": ["CNAME-service", "HTTP-fingerprint"],
            }
            with patch.object(c, "_verify_subdomain", return_value=manual_result), \
                 patch.object(c, "_run_subjack", return_value={"x.example.com"}), \
                 patch.object(c, "_run_nuclei_takeover", return_value=set()):
                findings = c.execute()
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "critical")
                self.assertIn("manual+subjack", findings[0].title)

    def test_tool_only_hit_reported_at_medium(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            Path(f"{dirs['subdomains']}/all_subdomains.txt").write_text(
                "y.example.com\n"
            )
            c = TakeoverCheck(target="example.com", dirs=dirs,
                              live_hosts=[], threads=1)
            with patch.object(c, "_verify_subdomain", return_value=None), \
                 patch.object(c, "_run_subjack", return_value={"y.example.com"}), \
                 patch.object(c, "_run_nuclei_takeover", return_value=set()):
                findings = c.execute()
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "medium")
                self.assertIn("tool-only", findings[0].tags)


if __name__ == "__main__":
    unittest.main()
