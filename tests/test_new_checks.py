"""Tests for the 4 new check modules: CSRF, GitHub leaks, S3 buckets, Tech-adaptive."""
import tempfile
import unittest
from unittest.mock import patch

from scanner.utils import create_dirs


def make_run(responses):
    responses = list(responses)
    idx = [0]
    def _run(cmd, **kwargs):
        if idx[0] >= len(responses):
            return (-1, "", "")
        r = responses[idx[0]]
        idx[0] += 1
        return r
    return _run


class TestCSRF(unittest.TestCase):
    def _check(self):
        from scanner.checks.csrf import CSRFCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return CSRFCheck(target="example.com", dirs=dirs,
                        live_hosts=["https://example.com"], threads=1)

    def test_token_names_regex(self):
        from scanner.checks.csrf import CSRFCheck
        for name in ["csrf", "_csrf", "_token", "authenticity_token",
                     "__RequestVerificationToken", "xsrf", "csrfmiddlewaretoken"]:
            self.assertTrue(CSRFCheck.TOKEN_NAMES.search(name),
                            f"'{name}' should match token regex")
        for benign in ["username", "password", "email", "comment"]:
            self.assertFalse(CSRFCheck.TOKEN_NAMES.search(benign),
                             f"'{benign}' should NOT match token regex")

    def test_extract_forms(self):
        c = self._check()
        html = '''
        <form method="POST" action="/login">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="hidden" name="_token" value="xyz">
        </form>
        <form method="GET" action="/search">
          <input type="text" name="q">
        </form>
        <form method="POST" action="/comment">
          <input type="text" name="body">
        </form>
        '''
        forms = c._extract_forms(html)
        # Only POST forms
        self.assertEqual(len(forms), 2)
        self.assertEqual(forms[0]["action"], "/login")
        self.assertIn("_token", forms[0]["hidden_fields"])
        self.assertEqual(forms[1]["action"], "/comment")
        self.assertEqual(forms[1]["hidden_fields"], [])

    def test_external_action_skipped(self):
        c = self._check()
        self.assertTrue(c._is_external_action(
            "https://facebook.com/login", "https://example.com/"))
        self.assertFalse(c._is_external_action(
            "/login", "https://example.com/"))
        self.assertFalse(c._is_external_action(
            "https://example.com/login", "https://example.com/"))

    def test_samesite_detection(self):
        c = self._check()
        self.assertTrue(c._has_samesite_strict_or_lax(
            "Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict"
        ))
        self.assertTrue(c._has_samesite_strict_or_lax(
            "Set-Cookie: auth_token=x; SameSite=Lax"
        ))
        self.assertFalse(c._has_samesite_strict_or_lax(
            "Set-Cookie: session=abc; HttpOnly; Secure"
        ))


class TestGitHubLeaks(unittest.TestCase):
    def _check(self):
        from scanner.checks.github_leaks import GitHubLeaksCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return GitHubLeaksCheck(target="example.com", dirs=dirs,
                                live_hosts=[], threads=1)

    def test_dorks_cover_core_secrets(self):
        from scanner.checks.github_leaks import GitHubLeaksCheck
        for required in ["aws_access_key_id", "password", "api_key",
                          "token", "secret", "private_key", "DATABASE_URL"]:
            self.assertIn(required, GitHubLeaksCheck.DORKS)

    def test_unauthenticated_produces_manual_stubs(self):
        c = self._check()
        with patch.dict("os.environ", {}, clear=True), \
             patch("scanner.checks.github_leaks.time.sleep", lambda *_a, **_k: None):
            # Clear GITHUB_TOKEN specifically
            import os
            os.environ.pop("GITHUB_TOKEN", None)
            findings = c.execute()
            # One info finding per dork
            self.assertGreater(len(findings), 10)
            for f in findings:
                self.assertEqual(f.severity, "info")
                self.assertIn("github.com/search", f.url)

    def test_authenticated_finds_real_hits(self):
        c = self._check()
        with patch.dict("os.environ", {"GITHUB_TOKEN": "fake"}, clear=False), \
             patch.object(c, "_api_search",
                          return_value=[{"name": "config.py", "path": "src/config.py",
                                        "html_url": "https://github.com/x/y/blob/main/src/config.py",
                                        "repository": "x/y"}]), \
             patch("scanner.checks.github_leaks.time.sleep", lambda *_a, **_k: None):
            findings = c.execute()
            self.assertTrue(findings)
            # A code-search hit is a MEDIUM lead (needs manual review),
            # not a confirmed credential disclosure.
            self.assertEqual(findings[0].severity, "medium")
            self.assertIn("needs-manual-review", findings[0].tags)
            self.assertIn("Possible leaked", findings[0].title)


class TestS3Buckets(unittest.TestCase):
    def _check(self):
        from scanner.checks.s3_buckets import S3BucketCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return S3BucketCheck(target="example.com", dirs=dirs,
                            live_hosts=[], threads=1)

    def test_name_variants(self):
        c = self._check()
        variants = c._name_variants()
        self.assertIn("example", variants)

    def test_candidates_contain_common_patterns(self):
        c = self._check()
        cands = c._generate_candidates()
        self.assertIn("example-backup", cands)
        self.assertIn("example-dev", cands)
        self.assertIn("example-logs", cands)
        self.assertIn("backup-example", cands)
        # No candidate must violate S3 naming rules
        import re
        for c_name in cands:
            self.assertTrue(3 <= len(c_name) <= 63)
            self.assertTrue(re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", c_name))

    def test_probe_detects_listable(self):
        c = self._check()
        xml_body = '''<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-backup</Name>
  <Contents><Key>db.sql</Key><Size>1234</Size></Contents>
</ListBucketResult>
__STATUS__:200
'''
        with patch("scanner.checks.s3_buckets.run",
                   return_value=(0, xml_body, "")):
            r = c._probe_s3("example-backup")
            self.assertIsNotNone(r)
            self.assertEqual(r["state"], "listable")

    def test_probe_detects_access_denied(self):
        c = self._check()
        body = ("<?xml version='1.0' encoding='UTF-8'?>"
                "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
                "\n__STATUS__:403")
        with patch("scanner.checks.s3_buckets.run",
                   return_value=(0, body, "")):
            r = c._probe_s3("example-dev")
            self.assertIsNotNone(r)
            self.assertEqual(r["state"], "access-denied")

    def test_probe_skips_nosuchbucket(self):
        c = self._check()
        body = ("<?xml version='1.0' encoding='UTF-8'?>"
                "<Error><Code>NoSuchBucket</Code></Error>"
                "\n__STATUS__:404")
        with patch("scanner.checks.s3_buckets.run",
                   return_value=(0, body, "")):
            self.assertIsNone(c._probe_s3("example-xyz"))


class TestTechAdaptive(unittest.TestCase):
    def _check(self):
        from scanner.checks.tech_adaptive import TechAdaptiveCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return TechAdaptiveCheck(target="example.com", dirs=dirs,
                                 live_hosts=["https://example.com"], threads=1)

    def test_fingerprint_wordpress(self):
        c = self._check()
        wp_body = ('HTTP/1.1 200 OK\r\n\r\n'
                   '<html><link rel="stylesheet" href="/wp-content/themes/style.css">'
                   '<meta name="generator" content="WordPress 6.4"></html>')
        with patch.object(c, "_fetch", return_value=(200, wp_body, "")):
            self.assertIn("wordpress", c._fingerprint("https://example.com"))

    def test_fingerprint_laravel(self):
        c = self._check()
        laravel_headers = ("HTTP/1.1 200 OK\r\n"
                           "X-Powered-By: Laravel\r\n"
                           "Set-Cookie: laravel_session=abc\r\n\r\n")
        with patch.object(c, "_fetch", return_value=(200, "<html></html>", laravel_headers)):
            self.assertIn("laravel", c._fingerprint("https://example.com"))

    def test_fingerprint_spring(self):
        c = self._check()
        body = ("HTTP/1.1 200 OK\r\n"
                "X-Application-Context: app:prod\r\n\r\n"
                "<html>Whitelabel Error Page SpringBoot</html>")
        with patch.object(c, "_fetch", return_value=(200, body, body)):
            self.assertIn("spring", c._fingerprint("https://example.com"))

    def test_fingerprint_none_on_plain_html(self):
        c = self._check()
        with patch.object(c, "_fetch", return_value=(200, "<html>plain</html>", "")):
            self.assertEqual(c._fingerprint("https://example.com"), set())


class TestRegistryIncludes(unittest.TestCase):
    def test_all_checks_includes_new(self):
        from scanner.checks import (ALL_CHECKS, CSRFCheck, GitHubLeaksCheck,
                                     S3BucketCheck, TechAdaptiveCheck)
        for cls in (CSRFCheck, GitHubLeaksCheck, S3BucketCheck, TechAdaptiveCheck):
            self.assertIn(cls, ALL_CHECKS)
        self.assertGreaterEqual(len(ALL_CHECKS), 32)


if __name__ == "__main__":
    unittest.main()
