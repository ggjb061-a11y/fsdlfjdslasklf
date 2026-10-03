"""
Behavior tests for the enhanced SQLi and XSS checks.

These tests use monkey-patched scanner.utils.run so no real HTTP
traffic is generated. The invariants verified here are the ones that
reduce false positives (baseline comparison, context detection,
double-confirmation of time delays).
"""
import tempfile
import unittest
from unittest.mock import patch

from scanner.checks.sql_injection import SQLInjectionCheck
from scanner.checks.xss import XSSCheck
from scanner.utils import create_dirs


def make_run(responses):
    """Build a mock scanner.utils.run that cycles through canned (rc, body, err)."""
    responses = list(responses)
    idx = [0]
    def _run(cmd, **kwargs):
        if idx[0] >= len(responses):
            return (-1, "", "")
        r = responses[idx[0]]
        idx[0] += 1
        return r
    return _run


class TestSQLInjectionNoFalsePositive(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dirs = create_dirs(self._tmp.name, "example.com")

    def _check(self):
        return SQLInjectionCheck(target="example.com", dirs=self.dirs,
                                 live_hosts=["https://example.com"], threads=1)

    def test_no_finding_on_clean_baseline(self):
        """Normal site with no SQL errors - must produce ZERO findings."""
        responses = [(0, "<html>Hello</html>", "")] * 200
        with patch("scanner.checks.sql_injection.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertEqual(found.findings, [])

    def test_error_signature_in_baseline_does_not_trigger(self):
        """If the baseline already contains an error string, probe must NOT alert.

        This prevents false positives on dev/debug pages that display errors
        for benign input.
        """
        responses = [(0, "You have an error in your SQL syntax<br>debug", "")] * 200
        with patch("scanner.checks.sql_injection.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertEqual(found.findings, [])

    def test_error_signature_only_in_probe_triggers(self):
        """Error signature absent from baseline but present after injection -> finding."""
        baseline_body = "<html>Normal page</html>"
        error_body = "<html>Error: You have an error in your SQL syntax near</html>"
        responses = [
            (0, baseline_body, ""),      # baseline for first param
            (0, error_body, ""),         # first payload: triggers
        ]
        with patch("scanner.checks.sql_injection.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertGreaterEqual(len(found.findings), 1)
            self.assertIn("error-based", found.findings[0].title)

    def test_tags_populated(self):
        """Confirmed finding must carry source + engine tags."""
        baseline_body = "<html>Normal page</html>"
        error_body = "You have an error in your SQL syntax at line 1"
        responses = [
            (0, baseline_body, ""),
            (0, error_body, ""),
        ]
        with patch("scanner.checks.sql_injection.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertTrue(found.findings)
            tags = found.findings[0].tags
            self.assertIn("sqli", tags)
            self.assertIn("error-based", tags)


class TestXSSNoFalsePositive(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dirs = create_dirs(self._tmp.name, "example.com")

    def _check(self):
        return XSSCheck(target="example.com", dirs=self.dirs,
                        live_hosts=["https://example.com"], threads=1)

    def test_no_finding_when_canary_not_reflected(self):
        """Canary not reflected -> no further probing, no finding."""
        responses = [(0, "<html>Hello</html>", "")] * 100
        with patch("scanner.checks.xss.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertEqual(found.findings, [])

    def test_canary_reflected_but_payload_encoded_no_finding(self):
        """Canary reflects but payload comes back HTML-encoded -> no finding."""
        canary = "xssmarker7x7"
        responses = [
            (0, f"<html>You searched for: {canary}</html>", ""),
            (0, f"<html>You searched for: &lt;script&gt;alert({canary})&lt;/script&gt;</html>", ""),
            (0, f"<html>You searched for: &lt;img src=x&gt;</html>", ""),
            (0, f"<html>You searched for: &lt;svg/onload&gt;</html>", ""),
        ] * 20
        with patch("scanner.checks.xss.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertEqual(found.findings, [])

    def test_canary_reflected_and_payload_survives_triggers(self):
        """Payload survives unencoded in body -> finding."""
        canary = "xssmarker7x7"
        responses = [
            (0, f"<html>Welcome {canary} enjoy</html>", ""),
            (0, f"<html>Welcome <script>alert({canary})</script> enjoy</html>", ""),
        ]
        with patch("scanner.checks.xss.run", side_effect=make_run(responses)):
            found = self._check()
            found.execute()
            self.assertGreaterEqual(len(found.findings), 1)
            self.assertIn("Reflected XSS", found.findings[0].title)


if __name__ == "__main__":
    unittest.main()
