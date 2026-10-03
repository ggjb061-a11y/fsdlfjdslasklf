"""Tests for HTTP Request Smuggling check."""
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from scanner.checks.http_smuggling import HTTPSmugglingCheck
from scanner.utils import create_dirs


class TestSmugglingBuilders(unittest.TestCase):
    def _check(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return HTTPSmugglingCheck(target="example.com", dirs=dirs,
                                   live_hosts=["https://example.com"], threads=1)

    def test_parse_url_https_default_port(self):
        from scanner.checks.http_smuggling import HTTPSmugglingCheck
        scheme, host, port = HTTPSmugglingCheck._parse("https://example.com/foo")
        self.assertEqual(scheme, "https")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

    def test_parse_url_http_default_port(self):
        from scanner.checks.http_smuggling import HTTPSmugglingCheck
        scheme, host, port = HTTPSmugglingCheck._parse("http://example.com/foo")
        self.assertEqual(scheme, "http")
        self.assertEqual(port, 80)

    def test_parse_url_explicit_port(self):
        from scanner.checks.http_smuggling import HTTPSmugglingCheck
        scheme, host, port = HTTPSmugglingCheck._parse("https://example.com:8443/x")
        self.assertEqual(port, 8443)

    def test_parse_bare_hostname(self):
        from scanner.checks.http_smuggling import HTTPSmugglingCheck
        scheme, host, port = HTTPSmugglingCheck._parse("example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)


class TestSmugglingDetectionLogic(unittest.TestCase):
    def _check(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return HTTPSmugglingCheck(target="example.com", dirs=dirs,
                                   live_hosts=["https://example.com"], threads=1)

    def test_no_finding_when_baseline_fails(self):
        c = self._check()
        with patch.object(c, "_baseline_time", return_value=0.0), \
             patch.object(c, "_benign_chunked"):
            c._test_host("https://example.com")
            self.assertEqual(c.findings, [])

    def test_no_finding_when_benign_chunked_also_hangs(self):
        """If server hangs on BENIGN chunked, suppress - it's broken, not smuggling."""
        c = self._check()
        with patch.object(c, "_baseline_time", return_value=0.5), \
             patch.object(c, "_benign_chunked", return_value=(10.0, b"")):
            c._test_host("https://example.com")
            self.assertEqual(c.findings, [])

    def test_no_finding_on_single_shot_only(self):
        """A single-shot hang without double-confirmation must NOT fire."""
        c = self._check()
        responses = iter([
            (10.0, b""),  # first CL.TE hangs
            (0.5, b"HTTP/1.1 400"),  # confirmation does NOT hang -> flake, skip
            (0.5, b"HTTP/1.1 400"),  # TE.CL first - normal
            (0.5, b"HTTP/1.1 400"),  # TE.CL second - normal
            (0.5, b"HTTP/1.1 400"),  # TE.TE first - normal
            (0.5, b"HTTP/1.1 400"),  # TE.TE second - normal
        ])
        with patch.object(c, "_baseline_time", return_value=0.5), \
             patch.object(c, "_benign_chunked", return_value=(0.5, b"ok")), \
             patch.object(c, "_probe_clte",
                           side_effect=lambda *a, **kw: next(responses)), \
             patch.object(c, "_probe_tecl",
                           side_effect=lambda *a, **kw: next(responses)), \
             patch.object(c, "_probe_tete_obfuscated",
                           side_effect=lambda *a, **kw: next(responses)):
            c._test_host("https://example.com")
            self.assertEqual(c.findings, [])

    def test_double_confirmed_fires(self):
        c = self._check()
        with patch.object(c, "_baseline_time", return_value=0.5), \
             patch.object(c, "_benign_chunked", return_value=(0.5, b"ok")), \
             patch.object(c, "_probe_clte",
                           side_effect=[(10.0, b""), (10.0, b"")]):
            c._test_host("https://example.com")
            self.assertEqual(len(c.findings), 1)
            self.assertEqual(c.findings[0].severity, "high")
            self.assertIn("CL.TE", c.findings[0].title)
            self.assertIn("http-smuggling", c.findings[0].tags)

    def test_tecl_variant_fires_when_only_tecl_hangs(self):
        c = self._check()
        with patch.object(c, "_baseline_time", return_value=0.5), \
             patch.object(c, "_benign_chunked", return_value=(0.5, b"ok")), \
             patch.object(c, "_probe_clte", return_value=(0.5, b"400")), \
             patch.object(c, "_probe_tecl",
                           side_effect=[(10.0, b""), (10.0, b"")]):
            c._test_host("https://example.com")
            self.assertEqual(len(c.findings), 1)
            self.assertIn("TE.CL", c.findings[0].title)

    def test_slow_baseline_skips(self):
        """Already-slow sites are not reliable targets for timing-based tests."""
        c = self._check()
        with patch.object(c, "_baseline_time", return_value=5.0), \
             patch.object(c, "_probe_clte"):
            c._test_host("https://example.com")
            self.assertEqual(c.findings, [])


class TestSmugglingRequestBytes(unittest.TestCase):
    """Verify the raw request bytes look right (no shell-escape surprises)."""

    def _check(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return HTTPSmugglingCheck(target="example.com", dirs=dirs,
                                   live_hosts=["https://example.com"], threads=1)

    def test_clte_request_has_both_headers(self):
        c = self._check()
        captured = {}
        def fake_send(scheme, host, port, request, timeout):
            captured["bytes"] = request
            return (0.5, b"HTTP/1.1 200")
        with patch.object(c, "_send_raw", side_effect=fake_send):
            c._probe_clte("https", "example.com", 443, timeout=5)
        req = captured["bytes"]
        self.assertIn(b"Content-Length: 6", req)
        self.assertIn(b"Transfer-Encoding: chunked", req)
        self.assertIn(b"\r\n\r\n", req)
        self.assertTrue(req.endswith(b"0\r\n\r\nX"))

    def test_tecl_request_has_both_headers(self):
        c = self._check()
        captured = {}
        def fake_send(scheme, host, port, request, timeout):
            captured["bytes"] = request
            return (0.5, b"HTTP/1.1 200")
        with patch.object(c, "_send_raw", side_effect=fake_send):
            c._probe_tecl("https", "example.com", 443, timeout=5)
        req = captured["bytes"]
        self.assertIn(b"Transfer-Encoding: chunked", req)
        self.assertIn(b"Content-Length: 4", req)
        self.assertIn(b"GPOST", req)


if __name__ == "__main__":
    unittest.main()
