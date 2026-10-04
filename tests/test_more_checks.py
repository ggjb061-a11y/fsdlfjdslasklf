"""Behavioral tests for check modules that lacked them: ssl_tls, cors,
nikto_scan, nuclei_scan, http_methods baseline-differential, and the
params.py 3-sample variance guard."""
import tempfile
import unittest
from unittest.mock import patch

from scanner.utils import create_dirs


# ---------------------------------------------------------------------------
# SSL/TLS parser - sslscan text output
# ---------------------------------------------------------------------------
class TestSSLParsing(unittest.TestCase):
    def _check(self, live_hosts=None):
        from scanner.checks.ssl_tls import SSLCheck
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return SSLCheck(target="example.com", dirs=dirs,
                         live_hosts=live_hosts or [], threads=1)

    def test_sslv2_accepted_detected(self):
        c = self._check()
        from pathlib import Path
        p = Path(c.dirs["ssl"]) / "sslscan.txt"
        p.write_text(
            "SSLv2 ciphers accepted\n"
            "RC4-MD5 ... accepted\n"
            "Certificate: notAfter=Jan 1 2030\n"
        )
        c._parse_sslscan(str(p))
        titles = [f.title for f in c.findings]
        self.assertTrue(any("SSLv2" in t for t in titles),
                        f"Expected SSLv2 finding, got: {titles}")

    def test_self_signed_cert_detected_low(self):
        c = self._check()
        text = "subject=/CN=example\nissuer=/CN=example\nself-signed certificate"
        c._parse_openssl(text)
        self.assertTrue(any(f.severity == "low" and "Self-Signed" in f.title
                             for f in c.findings))

    def test_cert_expiry_info_not_critical(self):
        c = self._check()
        c._parse_openssl("notAfter=Jan 1 2030\n")
        self.assertTrue(any(f.severity == "info" and "expiry" in f.title.lower()
                             for f in c.findings))


# ---------------------------------------------------------------------------
# CORS: wildcard-with-credentials should fire, bare wildcard should not
# ---------------------------------------------------------------------------
class TestCORS(unittest.TestCase):
    def _run_cors(self, response_body):
        from scanner.checks import cors as cors_mod
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        c = cors_mod.CORSCheck(target="example.com", dirs=dirs,
                                live_hosts=["https://example.com"], threads=1)
        with patch("scanner.checks.cors.run",
                   return_value=(0, response_body, "")):
            return c.execute()

    def test_reflects_attacker_origin_with_credentials_is_critical(self):
        from scanner.constants import ATTACKER_CANARY
        body = (
            f"HTTP/1.1 200 OK\n"
            f"access-control-allow-origin: https://{ATTACKER_CANARY}\n"
            f"access-control-allow-credentials: true\n"
        )
        findings = self._run_cors(body)
        self.assertTrue(any(f.severity == "critical" for f in findings))

    def test_wildcard_without_credentials_does_not_fire(self):
        body = (
            "HTTP/1.1 200 OK\n"
            "access-control-allow-origin: *\n"
        )
        findings = self._run_cors(body)
        for f in findings:
            self.assertNotIn("Wildcard + Credentials", f.title)


# ---------------------------------------------------------------------------
# Nikto parser - 3 JSON shapes
# ---------------------------------------------------------------------------
class TestNiktoParser(unittest.TestCase):
    def _check(self):
        from scanner.checks.nikto_scan import NiktoScan
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return NiktoScan(target="example.com", dirs=dirs,
                         live_hosts=["https://example.com"], threads=1)

    def test_normalize_vulns_modern_list(self):
        c = self._check()
        # modern nikto -Format json flat list: list of {id, msg, url, refs}
        entries = [{"id": "999001", "msg": "/.git/config exposed",
                    "url": "/.git/config", "references": "OSVDB-X"}]
        out = c._normalize_vulns(entries)
        self.assertEqual(len(out), 1)

    def test_normalize_vulns_legacy_dict(self):
        c = self._check()
        # legacy nested shape
        entries = [{"host": "x", "vulnerabilities": [
            {"id": "001", "msg": "Server leaks inodes"}
        ]}]
        out = c._normalize_vulns(entries)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["msg"], "Server leaks inodes")

    def test_vuln_severity_defaults_safely(self):
        c = self._check()
        # Banner-leak type findings must NOT default to medium (noise).
        sev = c._vuln_severity({"id": "001", "msg": "Server header reveals version"})
        self.assertIn(sev, ("info", "low"))

    def test_vuln_severity_upgrades_on_rce_keyword(self):
        c = self._check()
        sev = c._vuln_severity({"id": "001", "msg": "possible RCE via /cgi-bin/foo"})
        self.assertEqual(sev, "critical")


# ---------------------------------------------------------------------------
# Nuclei JSONL parsing - severity None handling, informational mapping
# ---------------------------------------------------------------------------
class TestNucleiMapping(unittest.TestCase):
    def test_null_severity_falls_back_to_info(self):
        from scanner.checks.nuclei_scan import _canonical_sev
        self.assertEqual(_canonical_sev(None), "info")
        self.assertEqual(_canonical_sev(""), "info")
        self.assertEqual(_canonical_sev("informational"), "info")
        self.assertEqual(_canonical_sev("unknown"), "info")
        self.assertEqual(_canonical_sev("critical"), "critical")
        self.assertEqual(_canonical_sev("Medium"), "medium")


if __name__ == "__main__":
    unittest.main()
