"""Tests for scanner data models."""
import unittest
from scanner.models import Finding, URLRecord, HostRecord, JSSecret, ScanResult


class TestFinding(unittest.TestCase):
    def test_sev_order(self):
        self.assertEqual(Finding("critical", "", "", "", "").sev_order(), 0)
        self.assertEqual(Finding("high", "", "", "", "").sev_order(), 1)
        self.assertEqual(Finding("medium", "", "", "", "").sev_order(), 2)
        self.assertEqual(Finding("low", "", "", "", "").sev_order(), 3)
        self.assertEqual(Finding("info", "", "", "", "").sev_order(), 4)
        self.assertEqual(Finding("unknown", "", "", "", "").sev_order(), 5)

    def test_case_insensitive_severity(self):
        self.assertEqual(Finding("CRITICAL", "", "", "", "").sev_order(), 0)
        self.assertEqual(Finding("High", "", "", "", "").sev_order(), 1)

    def test_default_fields(self):
        f = Finding("high", "title", "host", "detail", "source")
        self.assertEqual(f.tags, [])
        self.assertEqual(f.url, "")
        self.assertEqual(f.evidence, "")


class TestScanResult(unittest.TestCase):
    def test_count_by_severity(self):
        r = ScanResult("example.com", "2026-01-01", "/tmp")
        r.findings = [
            Finding("critical", "a", "h", "d", "s"),
            Finding("critical", "b", "h", "d", "s"),
            Finding("high", "c", "h", "d", "s"),
            Finding("info", "d", "h", "d", "s"),
        ]
        counts = r.count_by_severity()
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 0)
        self.assertEqual(counts["info"], 1)

    def test_sorted_findings(self):
        r = ScanResult("example.com", "2026-01-01", "/tmp")
        r.findings = [
            Finding("info", "i", "h", "d", "s"),
            Finding("critical", "c", "h", "d", "s"),
            Finding("high", "h", "h", "d", "s"),
        ]
        sorted_f = r.sorted_findings()
        self.assertEqual(sorted_f[0].severity, "critical")
        self.assertEqual(sorted_f[1].severity, "high")
        self.assertEqual(sorted_f[2].severity, "info")

    def test_findings_by_severity(self):
        r = ScanResult("example.com", "2026-01-01", "/tmp")
        r.findings = [
            Finding("high", "a", "h", "d", "s"),
            Finding("high", "b", "h", "d", "s"),
            Finding("low", "c", "h", "d", "s"),
        ]
        self.assertEqual(len(r.findings_by_severity("high")), 2)
        self.assertEqual(len(r.findings_by_severity("low")), 1)
        self.assertEqual(len(r.findings_by_severity("medium")), 0)

    def test_default_fields_present(self):
        """Regression test for the bug where host_records/ports_raw/js_endpoints
        were accessed but not declared on the dataclass."""
        r = ScanResult("example.com", "2026-01-01", "/tmp")
        self.assertEqual(r.host_records, [])
        self.assertEqual(r.ports_raw, [])
        self.assertEqual(r.js_endpoints, [])
        self.assertEqual(r.google_dorks, [])
        self.assertEqual(r.subdomains, [])
        self.assertEqual(r.live_hosts, [])
        self.assertEqual(r.emails, [])
        self.assertEqual(r.cms_info, {})


class TestURLRecord(unittest.TestCase):
    def test_defaults(self):
        u = URLRecord("https://example.com/")
        self.assertFalse(u.is_login)
        self.assertFalse(u.is_js)
        self.assertFalse(u.is_sensitive_file)
        self.assertFalse(u.is_api)
        self.assertEqual(u.method_source, "live")


class TestHostRecord(unittest.TestCase):
    def test_defaults(self):
        h = HostRecord("example.com")
        self.assertEqual(h.ip, "")
        self.assertEqual(h.technologies, [])
        self.assertEqual(h.open_ports, [])
        self.assertFalse(h.is_live)


if __name__ == "__main__":
    unittest.main()
