"""Tests for output modules (markdown, json)."""
import json
import tempfile
import unittest
from pathlib import Path

from scanner.models import ScanResult, Finding, URLRecord, JSSecret
from scanner.utils import create_dirs
from scanner.output import generate_markdown, generate_json


class TestMarkdownReport(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        r = ScanResult("example.com", "2026-01-01", dirs["base"])
        r.findings = [
            Finding("critical", "SQL Injection", "example.com", "SQLi in id param",
                    "nuclei", url="https://example.com?id=1"),
            Finding("high", "XSS", "example.com", "Reflected XSS",
                    "nuclei", url="https://example.com?q=xss"),
            Finding("medium", "Missing HSTS", "example.com", "no hsts header",
                    "headers"),
        ]
        r.subdomains = ["api.example.com", "www.example.com"]
        r.live_hosts = ["https://example.com", "https://api.example.com"]
        r.urls = [URLRecord("https://example.com/.env", 200, is_sensitive_file=True)]
        r.js_secrets = [JSSecret("https://example.com/app.js", "AWS Key", "AKIA...", 42)]
        r.emails = ["admin@example.com"]
        r.google_dorks = ["site:example.com filetype:pdf"]
        self.path = generate_markdown(r)
        self.content = Path(self.path).read_text()

    def test_markdown_generated(self):
        self.assertTrue(Path(self.path).exists())
        self.assertTrue(self.path.endswith(".md"))

    def test_markdown_contains_title(self):
        self.assertIn("# AutoVulnScan Report", self.content)
        self.assertIn("example.com", self.content)

    def test_markdown_severity_summary(self):
        self.assertIn("Severity Summary", self.content)
        self.assertIn("Critical", self.content)
        self.assertIn("High", self.content)

    def test_markdown_findings_present(self):
        self.assertIn("SQL Injection", self.content)
        self.assertIn("XSS", self.content)
        self.assertIn("Missing HSTS", self.content)


class TestJSONReport(unittest.TestCase):
    def test_json_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            r = ScanResult("example.com", "2026-01-01", dirs["base"])
            r.findings = [Finding("high", "XSS", "example.com", "d", "s")]
            r.subdomains = ["a.example.com"]
            r.google_dorks = ["site:example.com"]
            path = generate_json(r)
            data = json.loads(Path(path).read_text())
            self.assertEqual(data["target"], "example.com")
            self.assertEqual(data["total_findings"], 1)
            self.assertEqual(len(data["findings"]), 1)
            self.assertIn("google_dorks", data)


if __name__ == "__main__":
    unittest.main()
