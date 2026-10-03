"""Tests for SARIF and CSV output formats."""
import json
import tempfile
import unittest
from pathlib import Path

from scanner.models import ScanResult, Finding
from scanner.utils import create_dirs
from scanner.output import generate_sarif, generate_csv


class TestSARIF(unittest.TestCase):
    def test_sarif_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            r = ScanResult(target="example.com", scan_date="2026-01-01", base_dir=dirs["base"])
            r.findings = [
                Finding("critical", "RCE", "example.com", "detail", "nuclei"),
                Finding("medium", "Missing CSP", "example.com", "d", "headers"),
            ]
            path = generate_sarif(r)
            data = json.loads(Path(path).read_text())
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(len(data["runs"]), 1)
            self.assertEqual(len(data["runs"][0]["results"]), 2)
            levels = [r["level"] for r in data["runs"][0]["results"]]
            self.assertIn("error", levels)
            self.assertIn("warning", levels)

    def test_sarif_sources_become_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            r = ScanResult(target="example.com", scan_date="2026-01-01", base_dir=dirs["base"])
            r.findings = [
                Finding("high", "A", "h", "d", "nuclei"),
                Finding("high", "B", "h", "d", "nuclei"),
                Finding("high", "C", "h", "d", "headers"),
            ]
            path = generate_sarif(r)
            data = json.loads(Path(path).read_text())
            rules = data["runs"][0]["tool"]["driver"]["rules"]
            rule_ids = {r["id"] for r in rules}
            self.assertEqual(rule_ids, {"nuclei", "headers"})


class TestCSV(unittest.TestCase):
    def test_csv_contains_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            r = ScanResult(target="example.com", scan_date="2026-01-01", base_dir=dirs["base"])
            r.findings = [
                Finding("critical", "SQL Injection", "example.com", "d", "nuclei",
                        url="https://example.com?id=1"),
            ]
            path = generate_csv(r)
            content = Path(path).read_text()
            self.assertIn("SQL Injection", content)
            self.assertIn("critical", content)
            self.assertIn("severity,title", content.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
