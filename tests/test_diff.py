"""Tests for scan diff module."""
import json
import tempfile
import unittest
from pathlib import Path

from scanner.diff import ScanDiff


class TestScanDiff(unittest.TestCase):
    def _write_summary(self, path: Path, **kwargs) -> str:
        default = {
            "target": "example.com",
            "scan_date": "2026-01-01",
            "findings": [],
            "subdomains": [],
            "live_hosts": [],
            "urls_sensitive": [],
        }
        default.update(kwargs)
        path.write_text(json.dumps(default))
        return str(path)

    def test_new_findings_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write_summary(
                Path(tmp) / "base.json",
                findings=[{"severity": "high", "title": "A", "host": "x", "url": ""}],
            )
            curr = self._write_summary(
                Path(tmp) / "curr.json",
                findings=[
                    {"severity": "high", "title": "A", "host": "x", "url": ""},
                    {"severity": "critical", "title": "B", "host": "y", "url": ""},
                ],
            )
            d = ScanDiff(base, curr).compute()
            self.assertEqual(d["summary"]["new_findings"], 1)
            self.assertEqual(d["summary"]["resolved_findings"], 0)
            self.assertEqual(d["summary"]["persistent_findings"], 1)
            self.assertEqual(d["new_findings"][0]["title"], "B")

    def test_resolved_findings_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write_summary(
                Path(tmp) / "base.json",
                findings=[
                    {"severity": "high", "title": "A", "host": "x", "url": ""},
                    {"severity": "high", "title": "B", "host": "y", "url": ""},
                ],
            )
            curr = self._write_summary(
                Path(tmp) / "curr.json",
                findings=[{"severity": "high", "title": "A", "host": "x", "url": ""}],
            )
            d = ScanDiff(base, curr).compute()
            self.assertEqual(d["summary"]["resolved_findings"], 1)
            self.assertEqual(d["resolved_findings"][0]["title"], "B")

    def test_new_subdomains_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write_summary(Path(tmp) / "b.json", subdomains=["a.ex.com"])
            curr = self._write_summary(Path(tmp) / "c.json",
                                       subdomains=["a.ex.com", "b.ex.com", "c.ex.com"])
            d = ScanDiff(base, curr).compute()
            self.assertEqual(d["summary"]["new_subdomains"], 2)

    def test_markdown_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write_summary(Path(tmp) / "b.json")
            curr = self._write_summary(
                Path(tmp) / "c.json",
                findings=[{"severity": "critical", "title": "RCE", "host": "x", "url": ""}],
            )
            diff = ScanDiff(base, curr)
            md = diff.to_markdown()
            self.assertIn("Scan Diff", md)
            self.assertIn("RCE", md)


if __name__ == "__main__":
    unittest.main()
