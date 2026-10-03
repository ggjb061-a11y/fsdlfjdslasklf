"""Tests for scan checkpoint/resume."""
import tempfile
import unittest
from pathlib import Path

from scanner.checkpoint import CheckpointManager
from scanner.models import ScanResult, Finding, URLRecord


class TestCheckpoint(unittest.TestCase):
    def test_mark_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            cm = CheckpointManager(tmp)
            self.assertFalse(cm.is_done("recon"))
            cm.mark_done("recon", {"subdomains": ["a.example.com"]})
            self.assertTrue(cm.is_done("recon"))

            cm2 = CheckpointManager(tmp)
            self.assertTrue(cm2.is_done("recon"))
            self.assertEqual(cm2.get_data("recon")["subdomains"], ["a.example.com"])

    def test_mark_without_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            cm = CheckpointManager(tmp)
            cm.mark_done("passive")
            self.assertTrue(cm.is_done("passive"))

    def test_idempotent_mark(self):
        with tempfile.TemporaryDirectory() as tmp:
            cm = CheckpointManager(tmp)
            cm.mark_done("recon")
            cm.mark_done("recon")
            self.assertEqual(len(cm.state["phases_done"]), 1)

    def test_corrupted_checkpoint_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".checkpoint.json").write_text("not valid json {")
            cm = CheckpointManager(tmp)
            self.assertEqual(cm.state["phases_done"], [])

    def test_restore_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            cm = CheckpointManager(tmp)
            cm.mark_done("recon", {
                "subdomains": ["a.example.com", "b.example.com"],
                "live_hosts": ["https://a.example.com"],
                "whois": "test whois",
                "google_dorks": ["site:example.com"],
                "host_records": [],
            })
            cm.mark_done("passive", {
                "urls": [],
                "findings": [{"severity": "high", "title": "X", "host": "h",
                              "detail": "d", "source": "s"}],
                "emails": ["a@example.com"],
                "cms_info": {},
            })
            r = ScanResult("example.com", "2026-01-01", tmp)
            cm.restore_result(r)
            self.assertEqual(r.subdomains, ["a.example.com", "b.example.com"])
            self.assertEqual(r.emails, ["a@example.com"])
            self.assertEqual(len(r.findings), 1)


if __name__ == "__main__":
    unittest.main()
