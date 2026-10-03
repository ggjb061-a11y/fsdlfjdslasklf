"""Tests for recon module helpers (mmh3 hash, google dorks)."""
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from scanner.recon import ReconModule
from scanner.utils import create_dirs


class TestMMHHash(unittest.TestCase):
    """Verify our pure-python MurmurHash3 matches reference values."""

    def test_hash_known_values(self):
        """Known mmh3 32-bit outputs for test vectors."""
        self.assertEqual(ReconModule._mmh3_hash(b""), 0)

    def test_hash_consistency(self):
        self.assertEqual(
            ReconModule._mmh3_hash(b"hello"),
            ReconModule._mmh3_hash(b"hello"),
        )

    def test_hash_different(self):
        self.assertNotEqual(
            ReconModule._mmh3_hash(b"hello"),
            ReconModule._mmh3_hash(b"world"),
        )

    def test_hash_signed_32bit(self):
        """Result must fit in a signed 32-bit int (favicon convention)."""
        for data in [b"a", b"ab", b"abc", b"abcd", b"abcde", b"\xff\xff\xff\xff"]:
            h = ReconModule._mmh3_hash(data)
            self.assertGreaterEqual(h, -2**31)
            self.assertLess(h, 2**31)


class TestGoogleDorks(unittest.TestCase):
    def test_dorks_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            recon = ReconModule("example.com", dirs)
            recon._google_dorks()
            self.assertGreater(len(recon.google_dorks), 10)
            for dork in recon.google_dorks:
                self.assertIn("example.com", dork)

    def test_dorks_written_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            recon = ReconModule("example.com", dirs)
            recon._google_dorks()
            from pathlib import Path
            p = Path(f"{dirs['recon']}/google_dorks.txt")
            self.assertTrue(p.exists())
            self.assertGreater(len(p.read_text().splitlines()), 10)


if __name__ == "__main__":
    unittest.main()
