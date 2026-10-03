"""Tests for the shared rate-limiter in scanner.utils."""
import time
import unittest

from scanner.utils import set_rate_limit, _apply_rate_limit


class TestRateLimit(unittest.TestCase):
    def tearDown(self):
        set_rate_limit(0)

    def test_zero_rate_limit_no_delay(self):
        set_rate_limit(0)
        start = time.monotonic()
        _apply_rate_limit()
        _apply_rate_limit()
        _apply_rate_limit()
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 0.05)

    def test_rate_limit_enforces_delay(self):
        set_rate_limit(0.1)
        _apply_rate_limit()
        start = time.monotonic()
        _apply_rate_limit()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.08)


if __name__ == "__main__":
    unittest.main()
