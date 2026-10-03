"""
Behavior tests for the deep baseline-compared checks.

Each test mocks scanner.utils.run so no network traffic happens. The
invariants verified are the ones that reduce false positives:
  - no finding when baseline already contains the indicator
  - no finding when payload is just echoed (SSTI)
  - no finding on single-shot match (requires double-confirm)
"""
import tempfile
import unittest
from unittest.mock import patch

from scanner.utils import create_dirs


def make_run(responses, timings=None):
    """Return a fake run() cycling through canned (rc, body, '') responses."""
    responses = list(responses)
    timings_iter = iter(timings) if timings else None
    idx = [0]

    def _run(cmd, **kwargs):
        import time as _t
        if idx[0] >= len(responses):
            return (-1, "", "")
        r = responses[idx[0]]
        idx[0] += 1
        if timings_iter is not None:
            try:
                delay = next(timings_iter)
                _t.sleep(min(delay, 0.01))  # we only need relative ordering
            except StopIteration:
                pass
        return r
    return _run


class TestPathTraversalDepth(unittest.TestCase):
    def _check(self):
        from scanner.checks.path_traversal import PathTraversalCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return PathTraversalCheck(target="example.com", dirs=dirs,
                                   live_hosts=["https://example.com"], threads=1)

    def test_indicator_in_baseline_no_finding(self):
        """FP guard: a baseline that mentions /etc/passwd in prose must NOT
        trigger a finding."""
        baseline = "<html>Example: on Linux the user list lives in root:x:0:0:root:/root:/bin/bash</html>"
        responses = [(0, baseline, "")] * 300
        with patch("scanner.checks.path_traversal.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertEqual(c.findings, [])

    def test_indicator_only_in_payload_response(self):
        """Positive: indicator missing from baseline, present in two
        consecutive payload responses."""
        baseline = "<html>Normal homepage</html>"
        passwd_response = "<pre>root:x:0:0:root:/root:/bin/bash\nnobody:x:65534</pre>"
        responses = [
            (0, baseline, ""),           # baseline for first param
            (0, passwd_response, ""),    # first payload
            (0, passwd_response, ""),    # double-confirm fetch
        ]
        with patch("scanner.checks.path_traversal.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertGreaterEqual(len(c.findings), 1)
            self.assertIn("Local File Inclusion", c.findings[0].title)


class TestSSTIDepth(unittest.TestCase):
    def _check(self):
        from scanner.checks.ssti import SSTICheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return SSTICheck(target="example.com", dirs=dirs,
                        live_hosts=["https://example.com"], threads=1)

    def test_payload_echoed_no_finding(self):
        """FP guard: if the server echoes the raw payload (not evaluated),
        we must NOT fire. The echo guard sees '{{7*7}}' in the response."""
        baseline = "<html>normal</html>"
        echoed = "<html>You searched for: {{7*7}} - no results</html>"
        responses = [
            (0, baseline, ""),
            (0, echoed, ""),
        ] * 50
        # scanner.checks.base imported `run` into its namespace via
        # `from ..utils import run` - patch the LOCAL reference.
        with patch("scanner.checks.base.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertEqual(c.findings, [])

    def test_expected_in_baseline_no_finding(self):
        """FP guard: if '49' already appears in baseline, we must skip."""
        baseline = "<html>Items 1-49 on this page</html>"
        responses = [(0, baseline, "")] * 500
        with patch("scanner.checks.base.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertEqual(c.findings, [])

    def test_single_shot_match_requires_double_confirm(self):
        """New differential logic: if 49 appears in BOTH probes (primary
        and differential), the FP guard catches it even without a
        double-confirm failure."""
        baseline = "<html>normal</html>"
        hit = "<html>Result: 49</html>"  # same body for every probe
        responses = [(0, baseline, "")] + [(0, hit, "")] * 100
        with patch("scanner.checks.base.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            # 49 appears in BOTH {{7*7}} and {{2*5}} responses -> FP guard trips
            self.assertEqual(c.findings, [])

    def test_evaluated_double_confirmed_fires(self):
        """Positive case: {{7*7}} -> 49, {{2*5}} -> 10 with correct values
        in each response, no cross-contamination, double-confirmed."""
        baseline = "<html>normal page</html>"
        hit_49 = "<html>Result: 49 total items</html>"
        hit_10 = "<html>Result: xx total items</html>"  # avoid '10' substring in '49'-free body
        hit_10 = "<html>Report xx: 10 found</html>"
        responses = [
            (0, baseline, ""),      # baseline
            (0, hit_49, ""),        # primary probe ({{7*7}} -> 49)
            (0, hit_10, ""),        # differential probe ({{2*5}} -> 10)
            (0, hit_49, ""),        # double-confirm primary
            (0, hit_10, ""),        # double-confirm differential
        ] + [(0, baseline, "")] * 50
        with patch("scanner.checks.base.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertGreaterEqual(len(c.findings), 1)
            self.assertIn("SSTI", c.findings[0].title)


class TestCRLFDepth(unittest.TestCase):
    def _check(self):
        from scanner.checks.crlf import CRLFCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return CRLFCheck(target="example.com", dirs=dirs,
                        live_hosts=["https://example.com"], threads=1)

    def test_crlf_variants_declared(self):
        from scanner.checks.crlf import CRLFCheck
        labels = {v[0] for v in CRLFCheck.CRLF_VARIANTS}
        self.assertIn("url-pct", labels)
        self.assertIn("double-pct", labels)
        self.assertIn("utf8-overlong", labels)

    def test_baseline_also_reflects_no_finding(self):
        """FP guard: if the marker reflects even WITHOUT CRLF, it's reflection
        not response-splitting."""
        reflected = "HTTP/1.1 200 OK\r\nSet-Cookie: crlf7x7=crlfinj7x7marker\r\n"
        responses = [
            (0, reflected, ""),  # CRLF variant 1 reflects
            (0, reflected, ""),  # baseline WITHOUT CRLF also reflects -> FP
        ] * 10
        with patch("scanner.checks.crlf.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            self.assertEqual(c.findings, [])


class TestHostHeaderDepth(unittest.TestCase):
    def _check(self):
        from scanner.checks.host_header import HostHeaderCheck
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        dirs = create_dirs(self._tmp.name, "example.com")
        return HostHeaderCheck(target="example.com", dirs=dirs,
                              live_hosts=["https://example.com"], threads=1)

    def test_password_reset_paths_defined(self):
        from scanner.checks.host_header import HostHeaderCheck
        self.assertIn("/forgot-password", HostHeaderCheck.PASSWORD_RESET_PATHS)
        self.assertIn("/reset", HostHeaderCheck.PASSWORD_RESET_PATHS)

    def test_xforwarded_reflection_requires_baseline_absence(self):
        """FP guard: if the canary appears in the baseline too, it's
        just coincidence. All probes must return the canary-containing
        body (not just the xforwarded probe)."""
        canary_everywhere = "HTTP/1.1 200 OK\r\n\r\n<html>evil-attacker.com - we know this host</html>"
        # Every request in this test returns the canary body - so the
        # baseline-absence FP guard must trigger.
        responses = [(0, canary_everywhere, "")] * 300
        with patch("scanner.checks.host_header.run",
                   side_effect=make_run(responses)):
            c = self._check()
            c.execute()
            xf = [f for f in c.findings if "X-Forwarded-Host" in f.title]
            self.assertEqual(xf, [])


if __name__ == "__main__":
    unittest.main()
