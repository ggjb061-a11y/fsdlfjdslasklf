"""
Server-Side Template Injection detection with STRONG baseline comparison.

Five independent guards prevent false positives from reflections and
coincidental number occurrences:

  1. Baseline guard: expected result must NOT already appear in baseline.
  2. Primary probe: expected result MUST appear in probe response.
  3. Echo guard: raw payload must NOT appear in response (would mean
     the server is just echoing input, not evaluating).
  4. Differential probe: a SECOND payload with a different expected
     value (e.g. {{2*5}} -> 10) must evaluate to its own result.
     If both the primary and the differential expected values appear
     only in their respective responses (and NOT swapped), evaluation
     is confirmed. If they appear in each other's responses, it's
     just coincidence/reflection.
  5. Double-confirmation: both probes repeated.

This fixes the FP where "@(7*7)" was reported on sites where "49"
appears naturally in page content.
"""
import time
import urllib.parse

from .base import BaseCheck
from ..models import Finding


class SSTICheck(BaseCheck):
    """Differential + baseline-compared SSTI detection (no reflection FPs)."""

    name = "SSTI"
    description = "Differential SSTI detection with 5 false-positive guards"

    # (payload, expected, differential_payload, differential_expected, engines)
    # The differential uses the same engine syntax with different numbers so
    # that an evaluating engine returns a distinct result; a reflecting server
    # returns the same shape of response to both.
    PRIMARY = [
        ("{{7*7}}",       "49",       "{{2*5}}",       "10",       ["Jinja2", "Twig", "Nunjucks"]),
        ("${7*7}",        "49",       "${2*5}",        "10",       ["Freemarker", "Velocity"]),
        ("{7*7}",         "49",       "{2*5}",         "10",       ["Smarty", "Mustache"]),
        ("<%=7*7%>",      "49",       "<%=2*5%>",      "10",       ["ERB/Ruby", "ASP.NET"]),
        ("#{7*7}",        "49",       "#{2*5}",        "10",       ["Pug", "Ruby"]),
        ("{{7*'7'}}",     "7777777",  "{{3*'3'}}",     "333",      ["Jinja2"]),
        ("${{7*7}}",      "49",       "${{2*5}}",      "10",       ["Spring EL"]),
        ("@(7*7)",        "49",       "@(2*5)",        "10",       ["Razor"]),
    ]

    PARAMS = [
        "q", "query", "search", "name", "input",
        "msg", "message", "body", "comment",
        "username", "user", "email", "subject",
        "title", "description", "greeting", "template",
    ]

    def _check_param(self, base: str, param: str) -> bool:
        # Fresh (uncached) baseline specifically for this param
        baseline = self._fetch(self._url(base, param, "AutoVulnScanBaseline"))
        if not baseline:
            return False

        for payload, expected, diff_payload, diff_expected, engines in self.PRIMARY:
            # Guard 1: expected or differential-expected already common in baseline
            if baseline.count(expected) > 2 or baseline.count(diff_expected) > 2:
                continue
            if expected in baseline or diff_expected in baseline:
                continue

            # Guard 2: primary probe
            url = self._url(base, param, payload)
            body = self._fetch(url)
            if not body or len(body) < 10:
                continue

            # Guard 3: raw payload must NOT be echoed verbatim
            if payload in body:
                continue
            # Guard 2 cont: expected must appear
            if expected not in body:
                continue

            # Guard 4: differential probe (different math -> different result)
            diff_url = self._url(base, param, diff_payload)
            diff_body = self._fetch(diff_url)
            if not diff_body:
                continue
            # The differential expected (10) must appear in diff response
            if diff_expected not in diff_body:
                continue
            # And must NOT appear in primary response (would prove coincidence)
            if diff_expected in body:
                continue
            # And primary expected (49) must NOT appear in differential response
            if expected in diff_body:
                continue
            # And raw differential payload must NOT be echoed
            if diff_payload in diff_body:
                continue

            # Guard 5: double-confirm both
            time.sleep(0.3)
            body2 = self._fetch(url)
            diff_body2 = self._fetch(diff_url)
            if (not body2 or not diff_body2
                or expected not in body2
                or diff_expected not in diff_body2
                or payload in body2
                or diff_payload in diff_body2):
                continue

            engine = engines[0] if len(engines) == 1 else " / ".join(engines)
            self.findings.append(Finding(
                severity="critical",
                title=f"SSTI ({engine}) via '{param}'",
                host=base,
                detail=(
                    f"Parameter '{param}' evaluates template expressions.\n"
                    f"  * {payload!r} -> {expected!r} (double-confirmed)\n"
                    f"  * {diff_payload!r} -> {diff_expected!r} (differential probe)\n"
                    f"  * Raw payloads absent from both responses\n"
                    f"  * Expected results NOT present in benign baseline\n"
                    f"  * Expected results NOT swapped between probes\n"
                    f"Confirmed engine family: {engine}"
                ),
                source="ssti",
                url=url,
                tags=["ssti", "rce-potential", engine.lower().replace(" ", "-"),
                      f"param:{param}"],
                evidence=f"{payload}->{expected}; {diff_payload}->{diff_expected}",
            ))
            return True
        return False

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                try:
                    if self._check_param(base, param):
                        break
                except Exception as exc:
                    self.log.debug(f"  ssti {base} {param}: {exc}")
        return self.findings
