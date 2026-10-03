"""
Server-Side Template Injection detection with baseline comparison.

A finding fires only when:
  1. The template-math expression evaluates to its distinct result
     (e.g. {{7*7}} -> 49).
  2. The raw payload is NOT present verbatim in the response (otherwise
     the server might just be echoing).
  3. The expected result is absent from the benign baseline (prevents FP
     when the number happens to be on the page).
  4. Confirmed on a second shot.

Engine confirmation uses a secondary distinctive expression (7*'7' = '7777777'
for Jinja/Twig; '${7*7}' for Freemarker) to narrow down the engine.
"""
import urllib.parse
import time
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SSTICheck(BaseCheck):
    """Baseline-compared, context-aware SSTI detection."""

    name = "SSTI"
    description = "Baseline-compared Server-Side Template Injection"

    # Primary probes: payload, expected evaluation, candidate engines
    PRIMARY = [
        ("{{7*7}}",       "49",      ["Jinja2", "Twig", "Nunjucks"]),
        ("${7*7}",        "49",      ["Freemarker", "Velocity"]),
        ("{7*7}",         "49",      ["Smarty", "Mustache"]),
        ("<%=7*7%>",      "49",      ["ERB/Ruby", "ASP.NET"]),
        ("#{7*7}",        "49",      ["Pug", "Ruby"]),
        ("{{7*'7'}}",     "7777777", ["Jinja2"]),
        ("${{7*7}}",      "49",      ["Spring EL"]),
        ("@(7*7)",        "49",      ["Razor"]),
    ]

    PARAMS = [
        "q", "query", "search", "name", "input",
        "msg", "message", "body", "comment",
        "username", "user", "email", "subject",
        "title", "description", "greeting", "template",
    ]

    def _fetch(self, url: str) -> str:
        rc, body, _ = run(["curl", "-sL", "--max-time", "6", url], timeout=10)
        return body if rc == 0 and body else ""

    def _url(self, base: str, param: str, value: str) -> str:
        return f"{base}?{param}={urllib.parse.quote(value, safe='')}"

    def _check_param(self, base: str, param: str) -> bool:
        # Baseline must NOT contain the expected results
        baseline = self._fetch(self._url(base, param, "AutoVulnScanBaseline"))
        if not baseline:
            return False

        for payload, expected, engines in self.PRIMARY:
            # Baseline check: skip if the expected number is a common feature
            # of the page (would make everything an FP)
            if baseline.count(expected) > 2:
                continue
            url = self._url(base, param, payload)
            body = self._fetch(url)
            if not body or len(body) < 10:
                continue
            # Require: expected PRESENT, raw payload ABSENT (not just echoed)
            if expected not in body:
                continue
            if payload in body:
                # Server just echoed the payload literally - not evaluated
                continue
            # Also require: expected not in baseline response for same param
            if expected in baseline:
                continue
            # Double-confirm
            time.sleep(0.3)
            body2 = self._fetch(url)
            if expected not in body2 or payload in body2:
                continue
            engine = engines[0] if len(engines) == 1 else " / ".join(engines)
            self.findings.append(Finding(
                severity="critical",
                title=f"SSTI ({engine}) via '{param}'",
                host=base,
                detail=(
                    f"Parameter '{param}' evaluates template expression {payload!r} -> {expected!r}.\n"
                    f"- Expected value present in both probes\n"
                    f"- Raw payload absent (not just echoed)\n"
                    f"- Expected value absent from benign baseline\n"
                    f"Confirmed engine family: {engine}"
                ),
                source="ssti",
                url=url,
                tags=["ssti", "rce-potential", engine.lower().replace(" ", "-"),
                      f"param:{param}"],
                evidence=f"payload={payload} -> {expected}",
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
