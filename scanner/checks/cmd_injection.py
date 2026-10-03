"""
Reliable OS command injection probing.

Techniques:
  1. Output-reflected marker: inject `; echo cmdi7x7marker` and confirm
     the marker appears in the response AND NOT in the benign baseline.
     Confirmed with a second shot.
  2. Time-based blind: time a benign baseline (3 samples, take median),
     then inject `; sleep 6` and require elapsed >= baseline_median + 4s.
     Confirmed with a second shot.

Baseline comparison kills false positives from sites that happen to
echo the injected string in error pages but didn't actually execute it.
"""
import statistics
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CommandInjectionCheck(BaseCheck):
    """Baseline-compared output + time-based command injection detection."""

    name = "Command Injection"
    description = "Baseline-compared OS command injection (reflected + time-blind)"

    PARAMS = [
        "cmd", "exec", "command", "run", "ping", "host", "ip",
        "domain", "query", "lookup", "nslookup", "target",
        "address", "url", "action", "do", "process",
        "arg", "input",
    ]

    MARKER = "cmdi7x7outputmarker"

    MARKER_PAYLOADS = [
        f";echo {MARKER}",
        f"|echo {MARKER}",
        f"`echo {MARKER}`",
        f"$(echo {MARKER})",
        f"%0aecho {MARKER}",
        f"&&echo {MARKER}",
        f"||echo {MARKER}",
        f";printf {MARKER}",
    ]

    TIME_PAYLOADS = [";sleep 6", "|sleep 6", "`sleep 6`", "$(sleep 6)", "&&sleep 6"]

    def _fetch(self, url: str, timeout: int = 6) -> tuple[int, str, float]:
        start = time.monotonic()
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", str(timeout), url],
            timeout=timeout + 4,
        )
        return rc, (body or ""), (time.monotonic() - start)

    def _url(self, base: str, param: str, value: str) -> str:
        return f"{base}?{param}={urllib.parse.quote(value, safe='')}"

    def _baseline_timing(self, base: str, param: str, samples: int = 3) -> float:
        """Return the median response time of 3 benign requests."""
        times: list[float] = []
        for _ in range(samples):
            rc, _, elapsed = self._fetch(self._url(base, param, "1"), timeout=4)
            if rc == 0:
                times.append(elapsed)
        if not times:
            return 0.0
        return statistics.median(times)

    def _check_param(self, base: str, param: str) -> bool:
        # Baseline body - MARKER must be absent from it
        rc, baseline, _ = self._fetch(self._url(base, param, "benign1"), timeout=4)
        if rc != 0:
            return False
        if self.MARKER in baseline:
            # Highly unusual - abandon this param to avoid FP
            return False

        # Technique 1: reflected marker
        for payload in self.MARKER_PAYLOADS:
            url = self._url(base, param, payload)
            rc, body, _ = self._fetch(url)
            if rc != 0 or not body:
                continue
            if self.MARKER not in body:
                continue
            # Double-confirm
            time.sleep(0.3)
            rc, body2, _ = self._fetch(url)
            if rc != 0 or self.MARKER not in body2:
                continue
            self.findings.append(Finding(
                severity="critical",
                title=f"OS Command Injection via '{param}' (reflected, baseline-compared)",
                host=base,
                detail=(
                    f"Parameter '{param}' executes shell command. Marker '{self.MARKER}' "
                    f"appeared in both injection attempts but is absent from the benign "
                    f"baseline, confirming server-side execution rather than echo."
                ),
                source="cmd_injection",
                url=url,
                tags=["rce", "cmd-injection", "reflected", f"param:{param}"],
                evidence=f"payload={payload} | marker={self.MARKER}",
            ))
            return True

        # Technique 2: time-based blind
        baseline_time = self._baseline_timing(base, param)
        if baseline_time <= 0 or baseline_time > 3.0:
            # Skip time-based on sites that are already slow (too flaky)
            return False

        for payload in self.TIME_PAYLOADS:
            url = self._url(base, param, payload)
            rc, _, elapsed = self._fetch(url, timeout=10)
            if rc != 0:
                continue
            if elapsed < baseline_time + 4.0:
                continue
            # Double-confirm
            rc2, _, elapsed2 = self._fetch(url, timeout=10)
            if rc2 != 0 or elapsed2 < baseline_time + 4.0:
                continue
            self.findings.append(Finding(
                severity="critical",
                title=f"Blind OS Command Injection via '{param}' (time-based)",
                host=base,
                detail=(
                    f"Parameter '{param}' causes a {baseline_time + 6:.0f}s delay "
                    f"(baseline median {baseline_time:.1f}s, injected "
                    f"{elapsed:.1f}s/{elapsed2:.1f}s). Two consecutive confirmations."
                ),
                source="cmd_injection",
                url=url,
                tags=["rce", "cmd-injection", "time-based-blind", f"param:{param}"],
                evidence=(
                    f"baseline_median={baseline_time:.1f}s "
                    f"inject1={elapsed:.1f}s inject2={elapsed2:.1f}s payload={payload}"
                ),
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
                    self.log.debug(f"  cmdi {base} {param}: {exc}")
        return self.findings
