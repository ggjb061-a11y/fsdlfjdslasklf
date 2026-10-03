"""
Prototype Pollution probing for Node.js APIs.

Approach:
  Send `?__proto__[polluted7x7]=marker` and `?constructor[prototype][polluted7x7]=marker`
  then make a benign follow-up request and look for the marker reflected
  somewhere the server might have serialized a merged object.

False-positive guards:
  - Baseline body must NOT contain the marker.
  - Marker must appear in the FOLLOW-UP response, not the probe response
    (which could just echo).
"""
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class PrototypePollutionCheck(BaseCheck):
    name = "Prototype Pollution"
    description = "Test for Node.js prototype pollution via __proto__ / constructor.prototype"

    MARKER = "pollute7x7marker"

    PAYLOADS = [
        f"__proto__[polluted7x7]={MARKER}",
        f"__proto__.polluted7x7={MARKER}",
        f"constructor[prototype][polluted7x7]={MARKER}",
    ]

    def _fetch(self, url: str) -> str:
        rc, body, _ = run(["curl", "-sL", "--max-time", "6", url], timeout=10)
        return body if rc == 0 and body else ""

    def _check_host(self, base: str) -> None:
        baseline = self._fetch(base)
        if not baseline:
            return
        if self.MARKER in baseline:
            return  # unusable baseline

        for payload in self.PAYLOADS:
            probe_url = f"{base}?{payload}"
            self._fetch(probe_url)  # perform the pollution attempt
            time.sleep(0.4)
            followup = self._fetch(base)
            if self.MARKER in followup and self.MARKER not in baseline:
                # Double-confirm
                followup2 = self._fetch(base)
                if self.MARKER in followup2:
                    self.findings.append(Finding(
                        severity="high",
                        title="Prototype Pollution confirmed",
                        host=base,
                        detail=(
                            f"After sending '{payload}' the follow-up request "
                            f"reflects the marker '{self.MARKER}'. Node.js prototype "
                            f"pollution leaks the attacker-controlled property into "
                            f"subsequent responses."
                        ),
                        source="prototype_pollution",
                        url=probe_url,
                        tags=["prototype-pollution", "node"],
                        evidence=payload,
                    ))
                    return

    def execute(self) -> list[Finding]:
        for base in self._hosts(3):
            try:
                self._check_host(base)
            except Exception as exc:
                self.log.debug(f"  proto_pollution {base}: {exc}")
        return self.findings
