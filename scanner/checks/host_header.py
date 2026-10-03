"""Host header injection testing."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from ..constants import ATTACKER_CANARY


class HostHeaderCheck(BaseCheck):
    name = "Host Header Injection"
    description = "Test for Host header manipulation vulnerabilities"

    def execute(self) -> list[Finding]:
        evil_host = ATTACKER_CANARY

        for base in self._hosts():
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "8",
                 "-H", f"Host: {evil_host}", base],
                timeout=12,
            )
            if rc == 0 and out:
                for line in out.splitlines():
                    if line.lower().startswith("location:") and evil_host in line.lower():
                        self.findings.append(Finding(
                            severity="high",
                            title="Host Header Injection - Redirect",
                            host=base,
                            detail="Server redirects to attacker-controlled host via Host header",
                            source="host_header",
                            url=base,
                            evidence=line.strip(),
                        ))
                        break

            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "8",
                 "-H", f"X-Forwarded-Host: {evil_host}", base],
                timeout=12,
            )
            if body and evil_host in body:
                self.findings.append(Finding(
                    severity="medium",
                    title="X-Forwarded-Host Injection",
                    host=base,
                    detail="X-Forwarded-Host value reflected in response body",
                    source="host_header",
                    url=base,
                ))

            rc, out2, _ = run(
                ["curl", "-sI", "--max-time", "8",
                 "-H", f"Host: {evil_host}",
                 "-H", f"X-Forwarded-Host: {evil_host}", base],
                timeout=12,
            )
            if out2:
                for line in out2.splitlines():
                    ll = line.lower()
                    if "set-cookie" in ll and evil_host in ll:
                        self.findings.append(Finding(
                            severity="high",
                            title="Host Header Injection - Cookie Scope",
                            host=base,
                            detail="Injected Host header affects cookie scope",
                            source="host_header",
                            url=base,
                        ))
                        break

        return self.findings
