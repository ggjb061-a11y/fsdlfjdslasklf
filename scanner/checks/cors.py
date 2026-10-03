"""CORS misconfiguration detection."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CORSCheck(BaseCheck):
    name = "CORS"
    description = "Detect CORS misconfigurations that allow cross-origin attacks"

    def execute(self) -> list[Finding]:
        for host in self._hosts(10):
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "10",
                 "-H", "Origin: https://evil-attacker.com", host],
                timeout=15,
            )
            if rc != 0 or not out:
                continue
            out_lower = out.lower()

            if "access-control-allow-origin: https://evil-attacker.com" in out_lower:
                cred = "access-control-allow-credentials: true" in out_lower
                sev = "critical" if cred else "high"
                self.findings.append(Finding(
                    severity=sev,
                    title="CORS Misconfiguration - Reflects Arbitrary Origin",
                    host=host,
                    detail=(
                        "Server reflects attacker-controlled Origin in ACAO header"
                        + (" WITH credentials allowed - full account takeover possible." if cred
                           else " - sensitive data exposure possible.")
                    ),
                    source="cors",
                    url=host,
                ))
            elif "access-control-allow-origin: *" in out_lower:
                if "access-control-allow-credentials: true" in out_lower:
                    self.findings.append(Finding(
                        severity="high",
                        title="CORS Wildcard + Credentials",
                        host=host,
                        detail="Wildcard ACAO with credentials is invalid per spec but may be exploitable.",
                        source="cors",
                        url=host,
                    ))

            rc2, out2, _ = run(
                ["curl", "-sI", "--max-time", "10",
                 "-H", f"Origin: https://{self.target}.evil.com", host],
                timeout=15,
            )
            if out2 and f"access-control-allow-origin: https://{self.target}.evil.com" in out2.lower():
                self.findings.append(Finding(
                    severity="high",
                    title="CORS Origin Suffix Bypass",
                    host=host,
                    detail=f"Server trusts origins ending with the target domain (prefix-match bypass)",
                    source="cors",
                    url=host,
                ))

        return self.findings
