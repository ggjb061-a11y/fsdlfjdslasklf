"""Security headers analysis."""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class HeadersCheck(BaseCheck):
    name = "Security Headers"
    description = "Check for missing security headers and server info disclosure"

    REQUIRED = {
        "strict-transport-security": ("high",   "HSTS not set - downgrade attack possible"),
        "content-security-policy":   ("medium", "CSP missing - XSS risk increased"),
        "x-frame-options":           ("medium", "Clickjacking protection missing"),
        "x-content-type-options":    ("low",    "MIME sniffing protection missing"),
        "referrer-policy":           ("info",   "Referrer-Policy not set"),
        "permissions-policy":        ("info",   "Permissions-Policy not set"),
    }

    def execute(self) -> list[Finding]:
        for host in self._hosts():
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "10", "--location", host],
                timeout=15,
            )
            if rc != 0 or not out:
                continue
            out_lower = out.lower()

            if host.startswith("http://"):
                if "location: https://" not in out_lower:
                    self.findings.append(Finding(
                        severity="medium",
                        title="No HTTPS Redirect",
                        host=host,
                        detail="HTTP site does not redirect to HTTPS.",
                        source="headers",
                        url=host,
                    ))

            for header, (sev, msg) in self.REQUIRED.items():
                if header not in out_lower:
                    self.findings.append(Finding(
                        severity=sev,
                        title=f"Missing Header: {header}",
                        host=host,
                        detail=msg,
                        source="headers",
                        url=host,
                    ))

            for line in out.splitlines():
                if line.lower().startswith("server:"):
                    val = line.split(":", 1)[1].strip()
                    if re.search(r"\d+\.\d+", val):
                        self.findings.append(Finding(
                            severity="low",
                            title="Server Version Disclosure",
                            host=host,
                            detail=f"Server header reveals version: {val}",
                            source="headers",
                            url=host,
                            evidence=val,
                        ))

        return self.findings
