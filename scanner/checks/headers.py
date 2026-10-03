"""Security headers analysis."""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class HeadersCheck(BaseCheck):
    name = "Security Headers"
    description = "Check for missing security headers and server info disclosure"

    # Severity calibrated to realistic risk, not CVSS inflation:
    #  * HSTS missing is MEDIUM, not HIGH - it's a defensive control; actual
    #    exploitation needs an active MITM on first visit.
    #  * CSP / X-Frame-Options missing are LOW - defense-in-depth, don't
    #    themselves enable XSS or clickjacking; a real XSS vuln would be
    #    reported separately by XSSCheck as HIGH/CRITICAL.
    #  * MIME-type sniffing missing stays LOW.
    #  * Referrer-Policy / Permissions-Policy are INFO.
    REQUIRED = {
        "strict-transport-security": ("medium", "HSTS not set - defensive control missing; a first-visit MITM could downgrade."),
        "content-security-policy":   ("low",    "CSP header missing - defense-in-depth against XSS absent."),
        "x-frame-options":           ("low",    "X-Frame-Options missing - clickjacking defense missing."),
        "x-content-type-options":    ("low",    "X-Content-Type-Options missing - MIME sniffing possible."),
        "referrer-policy":           ("info",   "Referrer-Policy not set."),
        "permissions-policy":        ("info",   "Permissions-Policy not set."),
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
                        # Info-only: version disclosure doesn't itself exploit
                        # anything; it only hints at the target stack.
                        self.findings.append(Finding(
                            severity="info",
                            title="Server Version Disclosure",
                            host=host,
                            detail=f"Server header reveals version: {val}",
                            source="headers",
                            url=host,
                            evidence=val,
                        ))

        return self.findings
