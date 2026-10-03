"""CSP directive and Set-Cookie attribute analyzer."""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CSPCookieCheck(BaseCheck):
    """Audit present CSP for unsafe-inline / wildcard, and Set-Cookie flags."""

    name = "CSP + Cookie Audit"
    description = "Audit Content-Security-Policy for weak directives and Set-Cookie flags"

    def execute(self) -> list[Finding]:
        for host in self._hosts():
            rc, headers, _ = run(
                ["curl", "-sI", "--max-time", "10", "--location", host],
                timeout=15,
            )
            if rc != 0 or not headers:
                continue

            csp_value = None
            cookies = []
            for line in headers.splitlines():
                low = line.lower()
                if low.startswith("content-security-policy:"):
                    csp_value = line.split(":", 1)[1].strip()
                elif low.startswith("set-cookie:"):
                    cookies.append(line.split(":", 1)[1].strip())

            if csp_value:
                self._audit_csp(csp_value, host)
            for cookie in cookies:
                self._audit_cookie(cookie, host)

        return self.findings

    def _audit_csp(self, csp: str, host: str) -> None:
        low = csp.lower()
        if "unsafe-inline" in low:
            self.findings.append(Finding(
                severity="medium",
                title="CSP contains 'unsafe-inline'",
                host=host,
                detail=f"Content-Security-Policy allows inline scripts/styles - XSS protection weakened",
                source="csp",
                url=host,
                evidence=csp[:300],
            ))
        if "unsafe-eval" in low:
            self.findings.append(Finding(
                severity="medium",
                title="CSP contains 'unsafe-eval'",
                host=host,
                detail=f"Content-Security-Policy allows eval() - dangerous code execution",
                source="csp",
                url=host,
                evidence=csp[:300],
            ))
        if re.search(r"(script-src|default-src)\s+[^;]*\*(?:\s|;|$)", low):
            self.findings.append(Finding(
                severity="medium",
                title="CSP contains wildcard script source",
                host=host,
                detail=f"Content-Security-Policy script-src/default-src contains '*' - any origin allowed",
                source="csp",
                url=host,
                evidence=csp[:300],
            ))
        if "frame-ancestors" not in low:
            self.findings.append(Finding(
                severity="low",
                title="CSP missing frame-ancestors directive",
                host=host,
                detail="No frame-ancestors directive - clickjacking protection relies on X-Frame-Options only",
                source="csp",
                url=host,
            ))

    def _audit_cookie(self, cookie: str, host: str) -> None:
        parts = [p.strip() for p in cookie.split(";")]
        name_value = parts[0] if parts else ""
        name = name_value.split("=", 1)[0] if "=" in name_value else name_value
        flags = {p.lower().split("=")[0] for p in parts[1:]}

        is_sensitive = any(k in name.lower() for k in
                           ("session", "sid", "auth", "token", "csrf", "xsrf"))
        is_https = host.startswith("https://")

        missing = []
        if is_https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")

        if missing:
            sev = "medium" if is_sensitive else "low"
            self.findings.append(Finding(
                severity=sev,
                title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                host=host,
                detail=f"Cookie '{name}' lacks {', '.join(missing)}; sensitive cookies without these flags risk hijacking/CSRF",
                source="cookie",
                url=host,
                evidence=cookie[:200],
            ))

        if name.startswith("__Host-") and ("secure" not in flags or "path=/" not in [p.lower() for p in parts]):
            self.findings.append(Finding(
                severity="medium",
                title=f"Cookie '{name}' violates __Host- prefix rules",
                host=host,
                detail="__Host- prefix requires Secure flag and Path=/ (no Domain)",
                source="cookie",
                url=host,
            ))
        if name.startswith("__Secure-") and "secure" not in flags:
            self.findings.append(Finding(
                severity="medium",
                title=f"Cookie '{name}' violates __Secure- prefix rules",
                host=host,
                detail="__Secure- prefix requires Secure flag",
                source="cookie",
                url=host,
            ))
