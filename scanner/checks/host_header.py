"""
Host header injection detection: covers 4 attack classes.

1. Redirect poisoning: Host header manipulates Location in redirect.
2. X-Forwarded-Host reflection in response body.
3. Password-reset poisoning: body contains attacker-controlled URL
   (common on /forgot-password endpoints).
4. Cache-poisoning signal: unkeyed Host header reflected into cacheable
   response (Content-Type: text/html + no Vary on Host).
"""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from ..constants import ATTACKER_CANARY


class HostHeaderCheck(BaseCheck):
    """Comprehensive Host header injection detection."""

    name = "Host Header Injection"
    description = (
        "Host header injection: redirect poisoning, X-Forwarded-Host reflection, "
        "password-reset poisoning, cache-poisoning signal."
    )

    PASSWORD_RESET_PATHS = [
        "/forgot-password", "/forgot", "/reset", "/password-reset",
        "/reset-password", "/user/forgot", "/account/forgot",
        "/api/user/forgot-password", "/api/auth/forgot",
    ]

    def _check_redirect(self, base: str, canary: str) -> bool:
        rc, out, _ = run(
            ["curl", "-sI", "--max-time", "8",
             "-H", f"Host: {canary}", base],
            timeout=12,
        )
        if rc != 0 or not out:
            return False
        for line in out.splitlines():
            if line.lower().startswith("location:") and canary in line.lower():
                self.findings.append(Finding(
                    severity="high",
                    title="Host Header Injection - Redirect to attacker-controlled host",
                    host=base,
                    detail=(
                        f"Server redirects to attacker-controlled host when Host "
                        f"header is set to '{canary}'. Enables phishing + token theft."
                    ),
                    source="host_header",
                    url=base,
                    tags=["host-header", "redirect-poisoning"],
                    evidence=line.strip(),
                ))
                return True
        return False

    def _check_xforwarded_reflect(self, base: str, canary: str) -> bool:
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "8",
             "-H", f"X-Forwarded-Host: {canary}",
             "-H", f"X-Forwarded-Server: {canary}", base],
            timeout=12,
        )
        if body and canary in body:
            # Baseline: without the header, canary must NOT appear
            rc2, body2, _ = run(
                ["curl", "-sL", "--max-time", "8", base], timeout=12,
            )
            if body2 and canary not in body2:
                self.findings.append(Finding(
                    severity="medium",
                    title="X-Forwarded-Host Reflection",
                    host=base,
                    detail=(
                        f"X-Forwarded-Host value reflected in response body. "
                        f"Baseline (without header) does NOT contain the canary."
                    ),
                    source="host_header",
                    url=base,
                    tags=["host-header", "x-forwarded-host"],
                ))
                return True
        return False

    def _check_password_reset(self, base: str, canary: str) -> bool:
        for path in self.PASSWORD_RESET_PATHS:
            url = f"{base}{path}"
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "8",
                 "-X", "POST",
                 "-H", f"Host: {canary}",
                 "-d", "email=test@example.com", url],
                timeout=12,
            )
            if not body:
                continue
            # Look for the canary host inside what looks like a reset link
            if canary in body and ("reset" in body.lower() or "token" in body.lower()
                                    or "/password" in body.lower()):
                self.findings.append(Finding(
                    severity="high",
                    title=f"Password-Reset Poisoning via Host header ({path})",
                    host=base,
                    detail=(
                        f"Password-reset endpoint {url} includes the attacker-"
                        f"controlled Host '{canary}' in the response body. "
                        f"When the real victim triggers reset, the email will "
                        f"link to the attacker's host, leaking the reset token."
                    ),
                    source="host_header",
                    url=url,
                    tags=["host-header", "password-reset-poisoning", "critical-flow"],
                ))
                return True
        return False

    def _check_cache_poison_signal(self, base: str, canary: str) -> bool:
        rc, headers, _ = run(
            ["curl", "-sI", "--max-time", "8",
             "-H", f"X-Forwarded-Host: {canary}", base],
            timeout=12,
        )
        if rc != 0 or not headers:
            return False
        headers_low = headers.lower()

        # Only interesting if the response is cacheable AND Host is not keyed
        cacheable = any(sig in headers_low for sig in [
            "cache-control: public",
            "x-cache: hit",
            "age: ",
            "cdn-cache",
            "cf-cache-status",
        ])
        host_not_keyed = "vary:" not in headers_low or "host" not in \
            re.search(r"vary:\s*(.*)", headers_low, re.IGNORECASE).group(1) \
            if re.search(r"vary:", headers_low) else True
        has_canary_reflection = canary in headers_low

        if cacheable and host_not_keyed and has_canary_reflection:
            self.findings.append(Finding(
                severity="high",
                title="Cache Poisoning Signal via X-Forwarded-Host",
                host=base,
                detail=(
                    f"Response is cacheable (public / X-Cache: HIT / Age / CDN) "
                    f"AND unkeyed on Host AND X-Forwarded-Host is reflected. "
                    f"Poisoning the cache with attacker Host likely feasible."
                ),
                source="host_header",
                url=base,
                tags=["host-header", "cache-poisoning"],
            ))
            return True
        return False

    def execute(self) -> list[Finding]:
        canary = ATTACKER_CANARY
        for base in self._hosts():
            try:
                self._check_redirect(base, canary)
                self._check_xforwarded_reflect(base, canary)
                self._check_password_reset(base, canary)
                self._check_cache_poison_signal(base, canary)
            except Exception as exc:
                self.log.debug(f"  host_header {base}: {exc}")
        return self.findings
