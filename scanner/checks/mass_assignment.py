"""
Mass Assignment detection for JSON APIs.

Approach:
  Find a JSON-accepting endpoint (POST /users, PUT /profile, etc.) that
  currently works. Send a request with EXTRA sensitive fields injected
  (role, is_admin, verified, premium). If the response's JSON echoes
  those fields OR if a follow-up GET shows them persisted, the API is
  vulnerable.

This check requires auth context to be meaningful; it still probes the
public surface which can reveal mass-assignment on registration endpoints.
"""
import json
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class MassAssignmentCheck(BaseCheck):
    name = "Mass Assignment"
    description = "Detect APIs that accept privileged fields (role, is_admin...) from user input"

    TARGET_PATHS = [
        "/api/register", "/api/signup", "/register", "/signup",
        "/api/users", "/api/profile", "/users/create",
        "/api/account/create", "/api/user",
    ]

    PRIVILEGED_FIELDS = {
        "role": "admin",
        "is_admin": True,
        "isAdmin": True,
        "admin": True,
        "verified": True,
        "is_verified": True,
        "premium": True,
        "is_premium": True,
        "subscription": "premium",
        "credits": 999999,
    }

    def _fetch(self, url: str, method: str = "POST",
               body: str = None, timeout: int = 8) -> tuple[int, str]:
        args = ["curl", "-sk", "--max-time", str(timeout),
                "-X", method,
                "-H", "Content-Type: application/json",
                "-w", "\n__STATUS__:%{http_code}"]
        if body is not None:
            args += ["-d", body]
        args.append(url)
        rc, out, _ = run(args, timeout=timeout + 4)
        if rc != 0 or not out:
            return 0, ""
        m = re.search(r"__STATUS__:(\d+)\s*$", out)
        status = int(m.group(1)) if m else 0
        return status, out[:m.start()] if m else out

    def _check_endpoint(self, url: str) -> None:
        # Baseline: send minimal request
        minimal = json.dumps({"username": "testuser7x7",
                              "email": "test@example.com",
                              "password": "Passw0rd!2024"})
        status1, body1 = self._fetch(url, body=minimal)
        if status1 == 0:
            return

        # Attacker request: add privileged fields
        attacker = {"username": "testuser7x7b",
                    "email": "test2@example.com",
                    "password": "Passw0rd!2024"}
        attacker.update(self.PRIVILEGED_FIELDS)
        status2, body2 = self._fetch(url, body=json.dumps(attacker))

        # If response echoes any of the privileged values
        if status2 and status2 < 400 and body2:
            for field_name, field_value in self.PRIVILEGED_FIELDS.items():
                needle = f'"{field_name}"'
                if needle in body2 and needle not in body1:
                    self.findings.append(Finding(
                        severity="high",
                        title=f"Mass Assignment: '{field_name}' accepted at {url}",
                        host=url,
                        detail=(
                            f"API endpoint {url} accepts privileged field "
                            f"'{field_name}' in request body and reflects it in "
                            f"response. Attackers can elevate privileges at registration."
                        ),
                        source="mass_assignment",
                        url=url,
                        tags=["mass-assignment", f"field:{field_name}"],
                        evidence=body2[:300],
                    ))
                    return

    def execute(self) -> list[Finding]:
        for base in self._hosts(3):
            for path in self.TARGET_PATHS:
                try:
                    self._check_endpoint(base + path)
                except Exception as exc:
                    self.log.debug(f"  mass_assignment {base}{path}: {exc}")
        return self.findings
