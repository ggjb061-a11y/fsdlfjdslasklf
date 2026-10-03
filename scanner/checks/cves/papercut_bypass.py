"""CVE-2023-27350 - PaperCut Authentication Bypass."""
from .base import CVEDetector, CVEResult


class PaperCutBypass(CVEDetector):
    cve_id = "CVE-2023-27350"
    title = "PaperCut MF/NG Authentication Bypass"
    severity = "critical"
    affected = "PaperCut MF/NG <= 22.0.9"
    tags = ["cve-2023-27350", "papercut", "auth-bypass", "rce"]

    PATH = "/app?service=page/SetupCompleted"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.PATH, timeout=8)
        if not body:
            return None
        # Patched servers redirect to login (status 302/200 with login page).
        # Vulnerable servers return the SetupCompleted page directly with
        # a very specific marker ("Configuration Wizard : Setup Complete",
        # a Next button, or the SetupCompleted service id).
        body_lower = body.lower()
        if "papercut" not in body_lower:
            return None
        strong_markers = [
            "setupcompleted",
            "configuration wizard",
            "setup complete",
            "setup-complete",
        ]
        login_markers = ["login", "sign in", "username", "password"]
        has_strong = any(m in body_lower for m in strong_markers)
        looks_like_login = any(m in body_lower for m in login_markers)
        if has_strong and not looks_like_login:
            return CVEResult(
                vulnerable=True,
                url=base + self.PATH,
                evidence=body[:200],
                detail=(
                    "PaperCut SetupCompleted page reachable without auth. "
                    "Vulnerable versions let an attacker set up an admin "
                    "session via this flow and reach the Scripting feature -> RCE."
                ),
            )
        return None
