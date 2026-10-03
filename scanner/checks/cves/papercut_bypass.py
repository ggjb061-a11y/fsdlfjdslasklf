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
        if "papercut" in body.lower() and ("setup" in body.lower() or "admin" in body.lower()):
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
