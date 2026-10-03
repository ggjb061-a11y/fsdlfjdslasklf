"""Open redirect vulnerability testing."""
import re
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from ..constants import ATTACKER_CANARY


class OpenRedirectCheck(BaseCheck):
    name = "Open Redirect"
    description = "Test for unvalidated redirect parameters"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "returnUrl", "goto",
        "dest", "destination", "redir", "redirect_uri", "callback",
        "continue", "target", "link", "to", "out", "view", "ref",
    ]

    def execute(self) -> list[Finding]:
        canary = f"https://{ATTACKER_CANARY}"
        host_pattern = re.compile(
            rf"^location:\s*https?://(?:www\.)?{re.escape(ATTACKER_CANARY)}(?:[/:?#]|$)",
            re.IGNORECASE,
        )
        for host in self._hosts():
            for param in self.REDIRECT_PARAMS:
                test_url = f"{host}?{param}={canary}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8", "--max-redirs", "0", test_url],
                    timeout=12,
                )
                if rc != 0 or not out:
                    continue
                for line in out.splitlines():
                    if host_pattern.search(line.strip()):
                        self.findings.append(Finding(
                            severity="medium",
                            title=f"Open Redirect via ?{param}=",
                            host=host,
                            detail=f"Parameter '{param}' redirects to arbitrary host (Location points to attacker domain)",
                            source="open_redirect",
                            url=test_url,
                            evidence=line.strip(),
                        ))
                        break

        return self.findings
