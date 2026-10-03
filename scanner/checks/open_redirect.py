"""Open redirect vulnerability testing."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class OpenRedirectCheck(BaseCheck):
    name = "Open Redirect"
    description = "Test for unvalidated redirect parameters"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "returnUrl", "goto",
        "dest", "destination", "redir", "redirect_uri", "callback",
        "continue", "target", "link", "to", "out", "view", "ref",
    ]
    CANARY = "https://evil-attacker.com"

    def execute(self) -> list[Finding]:
        for host in self._hosts():
            for param in self.REDIRECT_PARAMS:
                test_url = f"{host}?{param}={self.CANARY}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8", "--max-redirs", "0", test_url],
                    timeout=12,
                )
                if rc == 0 and out:
                    for line in out.splitlines():
                        if line.lower().startswith("location:") and "evil-attacker.com" in line.lower():
                            self.findings.append(Finding(
                                severity="medium",
                                title=f"Open Redirect via ?{param}=",
                                host=host,
                                detail=f"Parameter '{param}' redirects to arbitrary URL",
                                source="open_redirect",
                                url=test_url,
                                evidence=line.strip(),
                            ))
                            break

        return self.findings
