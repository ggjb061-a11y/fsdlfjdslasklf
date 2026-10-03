"""CRLF injection testing."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CRLFCheck(BaseCheck):
    name = "CRLF Injection"
    description = "Test for HTTP response splitting via CRLF characters"

    PAYLOADS = [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0aSet-Cookie:crlf=injection",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "\\r\\nSet-Cookie:crlf=injection",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for payload in self.PAYLOADS:
                test_url = f"{base}/{payload}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", "--path-as-is", test_url],
                    timeout=8,
                )
                if rc != 0 or not out:
                    continue
                if "set-cookie: crlf=injection" in out.lower():
                    self.findings.append(Finding(
                        severity="high",
                        title="CRLF Injection - Header Injection",
                        host=base,
                        detail="Server reflects injected headers via CRLF characters in URL path",
                        source="crlf",
                        url=test_url,
                        evidence=out[:300],
                    ))
                    break

            redirect_params = ["url", "redirect", "next", "return", "goto"]
            for param in redirect_params:
                test_url = f"{base}?{param}=%0d%0aSet-Cookie:crlf=param"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", test_url],
                    timeout=8,
                )
                if out and "set-cookie: crlf=param" in out.lower():
                    self.findings.append(Finding(
                        severity="high",
                        title=f"CRLF Injection via Parameter: {param}",
                        host=base,
                        detail=f"Parameter '{param}' allows header injection via CRLF",
                        source="crlf",
                        url=test_url,
                        evidence=out[:300],
                    ))
                    break

        return self.findings
