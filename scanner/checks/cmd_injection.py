"""OS command injection probing."""
import time
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CommandInjectionCheck(BaseCheck):
    """Fire shell separators and detect command output / time delay."""

    name = "Command Injection"
    description = "Test for OS command injection via shell separators"

    PARAMS = [
        "cmd", "exec", "command", "run", "ping", "host", "ip",
        "domain", "query", "lookup", "nslookup", "target",
        "address", "url", "action", "do", "process",
    ]

    MARKER_PAYLOADS = [
        ";echo cmdi7x7marker",
        "|echo cmdi7x7marker",
        "`echo cmdi7x7marker`",
        "$(echo cmdi7x7marker)",
        "%0aecho cmdi7x7marker",
        "&&echo cmdi7x7marker",
    ]

    TIME_PAYLOADS = [";sleep 5", "|sleep 5", "`sleep 5`", "$(sleep 5)"]

    def execute(self) -> list[Finding]:
        marker = "cmdi7x7marker"
        for base in self._hosts():
            for param in self.PARAMS:
                for payload in self.MARKER_PAYLOADS:
                    import urllib.parse
                    enc = urllib.parse.quote(payload, safe="")
                    test_url = f"{base}?{param}={enc}"
                    rc, body, _ = run(
                        ["curl", "-sL", "--max-time", "6", test_url],
                        timeout=10,
                    )
                    if rc == 0 and body and marker in body:
                        self.findings.append(Finding(
                            severity="critical",
                            title=f"OS Command Injection via '{param}' (output reflected)",
                            host=base,
                            detail=f"Parameter '{param}' executes shell command; marker '{marker}' appeared in response",
                            source="cmd_injection",
                            url=test_url,
                            evidence=marker,
                        ))
                        return self.findings

                for payload in self.TIME_PAYLOADS:
                    import urllib.parse
                    enc = urllib.parse.quote(payload, safe="")
                    test_url = f"{base}?{param}={enc}"
                    start = len(payload) + 2
                    rc_fast, _, _ = run(
                        ["curl", "-s", "--max-time", "3",
                         f"{base}?{param}=normal"],
                        timeout=5,
                    )
                    rc_slow, body, _ = run(
                        ["curl", "-s", "--max-time", "8", test_url],
                        timeout=12,
                    )
                    if rc_fast == 0 and rc_slow == -1:
                        self.findings.append(Finding(
                            severity="critical",
                            title=f"Blind OS Command Injection via '{param}' (time-based)",
                            host=base,
                            detail=f"Parameter '{param}' sleeps 5s with payload {payload}",
                            source="cmd_injection",
                            url=test_url,
                            evidence=payload,
                        ))
                        return self.findings
        return self.findings
