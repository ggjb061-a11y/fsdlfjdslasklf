"""Server-Side Template Injection (SSTI) detection."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SSTICheck(BaseCheck):
    """Detect SSTI by injecting template math expressions and checking for evaluation."""

    name = "SSTI"
    description = "Test for Server-Side Template Injection in parameters"

    PAYLOADS = [
        ("Jinja2/Twig",   "{{7*7}}",       "49"),
        ("Jinja2/Twig",   "${7*7}",        "49"),
        ("Smarty",        "{7*7}",         "49"),
        ("ERB/Ruby",      "<%=7*7%>",      "49"),
        ("Freemarker",    "${7*7}",        "49"),
        ("JinjaMultiply", "{{7*'7'}}",     "7777777"),
    ]

    PARAMS = [
        "q", "query", "search", "name", "input",
        "msg", "message", "body", "comment",
        "username", "user", "email", "subject",
        "title", "description",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                for engine, payload, expected in self.PAYLOADS:
                    import urllib.parse
                    encoded = urllib.parse.quote(payload, safe="")
                    test_url = f"{base}?{param}={encoded}"
                    rc, body, _ = run(
                        ["curl", "-sL", "--max-time", "6", test_url],
                        timeout=10,
                    )
                    if rc != 0 or not body:
                        continue
                    if expected in body and payload not in body:
                        self.findings.append(Finding(
                            severity="critical",
                            title=f"SSTI - {engine} template engine",
                            host=base,
                            detail=f"Parameter '{param}' evaluates template expression {payload} -> {expected}",
                            source="ssti",
                            url=test_url,
                            evidence=f"Payload: {payload} | Evaluated: {expected}",
                        ))
                        return self.findings
        return self.findings
