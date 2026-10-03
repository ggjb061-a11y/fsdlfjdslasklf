"""Server-Side Request Forgery (SSRF) detection."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SSRFCheck(BaseCheck):
    """Non-cloud SSRF: detects reflections of internal targets back in response bodies."""

    name = "SSRF"
    description = "Test for SSRF via parameters that fetch arbitrary URLs"

    SSRF_PARAMS = [
        "url", "uri", "redirect", "redirect_url", "callback",
        "src", "source", "target", "dest", "destination",
        "link", "proxy", "fetch", "load", "file", "path",
        "image", "img", "img_url", "img_src",
        "feed", "resource", "domain", "endpoint", "host",
    ]

    PROBES = [
        ("localhost", "http://127.0.0.1/"),
        ("file-scheme", "file:///etc/passwd"),
        ("gopher", "gopher://127.0.0.1:6379/_INFO"),
        ("internal", "http://169.254.169.254/"),
    ]

    LOCALHOST_INDICATORS = [
        "root:x:0:0", "nobody:x:",
        "Apache/", "nginx/", "redis_version", "mysql_native",
        "Welcome to nginx",
    ]

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            baseline = self._baseline(base)
            for param in self.SSRF_PARAMS:
                for probe_name, probe_url in self.PROBES:
                    test_url = self._url(base, param, probe_url)
                    body = self._fetch(test_url, timeout=6)
                    if not body or len(body) < 50:
                        continue
                    for indicator in self.LOCALHOST_INDICATORS:
                        if indicator not in body:
                            continue
                        # Baseline guard: if the host's benign response already
                        # contains the indicator (e.g. Apache/nginx error page
                        # mentioning its own banner), it's not SSRF.
                        if baseline and indicator in baseline:
                            continue
                        self.findings.append(Finding(
                            severity="high",
                            title=f"SSRF via parameter '{param}' ({probe_name})",
                            host=base,
                            detail=f"Parameter '{param}' fetches arbitrary URLs; "
                                   f"response contains '{indicator}' indicating internal access",
                            source="ssrf",
                            url=test_url,
                            evidence=indicator,
                        ))
                        return self.findings
        return self.findings
