"""CVE-2022-22947 - Spring Cloud Gateway SpEL RCE (endpoint reachability)."""
from .base import CVEDetector, CVEResult


class SpringCloudGateway(CVEDetector):
    cve_id = "CVE-2022-22947"
    title = "Spring Cloud Gateway Actuator Reachable (SpEL RCE path)"
    severity = "high"
    affected = "Spring Cloud Gateway 3.1.0 / 3.0.0 - 3.0.6"
    tags = ["cve-2022-22947", "spring", "spel", "rce"]

    def probe(self, base, baseline_body):
        for p in ("/actuator/gateway/routes", "/actuator/gateway/routes/x",
                  "/actuator/gateway/refresh"):
            status, body = self._get(base + p, timeout=8)
            if not body:
                continue
            if ("gateway" in body.lower() and ("predicate" in body.lower()
                                                or "filters" in body.lower()
                                                or "GatewayFilterFactory" in body)):
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence=body[:200],
                    detail=(
                        "Spring Cloud Gateway actuator reachable. Prior to "
                        "3.1.1 / 3.0.7 the gateway accepts SpEL in route filters, "
                        "yielding unauth RCE."
                    ),
                )
        return None
