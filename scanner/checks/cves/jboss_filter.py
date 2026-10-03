"""CVE-2017-12149 - JBoss ReadOnlyAccessFilter deserialization."""
from .base import CVEDetector, CVEResult


class JBossReadOnly(CVEDetector):
    cve_id = "CVE-2017-12149"
    title = "JBoss ReadOnlyAccessFilter Deserialization (endpoint reachable)"
    severity = "high"
    affected = "JBoss EAP 6.x / AS 5.x / 6.x"
    tags = ["cve-2017-12149", "jboss", "deserialization", "rce"]

    ENDPOINTS = ["/invoker/readonly", "/invoker/EJBInvokerServlet",
                 "/invoker/JMXInvokerServlet"]

    def probe(self, base, baseline_body):
        for ep in self.ENDPOINTS:
            status, body = self._get(base + ep, timeout=8)
            if not body:
                continue
            # JBoss returns HTTP 500 with specific error string when
            # endpoint exists but no payload was sent
            if (status in (200, 500) and
                ("JBoss" in body or "org.jboss" in body or "readonly" in body.lower()
                 or "org.jboss.invocation" in body)):
                return CVEResult(
                    vulnerable=True,
                    url=base + ep,
                    evidence=body[:200],
                    detail=(
                        f"JBoss {ep} is reachable. Vulnerable versions "
                        "deserialize attacker-controlled payloads -> RCE."
                    ),
                )
        return None
