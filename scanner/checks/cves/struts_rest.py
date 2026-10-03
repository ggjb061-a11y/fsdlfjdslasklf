"""CVE-2017-9805 - Apache Struts REST plugin XStream RCE."""
from .base import CVEDetector, CVEResult


class StrutsREST(CVEDetector):
    cve_id = "CVE-2017-9805"
    title = "Apache Struts REST Plugin XStream RCE (endpoint reachable)"
    severity = "high"
    affected = "Apache Struts 2.5 - 2.5.12 (REST plugin with XStream)"
    tags = ["cve-2017-9805", "struts", "xstream", "deserialization", "rce"]

    def probe(self, base, baseline_body):
        for p in ("/orders/1", "/struts2-rest-showcase/orders.xhtml",
                  "/rest/orders", "/orders/1.xml"):
            status, body = self._get(base + p, timeout=8)
            if not body:
                continue
            body_lower = body.lower()
            # Require TWO distinct Struts-specific markers to fire. "orders"
            # alone is too generic (many e-commerce sites return it) so we
            # also require a Struts/XStream fingerprint plus an XML body.
            struts_markers = ("struts2", "org.apache.struts",
                               "xstream", "x-struts", "struts-rest")
            if not any(m in body_lower for m in struts_markers):
                continue
            if "<order" not in body_lower and "<orders" not in body_lower:
                continue
            if "<order" in baseline_body.lower():
                continue
            return CVEResult(
                vulnerable=True,
                url=base + p,
                evidence=body[:200],
                detail=(
                    "Struts REST plugin endpoint reachable. CVE-2017-9805 "
                    "allows unauth XStream deserialization -> RCE on "
                    "vulnerable versions."
                ),
            )
        return None
