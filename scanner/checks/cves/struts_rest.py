"""CVE-2017-9805 - Apache Struts REST plugin XStream RCE."""
from .base import CVEDetector, CVEResult


class StrutsREST(CVEDetector):
    cve_id = "CVE-2017-9805"
    title = "Apache Struts REST Plugin XStream RCE (endpoint reachable)"
    severity = "critical"
    affected = "Apache Struts 2.5 - 2.5.12 (REST plugin with XStream)"
    tags = ["cve-2017-9805", "struts", "xstream", "deserialization", "rce"]

    def probe(self, base, baseline_body):
        for p in ("/orders/1", "/struts2-rest-showcase/orders.xhtml",
                  "/rest/orders", "/orders/1.xml"):
            status, body = self._get(base + p, timeout=8)
            if not body:
                continue
            if ("orders" in body.lower() and ("<order" in body.lower() or
                                               "xml" in body.lower() or
                                               "struts" in body.lower())):
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence=body[:200],
                    detail=(
                        "Struts REST plugin endpoint reachable. CVE-2017-9805 "
                        "allows unauth XStream deserialization -> RCE."
                    ),
                )
        return None
