"""CVE-2019-2725 - Oracle WebLogic AsyncResponseService."""
from .base import CVEDetector, CVEResult


class WeblogicAsyncResponseService(CVEDetector):
    cve_id = "CVE-2019-2725"
    title = "Oracle WebLogic AsyncResponseService deserialization (endpoint reachable)"
    severity = "high"
    affected = "Oracle WebLogic Server 10.3.6.0 / 12.1.3.0"
    tags = ["cve-2019-2725", "weblogic", "deserialization", "rce"]

    ENDPOINTS = [
        "/_async/AsyncResponseService",
        "/_async/AsyncResponseServiceHttps",
        "/_async/AsyncResponseServiceJms",
    ]

    def probe(self, base, baseline_body):
        for ep in self.ENDPOINTS:
            status, body = self._get(base + ep, timeout=8)
            if not body:
                continue
            if ("AsyncResponseService" in body or
                "weblogic.wsee" in body or
                "<address>" in body and "wsdl" in body.lower()):
                return CVEResult(
                    vulnerable=True,
                    url=base + ep,
                    evidence="AsyncResponseService endpoint reachable",
                    detail=(
                        f"WebLogic {ep} is reachable. On unpatched versions, "
                        "this endpoint accepts crafted SOAP that triggers "
                        "deserialization -> unauth RCE (CVE-2019-2725)."
                    ),
                )
        return None
