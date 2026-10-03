"""CVE-2017-10271 - Oracle WebLogic WLS Security XMLDecoder."""
from .base import CVEDetector, CVEResult


class WeblogicWLSSecurity(CVEDetector):
    cve_id = "CVE-2017-10271"
    title = "Oracle WebLogic WLS Security XMLDecoder RCE (endpoint reachable)"
    severity = "critical"
    affected = "Oracle WebLogic Server 10.x / 12.x pre-patch"
    tags = ["cve-2017-10271", "weblogic", "xmldecoder", "rce"]

    ENDPOINT = "/wls-wsat/CoordinatorPortType"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.ENDPOINT, timeout=8)
        if not body:
            return None
        signals = ("CoordinatorPortType", "wls-wsat", "weblogic.wsee.wstx",
                   "WS-AtomicTransaction")
        if any(s in body for s in signals):
            # Endpoint is reachable; vulnerable if WebLogic version is unpatched.
            # We flag it as high-signal informational so operators patch.
            return CVEResult(
                vulnerable=True,
                url=base + self.ENDPOINT,
                evidence=f"WLS-WSAT endpoint reachable (status={status})",
                detail=(
                    "WebLogic WLS Security endpoint reachable. On unpatched "
                    "10.3.6 / 12.1.3 / 12.2.1 the XMLDecoder deserialization "
                    "yields unauth RCE. Verify version."
                ),
            )
        return None
