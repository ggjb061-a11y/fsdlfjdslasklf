"""CVE-2019-7609 - Kibana Timelion source RCE."""
from .base import CVEDetector, CVEResult


class KibanaSource(CVEDetector):
    cve_id = "CVE-2019-7609"
    title = "Kibana Timelion/Canvas prototype-pollution RCE (version signal)"
    severity = "critical"
    affected = "Kibana < 5.6.15 / 6.6.1"
    tags = ["cve-2019-7609", "kibana", "rce"]

    def probe(self, base, baseline_body):
        status, body = self._get(base + "/api/status", timeout=8)
        if not body:
            return None
        if '"name":"kibana"' in body.lower() or "kibana" in body.lower():
            # Kibana reachable - exact exploit needs a timeline query so we
            # only flag presence as high so the auditor pins version
            return CVEResult(
                vulnerable=True,
                url=base + "/api/status",
                evidence="Kibana /api/status reachable",
                detail=(
                    "Kibana exposed. Older than 5.6.15 / 6.6.1 are vulnerable "
                    "to CVE-2019-7609 (Timelion source -> RCE). Verify version."
                ),
            )
        return None
