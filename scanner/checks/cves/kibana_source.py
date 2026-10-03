"""CVE-2019-7609 - Kibana Timelion source RCE."""
from .base import CVEDetector, CVEResult


class KibanaSource(CVEDetector):
    cve_id = "CVE-2019-7609"
    title = "Kibana instance exposed (verify version for CVE-2019-7609)"
    severity = "info"
    affected = "Kibana < 5.6.15 / 6.6.1"
    tags = ["cve-2019-7609", "kibana", "needs-version-check"]

    def probe(self, base, baseline_body):
        status, body = self._get(base + "/api/status", timeout=8)
        if not body:
            return None
        # Only a presence signal, not a vulnerability. The exploit needs
        # a crafted Timelion query and a vulnerable version; neither is
        # verified here. Severity stays INFO until the version is confirmed.
        if '"name":"kibana"' in body.lower() or '"status":{"overall"' in body.lower():
            return CVEResult(
                vulnerable=True,
                url=base + "/api/status",
                evidence="Kibana /api/status reachable",
                detail=(
                    "Kibana /api/status is exposed. CVE-2019-7609 "
                    "(Timelion source -> RCE) affects < 5.6.15 / 6.6.1. "
                    "This check only confirms Kibana presence; verify the "
                    "running version against advisories before escalating."
                ),
            )
        return None
