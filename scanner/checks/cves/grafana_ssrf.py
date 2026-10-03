"""CVE-2020-13379 - Grafana SSRF via image rendering."""
from .base import CVEDetector, CVEResult


class GrafanaSSRF(CVEDetector):
    cve_id = "CVE-2020-13379"
    title = "Grafana SSRF via avatar endpoint"
    severity = "medium"
    affected = "Grafana < 6.7.4 / 7.0.2"
    tags = ["cve-2020-13379", "grafana", "ssrf"]

    def probe(self, base, baseline_body):
        # First confirm it's Grafana
        status, body = self._get(base + "/login", timeout=6)
        if not body or "grafana" not in body.lower():
            return None
        # Probe the vulnerable avatar endpoint
        probe_url = (base + "/avatar/https%3A%2F%2F127.0.0.1%3A443%2Fx")
        status, body = self._get(probe_url, timeout=6)
        if status in (200, 500) and "500" in str(status) and \
           "proxied" not in body.lower():
            return CVEResult(
                vulnerable=True,
                url=probe_url,
                evidence=f"status={status}",
                detail=(
                    "Grafana /avatar endpoint accepts arbitrary URL for "
                    "server-side fetch. Pre-6.7.4 / 7.0.2 this is SSRF."
                ),
            )
        return None
