"""CVE-2020-13379 - Grafana SSRF via image rendering."""
from .base import CVEDetector, CVEResult


class GrafanaSSRF(CVEDetector):
    cve_id = "CVE-2020-13379"
    title = "Grafana SSRF via avatar endpoint"
    severity = "medium"
    affected = "Grafana < 6.7.4 / 7.0.2"
    tags = ["cve-2020-13379", "grafana", "ssrf"]

    def probe(self, base, baseline_body):
        # First confirm it's Grafana AND baseline doesn't already carry
        # the proxy-fetch signatures (base-class invariant).
        status, body = self._get(base + "/login", timeout=6)
        if not body or "grafana" not in body.lower():
            return None
        # Differential probe: compare the avatar fetch with an attacker URL
        # against the same endpoint with a benign Gravatar hash. A real
        # SSRF makes the server perform an outbound fetch to 127.0.0.1:443
        # that typically takes longer and errors with a connect-refused or
        # TLS mismatch; a patched/non-vulnerable Grafana rejects the input.
        attacker_url = base + "/avatar/https%3A%2F%2F127.0.0.1%3A443%2Fx"
        benign_url = base + "/avatar/0" * 1  # a plain path, no scheme
        a_status, a_body = self._get(attacker_url, timeout=6)
        b_status, b_body = self._get(benign_url, timeout=6)
        if not a_body:
            return None
        proxy_markers = ("tls:", "x509:", "connection refused",
                          "no such host", "handshake", "eof")
        a_low = a_body.lower()
        b_low = (b_body or "").lower()
        has_marker = any(m in a_low for m in proxy_markers)
        baseline_has = any(m in baseline_body.lower() for m in proxy_markers) \
                       or any(m in b_low for m in proxy_markers)
        if has_marker and not baseline_has and a_status != b_status:
            return CVEResult(
                vulnerable=True,
                url=attacker_url,
                evidence=(
                    f"attacker_status={a_status} benign_status={b_status} "
                    f"differential markers present only in attacker response"
                ),
                detail=(
                    "Grafana /avatar endpoint attempted a server-side fetch "
                    "to 127.0.0.1:443 and leaked connect-level errors. "
                    "Pre-6.7.4 / 7.0.2 is vulnerable to CVE-2020-13379 SSRF."
                ),
            )
        return None
