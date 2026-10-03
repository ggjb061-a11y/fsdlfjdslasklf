"""CVE-2019-19781 - Citrix NetScaler ADC Path Traversal to RCE (Shitrix)."""
from .base import CVEDetector, CVEResult


class CitrixNetScaler(CVEDetector):
    cve_id = "CVE-2019-19781"
    title = "Citrix ADC/NetScaler Path Traversal (Shitrix)"
    severity = "critical"
    affected = "Citrix ADC/NetScaler 10.5/11.1/12.0/12.1/13.0"
    tags = ["cve-2019-19781", "citrix", "netscaler", "path-traversal", "rce"]

    PATHS = [
        "/vpn/../vpns/cfg/smb.conf",
        "/vpn/../vpns/portal/scripts/newbm.pl",
    ]

    def probe(self, base, baseline_body):
        for p in self.PATHS:
            status, body = self._get(base + p, timeout=8)
            if not body:
                continue
            # smb.conf has distinct markers
            if "[global]" in body or "workgroup" in body.lower() \
               or "encrypt passwords" in body.lower() \
               or "#!/usr/bin/perl" in body:
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence=body[:200],
                    detail=(
                        "Citrix NetScaler path traversal reads internal "
                        "config file. CVE-2019-19781 chain yields RCE."
                    ),
                )
        return None
