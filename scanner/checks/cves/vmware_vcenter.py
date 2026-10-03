"""CVE-2021-21972 - VMware vCenter OVA upload path exposure."""
from .base import CVEDetector, CVEResult


class VMwareVCenter(CVEDetector):
    cve_id = "CVE-2021-21972"
    title = "VMware vCenter Server vSphere Client Unauth RCE (endpoint)"
    severity = "critical"
    affected = "vCenter Server 6.5 / 6.7 / 7.0 pre-patch"
    tags = ["cve-2021-21972", "vmware", "vcenter", "rce"]

    PATH = "/ui/vropspluginui/rest/services/uploadova"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.PATH, timeout=8)
        # Vulnerable servers respond 405 Method Not Allowed (reachable, wrong method)
        # Patched/absent respond 404
        if status == 405 or (body and "uploadova" in body.lower()):
            return CVEResult(
                vulnerable=True,
                url=base + self.PATH,
                evidence=f"Endpoint reachable (status={status})",
                detail=(
                    "vCenter vRealize plugin endpoint reachable. On unpatched "
                    "versions, this endpoint accepts OVA uploads unauthenticated "
                    "-> file write -> RCE."
                ),
            )
        return None
