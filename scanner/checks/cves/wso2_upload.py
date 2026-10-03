"""CVE-2022-29464 - WSO2 arbitrary file upload."""
from .base import CVEDetector, CVEResult


class WSO2Upload(CVEDetector):
    cve_id = "CVE-2022-29464"
    title = "WSO2 Unrestricted Arbitrary File Upload (endpoint reachable)"
    severity = "critical"
    affected = "WSO2 Carbon products (API Manager, Identity Server, Enterprise Integrator)"
    tags = ["cve-2022-29464", "wso2", "file-upload", "rce"]

    PATH = "/fileupload/toolsAny"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.PATH, timeout=8)
        if not body:
            return None
        # Endpoint responds "Method Not Allowed" (405) or a WSO2-specific
        # error when reachable
        if status in (405, 500) or "wso2" in body.lower() or \
           "carbon" in body.lower() or "fileupload" in body.lower():
            return CVEResult(
                vulnerable=True,
                url=base + self.PATH,
                evidence=f"endpoint reachable (status={status})",
                detail=(
                    "WSO2 Carbon /fileupload/toolsAny reachable. On vulnerable "
                    "versions, arbitrary POST file upload yields webshell -> RCE."
                ),
            )
        return None
