"""CVE-2022-29464 - WSO2 arbitrary file upload."""
from .base import CVEDetector, CVEResult


class WSO2Upload(CVEDetector):
    cve_id = "CVE-2022-29464"
    title = "WSO2 Unrestricted Arbitrary File Upload (endpoint reachable)"
    severity = "high"
    affected = "WSO2 Carbon products (API Manager, Identity Server, Enterprise Integrator)"
    tags = ["cve-2022-29464", "wso2", "file-upload", "rce"]

    PATH = "/fileupload/toolsAny"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.PATH, timeout=8)
        if not body:
            return None
        body_lower = body.lower()
        # Require a WSO2-specific marker (not just "fileupload", which is
        # too generic). "Method Not Allowed" alone can come from any
        # framework that rejects GET on an upload endpoint.
        wso2_markers = ("wso2", "carbon-server", "org.wso2",
                         "wso2carbon", "wso2 identity")
        if any(m in body_lower for m in wso2_markers):
            return CVEResult(
                vulnerable=True,
                url=base + self.PATH,
                evidence=f"WSO2 endpoint reachable (status={status})",
                detail=(
                    "WSO2 Carbon /fileupload/toolsAny reachable. On vulnerable "
                    "versions, arbitrary POST file upload yields webshell -> RCE."
                ),
            )
        return None
