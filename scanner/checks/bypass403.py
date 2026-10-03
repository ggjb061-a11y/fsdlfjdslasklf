"""403 Forbidden bypass techniques."""
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class Bypass403Check(BaseCheck):
    name = "403 Bypass"
    description = "Test common techniques to bypass 403 Forbidden restrictions"

    BYPASS_HEADERS = [
        ["-H", "X-Original-URL: /"],
        ["-H", "X-Rewrite-URL: /"],
        ["-H", "X-Forwarded-For: 127.0.0.1"],
        ["-H", "X-Custom-IP-Authorization: 127.0.0.1"],
        ["-H", "X-Forwarded-Host: localhost"],
        ["-H", "X-Real-IP: 127.0.0.1"],
        ["-H", "X-Remote-IP: 127.0.0.1"],
        ["-H", "X-Client-IP: 127.0.0.1"],
        ["-H", "X-Host: localhost"],
    ]

    PATH_BYPASSES = [
        "/%2e/",
        "/./",
        "/.;/",
        "/..;/",
        "//",
    ]

    def execute(self) -> list[Finding]:
        for host in self._hosts(3):
            rc, out, _ = run(["curl", "-sI", "--max-time", "8", host], timeout=12)
            if not out or not out.splitlines():
                continue
            first = out.splitlines()[0]
            if self._status_code(first) != 403:
                continue

            for extra in self.BYPASS_HEADERS:
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8"] + extra + [host],
                    timeout=12,
                )
                code = self._status_code(out.splitlines()[0] if out and out.splitlines() else "")
                if code in (200, 301, 302):
                    hdr = extra[1] if len(extra) > 1 else ""
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"403 Bypass via Header: {hdr.split(':')[0]}",
                        host=host,
                        detail=f"Header {hdr} returns {code} where base returned 403",
                        source="403_bypass",
                        url=host,
                        evidence=hdr,
                    ))
                    break

            for suffix in self.PATH_BYPASSES:
                test_url = f"{host}{suffix}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", "--path-as-is", test_url],
                    timeout=8,
                )
                code = self._status_code(out.splitlines()[0] if out and out.splitlines() else "")
                if code == 200:
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"403 Bypass via Path: {suffix}",
                        host=host,
                        detail=f"Path manipulation {suffix} returns 200",
                        source="403_bypass",
                        url=test_url,
                    ))
                    break

        return self.findings
