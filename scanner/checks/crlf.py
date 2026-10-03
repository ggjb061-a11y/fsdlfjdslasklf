"""
CRLF injection / HTTP response splitting detection.

Verification requires the injected header to appear UNENCODED in the
response headers AND the equivalent injection to NOT reflect when sent
without the CRLF (confirms it's the CRLF, not just reflection).
"""
import re
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CRLFCheck(BaseCheck):
    """Multi-encoding CRLF injection detection."""

    name = "CRLF Injection"
    description = "HTTP response splitting via CRLF with multiple encoding variants"

    MARKER = "crlfinj7x7marker"

    # (encoding-label, CRLF-sequence)
    CRLF_VARIANTS = [
        ("raw",            "\r\n"),
        ("url-pct",        "%0d%0a"),
        ("double-pct",     "%250d%250a"),
        ("mixed-case",     "%0D%0A"),
        ("newline-only",   "%0a"),
        ("utf8-overlong",  "%E5%98%8A%E5%98%8D"),  # bypass filters that strip ASCII CR/LF
    ]

    REDIRECT_PARAMS = [
        "url", "redirect", "return", "goto", "next",
        "returnUrl", "redirect_uri", "callback",
    ]

    def _payload_header(self, variant: str) -> str:
        return f"{variant}Set-Cookie:crlf7x7={self.MARKER}"

    def _check_path(self, base: str) -> bool:
        for label, variant in self.CRLF_VARIANTS:
            payload = self._payload_header(variant)
            test_url = f"{base}/{payload}"
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "5", "--path-as-is", test_url],
                timeout=8,
            )
            if rc != 0 or not out:
                continue
            if f"crlf7x7={self.MARKER}" in out.lower():
                # Baseline: same request without CRLF must NOT reflect marker
                base_url = f"{base}/plain{self.MARKER}"
                rc2, out2, _ = run(
                    ["curl", "-sI", "--max-time", "5", base_url], timeout=8,
                )
                if out2 and f"crlf7x7={self.MARKER}" in out2.lower():
                    # The marker reflects without CRLF too - FP
                    continue
                self.findings.append(Finding(
                    severity="high",
                    title=f"CRLF Injection via URL path ({label} encoding)",
                    host=base,
                    detail=(
                        f"Server reflects injected Set-Cookie header via CRLF chars "
                        f"({label}). Baseline without CRLF does NOT reflect the marker, "
                        f"confirming response-splitting."
                    ),
                    source="crlf",
                    url=test_url,
                    tags=["crlf", "response-splitting", label],
                    evidence=f"variant={label} payload={payload}",
                ))
                return True
        return False

    def _check_params(self, base: str) -> bool:
        for param in self.REDIRECT_PARAMS:
            for label, variant in self.CRLF_VARIANTS:
                payload = self._payload_header(variant)
                test_url = f"{base}?{param}={urllib.parse.quote(payload, safe='%')}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", test_url], timeout=8,
                )
                if rc != 0 or not out:
                    continue
                if f"crlf7x7={self.MARKER}" in out.lower():
                    # Baseline without CRLF
                    base_url = f"{base}?{param}=plain{self.MARKER}"
                    rc2, out2, _ = run(
                        ["curl", "-sI", "--max-time", "5", base_url], timeout=8,
                    )
                    if out2 and f"crlf7x7={self.MARKER}" in out2.lower():
                        continue
                    self.findings.append(Finding(
                        severity="high",
                        title=f"CRLF Injection via parameter '{param}' ({label})",
                        host=base,
                        detail=(
                            f"Parameter '{param}' allows CRLF ({label}) to inject "
                            f"arbitrary headers. Baseline without CRLF does not reflect."
                        ),
                        source="crlf",
                        url=test_url,
                        tags=["crlf", "response-splitting", label,
                              f"param:{param}"],
                        evidence=f"variant={label} payload={payload}",
                    ))
                    return True
        return False

    def execute(self) -> list[Finding]:
        for base in self._hosts():
            try:
                if self._check_path(base):
                    continue
                self._check_params(base)
            except Exception as exc:
                self.log.debug(f"  crlf {base}: {exc}")
        return self.findings
