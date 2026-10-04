"""
Active Cross-Site Scripting (XSS) probing with context detection.

Rejects false positives by:
  1. Verifying the payload is reflected IN THE RESPONSE BODY (not just URL echo)
  2. Classifying reflection context (HTML, attribute, JS, URL)
  3. Confirming context-appropriate payload survives unencoded
"""
import re
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class XSSCheck(BaseCheck):
    """Context-aware reflected XSS detection."""

    name = "XSS"
    description = "Context-aware reflected XSS probing"

    PARAMS = [
        "q", "query", "search", "s", "keyword", "term",
        "name", "msg", "message", "body", "comment",
        "username", "user", "email", "subject", "title",
        "description", "ref", "redirect_url", "callback",
        "input", "text", "content",
    ]

    CANARY = "xssmarker7x7"

    # Each needle MUST include the canary so that minified JS already
    # containing e.g. `;alert(` cannot look like a confirmed payload echo.
    # The byte-exact match in step 3 then only fires when our full probe
    # survived unencoded.
    PAYLOADS = [
        ("html",      f"<script>alert({CANARY})</script>",        f"<script>alert({CANARY})".encode()),
        ("html-img",  f"<img src=x onerror=alert({CANARY})>",     f"onerror=alert({CANARY})".encode()),
        ("html-svg",  f"<svg/onload=alert({CANARY})>",            f"<svg/onload=alert({CANARY})".encode()),
        ("attr",      f"\" autofocus onfocus=alert({CANARY}) x=\"",  f"onfocus=alert({CANARY})".encode()),
        ("js",        f"';alert({CANARY});//",                    f";alert({CANARY})".encode()),
    ]

    def execute(self) -> list[Finding]:
        canary = self.CANARY
        for base in self._hosts():
            for param in self.PARAMS:
                # 1. Benign canary first - must be reflected to even bother probing
                probe_url = f"{base}?{param}={canary}"
                rc, body, _ = run(
                    ["curl", "-sL", "--max-time", "6", probe_url],
                    timeout=10,
                )
                if rc != 0 or not body or canary not in body:
                    continue

                # 2. Determine reflection context
                context = self._context(body, canary)

                # 3. Fire a context-appropriate payload
                for ctx, raw, needle in self.PAYLOADS:
                    if context != "unknown" and ctx not in context:
                        continue
                    url = f"{base}?{param}={urllib.parse.quote(raw, safe='')}"
                    rc, body2, _ = run(
                        ["curl", "-sL", "--max-time", "6", url],
                        timeout=10,
                    )
                    if rc != 0 or not body2:
                        continue
                    # Confirm the payload survives UNENCODED (byte-exact match)
                    if needle in body2.encode(errors="replace"):
                        self.findings.append(Finding(
                            severity="high",
                            title=f"Reflected XSS ({ctx}) via '{param}'",
                            host=base,
                            detail=(
                                f"Parameter '{param}' reflects into {context} context and the "
                                f"'{ctx}' payload survives unencoded. Payload {raw!r} reflected verbatim."
                            ),
                            source="xss",
                            url=url,
                            tags=["xss", "reflected", ctx],
                            evidence=raw,
                        ))
                        return self.findings
        return self.findings

    def _context(self, body: str, canary: str) -> str:
        """Classify where the canary lands in the body."""
        idx = body.find(canary)
        if idx == -1:
            return "unknown"
        # Look back ~200 bytes to detect enclosing context
        prefix = body[max(0, idx - 200):idx]
        suffix = body[idx + len(canary):idx + len(canary) + 200]

        # JS context: inside <script> block or between quotes in a JS variable
        last_script = prefix.rfind("<script")
        last_script_end = prefix.rfind("</script")
        if last_script > last_script_end:
            return "js"
        # Attribute context: `attr="...canary..."`
        if re.search(r'[a-z-]+\s*=\s*["\'][^"\'<>]*$', prefix, re.IGNORECASE):
            return "attr"
        # HTML text context
        if ">" in prefix.split("<")[-1] or ">" not in prefix:
            return "html"
        return "html"
