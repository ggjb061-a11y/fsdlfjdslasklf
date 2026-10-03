"""
Session management checks:
  1. Weak session cookie entropy (Shannon entropy)
  2. Session cookies without Secure flag on HTTPS site
  3. Session cookies without HttpOnly flag
"""
import math
import re
from collections import Counter
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class SessionMgmtCheck(BaseCheck):
    name = "Session Management"
    description = "Weak session cookie entropy, missing flags"

    SESSION_COOKIE_NAMES = re.compile(
        r"(session|sid|phpsessid|jsessionid|aspsessionid|aspxauth|cfid|cftoken|"
        r"laravel_session|django_session|rails_session|csrftoken|auth_token|"
        r"token|xsrf)",
        re.IGNORECASE,
    )

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _parse_set_cookie_lines(self, headers: str) -> list[tuple[str, str, dict]]:
        """Return [(name, value, {flag: True})] from Set-Cookie headers."""
        out = []
        for line in headers.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            raw = line.split(":", 1)[1].strip()
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
            name_value = parts[0]
            if "=" not in name_value:
                continue
            name, value = name_value.split("=", 1)
            flags = {}
            for attr in parts[1:]:
                low = attr.lower()
                if "=" in low:
                    k, v = low.split("=", 1)
                    flags[k.strip()] = v.strip()
                else:
                    flags[low] = True
            out.append((name.strip(), value.strip(), flags))
        return out

    def _fetch_headers(self, url: str) -> str:
        rc, body, _ = run(["curl", "-skI", "--max-time", "8", url], timeout=12)
        return body if rc == 0 and body else ""

    def _check_host(self, url: str) -> None:
        headers = self._fetch_headers(url)
        if not headers:
            return
        is_https = url.startswith("https://")
        for name, value, flags in self._parse_set_cookie_lines(headers):
            if not self.SESSION_COOKIE_NAMES.search(name):
                continue
            # Entropy check
            entropy = self._shannon_entropy(value)
            # Session IDs typically have >3.5 bits/char from base64/hex alphabets.
            # Values of < 2.5 bits/char on a cookie 8+ chars long are suspicious.
            if len(value) >= 8 and entropy < 2.5:
                self.findings.append(Finding(
                    severity="high",
                    title=f"Weak session cookie entropy: {name}",
                    host=url,
                    detail=(
                        f"Cookie '{name}' has {entropy:.2f} bits/char Shannon entropy "
                        f"over {len(value)} chars. Session tokens should be at least "
                        f"3.5 bits/char. Value may be predictable."
                    ),
                    source="session_mgmt",
                    url=url,
                    tags=["session", "weak-entropy", f"cookie:{name}"],
                    evidence=f"value={value[:80]!r} entropy={entropy:.2f}",
                ))
            # Secure / HttpOnly flags
            if is_https and "secure" not in flags:
                self.findings.append(Finding(
                    severity="medium",
                    title=f"Session cookie '{name}' missing Secure flag on HTTPS",
                    host=url,
                    detail=f"'{name}' on an HTTPS host without Secure flag may leak over plaintext.",
                    source="session_mgmt",
                    url=url,
                    tags=["session", "missing-secure", f"cookie:{name}"],
                ))
            if "httponly" not in flags:
                self.findings.append(Finding(
                    severity="medium",
                    title=f"Session cookie '{name}' missing HttpOnly flag",
                    host=url,
                    detail=f"'{name}' without HttpOnly is readable from JS - XSS -> session theft.",
                    source="session_mgmt",
                    url=url,
                    tags=["session", "missing-httponly", f"cookie:{name}"],
                ))

    def execute(self) -> list[Finding]:
        for url in self._hosts(5):
            try:
                self._check_host(url)
            except Exception as exc:
                self.log.debug(f"  session {url}: {exc}")
        return self.findings
