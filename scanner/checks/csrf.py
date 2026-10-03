"""
CSRF detection: find HTML forms missing CSRF tokens.

Approach:
  1. Fetch each live host and any discovered HTML URL.
  2. Parse <form> tags with method=POST (or no method, defaults to GET
     which is generally not CSRF-protectable but we skip it).
  3. For each POST form, scan hidden inputs for a token (common names:
     csrf, _csrf, _token, authenticity_token, __RequestVerificationToken,
     xsrf, csrf_token, csrfmiddlewaretoken, nonce).
  4. If NO token input AND NO SameSite cookie protection, flag it.

Baseline: forms that explicitly post to third-party endpoints (e.g.
google.com, facebook.com) are skipped.
"""
import re
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class CSRFCheck(BaseCheck):
    """Detect HTML forms that lack CSRF protection."""

    name = "CSRF"
    description = "Detect POST forms missing CSRF tokens (anti-CSRF audit)"

    TOKEN_NAMES = re.compile(
        r"\b(csrf|_csrf|_token|authenticity_token|__requestverificationtoken|"
        r"xsrf|csrf_token|csrfmiddlewaretoken|anti.?csrf|nonce|request.?verification)\b",
        re.IGNORECASE,
    )

    # Pages to probe for forms
    FORM_PATHS = [
        "/", "/login", "/signin", "/register", "/signup",
        "/account", "/profile", "/settings", "/admin",
        "/contact", "/forgot-password", "/reset-password",
    ]

    def _fetch(self, url: str) -> tuple[str, str]:
        """Return (body, response_headers)."""
        rc, body, _ = run(["curl", "-sL", "--max-time", "6",
                           "-D", "-", url], timeout=10)
        if rc != 0 or not body:
            return "", ""
        # Split headers / body on first blank line
        split = body.split("\r\n\r\n", 1)
        if len(split) == 2:
            return split[1], split[0]
        split = body.split("\n\n", 1)
        if len(split) == 2:
            return split[1], split[0]
        return body, ""

    def _has_samesite_strict_or_lax(self, headers: str) -> bool:
        headers_low = headers.lower()
        for line in headers_low.splitlines():
            if line.startswith("set-cookie:"):
                # Count sensitive session cookies
                if any(k in line for k in ("session", "sid", "auth", "token",
                                            "csrf", "xsrf")):
                    if "samesite=strict" in line or "samesite=lax" in line:
                        return True
        return False

    def _extract_forms(self, body: str) -> list[dict]:
        """Extract POST forms with their action and hidden fields."""
        forms = []
        for match in re.finditer(
            r"<form\b([^>]*)>(.*?)</form>", body, re.DOTALL | re.IGNORECASE
        ):
            attrs_str = match.group(1)
            inner = match.group(2)
            attrs = {}
            for am in re.finditer(
                r'(\w+)\s*=\s*["\']([^"\']*)["\']', attrs_str
            ):
                attrs[am.group(1).lower()] = am.group(2)
            method = attrs.get("method", "get").lower()
            if method != "post":
                continue
            action = attrs.get("action", "")
            hidden_fields = []
            for im in re.finditer(
                r'<input\b([^>]*)>', inner, re.IGNORECASE
            ):
                iattrs = {}
                for am in re.finditer(
                    r'(\w+)\s*=\s*["\']([^"\']*)["\']', im.group(1)
                ):
                    iattrs[am.group(1).lower()] = am.group(2)
                if iattrs.get("type", "").lower() == "hidden":
                    hidden_fields.append(iattrs.get("name", ""))
            forms.append({
                "action": action,
                "hidden_fields": hidden_fields,
                "snippet": match.group(0)[:300],
            })
        return forms

    def _is_external_action(self, action: str, host: str) -> bool:
        if not action or action.startswith("/") or action.startswith("?") or action.startswith("#"):
            return False
        if "://" not in action:
            return False
        parsed = urllib.parse.urlparse(action)
        host_part = urllib.parse.urlparse(host).netloc
        return parsed.netloc != "" and parsed.netloc != host_part

    def _check_url(self, url: str) -> None:
        body, headers = self._fetch(url)
        if not body:
            return
        has_samesite = self._has_samesite_strict_or_lax(headers)
        forms = self._extract_forms(body)
        for form in forms:
            if self._is_external_action(form["action"], url):
                continue
            has_token = any(self.TOKEN_NAMES.search(f or "")
                            for f in form["hidden_fields"])
            if has_token:
                continue
            # No token + no SameSite cookie - CSRF-vulnerable
            severity = "medium"
            if has_samesite:
                severity = "low"
            action_shown = form["action"] or url
            self.findings.append(Finding(
                severity=severity,
                title=f"CSRF Protection Missing on POST form (action={action_shown[:60]})",
                host=url,
                detail=(
                    f"POST form on {url} action='{action_shown}' has no CSRF "
                    f"token field (checked: csrf/_csrf/_token/authenticity_token/"
                    f"__RequestVerificationToken/xsrf/csrfmiddlewaretoken/nonce). "
                    f"SameSite cookie protection: {'present (Strict/Lax)' if has_samesite else 'absent'}. "
                    f"Hidden fields found: {form['hidden_fields'] or '(none)'}."
                ),
                source="csrf",
                url=url,
                tags=["csrf", "missing-token"] +
                     (["samesite-mitigated"] if has_samesite else []),
                evidence=form["snippet"],
            ))

    def execute(self) -> list[Finding]:
        for host in self._hosts(3):
            for path in self.FORM_PATHS:
                try:
                    self._check_url(f"{host}{path}")
                except Exception as exc:
                    self.log.debug(f"  csrf {host}{path}: {exc}")
        return self.findings
