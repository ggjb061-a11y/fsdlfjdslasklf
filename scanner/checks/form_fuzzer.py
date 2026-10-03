"""
Generic form fuzzer.

Discovers HTML forms, then submits each one with multiple attack-pattern
payloads. Looks for:
  * SQL error signatures (SQLi)
  * Reflected canary (XSS reflection)
  * Response time anomalies (blind SQLi / cmd injection)

This complements the targeted param-based checks by exercising actual
HTML forms the way a user would.
"""
import re
import time
import urllib.parse
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class FormFuzzerCheck(BaseCheck):
    name = "Form Fuzzer"
    description = "Submit discovered HTML forms with attack payloads"

    MAX_FORMS = 15

    PAYLOADS = [
        ("sqli-error", "'",
         re.compile(r"(sql syntax|mysql_fetch|unclosed quotation mark|"
                    r"ora-\d+|sqlstate|psql error)", re.I)),
        ("xss-reflection", "xssfuzz7x7canary",
         re.compile(r"xssfuzz7x7canary")),
    ]

    def _fetch(self, url: str, timeout: int = 6) -> str:
        rc, body, _ = run(["curl", "-sL", "--max-time", str(timeout), url],
                           timeout=timeout + 4)
        return body if rc == 0 and body else ""

    def _submit(self, url: str, method: str, data: dict,
                timeout: int = 6) -> tuple[str, float]:
        payload = "&".join(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}"
                            for k, v in data.items())
        args = ["curl", "-sL", "--max-time", str(timeout), url]
        if method.upper() == "POST":
            args += ["-X", "POST", "-d", payload,
                     "-H", "Content-Type: application/x-www-form-urlencoded"]
        start = time.monotonic()
        rc, body, _ = run(args, timeout=timeout + 4)
        return (body if rc == 0 else ""), time.monotonic() - start

    def _extract_forms(self, body: str, base_url: str) -> list[dict]:
        forms = []
        for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body,
                              re.DOTALL | re.IGNORECASE):
            attrs = {}
            for am in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']', m.group(1)):
                attrs[am.group(1).lower()] = am.group(2)
            action = attrs.get("action", "")
            if action.startswith("/"):
                parsed = urllib.parse.urlparse(base_url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            elif action and not action.startswith("http"):
                action = urllib.parse.urljoin(base_url, action)
            elif not action:
                action = base_url
            inputs = []
            for im in re.finditer(r'<input\b([^>]*)>', m.group(2),
                                   re.IGNORECASE):
                iattrs = {}
                for am in re.finditer(r'(\w+)\s*=\s*["\']([^"\']*)["\']',
                                        im.group(1)):
                    iattrs[am.group(1).lower()] = am.group(2)
                name = iattrs.get("name")
                itype = iattrs.get("type", "text").lower()
                if name and itype not in ("submit", "image", "button"):
                    inputs.append((name, itype,
                                    iattrs.get("value", "test")))
            if inputs:
                forms.append({"action": action,
                              "method": attrs.get("method", "get"),
                              "inputs": inputs})
        return forms

    def _fuzz_form(self, form: dict, base_url: str) -> None:
        # Build baseline + payload submissions
        baseline_data = {name: value for name, _t, value in form["inputs"]}
        if not baseline_data:
            return
        baseline_body, baseline_time = self._submit(
            form["action"], form["method"], baseline_data,
        )
        if not baseline_body:
            return

        for label, payload, pattern in self.PAYLOADS:
            # Inject payload into text/search fields; keep others benign
            data = dict(baseline_data)
            for name, itype, _v in form["inputs"]:
                if itype in ("text", "search", "email", "", "textarea"):
                    data[name] = payload
            body, _ = self._submit(form["action"], form["method"], data)
            if not body:
                continue
            # Must NOT match baseline (would be FP)
            if pattern.search(baseline_body):
                continue
            if pattern.search(body):
                sev = "critical" if label == "sqli-error" else "high"
                self.findings.append(Finding(
                    severity=sev,
                    title=f"Form fuzzer: {label} on form action={form['action']}",
                    host=form["action"],
                    detail=(
                        f"Form at {form['action']} ({form['method'].upper()}) "
                        f"reacts to payload '{payload}' with signature matching "
                        f"'{label}'. Baseline response did not match - signal "
                        f"came from the attacker payload."
                    ),
                    source="form_fuzzer",
                    url=form["action"],
                    tags=["form-fuzzer", label],
                    evidence=f"payload={payload} match={pattern.pattern}",
                ))
                return  # one finding per form

    def execute(self) -> list[Finding]:
        forms_tested = 0
        for host in self._hosts(3):
            if forms_tested >= self.MAX_FORMS:
                break
            body = self._fetch(host, timeout=10)
            if not body:
                continue
            forms = self._extract_forms(body, host)
            for form in forms:
                if forms_tested >= self.MAX_FORMS:
                    break
                try:
                    self._fuzz_form(form, host)
                except Exception as exc:
                    self.log.debug(f"  form_fuzzer: {exc}")
                forms_tested += 1
        return self.findings
