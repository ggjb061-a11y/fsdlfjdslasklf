"""Subdomain takeover detection."""
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run, read_lines


class TakeoverCheck(BaseCheck):
    name = "Subdomain Takeover"
    description = "Check for dangling DNS records vulnerable to subdomain takeover"

    TAKEOVER_FINGERPRINTS = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket",
        "No such app",
        "Trying to access your account?",
        "There's nothing here, yet.",
        "is not a registered InCloud WAF",
        "Domain is not configured",
        "No settings were found for this company",
        "project not found",
        "The request could not be satisfied",
    ]

    def execute(self) -> list[Finding]:
        subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        if not Path(subs_file).exists():
            return []

        if which("subjack"):
            out = f"{self.dirs['vuln']}/takeover.txt"
            run(
                ["subjack", "-w", subs_file, "-t", str(self.threads),
                 "-o", out, "-ssl"],
                timeout=300,
            )
            for line in read_lines(out):
                if "vulnerable" in line.lower() or "takeover" in line.lower():
                    self.findings.append(Finding(
                        severity="high",
                        title="Potential Subdomain Takeover",
                        host=line,
                        detail=f"Subdomain may be vulnerable to takeover: {line}",
                        source="subjack",
                    ))

        for sub in read_lines(subs_file)[:50]:
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "8", f"https://{sub}"],
                timeout=12,
            )
            if rc != 0 or not body:
                continue
            for fingerprint in self.TAKEOVER_FINGERPRINTS:
                if fingerprint in body:
                    self.findings.append(Finding(
                        severity="high",
                        title=f"Subdomain Takeover - {sub}",
                        host=sub,
                        detail=f"Response contains takeover fingerprint: {fingerprint}",
                        source="takeover_fingerprint",
                        url=f"https://{sub}",
                        evidence=fingerprint,
                    ))
                    break

        return self.findings
