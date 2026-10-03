"""Nuclei vulnerability scanner integration."""
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run, parse_jsonl


class NucleiScan(BaseCheck):
    name = "Nuclei"
    description = "Run nuclei template-based vulnerability scanning"

    def execute(self) -> list[Finding]:
        if not which("nuclei"):
            self.log.warning("  nuclei not installed")
            return []

        tf = self._targets_file()
        out_txt  = f"{self.dirs['nuclei']}/results.txt"
        out_json = f"{self.dirs['nuclei']}/results.jsonl"

        run(["nuclei", "-update-templates", "-silent"], timeout=120)

        run(
            [
                "nuclei",
                "-l", tf,
                "-severity", "critical,high,medium,low,info",
                "-tags", "cve,exposure,misconfig,sqli,xss,lfi,rce,ssrf,idor,redirect,takeover",
                "-o", out_txt,
                "-jsonl",
                "-output", out_json,
                "-silent",
                "-c", str(self.threads),
                "-timeout", "10",
                "-retries", "2",
                "-no-color",
            ],
            timeout=7200,
        )

        for row in parse_jsonl(out_json):
            info = row.get("info", {})
            sev = info.get("severity", "info").lower()
            raw_tags = info.get("tags") or []
            if isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            elif isinstance(raw_tags, list):
                tags = raw_tags
            else:
                tags = []
            self.findings.append(Finding(
                severity=sev,
                title=info.get("name", row.get("template-id", "?")),
                host=row.get("host", ""),
                detail=info.get("description", ""),
                source="nuclei",
                tags=tags,
                url=row.get("matched-at", row.get("host", "")),
                evidence=str(row.get("extracted-results", row.get("curl-command", ""))),
            ))

        return self.findings
