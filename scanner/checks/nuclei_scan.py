"""Nuclei vulnerability scanner integration."""
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run, parse_jsonl


# Canonical severity set used by Finding; nuclei emits a superset.
_CANONICAL = {"critical", "high", "medium", "low", "info"}
# Nuclei synonyms that must collapse into the canonical set.
_SEV_ALIASES = {
    "informational": "info",
    "unknown": "info",
    "none": "info",
}


def _canonical_sev(raw) -> str:
    """Map a nuclei severity to the canonical set.

    Nuclei emits `informational`, `unknown`, and occasionally `null` for
    template errors. Passing those straight to Finding would silently
    land in the `info` bucket via Finding's __post_init__ fallback, but
    keeping the mapping explicit (and unit-tested) prevents a future
    regression if the canonical set changes.
    """
    if raw is None:
        return "info"
    s = str(raw).strip().lower()
    if not s:
        return "info"
    if s in _SEV_ALIASES:
        return _SEV_ALIASES[s]
    if s in _CANONICAL:
        return s
    return "info"


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
            # `.get(..., "info").lower()` crashes when the key exists with
            # value None (nuclei occasionally emits "severity": null on
            # template errors) because None.lower() -> AttributeError.
            sev = _canonical_sev(info.get("severity"))
            raw_tags = info.get("tags") or []
            if isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            elif isinstance(raw_tags, list):
                tags = raw_tags
            else:
                tags = []
            # extracted-results is sometimes a list of strings; stringifying
            # the list produces noisy `['a', 'b']` repr. Join lines instead.
            extracted = row.get("extracted-results")
            if isinstance(extracted, list):
                evidence = "\n".join(str(x) for x in extracted)
            elif extracted:
                evidence = str(extracted)
            else:
                evidence = str(row.get("curl-command", ""))
            self.findings.append(Finding(
                severity=sev,
                title=info.get("name", row.get("template-id", "?")),
                host=row.get("host", ""),
                detail=info.get("description", ""),
                source="nuclei",
                tags=tags,
                url=row.get("matched-at", row.get("host", "")),
                evidence=evidence,
            ))

        return self.findings
