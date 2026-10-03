"""
sqlmap integration for deep SQL injection confirmation.

Runs as a second stage after the built-in SQLInjectionCheck:
  - If sqlmap is installed, probes live hosts and discovered parametric
    URLs with sqlmap's own detection, then parses its JSON log into
    Finding objects.
  - Falls back silently if sqlmap is not installed (we still have the
    built-in SQLi check).

sqlmap flags used:
  --batch              : no interactive prompts
  --level=3 --risk=2   : moderate thoroughness (default 1/1 misses many)
  --random-agent       : avoid blocklists on default UA
  --technique=BEUSTQ   : Boolean, Error, UNION, Stacked, Time, Query
  --threads 5          : parallel requests to one target
  --timeout 10 / --retries 1
  --output-dir         : contained to our dirs['vuln']/sqlmap/
  --flush-session      : don't reuse stale state between runs
  --crawl 0            : we feed URLs explicitly; sqlmap does not crawl further
  --skip-waf           : skip WAF probe (we already have wafw00f output)
"""
import json
import re
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run


class SqlmapCheck(BaseCheck):
    """Deep SQLi confirmation using sqlmap."""

    name = "SQLMap"
    description = "Second-stage SQL injection confirmation via sqlmap"

    # Default parameter names worth testing even when no params were discovered.
    DEFAULT_PARAMS = [
        "id", "user", "page", "search", "q",
        "category", "item", "year", "pid",
    ]

    def _sqlmap_bin(self) -> str | None:
        for name in ("sqlmap", "sqlmap.py"):
            p = which(name)
            if p:
                return p
        return None

    def _candidate_urls(self) -> list[str]:
        """Build the URL list sqlmap will test.

        1. Live hosts (apex) with a sentinel ?id=1 so sqlmap sees a param.
        2. Any URL already containing `?param=value` discovered by crawler/
           passive phases (held in dirs['urls']/all_urls_with_status.txt
           when present).
        """
        urls: list[str] = []
        for host in self._hosts(5):
            for param in self.DEFAULT_PARAMS[:3]:
                urls.append(f"{host}/?{param}=1")

        urls_file = Path(f"{self.dirs['urls']}/all_urls_with_status.txt")
        if urls_file.exists():
            try:
                for line in urls_file.read_text(errors="replace").splitlines():
                    parts = line.strip().split()
                    if not parts:
                        continue
                    u = parts[0]
                    if u.startswith("http") and "?" in u and "=" in u:
                        urls.append(u)
            except Exception:
                pass

        # Deduplicate while preserving order, cap to a sane limit.
        seen = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
            if len(deduped) >= 15:
                break
        return deduped

    def _run_sqlmap_on_url(self, binary: str, url: str, out_dir: str) -> list[dict]:
        """Run sqlmap on one URL. Returns list of injection dicts parsed from logs."""
        cmd = [
            binary,
            "-u", url,
            "--batch",
            "--level=3",
            "--risk=2",
            "--random-agent",
            "--technique=BEUSTQ",
            "--threads=5",
            "--timeout=10",
            "--retries=1",
            "--flush-session",
            "--crawl=0",
            "--skip-waf",
            "--output-dir", out_dir,
            "--disable-coloring",
        ]
        rc, out, err = run(cmd, timeout=900)
        combined = (out or "") + "\n" + (err or "")
        return self._parse_sqlmap_output(combined, url)

    def _parse_sqlmap_output(self, text: str, url: str) -> list[dict]:
        """Extract injection reports from sqlmap stdout.

        sqlmap emits one 'Parameter: foo' header followed by multiple
        'Type: / Title: / Payload:' triples. Every triple is a distinct
        injection technique on the same parameter.
        """
        if not text:
            return []
        injections: list[dict] = []
        for block in re.split(r"(?=Parameter:\s)", text):
            if not block.strip().startswith("Parameter:"):
                continue
            m_param = re.search(r"Parameter:\s*([^\s\(]+)", block)
            if not m_param:
                continue
            param = m_param.group(1).strip()
            # Each Type/Title/Payload triple inside this block is a separate
            # confirmed technique.
            triples = re.findall(
                r"Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+)",
                block,
            )
            for ttype, title, payload in triples:
                injections.append({
                    "parameter": param,
                    "type":      ttype.strip(),
                    "title":     title.strip(),
                    "payload":   payload.strip(),
                    "url":       url,
                })
        return injections

    def execute(self) -> list[Finding]:
        binary = self._sqlmap_bin()
        if not binary:
            self.log.debug("  sqlmap not installed - skipping deep-SQLi stage")
            return []

        out_dir = f"{self.dirs['vuln']}/sqlmap"
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        candidates = self._candidate_urls()
        if not candidates:
            self.log.debug("  no URL candidates for sqlmap")
            return []

        self.log.info(f"  sqlmap: testing {len(candidates)} URL(s)")
        for url in candidates:
            try:
                injections = self._run_sqlmap_on_url(binary, url, out_dir)
            except Exception as exc:
                self.log.debug(f"  sqlmap {url} failed: {exc}")
                continue
            for inj in injections:
                technique = inj["type"]
                tech_short = technique.split()[0].lower() if technique else "unknown"
                self.findings.append(Finding(
                    severity="critical",
                    title=f"SQL Injection ({tech_short}) via '{inj['parameter']}' [sqlmap]",
                    host=url,
                    detail=(
                        f"Detector: sqlmap.\n"
                        f"sqlmap confirmed SQL injection on parameter '{inj['parameter']}' "
                        f"at {url}. Technique: {technique}. "
                        f"Title: {inj['title']}."
                    ),
                    source="sqlmap",
                    url=url,
                    tags=["sqli", "sqlmap", "confirmed", tech_short,
                          f"param:{inj['parameter']}", "detector:sqlmap"],
                    evidence=f"Payload: {inj['payload']}",
                ))
        self.log.info(f"  sqlmap: {len(self.findings)} finding(s)")
        return self.findings
