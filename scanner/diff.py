"""
Scan comparison / diffing between two scan runs.

Produces a diff report highlighting:
- New findings not in the baseline
- Resolved findings present in baseline but not in current
- New subdomains, URLs, hosts
"""
import json
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.diff")


class ScanDiff:
    """Compare two scans by their summary.json files."""

    def __init__(self, baseline_path: str, current_path: str):
        self.baseline = self._load(baseline_path)
        self.current = self._load(current_path)
        self.diff: dict = {}

    @staticmethod
    def _load(path: str) -> dict:
        p = Path(path)
        if p.is_dir():
            cand = p / "06_reports" / "summary.json"
            if cand.exists():
                p = cand
        return json.loads(p.read_text())

    @staticmethod
    def _finding_key(f: dict) -> tuple:
        return (f.get("title", ""), f.get("host", ""), f.get("url", ""))

    def compute(self) -> dict:
        base_findings = {self._finding_key(f): f for f in self.baseline.get("findings", [])}
        curr_findings = {self._finding_key(f): f for f in self.current.get("findings", [])}

        new_findings = [curr_findings[k] for k in curr_findings if k not in base_findings]
        resolved = [base_findings[k] for k in base_findings if k not in curr_findings]
        persistent = [curr_findings[k] for k in curr_findings if k in base_findings]

        base_subs = set(self.baseline.get("subdomains", []))
        curr_subs = set(self.current.get("subdomains", []))

        base_hosts = set(self.baseline.get("live_hosts", []))
        curr_hosts = set(self.current.get("live_hosts", []))

        base_sensitive = set(self.baseline.get("urls_sensitive", []))
        curr_sensitive = set(self.current.get("urls_sensitive", []))

        self.diff = {
            "baseline_target": self.baseline.get("target"),
            "current_target":  self.current.get("target"),
            "baseline_date":   self.baseline.get("scan_date"),
            "current_date":    self.current.get("scan_date"),
            "summary": {
                "new_findings":        len(new_findings),
                "resolved_findings":   len(resolved),
                "persistent_findings": len(persistent),
                "new_subdomains":      len(curr_subs - base_subs),
                "lost_subdomains":     len(base_subs - curr_subs),
                "new_live_hosts":      len(curr_hosts - base_hosts),
                "new_sensitive_files": len(curr_sensitive - base_sensitive),
            },
            "new_findings":      new_findings,
            "resolved_findings": resolved,
            "new_subdomains":    sorted(curr_subs - base_subs),
            "lost_subdomains":   sorted(base_subs - curr_subs),
            "new_live_hosts":    sorted(curr_hosts - base_hosts),
            "new_sensitive":     sorted(curr_sensitive - base_sensitive),
        }
        return self.diff

    def to_markdown(self) -> str:
        if not self.diff:
            self.compute()
        d = self.diff
        md = [f"# Scan Diff - {d['current_target']}\n\n"]
        md.append(f"**Baseline:** {d['baseline_date']}  \n")
        md.append(f"**Current:**  {d['current_date']}  \n\n")

        md.append("## Summary\n\n")
        md.append("| Metric | Count |\n| --- | --- |\n")
        for k, v in d["summary"].items():
            md.append(f"| {k.replace('_', ' ').title()} | {v} |\n")
        md.append("\n")

        if d["new_findings"]:
            md.append(f"## New Findings ({len(d['new_findings'])})\n\n")
            md.append("| Severity | Title | Host |\n| --- | --- | --- |\n")
            for f in d["new_findings"]:
                md.append(f"| {f.get('severity', '?')} | {f.get('title', '')} | {f.get('host', '')} |\n")
            md.append("\n")

        if d["resolved_findings"]:
            md.append(f"## Resolved Findings ({len(d['resolved_findings'])})\n\n")
            md.append("| Severity | Title | Host |\n| --- | --- | --- |\n")
            for f in d["resolved_findings"]:
                md.append(f"| {f.get('severity', '?')} | {f.get('title', '')} | {f.get('host', '')} |\n")
            md.append("\n")

        if d["new_subdomains"]:
            md.append(f"## New Subdomains ({len(d['new_subdomains'])})\n\n")
            for s in d["new_subdomains"][:100]:
                md.append(f"- `{s}`\n")
            md.append("\n")

        if d["new_live_hosts"]:
            md.append(f"## New Live Hosts ({len(d['new_live_hosts'])})\n\n")
            for h in d["new_live_hosts"][:100]:
                md.append(f"- {h}\n")
            md.append("\n")

        if d["new_sensitive"]:
            md.append(f"## New Sensitive Files Exposed ({len(d['new_sensitive'])})\n\n")
            for u in d["new_sensitive"]:
                md.append(f"- {u}\n")
            md.append("\n")

        return "".join(md)

    def write(self, output_dir: str) -> tuple:
        if not self.diff:
            self.compute()
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "scan_diff.json"
        md_path   = out_dir / "scan_diff.md"
        json_path.write_text(json.dumps(self.diff, indent=2, default=str, ensure_ascii=False))
        md_path.write_text(self.to_markdown())
        logger.info(f"  Diff written: {json_path}, {md_path}")
        return str(json_path), str(md_path)
