"""CSV output for findings - easy triage in spreadsheets."""
import csv
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.output.csv")


def generate_csv(result) -> str:
    """Emit a CSV of all findings for spreadsheet triage."""
    path = f"{result.base_dir}/06_reports/findings.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "title", "host", "source", "url", "tags", "detail", "evidence"])
        for f in result.sorted_findings():
            w.writerow([
                f.severity,
                f.title,
                f.host,
                f.source,
                f.url,
                ",".join(f.tags or []),
                (f.detail or "")[:1000],
                (f.evidence or "")[:500],
            ])
    logger.info(f"  CSV report: {path}")
    return path
