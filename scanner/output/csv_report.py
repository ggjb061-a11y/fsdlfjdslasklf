"""CSV output for findings - easy triage in spreadsheets."""
import csv
import logging
from pathlib import Path

logger = logging.getLogger("autoscan.output.csv")


def _csv_safe(v) -> str:
    """Neutralize CSV-injection prefixes.

    A cell whose first character is =, +, -, @, \\t, or \\r is parsed as a
    formula by Excel/LibreOffice/Google Sheets when the user opens the
    report. An attacker-controlled finding title/host/evidence that starts
    with one of these characters becomes RCE on the auditor's workstation.
    Prepend an apostrophe to force the cell to be treated as text.
    """
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def generate_csv(result) -> str:
    """Emit a CSV of all findings for spreadsheet triage."""
    path = Path(result.base_dir) / "06_reports" / "findings.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        w.writerow(["severity", "title", "host", "source", "url", "tags", "detail", "evidence"])
        for f in result.sorted_findings():
            w.writerow([
                _csv_safe(f.severity),
                _csv_safe(f.title),
                _csv_safe(f.host),
                _csv_safe(f.source),
                _csv_safe(f.url),
                _csv_safe(",".join(f.tags or [])),
                _csv_safe((f.detail or "")[:1000]),
                _csv_safe((f.evidence or "")[:500]),
            ])
    logger.info(f"  CSV report: {path}")
    return str(path)
