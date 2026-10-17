"""PoC-08: --fail-on gate exits 0 (silent success) when target has a scheme prefix.

Root cause (autoscan.py:629-657  _severity_gate  +  621-626  _target_safe_name):

    def _severity_gate(threshold, output_dir, targets):
        for target in targets:
            safe = _target_safe_name(target)          # ← uses the RAW target
            target_dir = scanned_root / safe
            if not target_dir.exists():
                continue                               # ← silently skips!

    def _target_safe_name(target):
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", target)
        ...

The SCAN writes results under the sanitised+validated form:
    validate_target("https://example.com") → strips scheme → "example.com"
    create_dirs("example.com")             → directory   → "example_com/"

The GATE reads using the *original* (pre-validation) target string:
    _target_safe_name("https://example.com") → "https___example_com"

"https___example_com" != "example_com" → directory not found → gate returns
without calling sys.exit → the CI pipeline gets exit code 0 even though
critical findings exist.

No external network traffic; everything runs in-process / on the filesystem.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import report as _report     # noqa: E402

# Import the function under test (we patch sys.exit so it does not abort us).
import importlib
autoscan = importlib.import_module("autoscan")
_severity_gate    = autoscan._severity_gate
_target_safe_name = autoscan._target_safe_name


def _make_summary(output_dir: Path, safe_name: str, severity="critical") -> None:
    """Create a summary.json as the real scan would."""
    report_dir = output_dir / safe_name / "run_001" / "06_reports"
    report_dir.mkdir(parents=True)
    (report_dir / "summary.json").write_text(json.dumps({
        "severity_counts": {severity: 1, "high": 0, "medium": 0, "low": 0},
    }))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="poc08_"))

    # Results are stored under the VALIDATED target name: "example_com"
    _make_summary(tmp, "example_com", severity="critical")

    exit_calls: list[int] = []

    def fake_exit(code=0):
        exit_calls.append(code)

    with patch("autoscan.sys") as mock_sys:
        mock_sys.exit.side_effect = fake_exit

        # ── case A: target WITH scheme (as user might type it) ────────────────
        exit_calls.clear()
        try:
            _severity_gate("critical", str(tmp), ["https://example.com"])
        except Exception:
            pass
        scheme_exit = list(exit_calls)

        # ── case B: target WITHOUT scheme (correct form) ──────────────────────
        exit_calls.clear()
        try:
            _severity_gate("critical", str(tmp), ["example.com"])
        except Exception:
            pass
        clean_exit = list(exit_calls)

    # Vulnerable: with scheme → gate silently misses critical → no sys.exit(2)
    # Expected:   without scheme → gate detects critical → sys.exit(2)
    gate_fails_open  = (scheme_exit == [])          # no exit called
    gate_works_clean = (2 in clean_exit)            # exit(2) called

    # Also show the safe-name mismatch directly
    name_with_scheme = _target_safe_name("https://example.com")
    name_clean       = _target_safe_name("example.com")
    mismatch         = name_with_scheme != name_clean

    confirmed = gate_fails_open and gate_works_clean and mismatch
    detail = (
        f"scheme_target safe_name={name_with_scheme!r} exit_codes={scheme_exit} → fails_open={gate_fails_open} | "
        f"clean_target safe_name={name_clean!r} exit_codes={clean_exit} → detected={gate_works_clean}"
    )
    return _report(
        "PoC-08",
        "--fail-on gate exits 0 (fails open) when target includes scheme prefix",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
