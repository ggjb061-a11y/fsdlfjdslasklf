"""PoC-01: --resume always fails for dotted domains.

Root cause:
  * create_dirs() sanitises the target name: "example.com" -> "example_com"
    (autoscan.py relies on this for the folder name).
  * main() --resume recovers the target from the folder name (parts[-2]) and
    passes it to scan_target().
  * scan_target() calls validate_target(), whose hostname regex does not allow
    "_". So "example_com" is rejected before any work happens.

Expected (vulnerable): validate_target raises ValidationError for the
resumed name, so --resume never gets past its first line.
Control: the original dotted name validates fine.
"""
import argparse
import tempfile
from pathlib import Path

from _common import REPO_ROOT, report  # noqa: F401  (sets sys.path)

import autoscan
from scanner.utils import create_dirs
from scanner.validators import validate_target, ValidationError


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="poc01_"))
    base_dirs = create_dirs(str(tmp / "scans"), "example.com")
    base = Path(base_dirs["base"])

    # Same derivation as autoscan.main() for --resume.
    parts = str(base).split("/")
    resumed_name = parts[-2]

    args = argparse.Namespace(verbose=False, output=str(tmp), threads=1,
                              scope="full", only=None, wordlist=None,
                              format="json", fail_on=None, webhook=None)

    # Control: the original target is accepted.
    validate_target("example.com")

    try:
        # Real code path: scan_target() validates first, before any network I/O.
        autoscan.scan_target(resumed_name, args, resume_dir=str(base))
        confirmed = False
        detail = "scan_target accepted the resumed name (bug not present)"
    except ValidationError as exc:
        confirmed = True
        detail = (f"folder={base.parent.name!r} -> scan_target({resumed_name!r}) "
                  f"raised ValidationError: {exc}")
    return report("PoC-01", "--resume rejects every dotted domain", confirmed, detail)


if __name__ == "__main__":
    raise SystemExit(main())
