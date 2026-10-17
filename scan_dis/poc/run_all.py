"""Run every scan_dis PoC and print a summary.

Usage:  python3 scan_dis/poc/run_all.py
Exit code: 0 when every PoC reproduces, 1 otherwise.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
POCS = sorted(HERE.glob("poc_*.py"))


def main() -> int:
    failures = 0
    for poc in POCS:
        proc = subprocess.run([sys.executable, str(poc)], capture_output=True, text=True)
        print(proc.stdout.rstrip())
        if proc.returncode != 0:
            failures += 1
            if proc.stderr.strip():
                print(proc.stderr.rstrip())
        print()
    print(f"{len(POCS) - failures}/{len(POCS)} PoCs reproduced")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
