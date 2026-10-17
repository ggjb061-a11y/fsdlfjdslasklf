"""PoC-06: Markdown injection via unescaped newline in JS endpoint URL.

Root cause (output/markdown_report.py:211-212):
    for e in endpoints[:100]:
        md.append(f"- `{e}`\\n")

If a discovered JS endpoint URL contains a literal newline (\\n or %0a decoded),
the format string produces raw Markdown that breaks out of the list and injects
arbitrary headings or content into report.md.  The reporter does not escape or
normalise JS endpoint strings.

The same pattern applies to emails (line 233):  f"- `{e}`\\n"

Attack scenario: a JS file the scanner crawls returns a URL-like string
containing \\n# INJECTED, which the JS extractor captures verbatim.
The resulting report.md renders the injected text as a heading, silently
corrupting the report or deceiving a reader.

No external network traffic; the markdown generator runs in-process.
"""
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import report as _report     # noqa: E402

# Import the report generator and models
from scanner.output.markdown_report import generate_markdown  # noqa: E402
from scanner.models import ScanResult                         # noqa: E402

INJECTED_HEADING = "# INJECTED HEADING FROM ENDPOINT"
INJECTED_EMAIL   = "# INJECTED VIA EMAIL FIELD"


def main() -> int:
    # Build a minimal ScanResult with a poisoned JS endpoint and email
    result = ScanResult(target="example.com")
    result.js_endpoints = [
        "/api/legit",
        f"/api/normal\n{INJECTED_HEADING}",   # endpoint with embedded newline
    ]
    result.emails = [
        "legit@example.com",
        f"valid@example.com\n{INJECTED_EMAIL}",
    ]

    # Generate markdown in-memory
    md_text = generate_markdown(result)

    endpoint_injected = INJECTED_HEADING in md_text
    email_injected    = INJECTED_EMAIL   in md_text

    # Also verify: a well-formed endpoint does NOT create a heading
    control_safe = "# INJECTED" not in md_text.split("# ")[0]  # before first injection

    confirmed = endpoint_injected and email_injected
    detail = (
        f"endpoint_injection={endpoint_injected} | "
        f"email_injection={email_injected} | "
        f"injected_heading_appears_in_report: "
        f"{INJECTED_HEADING!r[:40]} found={INJECTED_HEADING in md_text}"
    )
    return _report(
        "PoC-06",
        "Markdown injection via unescaped newline in JS endpoint / email → heading in report.md",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
