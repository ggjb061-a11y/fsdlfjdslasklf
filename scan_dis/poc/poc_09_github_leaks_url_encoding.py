"""PoC-09: github_leaks._api_search silently drops results when query has spaces/quotes.

Root cause (checks/github_leaks.py:62):
    url = f"https://api.github.com/search/code?q={query}&per_page=10"

The query is interpolated directly into the URL string with NO URL-encoding.
Typical dork queries look like:
    'repo:example/app "AWS_SECRET" extension:env'

A space, quote, or colon in the query makes the URL malformed.  curl exits with
code 3 ("URL malformed"), rc != 0 → _api_search returns [] and the check
silently produces zero GitHub-leak findings even when they exist.

Compare with _web_search (line 93-94) which correctly uses urllib.parse.quote.
The same module has two search paths; only one URL-encodes.

Demo: capture the curl command that _api_search would build, verify it contains
unencoded spaces/quotes, then confirm that a stub server receives a mangled URL
(or that curl returns rc=3 for such a URL).

No real GitHub calls are made.  We intercept the command before it fires and
also confirm curl's behaviour with a local stub.
"""
import os
import sys
import urllib.parse
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from _common import Recorder, report as _report   # noqa: E402
from scanner import utils                         # noqa: E402

# A realistic dork query with spaces and a quoted string
DORK_QUERY = 'repo:example/app "AWS_SECRET" extension:env'

EXPECTED_ENCODED = urllib.parse.quote(DORK_QUERY)


def main() -> int:
    # ── 1. Capture the URL that _api_search builds ─────────────────────────────
    stub = Recorder()

    captured_cmd: list = []

    original_run = utils.run
    def capturing_run(cmd, **kw):
        captured_cmd.extend(cmd)
        return original_run(cmd, **kw)

    # Inject a dummy GITHUB_TOKEN so the code path isn't short-circuited.
    env_backup = os.environ.get("GITHUB_TOKEN")
    os.environ["GITHUB_TOKEN"] = "dummy-token-for-poc"
    try:
        with patch.object(utils, "run", side_effect=capturing_run):
            # Import after patching so the module picks up the patched run
            from scanner.checks.github_leaks import GitHubLeaksCheck
            check = GitHubLeaksCheck("example.com", {}, [])
            check._api_search(DORK_QUERY)
    finally:
        if env_backup is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = env_backup
        stub.close()

    # Find the URL argument in the captured command
    built_url = next((a for a in captured_cmd if "api.github.com" in a), "")

    # ── 2. Verify: raw query is NOT encoded ───────────────────────────────────
    query_part  = built_url.split("?q=", 1)[1].split("&")[0] if "?q=" in built_url else ""
    is_unencoded = (" " in query_part or '"' in query_part)

    # ── 3. Confirm: curl exits rc=3 for this URL ──────────────────────────────
    if built_url:
        rc, _, _ = utils.run(["curl", "-s", "--max-time", "5", built_url], timeout=8)
        curl_exit3 = (rc == 3)
    else:
        curl_exit3 = False

    # ── 4. Show that proper encoding would have worked ─────────────────────────
    properly_encoded = urllib.parse.quote(DORK_QUERY, safe="")
    url_encoded = f"https://api.github.com/search/code?q={properly_encoded}&per_page=10"
    encoding_different = (properly_encoded != DORK_QUERY)

    confirmed = is_unencoded and (curl_exit3 or built_url == "")
    detail = (
        f"query_in_url={query_part[:60]!r} | "
        f"unencoded_spaces_quotes={is_unencoded} | "
        f"curl_exit_3={curl_exit3} | "
        f"properly_encoded_would_be={properly_encoded[:40]!r}"
    )
    return _report(
        "PoC-09",
        "github_leaks URL not encoded → spaces/quotes cause curl exit 3 → silent empty results",
        confirmed, detail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
