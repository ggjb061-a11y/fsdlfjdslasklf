"""
GitHub leaked-secret exposure check.

Uses the GitHub public code search (unauthenticated web endpoint) to look
for the target domain alongside credential-shaped strings. We query:

  "<target>" aws_access_key_id
  "<target>" password
  "<target>" api_key
  "<target>" token
  "<target>" secret

Each hit is flagged. We rate-limit ourselves to one request per 2s to
avoid tripping GitHub throttling. If a GITHUB_TOKEN env var is present
we use the proper REST API with auth which is faster and more reliable.
"""
import json
import os
import re
import time
from .base import BaseCheck
from ..models import Finding
from ..utils import run


class GitHubLeaksCheck(BaseCheck):
    """Search GitHub public code for target-related credential leaks."""

    name = "GitHub Secret Exposure"
    description = "Search GitHub public code for the target domain beside credential-shaped strings"

    DORKS = [
        "aws_access_key_id",
        "aws_secret_access_key",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "api_secret",
        "token",
        "secret",
        "private_key",
        "BEGIN RSA PRIVATE KEY",
        "DATABASE_URL",
        "jdbc:mysql",
        "mongodb://",
        "redis://",
        "slack_token",
        "sendgrid",
        "stripe_api_key",
    ]

    @staticmethod
    def _github_token() -> str | None:
        return os.environ.get("GITHUB_TOKEN") or None

    def _api_search(self, query: str) -> list[dict]:
        """Call GitHub REST API (requires GITHUB_TOKEN)."""
        token = self._github_token()
        if not token:
            return []
        url = f"https://api.github.com/search/code?q={query}&per_page=10"
        rc, body, _ = run(
            ["curl", "-s", "--max-time", "15",
             "-H", f"Authorization: Bearer {token}",
             "-H", "Accept: application/vnd.github+json",
             "-H", "X-GitHub-Api-Version: 2022-11-28",
             url],
            timeout=20,
        )
        if rc != 0 or not body:
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []
        items = []
        for item in data.get("items", []):
            items.append({
                "name": item.get("name", ""),
                "path": item.get("path", ""),
                "html_url": item.get("html_url", ""),
                "repository": item.get("repository", {}).get("full_name", ""),
            })
        return items

    def _web_search(self, query: str) -> list[dict]:
        """Unauthenticated GitHub web search (lower reliability).

        Returns a stub result pointing at the search URL so the user can
        inspect manually. This avoids false positives from HTML parsing.
        """
        import urllib.parse
        encoded = urllib.parse.quote(query)
        search_url = f"https://github.com/search?q={encoded}&type=code"
        return [{
            "name": "(web search)",
            "path": "",
            "html_url": search_url,
            "repository": "(see URL)",
        }]

    def execute(self) -> list[Finding]:
        target = self.target
        token_available = bool(self._github_token())
        self.log.info(
            f"  GitHub leaks: {'authenticated' if token_available else 'unauthenticated (manual-review stubs)'}"
        )
        for dork in self.DORKS:
            # Rate-limit politely
            time.sleep(2 if not token_available else 0.5)
            query = f'"{target}" {dork}'
            try:
                if token_available:
                    hits = self._api_search(query)
                else:
                    hits = self._web_search(query)
            except Exception as exc:
                self.log.debug(f"  github dork {dork!r}: {exc}")
                continue
            if not hits:
                continue
            if token_available:
                for hit in hits:
                    # A code-search hit only proves the two strings appear
                    # in the same file - not that a real credential is
                    # exposed. The file may be a tutorial, template or
                    # test fixture. Severity is MEDIUM with the review
                    # tag; it escalates on manual confirmation.
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Possible leaked '{dork}' for {target} on GitHub",
                        host=target,
                        detail=(
                            f"GitHub code search found '{target}' near '{dork}' in "
                            f"{hit['repository']}/{hit['path']}. The hit alone does "
                            f"not prove a credential is exposed; open the file and "
                            f"check whether a real secret is on the matched line."
                        ),
                        source="github_leaks",
                        url=hit["html_url"],
                        tags=["github-exposure", f"keyword:{dork}", "needs-manual-review"],
                        evidence=f"repo={hit['repository']} file={hit['path']}",
                    ))
            else:
                # Unauthenticated path: emit an INFO finding pointing at the
                # manual search URL so the auditor can skim it themselves.
                hit = hits[0]
                self.findings.append(Finding(
                    severity="info",
                    title=f"GitHub search prepared: \"{target}\" {dork}",
                    host=target,
                    detail=(
                        "Set GITHUB_TOKEN env var and re-run for automated results. "
                        f"Manual URL: {hit['html_url']}"
                    ),
                    source="github_leaks",
                    url=hit["html_url"],
                    tags=["github-exposure", f"keyword:{dork}", "manual-check"],
                ))
        return self.findings
