"""URLScan.io public search API (free, no key, rate-limited)."""
from ._helpers import http_get_json, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
    data = http_get_json(url, timeout=25)
    if not isinstance(data, dict):
        return set()
    cands = []
    for r in data.get("results", []):
        if isinstance(r, dict):
            task = r.get("task", {})
            page = r.get("page", {})
            for key in ("domain", "apexDomain"):
                v = page.get(key) or task.get(key)
                if v:
                    cands.append(v)
    return filter_subs(cands, domain)
