"""HackerTarget hostsearch endpoint (free, 50 queries/day rate limit)."""
from ._helpers import http_get_text, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    body = http_get_text(url, timeout=20)
    if not body or "error" in body.lower() or "api count" in body.lower():
        return set()
    # Format: hostname,ip per line
    cands = []
    for line in body.splitlines():
        parts = line.strip().split(",")
        if parts and parts[0]:
            cands.append(parts[0])
    return filter_subs(cands, domain)
