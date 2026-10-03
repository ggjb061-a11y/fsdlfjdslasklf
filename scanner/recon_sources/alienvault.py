"""AlienVault OTX passive DNS (free, no API key)."""
from ._helpers import http_get_json, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = http_get_json(url, timeout=20)
    if not isinstance(data, dict):
        return set()
    cands = [row.get("hostname", "") for row in data.get("passive_dns", [])
             if isinstance(row, dict)]
    return filter_subs(cands, domain)
