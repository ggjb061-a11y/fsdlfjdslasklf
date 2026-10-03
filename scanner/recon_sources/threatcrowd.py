"""ThreatCrowd passive DNS (free, no API key)."""
from ._helpers import http_get_json, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    data = http_get_json(url, timeout=25)
    if not isinstance(data, dict):
        return set()
    return filter_subs(data.get("subdomains", []), domain)
