"""RapidDNS subdomain scraping (free, HTML output)."""
import re
from ._helpers import http_get_text, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    body = http_get_text(url, timeout=25)
    if not body:
        return set()
    # Extract hostnames from <td> cells
    candidates = re.findall(r">\s*([A-Za-z0-9._-]+\." + re.escape(domain) + r")\s*<", body)
    return filter_subs(candidates, domain)
