"""CommonCrawl index subdomain extraction (public, no key)."""
import re
import urllib.parse
from ._helpers import http_get_text, filter_subs


# A recent-ish CC index. CommonCrawl rotates indexes - using 2024 index.
CC_INDEX = "CC-MAIN-2024-10"


def fetch(domain: str) -> set[str]:
    url = (f"https://index.commoncrawl.org/{CC_INDEX}-index"
           f"?url=*.{domain}&output=json")
    body = http_get_text(url, timeout=30)
    if not body:
        return set()
    cands = set()
    host_re = re.compile(r'"url":\s*"https?://([^/"]+)/?')
    for line in body.splitlines():
        m = host_re.search(line)
        if m:
            cands.add(m.group(1))
    return filter_subs(cands, domain)
