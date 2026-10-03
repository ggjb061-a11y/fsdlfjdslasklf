"""BufferOver DNS - TLS cert passive DNS (public endpoint)."""
import re
from ._helpers import http_get_json, filter_subs


def fetch(domain: str) -> set[str]:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    data = http_get_json(url, timeout=20)
    if not isinstance(data, dict):
        return set()
    cands = []
    for key in ("FDNS_A", "RDNS"):
        for row in data.get(key, []) or []:
            if "," in str(row):
                # "ip,hostname"
                name = str(row).split(",", 1)[1]
                cands.append(name)
    return filter_subs(cands, domain)
