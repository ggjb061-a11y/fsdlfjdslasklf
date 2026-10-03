"""CertSpotter certificate transparency search (public, no key)."""
from ._helpers import http_get_json, filter_subs


def fetch(domain: str) -> set[str]:
    url = (f"https://api.certspotter.com/v1/issuances"
           f"?domain={domain}&include_subdomains=true&expand=dns_names")
    data = http_get_json(url, timeout=25)
    if not isinstance(data, list):
        return set()
    cands = []
    for cert in data:
        if isinstance(cert, dict):
            for name in cert.get("dns_names", []):
                cands.append(name)
    return filter_subs(cands, domain)
