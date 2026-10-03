"""Extract subdomains from JavaScript files already downloaded locally."""
import re
from pathlib import Path
from ._helpers import filter_subs


def fetch(domain: str, js_dir: str = None) -> set[str]:
    """Scan JS files in js_dir for strings that look like <domain> hostnames."""
    if not js_dir:
        return set()
    p = Path(js_dir)
    if not p.exists():
        return set()
    pattern = re.compile(
        rf"([A-Za-z0-9][A-Za-z0-9._-]*\.{re.escape(domain)})",
        re.IGNORECASE,
    )
    cands: set[str] = set()
    for f in p.rglob("*.js"):
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        for m in pattern.finditer(text):
            cands.add(m.group(1))
    return filter_subs(cands, domain)
