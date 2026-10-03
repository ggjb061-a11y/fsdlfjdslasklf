"""Shared helpers for recon_sources modules."""
import json
import re
from ..utils import run


def http_get_json(url: str, timeout: int = 20, extra_headers: list = None) -> dict | list | None:
    """GET URL, parse body as JSON. Returns None on any failure."""
    args = ["curl", "-s", "--max-time", str(timeout), "--compressed",
            "-H", "User-Agent: AutoVulnScan/3.9"]
    for h in (extra_headers or []):
        args += ["-H", h]
    args.append(url)
    rc, body, _ = run(args, timeout=timeout + 4)
    if rc != 0 or not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def http_get_text(url: str, timeout: int = 20, extra_headers: list = None) -> str:
    args = ["curl", "-s", "--max-time", str(timeout), "--compressed",
            "-H", "User-Agent: AutoVulnScan/3.9"]
    for h in (extra_headers or []):
        args += ["-H", h]
    args.append(url)
    rc, body, _ = run(args, timeout=timeout + 4)
    return body or ""


def filter_subs(candidates, target: str) -> set[str]:
    """Keep only lowercase names matching apex OR *.apex, strip ports and wildcards."""
    target = target.lower().strip()
    suffix = f".{target}"
    out: set[str] = set()
    for c in candidates:
        if not c:
            continue
        name = str(c).strip().lower().lstrip("*.")
        # Strip URL scheme if present
        name = re.sub(r"^https?://", "", name)
        # Strip path and port
        name = name.split("/", 1)[0].split(":", 1)[0]
        if not name or not re.match(r"^[a-z0-9._-]+$", name):
            continue
        if name == target or name.endswith(suffix):
            out.add(name)
    return out
