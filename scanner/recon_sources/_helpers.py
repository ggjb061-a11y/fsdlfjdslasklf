"""Shared helpers for recon_sources modules."""
import json
import logging
import re
from ..utils import run
from .. import __version__ as _VERSION

logger = logging.getLogger("autoscan.recon_sources.helpers")

# Default User-Agent. WAFs/CDNs blocklist tool-named UAs very aggressively,
# so a benign browser-like UA is the sane default - a blocked source would
# silently return empty across the board. Override via AUTOSCAN_UA env var.
import os as _os
_DEFAULT_UA = _os.environ.get(
    "AUTOSCAN_UA",
    "Mozilla/5.0 (compatible; AutoVulnScan/"
    + str(_VERSION)
    + "; +https://github.com/)"
)


def _is_valid_domain(domain: str) -> bool:
    """Loose hostname shape check so we never embed shell/URL metacharacters."""
    if not domain or len(domain) > 253:
        return False
    return re.fullmatch(r"[a-z0-9][a-z0-9.\-]{0,251}[a-z0-9]", domain.lower()) is not None


def http_get_json(url: str, timeout: int = 20, extra_headers: list = None) -> dict | list | None:
    """GET URL, parse body as JSON. Returns None on any failure."""
    args = ["curl", "-s", "--max-time", str(timeout), "--compressed",
            "-H", f"User-Agent: {_DEFAULT_UA}"]
    for h in (extra_headers or []):
        args += ["-H", h]
    args += ["--", url]
    rc, body, _ = run(args, timeout=timeout + 4)
    if rc != 0 or not body:
        logger.debug(f"  http_get_json({url}): empty response (rc={rc})")
        return None
    try:
        return json.loads(body)
    except Exception as exc:
        logger.debug(f"  http_get_json({url}): JSON parse failed: {exc}")
        return None


def http_get_text(url: str, timeout: int = 20, extra_headers: list = None) -> str:
    args = ["curl", "-s", "--max-time", str(timeout), "--compressed",
            "-H", f"User-Agent: {_DEFAULT_UA}"]
    for h in (extra_headers or []):
        args += ["-H", h]
    args += ["--", url]
    rc, body, _ = run(args, timeout=timeout + 4)
    if rc != 0:
        logger.debug(f"  http_get_text({url}): rc={rc}")
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
