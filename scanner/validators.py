"""
Input validators for scanner safety.

The scanner invokes many external security tools with user-supplied targets.
Even with list-form subprocess args, a target starting with `-` would be
interpreted as a flag by tools that don't support `--` separators. Also,
webhook URLs and other external inputs need validation.
"""
import ipaddress
import re
import urllib.parse

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$",
    re.IGNORECASE,
)

# Single-label hostnames that resolve to internal / metadata services on
# common VM substrates. Blocked by name regardless of IP resolution so an
# attacker cannot smuggle 'metadata.google.internal' past the IP check.
_INTERNAL_SINGLE_LABELS = {
    "localhost", "metadata", "instance-data",
    "host.docker.internal", "gateway.docker.internal",
    "kubernetes.default", "metadata.google.internal",
}


def _is_internal_ip(ip: ipaddress._BaseAddress) -> bool:
    """True if the address is private/loopback/link-local/reserved/multicast/
    unspecified. Handles IPv4-mapped IPv6 (::ffff:127.0.0.1) which the stdlib's
    `.is_private` does NOT treat as private on an IPv6Address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


class ValidationError(ValueError):
    """Raised when an input fails validation."""


def validate_target(target: str) -> str:
    """Return the cleaned target name or raise ValidationError.

    Rejects:
    - leading `-` or `--` (would be interpreted as flag by downstream tools)
    - control characters and whitespace
    - path separators (`/`, `\\`)
    - shell meta-characters (`$`, `` ` ``, `;`, `|`, `&`, `>`, `<`, `(`, `)`, `*`, `?`, `[`, `]`, `{`, `}`, `!`, `#`)
    - anything that isn't a syntactically valid hostname or IP
    - single-label hostnames that resolve to internal/metadata services
    """
    if not isinstance(target, str):
        raise ValidationError("target must be a string")
    t = target.strip()
    if not t:
        raise ValidationError("target cannot be empty")
    if len(t) > 253:
        # Longest legal hostname per RFC 1035. Cap on IP input too to prevent
        # resource exhaustion from a 10MB target string.
        raise ValidationError("target too long")
    if t.startswith("-"):
        raise ValidationError(f"target may not start with '-': {t!r}")
    for bad in ("/", "\\", "$", "`", ";", "|", "&", ">", "<",
                "(", ")", "*", "?", "[", "]", "{", "}", "!", "#", " ", "\t"):
        if bad in t:
            raise ValidationError(f"target contains forbidden character {bad!r}: {t!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in t):
        raise ValidationError(f"target contains control characters: {t!r}")

    try:
        ip = ipaddress.ip_address(t)
        return t
    except ValueError:
        pass

    # Block single-label metadata/internal hostnames even when the string
    # is otherwise a valid hostname.
    if t.lower() in _INTERNAL_SINGLE_LABELS:
        raise ValidationError(f"target resolves to an internal service: {t!r}")

    if _HOSTNAME_RE.match(t):
        return t
    raise ValidationError(f"not a valid hostname or IP: {t!r}")


def validate_webhook_url(url: str, allow_private: bool = False) -> str:
    """Return the URL unchanged after validation, or raise ValidationError.

    Only http/https schemes allowed. Private/loopback blocked by default,
    including IPv4-mapped IPv6 (::ffff:127.0.0.1) and single-label metadata
    hostnames.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("webhook URL is required")
    url = url.strip()
    if len(url) > 2048:
        raise ValidationError("webhook URL too long")
    if re.search(r"\s", url):
        raise ValidationError("webhook URL contains whitespace")
    if url.startswith("-") or url.startswith("@"):
        raise ValidationError(f"webhook URL may not start with '-' or '@': {url!r}")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"webhook scheme must be http(s): {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValidationError("webhook URL missing host")
    # userinfo in the authority can smuggle an unexpected host past clients
    # (http://127.0.0.1@evil.com) - reject it outright.
    if parsed.username or parsed.password:
        raise ValidationError("webhook URL must not contain userinfo")
    host = parsed.hostname
    if not host:
        raise ValidationError("webhook URL has empty host")
    # Strip IPv6 zone id ("fe80::1%eth0") before parsing.
    host_bare = host.split("%", 1)[0]
    if not allow_private:
        if host.lower() in _INTERNAL_SINGLE_LABELS:
            raise ValidationError(f"webhook host is an internal service: {host}")
        ip = None
        try:
            ip = ipaddress.ip_address(host_bare)
        except ValueError:
            pass
        if ip is not None and _is_internal_ip(ip):
            raise ValidationError(f"webhook host is in private/reserved range: {ip}")
    return url


def is_private_host(host: str) -> bool:
    """True if host resolves to a private, loopback, link-local, reserved,
    multicast, or unspecified address (including IPv4-mapped IPv6).

    Only checks literal IPs; DNS resolution not performed here.
    """
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return _is_internal_ip(ip)
