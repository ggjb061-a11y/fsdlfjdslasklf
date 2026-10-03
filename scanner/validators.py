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

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


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
    """
    if not isinstance(target, str):
        raise ValidationError("target must be a string")
    t = target.strip()
    if not t:
        raise ValidationError("target cannot be empty")
    if t.startswith("-"):
        raise ValidationError(f"target may not start with '-': {t!r}")
    for bad in ("/", "\\", "$", "`", ";", "|", "&", ">", "<",
                "(", ")", "*", "?", "[", "]", "{", "}", "!", "#", " ", "\t"):
        if bad in t:
            raise ValidationError(f"target contains forbidden character {bad!r}: {t!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in t):
        raise ValidationError(f"target contains control characters: {t!r}")

    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass

    if _HOSTNAME_RE.match(t):
        return t
    raise ValidationError(f"not a valid hostname or IP: {t!r}")


def validate_webhook_url(url: str, allow_private: bool = False) -> str:
    """Return the URL unchanged after validation, or raise ValidationError.

    Only http/https schemes allowed. Private/loopback blocked by default.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("webhook URL is required")
    if url.startswith("-") or url.startswith("@"):
        raise ValidationError(f"webhook URL may not start with '-' or '@': {url!r}")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"webhook scheme must be http(s): {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValidationError("webhook URL missing host")
    host = parsed.hostname
    if not host:
        raise ValidationError("webhook URL has empty host")
    if not allow_private:
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            pass
        if ip is not None:
            for net in _PRIVATE_RANGES:
                if ip in net:
                    raise ValidationError(f"webhook host is in private/reserved range: {ip}")
    return url


def is_private_host(host: str) -> bool:
    """True if host resolves to a private, loopback, link-local, or ULA address.

    Only checks literal IPs; DNS resolution not performed here to keep this cheap.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_RANGES)
