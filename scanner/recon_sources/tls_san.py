"""TLS certificate SAN enumeration via openssl s_client."""
import re
import socket
from ._helpers import filter_subs
from ..utils import run, which


def fetch(domain: str, ip: str = None) -> set[str]:
    """Connect to the host on 443, parse its certificate's SubjectAltName."""
    if not which("openssl"):
        return set()
    target = ip or domain
    try:
        # Resolve first to avoid openssl DNS surprise
        if not ip:
            try:
                socket.gethostbyname(domain)
            except Exception:
                return set()
    except Exception:
        pass

    # Pull cert text
    rc, out, err = run(
        ["openssl", "s_client", "-showcerts", "-servername", domain,
         "-connect", f"{target}:443"],
        stdin_data="", timeout=15,
    )
    cert_text = (out or "") + (err or "")
    if not cert_text or "BEGIN CERTIFICATE" not in cert_text:
        return set()

    # Pipe cert through 'openssl x509 -text' to get SAN
    rc2, decoded, _ = run(
        ["openssl", "x509", "-noout", "-text"],
        stdin_data=cert_text, timeout=10,
    )
    if rc2 != 0 or not decoded:
        return set()

    sans = re.findall(r"DNS:([A-Za-z0-9._*-]+)", decoded)
    return filter_subs(sans, domain)
