"""Shared utilities: tool detection, subprocess runner, directory setup, helpers."""
import subprocess
import shutil
import logging
import json
import re
import socket
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple

logger = logging.getLogger("autoscan.utils")

# curl --max-filesize default (10 MB) applied to every curl request made
# through run() to avoid DoS by hostile targets returning multi-GB bodies.
CURL_MAX_FILESIZE = 10 * 1024 * 1024
# curl --max-redirs: cap redirect chain length to prevent redirect-based SSRF
# into cloud metadata (169.254.169.254) etc.
CURL_MAX_REDIRS = 3

# ─── Tool detection ───────────────────────────────────────────────────────────

def which(name: str) -> Optional[str]:
    """Return absolute path of tool if it exists in PATH."""
    return shutil.which(name)


def tools_status(names: list) -> dict:
    """Return dict {tool: found/missing} for display."""
    return {n: ("✓" if which(n) else "✗") for n in names}


# ─── Subprocess runner ────────────────────────────────────────────────────────

_PROXY: Optional[str] = None
_AUTH_HEADERS: List[str] = []
_COOKIE: Optional[str] = None
_BASIC_AUTH: Optional[str] = None

# Rate-limiter state (thread-safe)
_RATE_LIMIT: float = 0.0
_LAST_REQUEST_LOCK = threading.Lock()
_LAST_REQUEST_TIME: float = 0.0


def set_proxy(proxy: Optional[str]) -> None:
    global _PROXY
    _PROXY = proxy


def get_proxy() -> Optional[str]:
    return _PROXY


def set_auth(headers: list = None, cookie: str = None,
             bearer: str = None, basic: str = None) -> None:
    """Register auth material to be injected into every curl call."""
    global _AUTH_HEADERS, _COOKIE, _BASIC_AUTH
    _AUTH_HEADERS = list(headers or [])
    if bearer:
        _AUTH_HEADERS.append(f"Authorization: Bearer {bearer}")
    _COOKIE = cookie
    _BASIC_AUTH = basic


def get_auth() -> dict:
    return {"headers": _AUTH_HEADERS, "cookie": _COOKIE, "basic": _BASIC_AUTH}


def set_rate_limit(delay_seconds: float) -> None:
    """Set a global inter-request delay (in seconds) for every outbound curl."""
    global _RATE_LIMIT
    _RATE_LIMIT = max(0.0, float(delay_seconds))


def _apply_rate_limit() -> None:
    global _LAST_REQUEST_TIME
    if _RATE_LIMIT <= 0:
        return
    with _LAST_REQUEST_LOCK:
        now = time.monotonic()
        elapsed = now - _LAST_REQUEST_TIME
        if elapsed < _RATE_LIMIT:
            time.sleep(_RATE_LIMIT - elapsed)
        _LAST_REQUEST_TIME = time.monotonic()

def run(
    cmd: List[str],
    output_file: Optional[str] = None,
    timeout: int = 300,
    cwd: Optional[str] = None,
    stdin_data: Optional[str] = None,
    merge_stderr: bool = False,
) -> Tuple[int, str, str]:
    """
    Run a command safely. Returns (returncode, stdout, stderr).
    Writes stdout to output_file if provided.
    Never raises on tool-not-found or timeout – returns negative rc.
    """
    if cmd and (cmd[0] == "curl" or cmd[0].endswith("/curl")):
        _apply_rate_limit()
        prefix = [cmd[0], "--max-filesize", str(CURL_MAX_FILESIZE),
                 "--max-redirs", str(CURL_MAX_REDIRS)]
        if _PROXY:
            prefix += ["--proxy", _PROXY]
        for hdr in _AUTH_HEADERS:
            prefix += ["-H", hdr]
        if _COOKIE:
            prefix += ["-H", f"Cookie: {_COOKIE}"]
        if _BASIC_AUTH:
            prefix += ["-u", _BASIC_AUTH]
        cmd = prefix + cmd[1:]
    try:
        env = None
        if _PROXY and cmd and cmd[0] not in ("curl",):
            import os
            env = {**os.environ, "HTTP_PROXY": _PROXY, "HTTPS_PROXY": _PROXY,
                   "http_proxy": _PROXY, "https_proxy": _PROXY}
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin_data,
            env=env,
        )
        out = result.stdout
        err = result.stderr
        if merge_stderr:
            out = out + ("\n" + err if err else "")
        if output_file and out.strip():
            Path(output_file).write_text(out)
        return result.returncode, out, err
    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout ({timeout}s): {cmd[0]}")
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except PermissionError:
        return -3, "", f"permission denied: {cmd[0]}"
    except Exception as exc:
        logger.debug(f"run({_redact_argv(cmd)}): {exc}")
        return -4, "", str(exc)


def _redact_argv(cmd: List[str]) -> List[str]:
    """Return a shallow copy of cmd with Authorization/Cookie/-u values masked.

    utils.run prepends auth material (Authorization: Bearer, Cookie, -u) to
    every curl invocation. On any curl exception the raw argv would reach the
    debug log, which is a real credential disclosure path.
    """
    out = []
    i = 0
    while i < len(cmd):
        tok = cmd[i]
        if tok == "-H" and i + 1 < len(cmd):
            hdr = cmd[i + 1]
            low = hdr.lower()
            if low.startswith("authorization:") or low.startswith("cookie:") \
                    or low.startswith("x-api-key:") or low.startswith("x-auth-token:"):
                name = hdr.split(":", 1)[0]
                out.extend([tok, f"{name}: <redacted>"])
            else:
                out.extend([tok, hdr])
            i += 2
            continue
        if tok == "-u" and i + 1 < len(cmd):
            out.extend([tok, "<redacted>"])
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


# ─── Directory builder ────────────────────────────────────────────────────────

def create_dirs(base: str, target: str) -> dict:
    """Create per-target timestamped directory tree. Returns path dict."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", target)
    safe = re.sub(r"_+", "_", safe).strip("_") or "target"
    root = Path(base).resolve() / safe / ts
    if Path(base).resolve() not in root.parents:
        raise ValueError(f"Unsafe target path: {target}")

    layout = {
        "base":         root,
        "recon":        root / "01_recon",
        "subdomains":   root / "01_recon" / "subdomains",
        "dns":          root / "01_recon" / "dns",
        "ports":        root / "01_recon" / "ports",
        "screenshots":  root / "01_recon" / "screenshots",
        "tech":         root / "01_recon" / "technologies",
        "urls":         root / "02_urls",
        "urls_live":    root / "02_urls" / "live",
        "urls_wayback": root / "02_urls" / "wayback",
        "js":           root / "03_js_analysis",
        "js_files":     root / "03_js_analysis" / "files",
        "js_secrets":   root / "03_js_analysis" / "secrets",
        "methods":      root / "04_http_methods",
        "vuln":         root / "05_vuln",
        "nuclei":       root / "05_vuln" / "nuclei",
        "nikto":        root / "05_vuln" / "nikto",
        "ssl":          root / "05_vuln" / "ssl",
        "dirs":         root / "05_vuln" / "dirs",
        "reports":      root / "06_reports",
    }

    for path in layout.values():
        path.mkdir(parents=True, exist_ok=True)

    return {k: str(v) for k, v in layout.items()}


# ─── File helpers ─────────────────────────────────────────────────────────────

def read_lines(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(errors="replace").splitlines() if l.strip()]


def write_lines(path: str, lines: List[str]) -> None:
    Path(path).write_text("\n".join(lines))


def parse_jsonl(path: str) -> List[dict]:
    """Parse newline-delimited JSON file. Skips malformed lines."""
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


# ─── Network helpers ─────────────────────────────────────────────────────────

def resolve_ip(domain: str) -> str:
    """Return first A record or empty string."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def resolve_all_ips(domain: str) -> List[str]:
    """Return all IPs for a domain."""
    try:
        return list({r[4][0] for r in socket.getaddrinfo(domain, None)})
    except Exception:
        return []


# ─── URL categorizers ────────────────────────────────────────────────────────

# Patterns that suggest login / auth pages
LOGIN_PATTERNS = re.compile(
    r"(login|signin|sign-in|auth|authenticate|account|portal|admin|dashboard|wp-admin|"
    r"panel|user|session|oauth|sso|saml|forgot.?password|reset.?password)", re.I
)

SENSITIVE_EXT = re.compile(
    r"\.(zip|tar|gz|bz2|7z|rar|sql|bak|backup|dump|db|sqlite|env|config|cfg|"
    r"conf|ini|log|key|pem|crt|cer|p12|pfx|ovpn|htpasswd|shadow)(\?.*)?$", re.I
)

JS_EXT = re.compile(r"\.js(\?.*)?$", re.I)

API_PATTERN = re.compile(
    r"(\/api\/|\/v\d+\/|\/graphql|\/rest\/|\/json|\/xml|\/soap)", re.I
)

STATIC_EXT = re.compile(
    r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|webp)(\?.*)?$", re.I
)


def categorize_url(url: str) -> dict:
    return {
        "is_login":          bool(LOGIN_PATTERNS.search(url)),
        "is_sensitive_file": bool(SENSITIVE_EXT.search(url)),
        "is_js":             bool(JS_EXT.search(url)),
        "is_api":            bool(API_PATTERN.search(url)),
        "is_static":         bool(STATIC_EXT.search(url)),
    }
