"""Shared utilities: tool detection, subprocess runner, directory setup, helpers."""
import subprocess
import shutil
import logging
import json
import re
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple

logger = logging.getLogger("autoscan.utils")

# ─── Tool detection ───────────────────────────────────────────────────────────

def which(name: str) -> Optional[str]:
    """Return absolute path of tool if it exists in PATH."""
    return shutil.which(name)


def tools_status(names: list) -> dict:
    """Return dict {tool: found/missing} for display."""
    return {n: ("✓" if which(n) else "✗") for n in names}


# ─── Subprocess runner ────────────────────────────────────────────────────────

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
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin_data,
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
        logger.debug(f"run({cmd}): {exc}")
        return -4, "", str(exc)


# ─── Directory builder ────────────────────────────────────────────────────────

def create_dirs(base: str, target: str) -> dict:
    """Create per-target timestamped directory tree. Returns path dict."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    root = Path(base) / safe / ts

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
