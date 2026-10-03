"""
JS file analyzer: downloads .js files and scans for secrets,
hardcoded credentials, API keys, endpoints, and sensitive data.
"""
import re
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import which, run, write_lines
from .models import JSSecret, Finding

logger = logging.getLogger("autoscan.js")

# ─── Secret patterns ──────────────────────────────────────────────────────────
# (name, regex, severity)
SECRET_PATTERNS = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}",                             "critical"),
    ("AWS Secret Key",        r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-z/+]{40}['\"]", "critical"),
    ("GitHub Token",          r"ghp_[A-Za-z0-9]{36}",                          "critical"),
    ("GitHub OAuth",          r"gho_[A-Za-z0-9]{36}",                          "critical"),
    ("Google API Key",        r"AIza[0-9A-Za-z\-_]{35}",                       "high"),
    ("Slack Token",           r"xox[baprs]-[0-9A-Za-z\-]+",                    "high"),
    ("Slack Webhook",         r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+", "high"),
    ("Firebase URL",          r"https://[a-z0-9\-]+\.firebaseio\.com",         "medium"),
    ("Heroku API Key",        r"(?i)heroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "high"),
    ("Stripe Key (live)",     r"sk_live_[0-9a-zA-Z]{24,}",                     "critical"),
    ("Stripe Key (test)",     r"sk_test_[0-9a-zA-Z]{24,}",                     "medium"),
    ("Twilio SID",            r"AC[0-9a-fA-F]{32}",                            "high"),
    ("Mailgun Key",           r"key-[0-9a-zA-Z]{32}",                          "high"),
    ("SendGrid Key",          r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",  "high"),
    ("JWT Token",             r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "medium"),
    ("Private Key Header",    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",   "critical"),
    ("Generic Password",      r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "high"),
    ("Generic Secret",        r"(?i)(secret|token|apikey|api_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "medium"),
    ("Basic Auth in URL",     r"https?://[^:@\s]+:[^:@\s]+@[^/\s]+",          "high"),
    ("S3 Bucket URL",         r"https?://[a-z0-9\-]+\.s3[\.\-][a-z0-9\-]*\.amazonaws\.com", "medium"),
    ("Internal IP",           r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?!\d)", "low"),
    ("Email Address",         r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "info"),
]

COMPILED = [(name, re.compile(pat), sev) for name, pat, sev in SECRET_PATTERNS]

# Regex to find additional API paths inside JS
ENDPOINT_RE = re.compile(
    r"""["'`](\/(api|v\d+|graphql|rest|auth|admin|user|login|account|token|oauth)[^"'`\s]{0,200})["'`]""",
    re.I,
)


class JSAnalyzer:
    """Download JS files and hunt for secrets and hidden endpoints."""

    def __init__(self, dirs: dict, js_urls: list, threads: int = 10):
        self.dirs = dirs
        self.js_urls = js_urls
        self.threads = threads
        self.secrets: list[JSSecret] = []
        self.endpoints_found: list[str] = []
        self.findings: list[Finding] = []

    # ─── Download ────────────────────────────────────────────────────────────

    def _download(self, url: str) -> tuple[str, str]:
        """Download a JS file. Returns (url, local_path)."""
        # Create a safe filename
        name = re.sub(r"[^a-zA-Z0-9._-]", "_", url.split("/")[-1].split("?")[0])
        if not name.endswith(".js"):
            name += ".js"
        # Avoid name collisions
        dest = Path(self.dirs["js_files"]) / name
        counter = 0
        while dest.exists():
            counter += 1
            dest = Path(self.dirs["js_files"]) / f"{name}_{counter}.js"

        rc, _, _ = run(
            ["curl", "-sL", "--max-time", "20", "--compressed",
             "-A", "Mozilla/5.0", "-o", str(dest), url],
            timeout=30,
        )
        if rc == 0 and dest.exists() and dest.stat().st_size > 0:
            return url, str(dest)
        return url, ""

    # ─── Analyze ─────────────────────────────────────────────────────────────

    def _analyze_file(self, url: str, path: str) -> None:
        """Scan a single JS file for secrets and endpoints."""
        try:
            content = Path(path).read_text(errors="replace")
        except Exception:
            return

        lines = content.splitlines()

        # Secret detection
        for name, pat, sev in COMPILED:
            for i, line in enumerate(lines, 1):
                for match in pat.finditer(line):
                    val = match.group(0)
                    # Deduplicate: skip if same pattern+value already seen
                    if not any(
                        s.pattern_name == name and s.match == val
                        for s in self.secrets
                    ):
                        self.secrets.append(JSSecret(
                            file_url=url,
                            pattern_name=name,
                            match=val[:120],  # truncate long matches
                            line=i,
                            severity=sev,
                        ))
                        self.findings.append(Finding(
                            severity=sev,
                            title=f"Secret: {name}",
                            host=url,
                            detail=f"Found at line {i}: {val[:80]}",
                            source="js_analyzer",
                            url=url,
                            evidence=val[:120],
                        ))

        # Endpoint extraction
        for match in ENDPOINT_RE.finditer(content):
            ep = match.group(1)
            if ep not in self.endpoints_found:
                self.endpoints_found.append(ep)

    # ─── Orchestrator ─────────────────────────────────────────────────────────

    def run(self) -> tuple[list, list, list]:
        """Returns (secrets, endpoints, findings)."""
        if not self.js_urls:
            logger.info("  No JS files to analyze")
            return [], [], []

        logger.info(f"  Downloading {len(self.js_urls)} JS files...")

        downloaded: list[tuple[str, str]] = []
        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as ex:
            futures = {ex.submit(self._download, url): url for url in self.js_urls}
            for future in as_completed(futures):
                url, path = future.result()
                if path:
                    downloaded.append((url, path))

        logger.info(f"  Downloaded: {len(downloaded)}")

        for url, path in downloaded:
            try:
                self._analyze_file(url, path)
            except Exception as exc:
                logger.debug(f"  analyze {url}: {exc}")

        # Save results
        secrets_file = f"{self.dirs['js_secrets']}/secrets.txt"
        endpoints_file = f"{self.dirs['js_secrets']}/endpoints.txt"

        secret_lines = [
            f"[{s.severity.upper()}] {s.pattern_name} | line {s.line} | {s.file_url}\n  Match: {s.match}"
            for s in self.secrets
        ]
        write_lines(secrets_file, secret_lines)
        write_lines(endpoints_file, sorted(set(self.endpoints_found)))

        logger.info(
            f"  JS analysis | secrets={len(self.secrets)}"
            f" | endpoints={len(self.endpoints_found)}"
        )
        return self.secrets, self.endpoints_found, self.findings
