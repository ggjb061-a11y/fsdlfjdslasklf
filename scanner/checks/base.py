"""
Base class for every vulnerability check.

Provides the shared helpers that used to be reimplemented in 12+ files:
  * _fetch(url)                    simple body-only fetch
  * _fetch_full(url)               (status, body, headers) in one call
  * _fetch_json(url)               parsed JSON or None
  * _post(url, body, headers)      POST helper
  * _url(base, param, value)       URL-encoded query builder
  * _baseline(host)                cached baseline-body fetcher
  * _status_code(line)             robust HTTP status parser (no "200 in line" bug)
"""
import json
import logging
import re
import time
import urllib.parse
from typing import Any

from ..models import Finding
from ..utils import run

logger = logging.getLogger("autoscan.checks")


class BaseCheck:
    """Abstract base for every vulnerability check module."""

    name: str = "base"
    description: str = ""

    # Default HTTP timeouts (seconds) - checks can override per-call too
    DEFAULT_FETCH_TIMEOUT = 8
    STATUS_SENTINEL = "\n__STATUS__:%{http_code}"

    def __init__(self, target: str, dirs: dict, live_hosts: list,
                 threads: int = 10, **kwargs):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads
        self.findings: list[Finding] = []
        self.log = logging.getLogger(f"autoscan.checks.{self.name}")
        self._baseline_cache: dict[str, str] = {}
        import threading as _threading
        self._baseline_lock = _threading.Lock()

    # =====================================================================
    # Host selection helpers
    # =====================================================================
    def _hosts(self, limit: int = 5) -> list:
        return self.live_hosts[:limit] or [f"https://{self.target}"]

    def _targets_file(self) -> str:
        from ..utils import write_lines
        tf = f"{self.dirs['vuln']}/targets.txt"
        hosts = self.live_hosts or [f"https://{self.target}", f"http://{self.target}"]
        write_lines(tf, hosts)
        return tf

    # =====================================================================
    # HTTP helpers (shared across all 42 check classes)
    # =====================================================================
    def _curl_args(self, url: str, timeout: int, method: str,
                    headers: list, data: Any, follow: bool,
                    insecure: bool, path_as_is: bool,
                    with_status: bool) -> list:
        """Build a curl argv the right way; adds -k by default for scans."""
        args = ["curl", "-s", "--max-time", str(timeout)]
        if insecure:
            args.append("-k")
        if follow:
            args.append("-L")
        if path_as_is:
            args.append("--path-as-is")
        if method.upper() != "GET":
            args += ["-X", method.upper()]
        for h in headers or []:
            args += ["-H", h]
        if data is not None:
            if not isinstance(data, (str, bytes)):
                data = json.dumps(data)
            args += ["-d", data]
        if with_status:
            args += ["-w", self.STATUS_SENTINEL]
        # `--` separator so a URL/host beginning with `-` (crafted redirect
        # target, attacker-controlled wordlist entry) cannot be re-parsed
        # as a curl option.
        args.append("--")
        args.append(url)
        return args

    def _run_curl(self, args: list, timeout: int) -> tuple[int, str]:
        rc, body, _ = run(args, timeout=timeout + 4)
        if rc != 0 or not body:
            return 0, ""
        return rc, body

    @staticmethod
    def _split_status(body: str) -> tuple[int, str]:
        """Extract trailing __STATUS__:NNN from body; return (code, body_without)."""
        if not body:
            return 0, ""
        m = re.search(r"__STATUS__:(\d+)\s*$", body)
        if m:
            return int(m.group(1)), body[: m.start()]
        return 0, body

    def _fetch(self, url: str, timeout: int = None,
                headers: list = None) -> str:
        """Simple fetch; returns body (empty string on failure)."""
        t = timeout or self.DEFAULT_FETCH_TIMEOUT
        args = self._curl_args(url, t, "GET", headers, None,
                                 follow=True, insecure=True,
                                 path_as_is=False, with_status=False)
        _, body = self._run_curl(args, t)
        return body

    def _fetch_full(self, url: str, timeout: int = None,
                     headers: list = None, follow: bool = True,
                     path_as_is: bool = False) -> tuple[int, str]:
        """Return (status, body) with status parsed robustly."""
        t = timeout or self.DEFAULT_FETCH_TIMEOUT
        args = self._curl_args(url, t, "GET", headers, None,
                                 follow=follow, insecure=True,
                                 path_as_is=path_as_is,
                                 with_status=True)
        _, body = self._run_curl(args, t)
        return self._split_status(body)

    def _fetch_headers(self, url: str, timeout: int = None,
                        headers: list = None) -> tuple[int, str]:
        """HEAD-like fetch; returns (status, headers_text)."""
        t = timeout or self.DEFAULT_FETCH_TIMEOUT
        args = ["curl", "-skI", "--max-time", str(t),
                "-w", self.STATUS_SENTINEL]
        for h in headers or []:
            args += ["-H", h]
        args.append(url)
        _, body = self._run_curl(args, t)
        return self._split_status(body)

    def _fetch_json(self, url: str, timeout: int = None,
                     headers: list = None) -> Any:
        """Fetch URL and parse body as JSON. Returns None on any failure."""
        body = self._fetch(url, timeout=timeout, headers=headers)
        if not body:
            return None
        try:
            return json.loads(body)
        except Exception:
            return None

    def _post(self, url: str, data: Any = None, headers: list = None,
               timeout: int = None, follow: bool = False) -> tuple[int, str]:
        """POST helper; data can be str, bytes, or any JSON-serializable."""
        t = timeout or self.DEFAULT_FETCH_TIMEOUT
        args = self._curl_args(url, t, "POST", headers, data,
                                 follow=follow, insecure=True,
                                 path_as_is=False, with_status=True)
        _, body = self._run_curl(args, t)
        return self._split_status(body)

    # =====================================================================
    # URL building
    # =====================================================================
    @staticmethod
    def _url(base: str, param: str, value: str) -> str:
        """Build a URL with a single URL-encoded query parameter.

        Correctly extends an existing query string instead of producing
        `?a=1?q=v`. Both the param NAME and value are URL-encoded so a
        name containing `&`/`=`/`#` cannot corrupt the request.
        """
        parsed = urllib.parse.urlparse(base)
        existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        existing.append((param, value))
        new_query = urllib.parse.urlencode(existing, quote_via=urllib.parse.quote,
                                            safe="")
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    # =====================================================================
    # Baseline caching - 1 benign request per host, cached
    # =====================================================================
    def _baseline(self, host: str, timeout: int = 6) -> str:
        """Return the benign baseline body for `host`, cached per instance.

        Thread-safe (shared across the check's worker pool) and does NOT
        cache empty bodies - a transient failure must not poison every
        later baseline comparison for the lifetime of the check.
        """
        cached = self._baseline_cache.get(host)
        if cached:
            return cached
        with self._baseline_lock:
            cached = self._baseline_cache.get(host)
            if cached:
                return cached
            body = self._fetch(host, timeout=timeout)
            if body:
                self._baseline_cache[host] = body
            return body or ""

    # =====================================================================
    # Status line parsing (used across checks)
    # =====================================================================
    @staticmethod
    def _status_code(status_line: str) -> int:
        """Extract numeric HTTP status from a 'HTTP/1.1 302 Found' line.

        Returns 0 if not parseable. Guards against the "200" in line bug.
        """
        if not status_line:
            return 0
        parts = status_line.split()
        for part in parts[1:3]:
            if part.isdigit() and 100 <= int(part) < 600:
                return int(part)
        return 0

    # =====================================================================
    # Lifecycle
    # =====================================================================
    def execute(self) -> list[Finding]:
        raise NotImplementedError

    def run(self) -> list[Finding]:
        try:
            self.log.info(f"  -> {self.name}")
            return self.execute()
        except Exception as exc:
            # Log the full traceback at DEBUG level so a quiet failure
            # can be traced; INFO level stays clean.
            self.log.error(f"    [!] {self.name}: {exc}")
            self.log.debug(f"    traceback:", exc_info=True)
            return []
