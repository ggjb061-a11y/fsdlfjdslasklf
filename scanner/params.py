"""
Parameter discovery: finds hidden GET/POST parameters on endpoints.
Uses arjun, paramspider, or built-in heuristic probing.
"""
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from .utils import which, run, read_lines, write_lines
from .models import Finding

logger = logging.getLogger("autoscan.params")

COMMON_PARAMS = [
    "id", "page", "search", "q", "query", "name", "user", "username",
    "email", "password", "url", "redirect", "next", "return", "callback",
    "file", "path", "dir", "cmd", "exec", "action", "type", "lang",
    "token", "key", "api_key", "apikey", "secret", "debug", "test",
    "admin", "format", "output", "mode", "view", "template",
    "include", "src", "source", "target", "dest", "cat", "category",
    "sort", "order", "limit", "offset", "from", "to", "date",
    "year", "month", "day", "ref", "v", "version", "data", "json",
    "xml", "html", "txt", "download", "upload", "export", "import",
]


class ParamDiscovery:
    """Discover hidden URL parameters on live endpoints."""

    def __init__(self, dirs: dict, live_hosts: list, urls: list, threads: int = 10):
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.urls = urls
        self.threads = threads
        self.found_params: dict[str, list] = {}
        self.findings: list[Finding] = []

    def _arjun(self) -> None:
        """Use arjun for parameter discovery if available."""
        if not which("arjun"):
            return
        targets = self.live_hosts[:5]
        for i, host in enumerate(targets):
            out = f"{self.dirs['urls']}/arjun_{i}.json"
            run(
                ["arjun", "-u", host, "-oJ", out, "-t", str(self.threads),
                 "--stable", "-m", "GET"],
                timeout=300,
            )

    def _paramspider(self) -> None:
        """Use paramspider if available."""
        if not which("paramspider"):
            return
        out_dir = f"{self.dirs['urls']}/paramspider"
        Path(out_dir).mkdir(exist_ok=True)
        # paramspider outputs to current dir by default
        run(
            ["paramspider", "-d", self.live_hosts[0].split("/")[2] if self.live_hosts
             else self.urls[0] if self.urls else ""],
            timeout=120,
        )

    def _builtin_probe(self) -> None:
        """Probe common parameters on endpoints to find reflected ones."""
        # Select unique base URLs (no params)
        base_urls = set()
        for u in self.urls:
            url = u if isinstance(u, str) else u.url
            base = url.split("?")[0]
            if base.startswith("http") and len(base_urls) < 20:
                base_urls.add(base)

        if not base_urls:
            base_urls = set(self.live_hosts[:10])

        canary = "autoscan7x7probe"

        def _test_url(base: str) -> tuple[str, list]:
            reflected = []
            # Get baseline response length
            rc, baseline, _ = run(
                ["curl", "-sL", "--max-time", "8", base],
                timeout=12,
            )
            if rc != 0:
                return base, []
            base_len = len(baseline)

            for param in COMMON_PARAMS:
                test_url = f"{base}{'&' if '?' in base else '?'}{param}={canary}"
                rc, body, _ = run(
                    ["curl", "-sL", "--max-time", "5", test_url],
                    timeout=8,
                )
                if rc != 0 or not body:
                    continue

                # Check if param is reflected in response (indicates it's accepted)
                if canary in body:
                    reflected.append(param)
                elif abs(len(body) - base_len) > 50:
                    # Response changed significantly – param is likely processed
                    reflected.append(param)

            return base, reflected

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as ex:
            futures = {ex.submit(_test_url, url): url for url in base_urls}
            for future in as_completed(futures):
                url, params = future.result()
                if params:
                    self.found_params[url] = params
                    # Check for potentially dangerous reflections
                    for p in params:
                        if p in ("cmd", "exec", "file", "path", "include",
                                 "src", "source", "url", "redirect", "template"):
                            self.findings.append(Finding(
                                severity="medium",
                                title=f"Interesting parameter reflected: {p}",
                                host=url,
                                detail=f"Parameter '{p}' is accepted and changes response on {url}",
                                source="param_discovery",
                                url=f"{url}?{p}=test",
                            ))

    def run(self) -> tuple[dict, list]:
        """Returns (found_params, findings)."""
        steps = [
            ("Arjun", self._arjun),
            ("ParamSpider", self._paramspider),
            ("Built-in probe", self._builtin_probe),
        ]
        for name, fn in steps:
            logger.info(f"  → {name}")
            try:
                fn()
            except Exception as exc:
                logger.error(f"    [!] {name}: {exc}")

        if self.found_params:
            lines = [f"{url}: {', '.join(params)}" for url, params in self.found_params.items()]
            write_lines(f"{self.dirs['urls']}/discovered_params.txt", lines)
            logger.info(f"  Params found on {len(self.found_params)} endpoints")

        return self.found_params, self.findings
