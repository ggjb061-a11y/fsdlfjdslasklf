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
        import json as _json
        targets = self.live_hosts[:5]
        for i, host in enumerate(targets):
            out = f"{self.dirs['urls']}/arjun_{i}.json"
            run(
                ["arjun", "-u", host, "-oJ", out, "-t", str(self.threads),
                 "--stable", "-m", "GET"],
                timeout=300,
            )
            p = Path(out)
            if not p.exists():
                continue
            try:
                data = _json.loads(p.read_text(errors="replace"))
            except Exception as exc:
                logger.debug(f"  arjun output parse failed: {exc}")
                continue
            if isinstance(data, dict):
                for url, info in data.items():
                    params = []
                    if isinstance(info, dict):
                        params = info.get("params", [])
                    elif isinstance(info, list):
                        params = info
                    if params:
                        existing = set(self.found_params.get(url, []))
                        existing.update(params)
                        self.found_params[url] = sorted(existing)
            elif isinstance(data, list):
                for entry in data:
                    url = entry.get("url", host) if isinstance(entry, dict) else host
                    params = entry.get("params", []) if isinstance(entry, dict) else []
                    if params:
                        existing = set(self.found_params.get(url, []))
                        existing.update(params)
                        self.found_params[url] = sorted(existing)

    def _paramspider(self) -> None:
        """Use paramspider if available. Output goes under dirs['urls']/paramspider."""
        if not which("paramspider"):
            return
        from .utils import read_lines
        out_dir = Path(f"{self.dirs['urls']}/paramspider")
        out_dir.mkdir(exist_ok=True)
        if self.live_hosts:
            host_str = self.live_hosts[0].split("/")[2] if "://" in self.live_hosts[0] else self.live_hosts[0]
        elif self.urls:
            first = self.urls[0]
            url = first.url if hasattr(first, "url") else str(first)
            host_str = url.split("/")[2] if "://" in url else url
        else:
            return
        rc, _, _ = run(
            ["paramspider", "-d", host_str, "-o", str(out_dir / f"{host_str}.txt")],
            timeout=120,
            cwd=str(out_dir),
        )
        for p in out_dir.glob("*.txt"):
            for line in read_lines(str(p)):
                if "?" in line and "=" in line:
                    base, qs = line.split("?", 1)
                    params = sorted({seg.split("=")[0] for seg in qs.split("&") if seg})
                    if params:
                        existing = set(self.found_params.get(base, []))
                        existing.update(params)
                        self.found_params[base] = sorted(existing)

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
        import re as _re

        def _fetch_with_status(url: str, timeout: int = 8) -> tuple[int, str]:
            """Return (http_status, body). Status 0 means fetch failed."""
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", str(timeout),
                 "-w", "\n__PARAMS_STATUS__:%{http_code}", url],
                timeout=timeout + 4,
            )
            if rc != 0 or not body:
                return 0, ""
            m = _re.search(r"__PARAMS_STATUS__:(\d+)\s*$", body)
            if m:
                return int(m.group(1)), body[:m.start()]
            return 0, body

        def _test_url(base: str) -> tuple[str, list]:
            reflected = []
            # Sample the baseline 3 times to measure natural variance.
            # Dynamic pages (CSRF tokens, timestamps, build hashes) differ
            # from themselves by more than 50 bytes on refetch, which the
            # old single-sample code mistook for parameter-induced change.
            samples = []
            base_status = 0
            for _ in range(3):
                st, body = _fetch_with_status(base, timeout=8)
                if st:
                    samples.append((st, body))
                    base_status = st
            if len(samples) < 2:
                return base, []
            base_len = len(samples[0][1])
            lengths = [len(b) for _s, b in samples]
            natural_variance = max(lengths) - min(lengths)
            # Require diff > max(variance*2, 50, 2% of body) so neither a
            # noisy large page nor a tiny page produces a flood of FPs.
            length_floor = max(50, natural_variance * 2, int(base_len * 0.02))

            # Case-insensitive canary check, so a server that normalizes case
            # (uppercase in a 'echo back' error) still matches.
            canary_bytes = canary.lower().encode()

            for param in COMMON_PARAMS:
                test_url = f"{base}{'&' if '?' in base else '?'}{param}={canary}"
                st, body = _fetch_with_status(test_url, timeout=5)
                if not st or not body:
                    continue
                # Only consider the body-length heuristic when both responses
                # share the same 2xx/3xx class; otherwise a 404 or WAF-block
                # page would look 'accepted' for every param.
                same_class = (st // 100) == (base_status // 100)

                # Reflection check (robust to case changes).
                if canary_bytes in body.encode(errors="replace").lower():
                    reflected.append(param)
                elif same_class and abs(len(body) - base_len) > length_floor:
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
