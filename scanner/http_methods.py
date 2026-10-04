"""
HTTP method detection: finds allowed methods per endpoint and detects
dangerous method exposure (PUT, DELETE, TRACE, etc.).
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import which, run, write_lines
from .models import Finding

logger = logging.getLogger("autoscan.methods")

METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
                   "HEAD", "TRACE", "CONNECT"]

DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT"}


class MethodTester:
    """Test which HTTP methods are accepted on live hosts."""

    def __init__(self, dirs: dict, live_hosts: list, threads: int = 10):
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads
        self.allowed_methods: dict[str, list] = {}   # host -> [methods]
        self.findings: list[Finding] = []

    @staticmethod
    def _parse_status(headers: str) -> int:
        if not headers:
            return 0
        first = headers.splitlines()[0] if headers.splitlines() else ""
        if "HTTP/" not in first:
            return 0
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return 0

    @staticmethod
    def _content_length(headers: str) -> int:
        for line in (headers or "").splitlines():
            if line.lower().startswith("content-length:"):
                try:
                    return int(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    return 0
        return 0

    def _test_host(self, host: str) -> tuple[str, list, dict]:
        """Test all methods on a host using curl.

        Returns (host, allowed_methods, meta). meta carries XST evidence.

        FP guard: compare against a GET baseline. SPAs, catch-all routers,
        and WAFs return 200 to every method on `/`, which the old
        status-only check mistook for 'method accepted'. We mark a method
        'accepted' only when its response differs materially from the GET
        baseline (different 2xx/3xx class, or Content-Length delta > 20%).
        """
        allowed: list = []
        meta: dict = {}

        # OPTIONS Allow header is the authoritative source when present.
        rc, out, _ = run(
            ["curl", "-sI", "--max-time", "10", "-X", "OPTIONS", host],
            timeout=15,
        )
        if rc == 0 and out:
            for line in out.splitlines():
                if line.lower().startswith("allow:"):
                    methods = [m.strip().upper() for m in line.split(":", 1)[1].split(",")]
                    allowed = [m for m in methods if m]
                    break

        if not allowed:
            # GET baseline
            rc, base_headers, _ = run(
                ["curl", "-sI", "--max-time", "8", "-X", "GET", host],
                timeout=12,
            )
            if rc != 0 or not base_headers:
                return host, [], meta
            base_status = self._parse_status(base_headers)
            base_clen = self._content_length(base_headers)
            if not base_status:
                return host, [], meta

            for method in METHODS_TO_TEST:
                rc, m_headers, _ = run(
                    ["curl", "-sI", "--max-time", "8", "-X", method, host],
                    timeout=12,
                )
                if rc != 0 or not m_headers:
                    continue
                status = self._parse_status(m_headers)
                if not status or status in (405, 501):
                    continue
                # Baseline-differential: method is 'accepted' only when
                # the response differs from GET (status class or sizable
                # Content-Length delta). Otherwise it's a catch-all 200.
                m_clen = self._content_length(m_headers)
                same_class = (status // 100) == (base_status // 100)
                size_delta_pct = 0.0
                if base_clen:
                    size_delta_pct = abs(m_clen - base_clen) / max(1, base_clen)
                if method == "GET":
                    allowed.append(method)
                    continue
                if not same_class or size_delta_pct > 0.2:
                    allowed.append(method)

            # Real XST probe: send a TRACE with a nonce header and look
            # for the nonce reflected in the response body. The old
            # check only looked at status and emitted an XST finding on
            # any non-405 response.
            if "TRACE" in allowed:
                nonce = "autoscan7x7xst"
                rc, body, _ = run(
                    ["curl", "-s", "--max-time", "8", "-X", "TRACE",
                     "-H", f"X-XST-Probe: {nonce}", host],
                    timeout=12,
                )
                if rc == 0 and body and nonce in body:
                    meta["xst_confirmed"] = True

        return host, allowed, meta

    def run(self) -> dict:
        if not self.live_hosts:
            return {}

        targets = self.live_hosts[:20]  # limit to avoid excessive scanning
        logger.info(f"  Testing HTTP methods on {len(targets)} hosts...")

        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as ex:
            futures = {ex.submit(self._test_host, h): h for h in targets}
            for future in as_completed(futures):
                host, methods, meta = future.result()
                if methods:
                    self.allowed_methods[host] = methods

                    # Flag dangerous methods except TRACE, which gets its own
                    # XST-specific finding below.
                    dangerous_found = (set(methods) & DANGEROUS) - {"TRACE"}
                    if dangerous_found:
                        sev = "high" if "PUT" in dangerous_found or "DELETE" in dangerous_found else "medium"
                        self.findings.append(Finding(
                            severity=sev,
                            title=f"Dangerous HTTP Methods Enabled: {', '.join(sorted(dangerous_found))}",
                            host=host,
                            detail=(
                                f"Host accepts: {', '.join(sorted(dangerous_found))}. "
                                "These methods can allow unauthorized file upload/deletion."
                            ),
                            source="method_tester",
                            url=host,
                        ))

                    if "TRACE" in methods:
                        # XST requires the server to ECHO our request back.
                        # If the nonce probe reflected, this is a real XST
                        # risk; otherwise it's informational.
                        if meta.get("xst_confirmed"):
                            self.findings.append(Finding(
                                severity="medium",
                                title="HTTP TRACE Enabled with request-echo (XST confirmed)",
                                host=host,
                                detail=(
                                    "TRACE method is enabled and echoes request "
                                    "headers back in the response body. Cross-Site "
                                    "Tracing (XST) is viable on clients that still "
                                    "allow custom TRACE methods."
                                ),
                                source="method_tester",
                                url=host,
                            ))
                        else:
                            self.findings.append(Finding(
                                severity="info",
                                title="HTTP TRACE Enabled (no echo)",
                                host=host,
                                detail=(
                                    "TRACE is accepted but the request-echo probe "
                                    "did not reflect our nonce header, so XST is "
                                    "not directly exploitable here."
                                ),
                                source="method_tester",
                                url=host,
                            ))

        # Save results
        lines = []
        for host, methods in self.allowed_methods.items():
            dangerous_tag = " ⚠️  DANGEROUS" if set(methods) & DANGEROUS else ""
            lines.append(f"{host}: {', '.join(methods)}{dangerous_tag}")
        write_lines(f"{self.dirs['methods']}/allowed_methods.txt", lines)

        logger.info(f"  Method test done | {len(self.allowed_methods)} hosts")
        return self.allowed_methods
