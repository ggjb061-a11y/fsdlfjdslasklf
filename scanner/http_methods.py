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

    def _test_host(self, host: str) -> tuple[str, list]:
        """Test all methods on a host using curl. Returns (host, allowed_methods)."""
        allowed = []

        # First try OPTIONS to get allowed methods directly
        rc, out, _ = run(
            ["curl", "-sI", "--max-time", "10", "-X", "OPTIONS", host],
            timeout=15,
        )
        if rc == 0 and out:
            for line in out.splitlines():
                if line.lower().startswith("allow:"):
                    methods = [m.strip().upper() for m in line.split(":", 1)[1].split(",")]
                    allowed = methods
                    break

        # If OPTIONS didn't reveal methods, test each one
        if not allowed:
            for method in METHODS_TO_TEST:
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8", "-X", method, host],
                    timeout=12,
                )
                if rc == 0 and out:
                    first_line = out.splitlines()[0] if out.splitlines() else ""
                    # Consider 2xx, 3xx, 401, 405 as "known response" (method recognized)
                    status = 0
                    if "HTTP/" in first_line:
                        parts = first_line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            status = int(parts[1])
                    # 405 = method not allowed (but recognized), skip
                    # 501 = not implemented, skip
                    if status and status not in (405, 501):
                        allowed.append(method)

        return host, allowed

    def run(self) -> dict:
        if not self.live_hosts:
            return {}

        targets = self.live_hosts[:20]  # limit to avoid excessive scanning
        logger.info(f"  Testing HTTP methods on {len(targets)} hosts...")

        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as ex:
            futures = {ex.submit(self._test_host, h): h for h in targets}
            for future in as_completed(futures):
                host, methods = future.result()
                if methods:
                    self.allowed_methods[host] = methods

                    # Flag dangerous methods
                    dangerous_found = set(methods) & DANGEROUS
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
                        self.findings.append(Finding(
                            severity="medium",
                            title="HTTP TRACE Enabled (XST risk)",
                            host=host,
                            detail="TRACE method is enabled. Can be used in Cross-Site Tracing (XST) attacks.",
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
