"""Base class for all vulnerability checks."""
import logging
from ..models import Finding

logger = logging.getLogger("autoscan.checks")


class BaseCheck:
    """Abstract base for every vulnerability check module."""

    name: str = "base"
    description: str = ""

    def __init__(self, target: str, dirs: dict, live_hosts: list, threads: int = 10, **kwargs):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads
        self.findings: list[Finding] = []
        self.log = logging.getLogger(f"autoscan.checks.{self.name}")

    def _hosts(self, limit: int = 5) -> list:
        return self.live_hosts[:limit] or [f"https://{self.target}"]

    def _targets_file(self) -> str:
        from ..utils import write_lines
        tf = f"{self.dirs['vuln']}/targets.txt"
        hosts = self.live_hosts or [f"https://{self.target}", f"http://{self.target}"]
        write_lines(tf, hosts)
        return tf

    @staticmethod
    def _status_code(status_line: str) -> int:
        """Extract numeric HTTP status from a 'HTTP/1.1 302 Found' line.

        Returns 0 if not parseable. Guards against the common bug of
        checking `"200" in status_line` which spuriously matches lines
        with 200X-numbered dates or servers.
        """
        if not status_line:
            return 0
        parts = status_line.split()
        for part in parts[1:3]:
            if part.isdigit() and 100 <= int(part) < 600:
                return int(part)
        return 0

    def execute(self) -> list[Finding]:
        raise NotImplementedError

    def run(self) -> list[Finding]:
        try:
            self.log.info(f"  -> {self.name}")
            return self.execute()
        except Exception as exc:
            self.log.error(f"    [!] {self.name}: {exc}")
            return []
