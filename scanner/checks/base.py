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

    def execute(self) -> list[Finding]:
        raise NotImplementedError

    def run(self) -> list[Finding]:
        try:
            self.log.info(f"  -> {self.name}")
            return self.execute()
        except Exception as exc:
            self.log.error(f"    [!] {self.name}: {exc}")
            return []
