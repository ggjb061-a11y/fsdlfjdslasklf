"""Directory brute-force scanning."""
import json
import re
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run, read_lines

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/opt/wordlists/common.txt",
]

INTERESTING_PATHS = re.compile(
    r"/(admin|login|dashboard|debug|\.git|\.env|config|backup|phpinfo|server-status|wp-admin|setup|test|dev|staging|internal)",
    re.IGNORECASE,
)


class DirBruteCheck(BaseCheck):
    name = "Directory Brute-force"
    description = "Enumerate directories and files using wordlists"

    def __init__(self, *args, wordlist: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.custom_wordlist = wordlist

    def _first_wordlist(self) -> str | None:
        if self.custom_wordlist and Path(self.custom_wordlist).exists():
            return self.custom_wordlist
        for p in WORDLISTS:
            if Path(p).exists():
                return p
        return None

    def execute(self) -> list[Finding]:
        wordlist = self._first_wordlist()
        if not wordlist:
            self.log.debug("  No wordlist - skipping dir brute")
            return []

        targets = self._hosts(3)
        for i, host in enumerate(targets):
            gob = f"{self.dirs['dirs']}/gobuster_{i}.txt"
            ffu = f"{self.dirs['dirs']}/ffuf_{i}.json"
            fer = f"{self.dirs['dirs']}/feroxbuster_{i}.txt"
            if which("gobuster"):
                run(
                    ["gobuster", "dir", "-u", host, "-w", wordlist,
                     "-o", gob, "-t", str(self.threads),
                     "-q", "--no-error", "-b", "404,429"],
                    timeout=600,
                )
                self._parse_gobuster(gob, host)
            elif which("ffuf"):
                run(
                    ["ffuf", "-w", f"{wordlist}:FUZZ",
                     "-u", f"{host}/FUZZ",
                     "-of", "json",
                     "-o", ffu,
                     "-t", str(self.threads), "-s",
                     "-fc", "404,429",
                     "-mc", "all"],
                    timeout=600,
                )
                self._parse_ffuf(ffu, host)
            elif which("feroxbuster"):
                run(
                    ["feroxbuster", "-u", host, "-w", wordlist,
                     "-o", fer, "-t", str(self.threads),
                     "-q", "--no-state", "--filter-status", "404,429"],
                    timeout=600,
                )
                self._parse_feroxbuster(fer, host)

        return self.findings

    def _add_hit(self, url: str, status: int, host: str) -> None:
        if INTERESTING_PATHS.search(url):
            sev = "high" if any(p in url.lower() for p in [".git", ".env", "config", "admin", "phpinfo"]) else "medium"
        else:
            sev = "info"
        self.findings.append(Finding(
            severity=sev,
            title=f"Directory/File Found: {url}",
            host=host,
            detail=f"HTTP {status} on {url}",
            source="dirbrute",
            url=url,
        ))

    def _parse_gobuster(self, path: str, host: str) -> None:
        for line in read_lines(path):
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                url = host.rstrip("/") + m.group(1)
                self._add_hit(url, int(m.group(2)), host)

    def _parse_ffuf(self, path: str, host: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(errors="replace"))
        except Exception as exc:
            self.log.debug(f"  ffuf JSON parse failed: {exc}")
            return
        for r in data.get("results", []):
            url = r.get("url", "")
            status = r.get("status", 0)
            if url and status not in (404, 429):
                self._add_hit(url, int(status), host)

    def _parse_feroxbuster(self, path: str, host: str) -> None:
        for line in read_lines(path):
            m = re.match(r"^(\d+)\s+.*?(https?://\S+)", line)
            if m:
                status = int(m.group(1))
                url = m.group(2)
                if status not in (404, 429):
                    self._add_hit(url, status, host)
