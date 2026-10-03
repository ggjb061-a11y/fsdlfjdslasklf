"""Directory brute-force scanning."""
from pathlib import Path
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/opt/wordlists/common.txt",
]


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
            out_file = f"{self.dirs['dirs']}/gobuster_{i}.txt"
            if which("gobuster"):
                run(
                    ["gobuster", "dir", "-u", host, "-w", wordlist,
                     "-o", out_file, "-t", str(self.threads),
                     "-q", "--no-error", "-b", "404,429"],
                    timeout=600,
                )
            elif which("ffuf"):
                run(
                    ["ffuf", "-w", f"{wordlist}:FUZZ",
                     "-u", f"{host}/FUZZ",
                     "-of", "json",
                     "-o", f"{self.dirs['dirs']}/ffuf_{i}.json",
                     "-t", str(self.threads), "-s",
                     "-fc", "404,429",
                     "-mc", "all"],
                    timeout=600,
                )
            elif which("feroxbuster"):
                run(
                    ["feroxbuster", "-u", host, "-w", wordlist,
                     "-o", out_file, "-t", str(self.threads),
                     "-q", "--no-state", "--filter-status", "404,429"],
                    timeout=600,
                )

        return self.findings
