"""
Vulnerability scanning orchestrator.
Runs each modular check class and aggregates findings.
Each check is implemented in its own module under scanner/checks/.
"""
import logging
from .models import Finding
from .checks import (
    HeadersCheck, CORSCheck, SSLCheck,
    SwaggerCheck, GraphQLCheck, CRLFCheck,
    HostHeaderCheck, CloudMetadataCheck,
    SSRFCheck, XXECheck, SSTICheck, PathTraversalCheck,
    SQLInjectionCheck, CommandInjectionCheck,
    NoSQLInjectionCheck, JWTWeaknessCheck,
    DeserializationCheck, CSPCookieCheck, LDAPInjectionCheck,
    XSSCheck, FamousCVEsCheck,
    NucleiScan, NiktoScan, DirBruteCheck,
    TakeoverCheck, Bypass403Check, OpenRedirectCheck,
)

logger = logging.getLogger("autoscan.vuln")


class VulnScanner:
    """
    Orchestrates all vulnerability checks.
    Each check is a self-contained class in scanner/checks/.
    """

    CHECK_CLASSES = [
        HeadersCheck,
        CORSCheck,
        SSLCheck,
        SwaggerCheck,
        GraphQLCheck,
        CRLFCheck,
        HostHeaderCheck,
        CloudMetadataCheck,
        SSRFCheck,
        XXECheck,
        SSTICheck,
        PathTraversalCheck,
        SQLInjectionCheck,
        CommandInjectionCheck,
        NoSQLInjectionCheck,
        JWTWeaknessCheck,
        DeserializationCheck,
        CSPCookieCheck,
        LDAPInjectionCheck,
        XSSCheck,
        FamousCVEsCheck,
        NucleiScan,
        NiktoScan,
        DirBruteCheck,
        TakeoverCheck,
        Bypass403Check,
        OpenRedirectCheck,
    ]

    def __init__(self, target: str, dirs: dict, live_hosts: list,
                 threads: int = 10, wordlist: str = None):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads
        self.wordlist = wordlist
        self.findings: list[Finding] = []

    def _instantiate(self, cls) -> object:
        """Build check instance passing wordlist to DirBruteCheck."""
        kwargs = {}
        if cls is DirBruteCheck:
            kwargs["wordlist"] = self.wordlist
        return cls(
            target=self.target,
            dirs=self.dirs,
            live_hosts=self.live_hosts,
            threads=self.threads,
            **kwargs,
        )

    def run(self) -> list[Finding]:
        for cls in self.CHECK_CLASSES:
            check = self._instantiate(cls)
            self.findings.extend(check.run())

        seen = set()
        unique = []
        duplicates = 0
        for f in self.findings:
            key = (f.title, f.host, f.url, f.evidence[:100])
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                duplicates += 1
        self.findings = unique

        if duplicates:
            logger.info(f"  Vuln scan complete | {len(self.findings)} findings ({duplicates} duplicates collapsed)")
        else:
            logger.info(f"  Vuln scan complete | {len(self.findings)} findings")
        return self.findings
