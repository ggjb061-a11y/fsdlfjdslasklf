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
    SQLInjectionCheck, SqlmapCheck, CommandInjectionCheck,
    NoSQLInjectionCheck, JWTWeaknessCheck,
    DeserializationCheck, CSPCookieCheck, LDAPInjectionCheck,
    XSSCheck, FamousCVEsCheck,
    CSRFCheck, GitHubLeaksCheck, S3BucketCheck, TechAdaptiveCheck,
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
        SqlmapCheck,
        CommandInjectionCheck,
        NoSQLInjectionCheck,
        JWTWeaknessCheck,
        DeserializationCheck,
        CSPCookieCheck,
        LDAPInjectionCheck,
        XSSCheck,
        FamousCVEsCheck,
        CSRFCheck,
        GitHubLeaksCheck,
        S3BucketCheck,
        TechAdaptiveCheck,
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

        # Dual-detector correlation: when both the built-in SQLi engine and
        # sqlmap flag the same (host-root, parameter), emit an extra
        # "DUAL-CONFIRMED" finding with the highest confidence tag. The
        # original per-detector findings stay so the report shows the full
        # evidence from each tool.
        self._correlate_sqli()

        if duplicates:
            logger.info(f"  Vuln scan complete | {len(self.findings)} findings ({duplicates} duplicates collapsed)")
        else:
            logger.info(f"  Vuln scan complete | {len(self.findings)} findings")
        return self.findings

    @staticmethod
    def _host_root(host: str) -> str:
        """Reduce a URL / host-with-query to just scheme://host[:port] for correlation."""
        if "://" in host:
            parts = host.split("/")
            if len(parts) >= 3:
                return "/".join(parts[:3])
        return host.split("?")[0].split("/")[0] if host else host

    def _correlate_sqli(self) -> None:
        """Find (host_root, param) pairs flagged by BOTH detectors and emit a merged finding."""
        from collections import defaultdict

        def _param_from_tags(tags: list[str]) -> str | None:
            for t in tags or []:
                if t.startswith("param:"):
                    return t.split(":", 1)[1]
            return None

        buckets: dict[tuple[str, str], dict[str, list[Finding]]] = defaultdict(
            lambda: {"builtin": [], "sqlmap": []}
        )
        for f in self.findings:
            if f.source not in ("sqli", "sqlmap"):
                continue
            param = _param_from_tags(f.tags)
            if not param:
                continue
            key = (self._host_root(f.host), param)
            detector = "sqlmap" if f.source == "sqlmap" else "builtin"
            buckets[key][detector].append(f)

        dual_findings: list[Finding] = []
        for (host_root, param), by_det in buckets.items():
            if by_det["builtin"] and by_det["sqlmap"]:
                builtin_techniques = sorted({
                    t for f in by_det["builtin"]
                    for t in f.tags if t in ("error-based", "boolean-based", "time-based", "union-based")
                })
                sqlmap_techniques = sorted({
                    t for f in by_det["sqlmap"]
                    for t in f.tags if t in ("error-based", "boolean-based", "time-based",
                                              "union", "stacked", "query")
                })
                dual_findings.append(Finding(
                    severity="critical",
                    title=f"SQL Injection DUAL-CONFIRMED via '{param}' [built-in + sqlmap]",
                    host=host_root,
                    detail=(
                        f"Detectors: AutoVulnScan built-in AND sqlmap both confirmed SQLi\n"
                        f"on parameter '{param}' at {host_root}.\n"
                        f"  built-in techniques: {', '.join(builtin_techniques) or 'see individual finding'}\n"
                        f"  sqlmap techniques:   {', '.join(sqlmap_techniques) or 'see individual finding'}\n"
                        f"Two independent detectors agreeing is the highest confidence tier."
                    ),
                    source="correlator",
                    url=host_root,
                    tags=["sqli", "dual-confirmed", "high-confidence",
                          f"param:{param}", "detector:builtin+sqlmap"],
                    evidence=(
                        f"built-in evidence: {by_det['builtin'][0].evidence[:150]}\n"
                        f"sqlmap evidence:   {by_det['sqlmap'][0].evidence[:150]}"
                    ),
                ))
        if dual_findings:
            self.findings.extend(dual_findings)
            logger.info(f"  SQLi correlation: {len(dual_findings)} dual-confirmed finding(s)")
