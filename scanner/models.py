"""Data models for the scan results."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    severity: str          # critical / high / medium / low / info
    title: str
    host: str
    detail: str
    source: str            # tool/module name
    tags: list = field(default_factory=list)
    url: str = ""
    evidence: str = ""

    def sev_order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            self.severity.lower(), 5
        )


@dataclass
class URLRecord:
    url: str
    status: Optional[int] = None
    content_type: str = ""
    title: str = ""
    server: str = ""
    redirect_to: str = ""
    is_login: bool = False
    is_js: bool = False
    is_static: bool = False       # css/img/font
    is_sensitive_file: bool = False   # zip/bak/sql/env/config
    is_api: bool = False
    method_source: str = "live"   # live | wayback | gau


@dataclass
class HostRecord:
    domain: str
    ip: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    technologies: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    is_live: bool = False
    http_methods: list = field(default_factory=list)  # allowed HTTP methods
    cdn: str = ""
    waf: str = ""


@dataclass
class JSSecret:
    file_url: str
    pattern_name: str
    match: str
    line: int = 0
    severity: str = "high"


@dataclass
class ScanResult:
    target: str
    scan_date: str
    base_dir: str
    hosts: list = field(default_factory=list)          # list[HostRecord]
    subdomains: list = field(default_factory=list)      # list[str]
    live_hosts: list = field(default_factory=list)      # list[str] bare URLs
    urls: list = field(default_factory=list)            # list[URLRecord]
    findings: list = field(default_factory=list)        # list[Finding]
    dns_records: dict = field(default_factory=dict)
    whois: str = ""
    waf: str = ""
    js_secrets: list = field(default_factory=list)      # list[JSSecret]
    allowed_methods: dict = field(default_factory=dict) # host -> [methods]

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: f.sev_order())

    def findings_by_severity(self, sev: str) -> list:
        return [f for f in self.findings if f.severity.lower() == sev.lower()]

    def count_by_severity(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            s = f.severity.lower()
            counts[s] = counts.get(s, 0) + 1
        return counts
