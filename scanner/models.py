"""Data models for the scan results."""
from dataclasses import dataclass, field, asdict
from typing import Optional


# Valid severity levels (ordered most-to-least severe)
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Approximate CVSS 3.1 base-score mapping per severity level.
# Used for compliance reports; checks can override via a specific score.
CVSS_ESTIMATE = {
    "critical": 9.5,
    "high":     8.0,
    "medium":   6.0,
    "low":      3.5,
    "info":     0.0,
}

# OWASP Top 10 2021 category hints, keyed by source/tag pattern.
# Checks can override by setting tags like "owasp:A03".
OWASP_HINTS = {
    "sqli":              "A03:2021-Injection",
    "cmd_injection":     "A03:2021-Injection",
    "nosql_injection":   "A03:2021-Injection",
    "ldap_injection":    "A03:2021-Injection",
    "xss":               "A03:2021-Injection",
    "crlf":              "A03:2021-Injection",
    "ssti":              "A03:2021-Injection",
    "email_header_injection": "A03:2021-Injection",
    "sqlmap":            "A03:2021-Injection",
    "path_traversal":    "A01:2021-Broken Access Control",
    "cors":              "A05:2021-Security Misconfiguration",
    "headers":           "A05:2021-Security Misconfiguration",
    "csp":               "A05:2021-Security Misconfiguration",
    "cookie":            "A05:2021-Security Misconfiguration",
    "ssl":               "A02:2021-Cryptographic Failures",
    "testssl":           "A02:2021-Cryptographic Failures",
    "sslscan":           "A02:2021-Cryptographic Failures",
    "jwt":               "A02:2021-Cryptographic Failures",
    "session_mgmt":      "A07:2021-Identification and Authentication Failures",
    "oauth_saml":        "A07:2021-Identification and Authentication Failures",
    "mass_assignment":   "A01:2021-Broken Access Control",
    "takeover":          "A01:2021-Broken Access Control",
    "403_bypass":        "A01:2021-Broken Access Control",
    "open_redirect":     "A01:2021-Broken Access Control",
    "ssrf":              "A10:2021-SSRF",
    "cloud_metadata":    "A10:2021-SSRF",
    "xxe":               "A05:2021-Security Misconfiguration",
    "deserialization":   "A08:2021-Software and Data Integrity Failures",
    "prototype_pollution": "A08:2021-Software and Data Integrity Failures",
    "github_leaks":      "A07:2021-Identification and Authentication Failures",
    "s3_buckets":        "A05:2021-Security Misconfiguration",
    "http_smuggling":    "A05:2021-Security Misconfiguration",
    "csrf":              "A01:2021-Broken Access Control",
    "host_header":       "A05:2021-Security Misconfiguration",
    "graphql_deep":      "A05:2021-Security Misconfiguration",
    "swagger_discovery": "A05:2021-Security Misconfiguration",
    "openapi_fuzzer":    "A01:2021-Broken Access Control",
    "form_fuzzer":       "A03:2021-Injection",
    "nuclei":            "A06:2021-Vulnerable and Outdated Components",
    "nikto":             "A06:2021-Vulnerable and Outdated Components",
    "mail_security":     "A05:2021-Security Misconfiguration",
    "dnssec":            "A05:2021-Security Misconfiguration",
    "shodan_internetdb": "A06:2021-Vulnerable and Outdated Components",
    "security_txt":      "A05:2021-Security Misconfiguration",
    "robots":            "A05:2021-Security Misconfiguration",
    "sensitive_files":   "A05:2021-Security Misconfiguration",
    "sitemap":           "A05:2021-Security Misconfiguration",
    "cms_detect":        "A06:2021-Vulnerable and Outdated Components",
    "method_tester":     "A05:2021-Security Misconfiguration",
    "exchange":          "A06:2021-Vulnerable and Outdated Components",
    "gitlab":            "A06:2021-Vulnerable and Outdated Components",
    "follina":           "A08:2021-Software and Data Integrity Failures",
    "struts2":           "A08:2021-Software and Data Integrity Failures",
    "weblogic":          "A06:2021-Vulnerable and Outdated Components",
    "jboss":             "A08:2021-Software and Data Integrity Failures",
    "spring4shell":      "A03:2021-Injection",
    "confluence":        "A03:2021-Injection",
    "shellshock":        "A03:2021-Injection",
    "log4shell":         "A03:2021-Injection",
    "param_discovery":   "A05:2021-Security Misconfiguration",
    "subjack":           "A01:2021-Broken Access Control",
    "takeover_fingerprint": "A01:2021-Broken Access Control",
    "f5_bigip":          "A06:2021-Vulnerable and Outdated Components",
    "citrix":            "A06:2021-Vulnerable and Outdated Components",
    "phpunit":           "A08:2021-Software and Data Integrity Failures",
    "drupalgeddon":      "A06:2021-Vulnerable and Outdated Components",
    "papercut":          "A07:2021-Identification and Authentication Failures",
    "tech_adaptive":     "A06:2021-Vulnerable and Outdated Components",
    "dns_axfr":          "A05:2021-Security Misconfiguration",
    "js_analyzer":       "A07:2021-Identification and Authentication Failures",
    "dirbrute":          "A05:2021-Security Misconfiguration",
    "graphql":           "A05:2021-Security Misconfiguration",
    "openssl":           "A02:2021-Cryptographic Failures",
    "probe":             "A05:2021-Security Misconfiguration",
    "correlator":        "A03:2021-Injection",
}


def _normalize_severity(sev: str) -> str:
    """Return a canonical severity string. Unknown values map to 'info'."""
    if not sev:
        return "info"
    s = str(sev).strip().lower()
    return s if s in SEV_ORDER else "info"


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

    def __post_init__(self):
        # Normalize severity to a canonical value
        self.severity = _normalize_severity(self.severity)
        # Normalize tags: strip, lowercase, remove duplicates while
        # preserving first-seen order
        seen = set()
        normalized = []
        for t in self.tags or []:
            if not t:
                continue
            tag = str(t).strip().lower().replace(" ", "-")
            if tag and tag not in seen:
                seen.add(tag)
                normalized.append(tag)
        self.tags = normalized

    def sev_order(self) -> int:
        return SEV_ORDER.get(self.severity, len(SEVERITIES))

    def cvss_estimate(self) -> float:
        """Approximate CVSS 3.1 base score for this severity."""
        return CVSS_ESTIMATE.get(self.severity, 0.0)

    def owasp_category(self) -> str:
        """Best-effort OWASP Top 10 2021 mapping."""
        # 1. Explicit "owasp:XX" tag wins
        for t in self.tags:
            if t.startswith("owasp:"):
                return t.split(":", 1)[1]
        # 2. Source-based hint
        src = (self.source or "").lower()
        if src in OWASP_HINTS:
            return OWASP_HINTS[src]
        # 2b. CVE-prefixed sources all map to Vulnerable Components
        if src.startswith("cve:") or src.startswith("cve-"):
            return "A06:2021-Vulnerable and Outdated Components"
        # 3. Tag-based hint
        for t in self.tags:
            if t in OWASP_HINTS:
                return OWASP_HINTS[t]
        return "A05:2021-Security Misconfiguration"  # safe default for misconfig-like findings

    def to_dict(self) -> dict:
        """Dict representation including derived fields."""
        d = asdict(self)
        d["cvss_estimate"] = self.cvss_estimate()
        d["owasp"] = self.owasp_category()
        d["sev_order"] = self.sev_order()
        return d


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

    def __post_init__(self):
        self.severity = _normalize_severity(self.severity)


@dataclass
class ScanResult:
    target: str
    scan_date: str
    base_dir: str
    host_records: list = field(default_factory=list)    # list[HostRecord]
    subdomains: list = field(default_factory=list)      # list[str]
    live_hosts: list = field(default_factory=list)      # list[str] bare URLs
    urls: list = field(default_factory=list)            # list[URLRecord]
    findings: list = field(default_factory=list)        # list[Finding]
    dns_records: dict = field(default_factory=dict)
    whois: str = ""
    waf: str = ""
    js_secrets: list = field(default_factory=list)      # list[JSSecret]
    js_endpoints: list = field(default_factory=list)    # list[str]
    ports_raw: list = field(default_factory=list)       # list[str]
    allowed_methods: dict = field(default_factory=dict) # host -> [methods]
    emails: list = field(default_factory=list)          # list[str]
    cms_info: dict = field(default_factory=dict)        # host -> cms string
    found_params: dict = field(default_factory=dict)    # url -> [param names]
    google_dorks: list = field(default_factory=list)    # list[str]
    asn_info: dict = field(default_factory=dict)        # ip -> {asn, prefix, country, ...}
    shodan_info: dict = field(default_factory=dict)     # ip -> {ports, vulns, ...}
    geo_info: dict = field(default_factory=dict)        # ip -> {country, city, org, ...}
    http_versions: dict = field(default_factory=dict)   # host -> {h2, h3, tls_version}

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: f.sev_order())

    def findings_by_severity(self, sev: str) -> list:
        sev = _normalize_severity(sev)
        return [f for f in self.findings if f.severity == sev]

    def count_by_severity(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def count_by_owasp(self) -> dict:
        """Aggregate findings by OWASP Top 10 category."""
        out: dict[str, int] = {}
        for f in self.findings:
            cat = f.owasp_category()
            out[cat] = out.get(cat, 0) + 1
        return out

    def count_by_source(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.source] = out.get(f.source, 0) + 1
        return out

    def total_cvss(self) -> float:
        """Aggregate CVSS estimate for all findings (useful as a risk score)."""
        return sum(f.cvss_estimate() for f in self.findings)
