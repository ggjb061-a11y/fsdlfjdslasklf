# AutoVulnScan - Project Architecture

## Overview

AutoVulnScan is a professional automated security assessment framework for
authorized penetration testing. It performs full-chain reconnaissance,
intelligence gathering, URL discovery, JS analysis, parameter discovery,
HTTP method testing, and vulnerability scanning, then produces reports in
HTML, JSON, and Markdown formats.

## Design Principles

1. **Separation of concerns** - each phase is a self-contained module
2. **OOP + modular** - every vulnerability check is a dedicated class under `scanner/checks/`
3. **Graceful degradation** - every external tool is optional; curl fallbacks exist
4. **Accuracy over quantity** - no false positives from unverifiable heuristics
5. **No paid APIs** - everything uses direct tool invocation or free public endpoints
6. **Resumable** - checkpoints persist state so interrupted scans can continue
7. **Testable** - heavy regex/parse/hash logic lives in pure functions with unit tests

## Directory Structure

```
AutoVulnScan/
├── autoscan.py                    # CLI entry point + phase orchestration
├── setup.sh                       # External-tool installer
├── requirements.txt               # Python deps
├── .env.example                   # Config template
├── PROJECT_ARCHITECTURE.md        # This file
├── PROJECT_CHANGELOG.md           # Change history
│
├── scanner/                       # Core library
│   ├── __init__.py                # Version
│   ├── models.py                  # Dataclasses: Finding, URLRecord, HostRecord, JSSecret, ScanResult
│   ├── utils.py                   # which(), run(), create_dirs, URL categorizers, proxy
│   ├── checkpoint.py              # CheckpointManager: resume support
│   ├── diff.py                    # ScanDiff: compare two scans
│   ├── reporter.py                # HTML report orchestrator
│   │
│   ├── recon.py                   # ReconModule: subdomains, DNS, AXFR, vhost, favicon, dorks, ports, WAF
│   ├── passive.py                 # PassiveModule: robots, sitemap, CMS, emails, sensitive files, screenshots
│   ├── crawler.py                 # CrawlerModule: gau, wayback, hakrawler, katana, gospider
│   ├── js_analyzer.py             # JSAnalyzer: 22 secret regex patterns, endpoint extraction
│   ├── http_methods.py            # MethodTester: 9-method probing, XST detection
│   ├── params.py                  # ParamDiscovery: arjun, paramspider, reflective probing
│   ├── vulnscan.py                # VulnScanner: orchestrates checks/
│   │
│   ├── checks/                    # Individual vulnerability check classes
│   │   ├── __init__.py            # ALL_CHECKS registry
│   │   ├── base.py                # BaseCheck abstract class
│   │   ├── headers.py             # Security headers audit
│   │   ├── cors.py                # CORS misconfig
│   │   ├── ssl_tls.py             # testssl.sh/sslscan/openssl
│   │   ├── swagger.py             # API doc discovery
│   │   ├── graphql.py             # GraphQL introspection
│   │   ├── crlf.py                # CRLF injection
│   │   ├── host_header.py         # Host header injection
│   │   ├── cloud_meta.py          # SSRF to AWS/GCP/Azure metadata
│   │   ├── nuclei_scan.py         # Nuclei integration
│   │   ├── nikto_scan.py          # Nikto integration
│   │   ├── dirbrute.py            # gobuster/ffuf/feroxbuster
│   │   ├── takeover.py            # Subdomain takeover
│   │   ├── bypass403.py           # 403 bypass techniques
│   │   └── open_redirect.py       # Open redirect
│   │
│   └── output/                    # Report format generators
│       ├── __init__.py
│       ├── markdown_report.py     # Markdown generator
│       └── json_report.py         # JSON generator
│
└── tests/                         # Unit tests
    ├── __init__.py
    ├── test_models.py             # Dataclass model tests
    ├── test_utils.py              # URL categorizers, parsing, dirs
    ├── test_recon.py              # mmh3 hash, google dorks
    ├── test_output.py             # Markdown + JSON reports
    ├── test_checkpoint.py         # Resume capability
    ├── test_diff.py               # Scan diffing
    └── test_checks.py             # All vuln check classes
```

## Scan Pipeline (8 Phases)

```
Phase 1: RECONNAISSANCE  (ReconModule)
  - WHOIS, DNS (incl. AXFR), subfinder/amass/assetfinder/findomain/sublist3r
  - crt.sh CT logs, reverse-IP lookup
  - httpx live-host probing with tech detection
  - Vhost discovery (Host header manipulation)
  - Favicon hashing (pure-python mmh3)
  - Google dork query generation (21 queries)
  - nmap + masscan port scanning
  - whatweb + wafw00f fingerprinting

Phase 2: PASSIVE INTELLIGENCE  (PassiveModule)
  - robots.txt + sitemap.xml parsing
  - CMS detection (meta generator + path probing)
  - WordPress REST API user enumeration
  - Email harvesting (/, /contact, /about, /team, /impressum, /privacy)
  - 40+ sensitive-path probing (.env, .git, backups, phpinfo, etc.)
  - gowitness/eyewitness screenshots

Phase 3: URL COLLECTION  (CrawlerModule)
  - GAU, wayback CDX, hakrawler, katana, gospider
  - Curl + regex fallback
  - Auto-categorization: login, JS, sensitive, API, static

Phase 4: JAVASCRIPT ANALYSIS  (JSAnalyzer)
  - Download JS files, extract with 22 secret regex patterns
  - Endpoint extraction from JS source

Phase 5: PARAMETER DISCOVERY  (ParamDiscovery)
  - arjun + paramspider + reflective canary probing

Phase 6: HTTP METHOD DETECTION  (MethodTester)
  - 9 methods tested; flags dangerous (PUT/DELETE/TRACE/CONNECT)

Phase 7: VULNERABILITY SCANNING  (VulnScanner -> checks/)
  - Each check is a BaseCheck subclass
  - Deduplicated findings by (title, host)

Phase 8: REPORT  (reporter.generate -> output/*)
  - HTML (dark-themed, collapsible sections)
  - JSON (machine-readable summary)
  - Markdown (GitHub-flavored)
```

## Data Flow

```
CLI args -> scan_target()
             |
             +-> CheckpointManager (restore if --resume)
             |
             +-> ReconModule.run()      -> result.subdomains, live_hosts, ...
             +-> PassiveModule.run()    -> result.urls, findings, emails
             +-> CrawlerModule.run()    -> result.urls
             +-> JSAnalyzer.run()       -> result.js_secrets, js_endpoints
             +-> ParamDiscovery.run()   -> result.found_params
             +-> MethodTester.run()     -> result.allowed_methods
             +-> VulnScanner.run()      -> result.findings (via 14 checks)
             |
             +-> reporter.generate(result)
                   +-> HTML (reporter.py template)
                   +-> JSON (output/json_report.py)
                   +-> Markdown (output/markdown_report.py)
```

## Extensibility

### Adding a new vulnerability check

1. Create `scanner/checks/my_check.py`:
   ```python
   from .base import BaseCheck
   from ..models import Finding
   from ..utils import run

   class MyCheck(BaseCheck):
       name = "My Check"
       description = "What it tests"

       def execute(self) -> list[Finding]:
           for host in self._hosts():
               # ... probe ...
               self.findings.append(Finding(...))
           return self.findings
   ```

2. Import in `scanner/checks/__init__.py` and append to `ALL_CHECKS`.
3. Add to `VulnScanner.CHECK_CLASSES` in `scanner/vulnscan.py`.
4. Write tests in `tests/test_checks.py`.

### Adding a new output format

1. Create `scanner/output/my_format.py` with `generate_my_format(result)` returning path.
2. Export it in `scanner/output/__init__.py`.
3. Call it in `scanner/reporter.py` generate().

### Adding a new recon source

1. Add a `_source_name` method to `ReconModule`.
2. Append to the orchestrator `steps` list in `ReconModule.run()`.

## Security Model

- The scanner itself must not become an attack vector:
  - No eval/exec of external data
  - No shell=True in subprocess (`utils.py` uses list form)
  - Path sanitizer in `create_dirs()` strips path separators
  - All proxy support goes through curl --proxy and env vars
  - XML parsing uses `xml.etree.ElementTree` (stdlib; no DTD processing)
- Targets must be explicitly confirmed (`--confirm` or interactive)
- Rate limiting via `--rate-limit` prevents accidental DoS

## External Tools (Optional)

Every tool is probed via `which()`; the scanner degrades gracefully if any
are missing. Install with `./setup.sh` or manually.

Required (hard dep): curl, python3, pip
Recommended: subfinder, httpx, nuclei, nmap, nikto, gau, katana, gobuster/ffuf

## Checkpoints / Resume

State persisted to `<base_dir>/.checkpoint.json` after each phase.
Resume with `python autoscan.py --resume <base_dir>`.
Already-completed phases are skipped; their data is restored into the ScanResult.

## Scan Diffing

Compare two scans with `python autoscan.py --diff <baseline> <current>`.
Produces `scan_diff.json` and `scan_diff.md` showing new/resolved findings,
new subdomains, new sensitive files, etc.
