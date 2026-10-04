# AutoVulnScan - Project Changelog

Version numbers follow the project's own `scanner/__init__.py::__version__`.

## 4.4.0 (2026-10-04) - params/http_methods baseline FP fixes, expanded JSON, nikto/nuclei hardening, +14 tests

### False-positive fixes
- `params.py`: 3-sample baseline variance + HTTP status comparison +
  relative size floor (`max(50, variance*2, body*0.02)`). A single
  baseline sample used to misfire on every dynamic page (CSRF tokens,
  timestamps, build hashes) because the page differed from itself by
  more than 50 bytes on refetch. 404 / 500 / WAF-block responses are
  no longer counted as 'parameter accepted'.
- `http_methods.py`: baseline-differential method detection. The old
  status-only check marked a method 'accepted' on any 2xx/3xx, so
  SPAs and WAFs that return 200 for every method on `/` produced
  false 'PUT accepted' / 'DELETE accepted' findings. Now compares
  Content-Length delta and status class against a GET baseline, and
  the TRACE XST probe actually looks for a nonce header reflected in
  the response body (real XST confirmation vs informational).
- `nikto`: parser now handles the flat-list shape (previously
  silently dropped), and the default severity for findings with no
  explicit severity field is `info` instead of `medium`. Banner-leak
  / version-disclosure findings no longer inflate the report.
- `nuclei`: `_canonical_sev` extracted and unit-tested. Fixes a
  crash on `"severity": null` (nuclei emits it on template errors)
  and maps `informational` / `unknown` to the canonical `info`.
  `extracted-results` lists are joined line-by-line instead of
  stringified as `['a', 'b']`.

### Reports
- `json_report.py` now includes the fields the HTML report shows but
  the JSON output had silently dropped: `host_records`, `js_endpoints`,
  `asn_info`, `shodan_info`, `geo_info`, `http_versions`,
  `owasp_counts`, `total_cvss_estimate`, and full URL records.
  Findings now use `Finding.to_dict()` so `cvss_estimate`, `owasp`,
  and `sev_order` land in the artifact. A `TypeError` on
  serialization now falls back to `repr` and logs a warning instead
  of killing the whole JSON export mid-write.

### Tests (259 passing, +14 new)
- `test_more_checks.py`: behavioral tests for SSL/TLS (sslscan +
  openssl parsing), CORS (ACAO + credentials fires critical; bare
  wildcard does not), Nikto (3 JSON shapes, severity gating), and
  Nuclei (`_canonical_sev` null/informational/unknown mapping).
- `test_cves.py`: Grafana SSRF detector (differential, benign
  rejection, baseline-guard) and PhpFpmNginx positive + negative.

---

## 4.3.1 (2026-10-04) - Dep CVEs, CSV injection, crawler scope, form safety

### Security
- `requests` pinned to `>=2.32.3,<3` to pick up CVE-2023-32681
  (Proxy-Authorization leak, fixed 2.31.0) and CVE-2024-35195
  (cert-verify bypass on Session reuse, fixed 2.32.0).
- `Jinja2` pinned to `>=3.1.6,<4` to pick up CVE-2024-22195 (attr XSS,
  3.1.3), CVE-2024-34064 (xmlattr injection, 3.1.4), and
  CVE-2024-56326 / CVE-2024-56201 (sandbox escape, 3.1.6).
- `click` removed from dependencies (never imported; CLI uses argparse).
- **CSV injection** in `output/csv_report.py`: leading `=`, `+`, `-`,
  `@`, `\t`, `\r` in a cell are now neutralized with a prepended
  apostrophe, and `QUOTE_ALL` is set. An attacker-controlled finding
  title like `=cmd|'/c calc'!A1` no longer executes as a formula
  when the auditor opens the report in Excel/Sheets.
- **Crawler deep-crawl scope**: the queue now re-verifies host netloc
  (equal to target or `.target` suffix) before fetching. `_add_raw`
  previously only guarded storage; a crawled external link (CDN,
  analytics, attacker redirect) was still fetched and its body parsed.
- **form_fuzzer destructive-action guardrail**: skip forms whose
  action or input name matches a destructive pattern (delete, destroy,
  logout, transfer, pay, checkout, cancel, revoke, deactivate,
  resetpassword, changepassword). Also skip CSRF-protected POST forms
  entirely instead of re-using the valid anti-CSRF token.

### Correctness
- `grafana_ssrf`: fixed dead-code bug `status in (200,500) and "500"
  in str(status)` (always evaluated to `status==500`). Probe is now a
  differential comparison between attacker and benign URLs, requiring
  connect-level markers (tls:, x509:, connection refused, no such
  host) baseline-absent per the base-class invariant.
- `recon_extended` SPF/DMARC parsing:
  - DMARC `p=none` match boundary-anchored so `p=reject; sp=none`
    no longer mis-flags.
  - SPF `all` qualifier parsed by tokenizing the final `all`
    mechanism; a record ending in bare `all` (no qualifier) now
    resolves to `+all` per RFC 7208.
  - SPF `ptr` mechanism flagged as low per RFC 7208 §5.5.

### False-positive fixes
- `js_analyzer`:
  - Removed Email Address from SECRET_PATTERNS entirely (noise).
  - Recalibrated severities to real exploitability:
    Google API Key high→low, Firebase URL / S3 bucket URL / Stripe
    test key medium→info, Twilio SID high→low, JWT medium→info.
  - All patterns anchored with `\b` or negative lookarounds so
    cache-busting content hashes and minified identifiers no longer
    trigger.
  - Generic Secret regex tightened: `token` / `apikey` keys that
    fired on `csrfToken` / `_token` / i18n keys replaced with a
    stricter name set + 16-char min of base64/url-safe chars.
  - LinkFinder regex typo `%%` → `%` fixed.
- `passive` email extraction boundary-anchored; asset-suffix filter
  extended (jpeg, svg, webp, ico, avif, css, js, map, woff, woff2,
  ttf, min.js, min.css, bundle.js); placeholder-domain filter added
  (example.com / example.org / test.com / localhost).
- `markdown_report`:
  - `_md_cell` escapes backticks, pipes, newlines, backslashes,
    angle brackets. Truncation now happens BEFORE escaping.
  - Fenced code blocks pick a fence length longer than the longest
    run of backticks in the content.
  - URL cells percent-encode `(`, `)`, `<`, `>`, whitespace and wrap
    the link target in `<...>`.
- `recon_sources/_helpers`: logger added, default UA moved off a
  tool-named value WAFs blocklist on sight; `--` separator before
  URL in curl argv.

### Tests (245 passing)
- Added negative test asserting CSV injection prefix neutralization.
- `test_checks_use_constant_canary` fixed: it was a tautology
  (`cors.__dict__ | {"ATTACKER_CANARY": None}` always contains the
  key). Replaced with real import check across cors / open_redirect /
  host_header.

---

## 4.3.0 (2026-10-04) - Secret-redaction, SSRF-tight validators, FP fixes from 20-agent audit

### Security - stop persisting live secrets in reports
- `jwt_weakness`: emit sha256_prefix+len instead of the cracked
  secret; for alg=none emit only the header (payload claims are
  confidential even without a valid signature).
- `js_analyzer`: mask matched secrets (first4...last4 + sha256_prefix),
  never persist the raw token in JSSecret.match or Finding.evidence.
- `session_mgmt`: evidence shows len+entropy, never the cookie value.
- `csp_cookies`: strip name=value, keep only flag portion.
- `oauth_saml`: strip code=/access_token=/id_token=/state=/token=
  values and fragment from Location before persisting.
- `openapi_fuzzer` / `graphql_deep`: never dump response body on a
  sensitive-field regex hit — first 300 bytes IS the leaked data.
- `utils.run`: redact Authorization / Cookie / -u / X-Api-Key values
  before logging argv on exception.

### Security - validators tightened
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`) now blocked (stdlib
  `is_private` does not treat it as private on `IPv6Address`).
- All `ipaddress` semantic properties checked (private, loopback,
  link-local, reserved, multicast, unspecified).
- Single-label internal hostnames blocked by name (localhost,
  metadata, metadata.google.internal, host.docker.internal, …).
- userinfo rejected in webhook URLs; length caps (253 / 2048);
  whitespace rejection; IPv6 zone-id stripped.

### Security - canary & argv injection
- `ATTACKER_CANARY` was a real `.com` domain. Changed to
  `attacker.example` (RFC 2606), overridable via `AUTOSCAN_CANARY`.
- `BaseCheck._curl_args` now emits `--` before every URL.

### Security - HTML report
- Template `<a href>` runs through a `safe_url` filter that rejects
  `javascript:` / `data:` / `vbscript:` schemes; `target=_blank`
  links get `rel="noopener noreferrer"`.
- All report emitters (reporter / json / markdown / sarif) call
  `parent.mkdir(parents=True)` and write with `encoding="utf-8"`.

### False-positive fixes
- `sql_injection` time-based: baseline-relative threshold
  (`baseline_median + 4s`) with 3-sample median baseline. Slow
  endpoints no longer FP on absolute 4.5s wait.
- `sql_injection` UNION probe: differential test between col=1
  (clean) and col=10 (error). Generic English-phrase bucket
  excluded (fired on WAF block pages for every payload).
- `xss`: payload needle now includes the canary token, so minified
  JS already containing `;alert(` cannot look like confirmed XSS.
- `crawler` scope: substring host match replaced with netloc
  suffix check; `evilexample.com` / `notexample.com` no longer admitted.
- `tech_adaptive` Laravel Ignition: critical → high; requires a
  Laravel-specific marker instead of the English word "ignition".

### Correctness - BaseCheck helpers
- `_url` now extends existing query strings via
  `urlencode(parse_qsl(parsed.query) + [(name, value)])` instead of
  concatenating a second `?`.
- `_baseline` is thread-safe (double-checked lock) and does NOT
  cache empty bodies.

### Correctness - orchestrator
- `--resume` applies `set_auth` / `set_rate_limit` and runs
  `--fail-on` (previously `sys.exit(0)` before the gate).
- `--fail-on` forces JSON into the output format list.
- Target-dir lookup now uses the same sanitizer as `create_dirs`.
- `input()` for the authorization prompt handles
  `KeyboardInterrupt` / `EOFError` cleanly.

### Checkpoint
- Atomic write via tmp+rename so a SIGINT between phases cannot
  leave a half-written `.checkpoint.json`.

### Tests (243 passing)
- PaperCut negative test (patched server redirecting to login page
  must NOT fire).
- Struts REST negative test (generic `<orders>` without Struts
  fingerprint must NOT fire).

---

## 4.2.3 (2026-10-03) - Severity recalibration + FP hardening on CVE detectors

### Severity moderated (endpoint-reachability only, not confirmed exploit)
- `kibana_source`: critical → info
  (`/api/status` only shows Kibana is deployed).
- `spring_gateway`, `weblogic_async`, `weblogic_wls_sec`,
  `jboss_filter`, `struts_rest`, `wso2_upload`: critical → high.

### FP hardening on weak heuristics
- `papercut_bypass`: require strong SetupCompleted markers AND
  absence of login-page markers.
- `struts_rest`: require TWO distinct markers (Struts fingerprint
  AND XML `<order>` element).
- `wso2_upload`: require WSO2-specific marker.
- `ssrf`: baseline guard so Apache/nginx banners in error pages
  don't FP.
- `xxe`: tightened OOB heuristic and demoted to medium (no file
  content disclosed).

### Follow-ups in the same series
- `deserialization`: high → medium (blob presence ≠ exploitable).
- `nosql_injection` + `ldap_injection`: baseline-compare benign
  login first, so template echoes like `"token": null` don't
  trigger an auth-bypass finding.

---

## 4.2.2 (2026-10-03) - Complete OWASP mapping (0 unmapped sources)

- Expanded `OWASP_HINTS` with 35 new source mappings covering mail
  security, DNSSEC, dirbrute, Shodan InternetDB, CMS detect,
  DNS AXFR, method tester, Follina, Struts2, WebLogic, JBoss,
  Spring4Shell, Confluence, Shellshock, Log4Shell, F5 BIG-IP, Citrix,
  PHPUnit, Drupalgeddon, PaperCut, tech_adaptive, Exchange, GitLab,
  subjack, security.txt, robots, sensitive files, sitemap, GraphQL,
  OpenSSL, probe, param discovery, JS analyzer, correlator,
  takeover fingerprint.
- `owasp_category()` adds CVE-prefix handling and `A05` safe default.
- Final: 0 unmapped sources across 68 Finding emitters.

---

## 4.2.1 (2026-10-03) - Real-world scan feedback: FP fixes + severity recalibration

### False-positive fixes revealed by scanning ftth.iq
- **SSTI**: differential probe. `{{7*7}}=49` AND `{{2*5}}=10` must
  differ. Previously `49` appearing naturally in page UI (page count
  "page 1 of 49", product count) triggered a critical. 8 payloads
  with 5-guard chain (baseline / primary / echo / differential /
  double-confirm) now required.
- **Command Injection**: added reflection probe before attack
  probes. If the server echoes URL parameters into HTML, abandon
  the parameter — can't distinguish exec from echo.
- **Nikto parsing**: rewrote with `_normalize_vulns` handling 3
  shapes (modern list, legacy dict with vulnerabilities, flat list).
  Previously showed `Nikto: ?` with raw JSON blob as detail.
- `setup.sh` pip fallback chain (pip → `--break-system-packages`
  → apt).

### Severity recalibration — realistic, not inflated
- HSTS missing: HIGH → MEDIUM (defensive, needs active MITM on
  first visit).
- CSP missing: MEDIUM → LOW (defense-in-depth; XSSCheck already
  reports actual XSS separately).
- X-Frame-Options missing: MEDIUM → LOW.
- Server version disclosure: LOW → INFO.
- TLSv1.0 enabled: MEDIUM → LOW (deprecated by PCI-DSS, mitigated
  client-side).
- Self-signed cert: MEDIUM → LOW (trust-chain, not exploit path).
- SPF missing / DMARC missing: MEDIUM → LOW.
- SPF `+all`: HIGH → MEDIUM. DMARC `p=none`: MEDIUM → LOW.
- SSLv2 / SSLv3 stay HIGH (DROWN / POODLE are real exploits).

---

## 4.2.0 (2026-10-02) - Polish pass: BaseCheck shared helpers, Finding model upgrades, interactive HTML

### Added
- `BaseCheck` grew shared HTTP helpers used across all 42 checks:
  `_fetch`, `_fetch_full`, `_fetch_headers`, `_fetch_json`, `_post`,
  `_url`, `_baseline` (cached), `_status_code` (robust).
- `Finding` model: `__post_init__` normalizes severity to the
  canonical set (`critical`/`high`/`medium`/`low`/`info`) and
  deduplicates tags (lowercase, strip, order-preserving).
- `Finding.cvss_estimate()` returns approximate CVSS 3.1 base
  score; `Finding.owasp_category()` maps to OWASP Top 10 2021.
- `ScanResult.count_by_owasp()`, `count_by_source()`,
  `total_cvss()`.
- Interactive HTML report: OWASP mapping table, severity filter
  buttons, collapsible sections.

### Changed
- All 42 checks now inherit shared helpers from `BaseCheck` instead
  of reimplementing `curl` wrappers.

---

## 4.1.0 (2026-10-01) - +8 deep checks, LinkFinder JS extraction, benchmark, pyproject, pre-commit

### Added - 8 deep vulnerability checks
- `MassAssignmentCheck`: JSON API privilege-field injection
  (role, is_admin, verified, premium) with differential baseline.
- `HTTPSmugglingCheck`: CL.TE / TE.CL / TE.TE timing-based with
  double-confirmation and benign-chunked reverse probe.
- `JWTWeaknessCheck`: alg=none detection + HS256 weak-secret
  brute force against a common-secret list.
- `SessionMgmtCheck`: Shannon-entropy test on session cookies +
  missing Secure/HttpOnly flags.
- `GraphQLDeepCheck`: introspection schema dump, field-suggestion
  disclosure, query batching DoS, alias amplification, unauth
  sensitive query probing.
- `OAuthSAMLCheck`: OIDC discovery exposure, redirect_uri wildcard
  (`attacker.example` canary), missing state parameter, SAML
  metadata exposure.
- `PrototypePollutionCheck`: `__proto__[polluted7x7]=marker` with
  follow-up request to detect persisted pollution.
- `OpenAPIFuzzerCheck`: fetch OpenAPI spec, probe GET endpoints
  for unauthenticated access to sensitive fields.

### Added - LinkFinder regex for JS endpoint extraction
- Extended `js_analyzer` with LinkFinder-style regex for broader
  path/URL discovery inside bundled JavaScript.

### Added - infra
- `benchmark.py`: measure elapsed time, finding count, CVSS total.
- `pyproject.toml`: PEP 621 metadata.
- Pre-commit hook with ruff + pytest.

---

## 4.0.0 (2026-09-30) - 20 CVE detectors + deep crawler + 8 subdomain sources + bulletproof setup

### Added - 20 flagship CVE detectors (`scanner/checks/cves/`)
- `apache_2449_pt`, `apache_2450_pt`, `citrix_netscaler`,
  `elasticsearch_groovy`, `f5_tmui`, `grafana_ssrf`,
  `jboss_filter`, `kibana_source`, `papercut_bypass`,
  `php_fpm_nginx`, `rails_accept`, `solr_replication`,
  `spring_function`, `spring_gateway`, `struts_rest`,
  `vmware_vcenter`, `weblogic_async`, `weblogic_console`,
  `weblogic_wls_sec`, `wso2_upload`.
- Each detector lives in its own module, is instantiated by
  `CVEMegaCheck`, must consult the baseline body before firing,
  and uses marker-based or distinctive-string evidence.

### Added - deep crawler (`scanner/crawler.py`)
- 7 sources: live, Wayback, gau, hakrawler, katana, GoSpider,
  deep BFS from recon seeds.
- Common-paths probe, URL de-dup, interesting-path tagger
  (login / sensitive / API).

### Added - 8 subdomain sources (`scanner/recon_sources/`)
- subfinder, assetfinder, amass passive, chaos, crtsh,
  bufferover, hackertarget, alienvault, certspotter, urlscan.

### Added - bulletproof `setup.sh`
- 3-step fallback (pip → `--break-system-packages` → apt system
  package) and retry wrapper for `go install`.

---

## 3.5.0 (2026-10-03) - sqlmap integration (second-stage SQLi confirmation)

### Added
- **SqlmapCheck** (`scanner/checks/sqlmap_scan.py`): new check that runs
  after the built-in `SQLInjectionCheck`. If `sqlmap` is on PATH, it
  invokes it against live hosts (with sentinel `?id=1` params) and any
  discovered parametric URLs. Parses sqlmap stdout for every
  `Parameter: / Type: / Title: / Payload:` triple and emits a critical
  finding per technique with `sqli`+`sqlmap`+`confirmed`+<technique> tags.

  Flags used:
  `--batch --level=3 --risk=2 --random-agent --technique=BEUSTQ
   --threads=5 --timeout=10 --flush-session --crawl=0 --skip-waf
   --output-dir <vuln>/sqlmap`

  Candidate URL list capped at 15 to keep runtime bounded.
  Degrades silently if sqlmap is absent (built-in SQLi check still runs).

- Added `sqlmap` to `setup.sh` apt install list.
- Added `sqlmap` to `ALL_TOOLS` tool-availability dashboard.

### Tests (117 passing)
- `test_sqlmap.py`:
  - Parses sqlmap output with multiple Type/Title/Payload triples under
    one `Parameter:` block (3 techniques, same param → 3 injections)
  - Empty / malformed input returns `[]`
  - Candidate URLs include live hosts with sentinel param
  - Discovered URLs with `?p=v` are included
  - Static files (css, images) excluded from candidates
  - Candidate list capped at 15
  - No sqlmap binary → `execute()` returns `[]`
  - Mocked injection produces critical Finding with correct tags

### Totals
- **28 vulnerability check classes** (up from 27)
- **117 tests passing** (up from 109)

## 3.4.0 (2026-10-03) - Depth pass: comprehensive SQLi/XSS, famous CVEs, massive recon expansion

Driven by user request: "add well-known famous vulns, make existing checks
deeper and more professional, expand recon massively, test for false positives."

### SQL Injection rewritten for depth and accuracy
`scanner/checks/sql_injection.py` is now a 4-technique probe:
1. **Error-based** across 6 DB engines (MySQL / PostgreSQL / MSSQL / Oracle /
   SQLite / Generic) with 70+ signatures - and crucially, each signature is
   compared against a benign baseline so pre-existing error strings on
   debug pages don't trigger false positives.
2. **Boolean-based** - response-length delta between `1=1` and `1=2`
   payloads; requires TRUE ≈ baseline (delta < 50B) and FALSE ≫ baseline
   (delta > 500B) to confirm.
3. **Time-based blind** - MySQL SLEEP / PostgreSQL pg_sleep / MSSQL
   WAITFOR DELAY / Oracle DBMS_PIPE.RECEIVE_MESSAGE. Requires ≥4.5s delay
   AND confirmation on a second shot to kill network-flake FPs.
4. **UNION-based** via ORDER BY column enumeration.

### XSS now active + context-aware
New `scanner/checks/xss.py` detects reflected XSS by:
1. Firing a benign canary first; abort unless reflected.
2. Classifying the reflection context (HTML / attribute / JavaScript).
3. Firing a context-appropriate payload; emit a finding ONLY when the
   payload bytes survive unencoded in the body.

### Famous CVE detection module
New `scanner/checks/famous_cves.py` fingerprints:
- CVE-2021-44228 **Log4Shell** (JNDI in User-Agent/Referer/X-Api-Version)
- CVE-2014-6271 **Shellshock** (bash function definition payload)
- CVE-2017-5638 **Apache Struts2 OGNL**
- CVE-2022-22965 **Spring4Shell**
- CVE-2022-26134 **Atlassian Confluence OGNL**
- CVE-2022-1388  **F5 BIG-IP iControl REST auth bypass**
- CVE-2021-26855 / CVE-2021-34473 **Exchange ProxyLogon/ProxyShell detection**
- CVE-2021-22205 **GitLab (passive detection)**
- CVE-2022-30190 **Follina ms-msdt URI**
- CVE-2018-7600  **Drupalgeddon 2**
- CVE-2017-9841  **PHPUnit eval-stdin.php**

### Massive recon expansion (new `scanner/recon_extended.py`)
Hooked into `ReconModule.run()` as a final step:
- **ASN / BGP lookup** via Team Cymru whois (dig TXT)
- **Shodan InternetDB** (`internetdb.shodan.io`) - FREE, no API key -
  returns open ports, hostnames, known CVEs per IP; emits findings for
  each CVE reported.
- **SPF / DMARC / DNSSEC analysis** - flags `+all`, `?all`, missing policies,
  `p=none`, absent DS record.
- **security.txt discovery** at `/.well-known/security.txt`
- **HTTP/2 + HTTP/3 detection** via ALPN probe + Alt-Svc header
- **IP geolocation** via `ip-api.com` free tier
- **DNS brute-force** with built-in top-100 wordlist (socket-based,
  parallel ThreadPoolExecutor)
- **Subdomain permutation** (altdns-style: `{sub}-dev`, `dev-{sub}`,
  `-staging`, `-test`, `-admin`, etc.) with resolve-verification -
  only resolved names are kept.
- Writes `extended_recon.json` summary into the recon directory.

### Model additions
`ScanResult` now has `asn_info`, `shodan_info`, `geo_info`, `http_versions`
dict fields, properly declared on the dataclass.

### Tests (109 passing, up from 96)
- `test_sqli_xss.py`:
  - SQLi: zero findings on clean baseline
  - SQLi: zero findings when error signature pre-exists in baseline (FP guard)
  - SQLi: triggers only when signature is new in response
  - SQLi: finding carries `sqli` + engine + technique tags
  - XSS: no finding when canary not reflected
  - XSS: no finding when canary reflects but payload is HTML-encoded
  - XSS: finding when payload survives unencoded
- `test_recon_extended.py`: permutation generation, wordlist well-formed
- `test_checks.py`: FamousCVEs method presence, XSS payload contexts

### Files Added
- `scanner/checks/sql_injection.py` (rewritten)
- `scanner/checks/xss.py`
- `scanner/checks/famous_cves.py`
- `scanner/recon_extended.py`
- `tests/test_sqli_xss.py`
- `tests/test_recon_extended.py`

### Totals
- **27 vulnerability check classes** (up from 25)
- **109 tests passing** (up from 96)
- **5 output formats** (HTML/JSON/Markdown/SARIF/CSV)
- **Recon surfaces:** WHOIS, DNS, AXFR, 6 subdomain sources (subfinder/amass/
  assetfinder/findomain/sublist3r/crt.sh), reverse-IP, vhost, favicon mmh3,
  Google dorks, nmap, masscan, whatweb, wafw00f, **ASN, Shodan InternetDB,
  SPF/DMARC/DNSSEC, security.txt, HTTP/2/3, geolocation, DNS brute-force,
  altdns permutations**.

## 3.3.0 (2026-10-03) - Scanner-self-security + SARIF + 3 more vuln classes

Driven by the second round of audit findings (105 raw -> 45 confirmed).
Focus: hardening the scanner against hostile targets, real rate limiting,
new vulnerability classes, more output formats.

### Scanner self-security (new scanner/validators.py)
- `validate_target()`: strict regex (RFC 1035 hostname / IP), rejects
  leading `-`, path separators, shell meta-chars, control chars.
  Prevents argument injection into every downstream tool.
- `validate_webhook_url()`: requires http/https scheme, rejects `-`/`@`
  prefixes, blocks private/loopback/link-local IPs by default. SSRF
  guard for scanner-triggered callbacks.
- `is_private_host()` helper for consumer modules.

### Rate limiting that actually works (scanner/utils.py)
- `set_rate_limit()` + `_apply_rate_limit()`: thread-safe lock enforces
  inter-request delay against the wall clock. autoscan.py applies it
  before every curl invocation (not just between targets).
- Every curl command now carries `--max-filesize` (10 MB cap) and
  `--max-redirs 3` to prevent DoS by hostile targets and redirect-based
  SSRF to cloud metadata endpoints.

### XXE protection in sitemap parsing (scanner/passive.py)
- Switched to defusedxml (fallback to stdlib with DOCTYPE/ENTITY refusal).
- Hard 10 MB cap on sitemap body before parsing (billion-laughs guard).
- robots.txt disallow parser now strips inline comments.

### 3 new vulnerability check classes (25 total, up from 22)
- **DeserializationCheck**: 8 signature regexes for Java/PHP/.NET/
  pickle/Ruby/Node serialized blobs scanned across Set-Cookie,
  hidden form fields, URL params.
- **CSPCookieCheck**: parses present CSP for `unsafe-inline`,
  `unsafe-eval`, wildcard script sources, missing frame-ancestors;
  audits every Set-Cookie for Secure/HttpOnly/SameSite and the
  `__Host-`/`__Secure-` prefix rules.
- **LDAPInjectionCheck**: 5 wildcard payloads against 7 login paths,
  with baseline comparison for auth bypass and error-signature matching.

### 2 new output formats (5 total)
- **SARIF 2.1.0** (scanner/output/sarif_report.py): GitHub Advanced
  Security code-scanning compatible. Severity maps to error/warning/note.
  Rules deduplicated by source.
- **CSV** (scanner/output/csv_report.py): findings as spreadsheet rows
  for triage.
- `--format` CLI extended: `{all, html, json, markdown, sarif, csv}`.
  `all` emits all five.

### Correctness fixes from this round
- CheckpointManager tolerates added/removed dataclass fields via
  `_safe_init()` filter - older checkpoints no longer kill resume.
- `run_phase` dead helper deleted from autoscan.py.
- Vhost discovery reordered to run BEFORE dedup+httpx so new vhosts
  land in all_subdomains.txt and get probed downstream.
- webhook URL now goes through `--` separator in curl invocation.

### Tests: 96 passing (up from 69)
- `test_validators.py`: hostname/IP acceptance, flag rejection,
  shell-meta rejection, webhook scheme + private-IP blocking.
- `test_rate_limit.py`: zero-rate no-delay invariant + actual delay
  enforcement with wall-clock timing.
- `test_sarif_csv.py`: SARIF 2.1.0 shape, severity mapping, rule
  deduplication, CSV field presence.
- `test_checks.py` extended: deserialization signatures, CSP finding
  emission, LDAP payload counts.

### Files Added
- `scanner/validators.py`
- `scanner/checks/deserialization.py`
- `scanner/checks/csp_cookies.py`
- `scanner/checks/ldap_injection.py`
- `scanner/output/sarif_report.py`
- `scanner/output/csv_report.py`
- `tests/test_validators.py`
- `tests/test_rate_limit.py`
- `tests/test_sarif_csv.py`

## 3.2.0 (2026-10-03) - Post-audit hardening

Driven by findings from a multi-agent audit (6 dimensions, adversarial
verification). Fixes correctness bugs introduced by the v3.0 refactor
and closes high-impact feature gaps.

### Critical bug fixes
- **Nuclei results silently dropped** (`scanner/checks/nuclei_scan.py:49`):
  `info.tags` from modern nuclei is a list, not a comma-string. Previous
  code called `.split(",")` on a list → every nuclei finding discarded.
  Now handles both list and string forms.
- **SSL check never produced findings** (`scanner/checks/ssl_tls.py:32`):
  testssl.sh JSON is a top-level list; code called `.get("findings")`
  on it (list has no .get) → silent AttributeError. Now detects both
  shapes. Also added `_parse_sslscan` and `_parse_openssl` so the two
  fallback branches now emit findings.
- **DirBruteCheck emitted no findings** (`scanner/checks/dirbrute.py`):
  ran gobuster/ffuf/feroxbuster but never read their output. Now parses
  all three formats and classifies hits (sensitive paths → high, admin/debug
  → medium, other → info).
- **ParamDiscovery._arjun output never parsed**: arjun JSON output is
  now read and merged into `found_params`.
- **ParamDiscovery._paramspider output never collected**: now accepts a
  URLRecord in the fallback (previous code crashed) and reads the generated
  text file.
- **Status code substring match ("200" in first_line)**: `BaseCheck._status_code`
  now parses the status line correctly. Used by Bypass403Check, SwaggerCheck,
  passive CMS probe.
- **autoscan.py log handler check**: `setup_logging` was called once;
  every subsequent target's logs went to the first target's log file.
  Now tracks and replaces the target-specific file handler per scan.
- **--only PHASE skipped upstream dependencies**: running `--only vuln`
  left `live_hosts` empty. Added `PHASE_DEPS` map; --only PHASE now runs
  the dependency chain.
- **--format flag was ignored**: `generate()` emitted all three formats
  unconditionally. Now accepts a `formats` list; autoscan.py passes the
  CLI value through.
- **Resume mode did not mkdir directories**: added mkdir loop before
  logging setup.
- **Multi-target run had no exception boundary**: one bad target killed
  the batch. Now wrapped per-target in try/except; KeyboardInterrupt
  returns 130, other errors log and continue.
- **crt.sh filter false-positive**: `.endswith(target)` matched
  `evilexample.com` for `example.com`. Now requires the leading dot.
- **Subdomain dedup substring match**: `target in s` similarly matched
  unrelated siblings. Now requires exact match or `.target` suffix.
- **Vhost discovery baseline failure trap**: a failed baseline request
  silently set `baseline_len=0`, causing every vhost to be reported.
  Now returns early if the baseline request fails.
- **Favicon hash on text-decoded binary**: `subprocess.run(text=True)`
  corrupted binary favicon bytes. Now uses raw `subprocess.run` with
  `capture_output` to preserve binary data for the mmh3 hash.
- **nmap open_ports attached only to first host record**: now attaches
  to every host record whose domain matches the target.
- **Open-redirect false positive on reflected URL**: anchor-matched
  `evil-attacker.com` anywhere in Location header. Now requires
  `Location:` to point directly at the attacker-controlled host.
- **MethodTester duplicate TRACE finding**: TRACE caused both the
  aggregate dangerous-methods finding and the XST finding to fire.
  Now the aggregate excludes TRACE.
- **VulnScanner finding dedup silently dropped distinct findings**:
  the key was `(title, host)` only, collapsing findings on different
  URLs. Now `(title, host, url, evidence[:100])`.

### New vulnerability checks (4 added, 22 total)
- **SQLInjectionCheck** - 6 payloads × 17 params × 18 DB-engine error
  signatures (MySQL, PostgreSQL, Oracle, MSSQL, SQLite).
- **CommandInjectionCheck** - 6 marker payloads (output-reflected)
  and 4 time-based blind payloads across 17 params.
- **NoSQLInjectionCheck** - MongoDB `$ne`/`$gt`/`$regex` operator payloads
  against 7 common login endpoints; detects auth bypass via token response.
- **JWTWeaknessCheck** - extracts JWT tokens from pages, detects
  alg=none, HS256 weak-secret cracking against 19 common secrets,
  flags kid-header path traversal.

### Code quality
- **Centralized `evil-attacker.com` canary** → `scanner/constants.py::ATTACKER_CANARY`.
  Used by CORSCheck, OpenRedirectCheck, HostHeaderCheck.
- **Dead imports removed**: `hashlib`, `struct` from recon.py.
- **`BaseCheck._status_code` helper**: safer status-line parsing.
- **Auth support in `utils.run`**: `--cookie`, `--header`, `--bearer`,
  `--basic-auth` CLI flags; auth material injected into every curl call.
- **`--fail-on {critical,high,medium,low}` severity gate**: exits 2 on
  threshold crossed, suitable for CI pipelines.
- **`--config FILE` flag** (reserved; honored by future config loader).

### Tests
69 passing (up from 57). New coverage:
- SQLi/CMDi/NoSQLi check static data integrity
- JWT regex + weak-secret recovery + random-secret rejection
- Status-code parser with regression test for the "200 in substring" bug
- Auth helper setters
- Constants centralization

### Files Added
- `scanner/constants.py`
- `scanner/checks/sql_injection.py`
- `scanner/checks/cmd_injection.py`
- `scanner/checks/nosql_injection.py`
- `scanner/checks/jwt_weakness.py`

## 3.1.0 (2026-10-03)

### Added
- **Markdown report format** - `scanner/output/markdown_report.py` emits a
  GitHub-flavored markdown report with severity tables, findings grouped by
  severity, and all data sections. `report.md` written to `06_reports/`.
- **Scan checkpoint / resume** - `scanner/checkpoint.py` persists per-phase
  state to `.checkpoint.json`. `python autoscan.py --resume <base_dir>` restores
  the result and skips completed phases.
- **Scan diffing** - `scanner/diff.py` compares two scan runs by their
  `summary.json`. Produces JSON + Markdown showing new, resolved, and
  persistent findings; new subdomains; new live hosts; new sensitive files.
  CLI: `python autoscan.py --diff <baseline_dir> <current_dir>`.
- **Unit test suite** - `tests/` directory with 53 tests covering models,
  utils (URL categorizers, parsing, dirs), recon (mmh3 hash, dorks), output
  (markdown + JSON), checkpoint, diff, and all 14 check classes.
- `--format` CLI flag selecting output format(s).
- `--version` CLI flag.
- Path-traversal hardening in `create_dirs()` - the sanitized target name
  cannot escape the output root.

### Changed
- `scanner/reporter.py` now orchestrates HTML, JSON, and Markdown generators
  rather than embedding the JSON summary inline.
- `autoscan.py` phase orchestration integrates `CheckpointManager` so
  each phase persists its data on completion.
- Banner version now derived from `scanner.__version__`.

### Files Added
- `scanner/output/__init__.py`
- `scanner/output/markdown_report.py`
- `scanner/output/json_report.py`
- `scanner/checkpoint.py`
- `scanner/diff.py`
- `tests/__init__.py`
- `tests/test_models.py`
- `tests/test_utils.py`
- `tests/test_recon.py`
- `tests/test_output.py`
- `tests/test_checkpoint.py`
- `tests/test_diff.py`
- `tests/test_checks.py`
- `PROJECT_ARCHITECTURE.md`
- `PROJECT_CHANGELOG.md`

### Tested
- 53 unit tests passing (`python3 -m unittest discover -s tests`)

## 3.0.0 (2026-10-03)

### Added
- **DNS Zone Transfer (AXFR)** probing in `ReconModule`.
- **Virtual host discovery** via Host header manipulation.
- **Favicon hashing** (pure-python MurmurHash3) for service fingerprinting.
- **Google dork generator** - 21 queries for manual recon.
- **Swagger/OpenAPI endpoint discovery** - 18 common paths.
- **GraphQL introspection detection** with schema dump.
- **CRLF injection** testing in path and parameters.
- **Host header injection** - redirect, cookie scope, X-Forwarded-Host.
- **Cloud metadata SSRF** - AWS/GCP/Azure endpoints via 13 SSRF params.
- Modular `scanner/checks/` directory - 14 BaseCheck subclasses.
- `--proxy` CLI flag (Burp/ZAP) wired through curl + env vars.
- `--wordlist` CLI flag for custom directory brute-force wordlist.

### Fixed
- `__init__.py` version string 2.0.0 -> 3.0.0 (matched banner).
- `ScanResult` dataclass: added `host_records`, `ports_raw`, `js_endpoints`,
  `google_dorks` fields (previously assigned as dynamic attrs).
- Removed unused `datetime` import from `reporter.py`.
- `passive.py _cms_detect` CMS path probing was a no-op (`pass` body);
  now parses status and emits findings.
- Enhanced CORSCheck with origin-suffix bypass detection.
- Enhanced Bypass403Check with 9 header techniques + 5 path manipulations.
- Enhanced TakeoverCheck with 10 service fingerprints.

### Changed
- Monolithic `scanner/vulnscan.py` split into 14 classes under
  `scanner/checks/`. `vulnscan.py` is now a thin orchestrator.

## 2.0.0

Initial baseline: 6-phase scanner (recon, crawl, JS, methods, vuln, report).
