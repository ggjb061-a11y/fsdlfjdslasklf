# AutoVulnScan - Project Changelog

Version numbers follow the project's own `scanner/__init__.py::__version__`.

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
