# AutoVulnScan - Project Changelog

Version numbers follow the project's own `scanner/__init__.py::__version__`.

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
