#!/usr/bin/env python3
"""
AutoVulnScan – Automated Security Assessment Framework
For authorized penetration testing and bug bounty programs ONLY.

Usage:
    python autoscan.py -t example.com
    python autoscan.py -t example.com --threads 20 --skip-vuln
    python autoscan.py -t example.com --only recon --confirm
"""
import argparse
import logging
import sys
from datetime import datetime

from scanner.utils import create_dirs, tools_status
from scanner.models import ScanResult
from scanner.recon import ReconModule
from scanner.crawler import CrawlerModule
from scanner.js_analyzer import JSAnalyzer
from scanner.http_methods import MethodTester
from scanner.vulnscan import VulnScanner
from scanner.reporter import generate

BANNER = r"""
     _         _      __   __      _        ____
    / \  _   _| |_ ___\ \ / /_   _| |_ __  / ___|  ___ __ _ _ __
   / _ \| | | | __/ _ \\ V /| | | | | '_ \ \___ \ / __/ _` | '_ \
  / ___ \ |_| | || (_) || | | |_| | | | | | ___) | (_| (_| | | | |
 /_/   \_\__,_|\__\___/ |_|  \__,_|_|_| |_||____/ \___\__,_|_| |_|

  v2.0 | Automated Security Assessment | Authorized Use ONLY
"""

ALL_TOOLS = [
    "subfinder", "amass", "assetfinder", "findomain",
    "httpx", "nmap", "masscan", "whatweb", "wafw00f",
    "gau", "hakrawler", "katana", "gospider",
    "nuclei", "nikto", "testssl.sh", "sslscan",
    "gobuster", "ffuf", "feroxbuster", "subjack",
    "curl", "dig", "whois", "openssl",
]


def setup_logging(verbose: bool, log_file: str) -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(message)s"
    datefmt = "%H:%M:%S"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
    )


def cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="autoscan",
        description="Automated security scanner for authorized testing.",
    )
    p.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", default="scans", help="Base output directory (default: scans)")
    p.add_argument("--threads", type=int, default=10, help="Thread count (default: 10)")
    p.add_argument("--only", choices=["recon", "crawl", "js", "methods", "vuln"],
                   help="Run only one phase")
    p.add_argument("--skip-recon", action="store_true")
    p.add_argument("--skip-crawl", action="store_true")
    p.add_argument("--skip-js", action="store_true")
    p.add_argument("--skip-methods", action="store_true")
    p.add_argument("--skip-vuln", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--confirm", action="store_true", help="Skip authorization prompt")
    return p.parse_args()


def phase(log, title: str) -> None:
    bar = "─" * 60
    log.info("")
    log.info(bar)
    log.info(f"  {title}")
    log.info(bar)


def main() -> None:
    print(BANNER)
    args = cli()

    target = args.target.removeprefix("https://").removeprefix("http://").rstrip("/")

    if not args.confirm:
        print(f"\n  [!] Target: {target}")
        print("  [!] Scanning without authorization is ILLEGAL.\n")
        ans = input("  Confirm you have authorization [yes/NO]: ").strip().lower()
        if ans != "yes":
            print("  Aborted.")
            sys.exit(0)

    dirs = create_dirs(args.output, target)
    setup_logging(args.verbose, f"{dirs['base']}/scan.log")
    log = logging.getLogger("autoscan")

    # Show tool availability
    status = tools_status(ALL_TOOLS)
    found = sum(1 for v in status.values() if v == "✓")
    log.info(f"Tools available: {found}/{len(ALL_TOOLS)}")
    for tool, st in status.items():
        log.debug(f"  {st} {tool}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log.info(f"Target:    {target}")
    log.info(f"Output:    {dirs['base']}")
    log.info(f"Threads:   {args.threads}")
    log.info(f"Started:   {now}")

    result = ScanResult(target=target, scan_date=now, base_dir=dirs["base"])

    should = lambda name: (args.only is None or args.only == name) and not getattr(args, f"skip_{name}", False)

    # ── Phase 1: Recon ────────────────────────────────────────────────────
    if should("recon"):
        phase(log, "PHASE 1 – RECONNAISSANCE")
        recon = ReconModule(target, dirs, threads=args.threads)
        recon.run()
        result.subdomains = recon.subdomains
        result.live_hosts = recon.live_hosts
        result.host_records = recon.host_records
        result.dns_records = recon.dns_records
        result.whois = recon.whois
        result.waf = recon.waf
        result.ports_raw = recon.ports_raw
        log.info(f"  Subdomains: {len(result.subdomains)} | Live: {len(result.live_hosts)}")

    # ── Phase 2: URL Crawling ─────────────────────────────────────────────
    if should("crawl"):
        phase(log, "PHASE 2 – URL COLLECTION (Wayback + Live)")
        crawler = CrawlerModule(target, dirs, result.live_hosts, threads=args.threads)
        url_records = crawler.run()
        result.urls = url_records
        log.info(f"  URLs collected: {len(result.urls)}")

    # ── Phase 3: JS Analysis ─────────────────────────────────────────────
    if should("js"):
        phase(log, "PHASE 3 – JAVASCRIPT ANALYSIS")
        js_urls = [u.url for u in result.urls if u.is_js]
        analyzer = JSAnalyzer(dirs, js_urls, threads=args.threads)
        secrets, endpoints, js_findings = analyzer.run()
        result.js_secrets = secrets
        result.js_endpoints = endpoints
        result.findings.extend(js_findings)
        log.info(f"  JS secrets: {len(secrets)} | Endpoints: {len(endpoints)}")

    # ── Phase 4: HTTP Methods ─────────────────────────────────────────────
    if should("methods"):
        phase(log, "PHASE 4 – HTTP METHOD DETECTION")
        tester = MethodTester(dirs, result.live_hosts, threads=args.threads)
        result.allowed_methods = tester.run()
        result.findings.extend(tester.findings)
        log.info(f"  Hosts tested: {len(result.allowed_methods)}")

    # ── Phase 5: Vuln Scanning ────────────────────────────────────────────
    if should("vuln"):
        phase(log, "PHASE 5 – VULNERABILITY SCANNING")
        vuln = VulnScanner(target, dirs, result.live_hosts, threads=args.threads)
        vuln_findings = vuln.run()
        result.findings.extend(vuln_findings)

    # ── Phase 6: Report ───────────────────────────────────────────────────
    phase(log, "PHASE 6 – GENERATING REPORT")
    report_path = generate(result)
    counts = result.count_by_severity()

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE – {target}")
    print(f"{'='*60}")
    print(f"  Subdomains     : {len(result.subdomains)}")
    print(f"  Live hosts     : {len(result.live_hosts)}")
    print(f"  URLs collected : {len(result.urls)}")
    print(f"  JS secrets     : {len(result.js_secrets)}")
    print(f"  ──────────────────────────────────────")
    print(f"  Critical       : {counts['critical']}")
    print(f"  High           : {counts['high']}")
    print(f"  Medium         : {counts['medium']}")
    print(f"  Low            : {counts['low']}")
    print(f"  Info           : {counts['info']}")
    print(f"  Total findings : {len(result.findings)}")
    print(f"{'='*60}")
    print(f"  HTML Report    : {report_path}")
    print(f"  JSON Report    : {dirs['reports']}/summary.json")
    print(f"  All outputs    : {dirs['base']}/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
