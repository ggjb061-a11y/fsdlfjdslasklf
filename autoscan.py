#!/usr/bin/env python3
"""
AutoVulnScan – Automated Security Assessment Framework
For authorized penetration testing and bug bounty programs ONLY.

Usage:
    python autoscan.py -t example.com
    python autoscan.py -l targets.txt --threads 20
    python autoscan.py -t example.com --scope quick --confirm
    python autoscan.py -t example.com --webhook https://hooks.slack.com/services/XXX
"""
import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from scanner.utils import create_dirs, tools_status, run
from scanner.models import ScanResult
from scanner.recon import ReconModule
from scanner.crawler import CrawlerModule
from scanner.js_analyzer import JSAnalyzer
from scanner.http_methods import MethodTester
from scanner.passive import PassiveModule
from scanner.params import ParamDiscovery
from scanner.vulnscan import VulnScanner
from scanner.reporter import generate

BANNER = r"""
     _         _      __   __      _        ____
    / \  _   _| |_ ___\ \ / /_   _| |_ __  / ___|  ___ __ _ _ __
   / _ \| | | | __/ _ \\ V /| | | | | '_ \ \___ \ / __/ _` | '_ \
  / ___ \ |_| | || (_) || | | |_| | | | | | ___) | (_| (_| | | | |
 /_/   \_\__,_|\__\___/ |_|  \__,_|_|_| |_||____/ \___\__,_|_| |_|

  v3.0 | Automated Security Assessment | Authorized Use ONLY
"""

ALL_TOOLS = [
    "subfinder", "amass", "assetfinder", "findomain", "sublist3r",
    "httpx", "nmap", "masscan", "whatweb", "wafw00f",
    "gau", "hakrawler", "katana", "gospider",
    "nuclei", "nikto", "testssl.sh", "sslscan",
    "gobuster", "ffuf", "feroxbuster", "subjack",
    "arjun", "paramspider", "gowitness", "eyewitness",
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
    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Target domain (e.g. example.com)")
    target_group.add_argument("-l", "--list", help="File with list of target domains (one per line)")

    p.add_argument("-o", "--output", default="scans", help="Base output directory (default: scans)")
    p.add_argument("--threads", type=int, default=10, help="Thread count (default: 10)")
    p.add_argument("--scope", choices=["quick", "full"], default="full",
                   help="quick = recon+passive only | full = all phases (default: full)")
    p.add_argument("--only", choices=["recon", "passive", "crawl", "js", "params", "methods", "vuln"],
                   help="Run only one phase")
    p.add_argument("--skip-recon", action="store_true")
    p.add_argument("--skip-passive", action="store_true")
    p.add_argument("--skip-crawl", action="store_true")
    p.add_argument("--skip-js", action="store_true")
    p.add_argument("--skip-params", action="store_true")
    p.add_argument("--skip-methods", action="store_true")
    p.add_argument("--skip-vuln", action="store_true")
    p.add_argument("--rate-limit", type=float, default=0,
                   help="Delay in seconds between requests (default: 0)")
    p.add_argument("--webhook", help="Webhook URL for scan completion notification (Slack/Discord)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--confirm", action="store_true", help="Skip authorization prompt")
    return p.parse_args()


def phase_banner(log, title: str) -> None:
    bar = "─" * 60
    log.info("")
    log.info(bar)
    log.info(f"  {title}")
    log.info(bar)


def send_webhook(url: str, target: str, counts: dict, report_path: str) -> None:
    """Send scan completion notification via webhook (Slack/Discord compatible)."""
    payload = {
        "text": (
            f"*AutoVulnScan Complete* – `{target}`\n"
            f"Critical: {counts['critical']} | High: {counts['high']} "
            f"| Medium: {counts['medium']} | Low: {counts['low']}\n"
            f"Report: `{report_path}`"
        ),
    }
    run(
        ["curl", "-s", "--max-time", "10", "-X", "POST",
         "-H", "Content-Type: application/json",
         "-d", json.dumps(payload), url],
        timeout=15,
    )


def scan_target(target: str, args: argparse.Namespace) -> ScanResult:
    """Run the full scan pipeline on a single target."""
    target = target.removeprefix("https://").removeprefix("http://").rstrip("/")

    dirs = create_dirs(args.output, target)
    log_file = f"{dirs['base']}/scan.log"

    if not logging.getLogger("autoscan").handlers:
        setup_logging(args.verbose, log_file)
    else:
        logging.getLogger("autoscan").addHandler(logging.FileHandler(log_file))

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
    log.info(f"Scope:     {args.scope}")
    log.info(f"Started:   {now}")

    result = ScanResult(target=target, scan_date=now, base_dir=dirs["base"])
    quick = args.scope == "quick"

    def should(name: str) -> bool:
        if args.only:
            return args.only == name
        if getattr(args, f"skip_{name}", False):
            return False
        if quick and name in ("crawl", "js", "params", "methods", "vuln"):
            return False
        return True

    # ── Phase 1: Recon ────────────────────────────────────────────────────
    if should("recon"):
        phase_banner(log, "PHASE 1 – RECONNAISSANCE")
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

    # ── Phase 2: Passive Intelligence ─────────────────────────────────────
    if should("passive"):
        phase_banner(log, "PHASE 2 – PASSIVE INTELLIGENCE")
        passive = PassiveModule(target, dirs, result.live_hosts, threads=args.threads)
        extra_urls, passive_findings, emails = passive.run()
        result.urls.extend(extra_urls)
        result.findings.extend(passive_findings)
        result.emails = emails
        result.cms_info = passive.cms_info
        log.info(f"  Passive: {len(extra_urls)} URLs | {len(passive_findings)} findings | {len(emails)} emails")

    # ── Phase 3: URL Crawling ─────────────────────────────────────────────
    if should("crawl"):
        phase_banner(log, "PHASE 3 – URL COLLECTION (Wayback + Live)")
        crawler = CrawlerModule(target, dirs, result.live_hosts, threads=args.threads)
        url_records = crawler.run()
        result.urls.extend(url_records)
        log.info(f"  URLs collected: {len(result.urls)}")

    # ── Phase 4: JS Analysis ─────────────────────────────────────────────
    if should("js"):
        phase_banner(log, "PHASE 4 – JAVASCRIPT ANALYSIS")
        js_urls = list({u.url for u in result.urls if u.is_js})
        analyzer = JSAnalyzer(dirs, js_urls, threads=args.threads)
        secrets, endpoints, js_findings = analyzer.run()
        result.js_secrets = secrets
        result.js_endpoints = endpoints
        result.findings.extend(js_findings)
        log.info(f"  JS secrets: {len(secrets)} | Endpoints: {len(endpoints)}")

    # ── Phase 5: Parameter Discovery ──────────────────────────────────────
    if should("params"):
        phase_banner(log, "PHASE 5 – PARAMETER DISCOVERY")
        param_disc = ParamDiscovery(dirs, result.live_hosts, result.urls, threads=args.threads)
        found_params, param_findings = param_disc.run()
        result.found_params = found_params
        result.findings.extend(param_findings)
        log.info(f"  Params found: {sum(len(v) for v in found_params.values())} on {len(found_params)} endpoints")

    # ── Phase 6: HTTP Methods ─────────────────────────────────────────────
    if should("methods"):
        phase_banner(log, "PHASE 6 – HTTP METHOD DETECTION")
        tester = MethodTester(dirs, result.live_hosts, threads=args.threads)
        result.allowed_methods = tester.run()
        result.findings.extend(tester.findings)
        log.info(f"  Hosts tested: {len(result.allowed_methods)}")

    # ── Phase 7: Vuln Scanning ────────────────────────────────────────────
    if should("vuln"):
        phase_banner(log, "PHASE 7 – VULNERABILITY SCANNING")
        vuln = VulnScanner(target, dirs, result.live_hosts, threads=args.threads)
        vuln_findings = vuln.run()
        result.findings.extend(vuln_findings)

    # ── Phase 8: Report ───────────────────────────────────────────────────
    phase_banner(log, "PHASE 8 – GENERATING REPORT")
    report_path = generate(result)
    counts = result.count_by_severity()

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE – {target}")
    print(f"{'='*60}")
    print(f"  Subdomains     : {len(result.subdomains)}")
    print(f"  Live hosts     : {len(result.live_hosts)}")
    print(f"  URLs collected : {len(result.urls)}")
    print(f"  JS secrets     : {len(result.js_secrets)}")
    print(f"  Emails         : {len(getattr(result, 'emails', []))}")
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
    print(f"  Finished at    : {end_time}")
    print(f"{'='*60}\n")

    # Webhook notification
    if args.webhook:
        send_webhook(args.webhook, target, counts, report_path)
        log.info(f"  Webhook sent to {args.webhook}")

    return result


def main() -> None:
    print(BANNER)
    args = cli()

    # Collect targets
    targets: list[str] = []
    if args.target:
        targets = [args.target]
    elif args.list:
        p = Path(args.list)
        if not p.exists():
            print(f"  [!] File not found: {args.list}")
            sys.exit(1)
        targets = [l.strip() for l in p.read_text().splitlines()
                    if l.strip() and not l.strip().startswith("#")]

    if not targets:
        print("  [!] No targets specified.")
        sys.exit(1)

    if not args.confirm:
        print(f"\n  [!] Targets ({len(targets)}): {', '.join(targets[:5])}"
              + (f" ... +{len(targets)-5} more" if len(targets) > 5 else ""))
        print("  [!] Scanning without authorization is ILLEGAL.\n")
        ans = input("  Confirm you have authorization [yes/NO]: ").strip().lower()
        if ans != "yes":
            print("  Aborted.")
            sys.exit(0)

    start = time.time()

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{'#'*60}")
            print(f"  TARGET {i}/{len(targets)}: {target}")
            print(f"{'#'*60}")

        scan_target(target, args)

        if args.rate_limit > 0 and i < len(targets):
            time.sleep(args.rate_limit)

    elapsed = time.time() - start
    if len(targets) > 1:
        print(f"\n{'='*60}")
        print(f"  ALL {len(targets)} TARGETS COMPLETE in {elapsed:.0f}s")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
