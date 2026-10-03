"""Reconnaissance: subdomains, DNS, WHOIS, port scanning, live host probing."""
import logging
from pathlib import Path
from .utils import which, run, read_lines, write_lines, resolve_ip, resolve_all_ips
from .models import HostRecord, Finding

logger = logging.getLogger("autoscan.recon")


class ReconModule:
    """
    Phase 1 – Passive and active reconnaissance.
    Collects: subdomains, DNS records, WHOIS, open ports, live HTTP hosts.
    """

    def __init__(self, target: str, dirs: dict, threads: int = 10):
        self.target = target
        self.dirs = dirs
        self.threads = threads

        self.subdomains: list[str] = []
        self.live_hosts: list[str] = []
        self.host_records: list[HostRecord] = []
        self.dns_records: dict = {}
        self.whois: str = ""
        self.waf: str = ""
        self.ports_raw: list[str] = []
        self.google_dorks: list[str] = []
        self.findings: list = []

    # ─── WHOIS ────────────────────────────────────────────────────────────────

    def _whois(self) -> None:
        out_file = f"{self.dirs['recon']}/whois.txt"
        rc, out, _ = run(["whois", self.target], output_file=out_file, timeout=30)
        if out:
            self.whois = out[:4000]
            logger.debug(f"WHOIS collected ({len(out)} chars)")

    # ─── DNS ──────────────────────────────────────────────────────────────────

    def _dns(self) -> None:
        out_file = f"{self.dirs['dns']}/records.txt"
        records: dict = {}

        if which("dig"):
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "PTR"]:
                _, out, _ = run(["dig", "+short", rtype, self.target], timeout=15)
                vals = [v.strip().rstrip(".") for v in out.splitlines() if v.strip()]
                if vals:
                    records[rtype] = vals
        elif which("nslookup"):
            _, out, _ = run(["nslookup", self.target], timeout=15)
            records["nslookup_raw"] = [l.strip() for l in out.splitlines() if l.strip()]

        # Also resolve all IPs directly
        ips = resolve_all_ips(self.target)
        if ips:
            records.setdefault("A_resolved", ips)

        self.dns_records = records

        lines = []
        for rtype, vals in records.items():
            lines.append(f"{rtype}:")
            lines.extend(f"  {v}" for v in vals)
        Path(out_file).write_text("\n".join(lines))

    # ─── SUBDOMAINS ───────────────────────────────────────────────────────────

    def _subfinder(self) -> None:
        if not which("subfinder"):
            return
        out = f"{self.dirs['subdomains']}/subfinder.txt"
        rc, stdout, _ = run(
            ["subfinder", "-d", self.target, "-silent", "-t", str(self.threads)],
            output_file=out, timeout=300,
        )
        self.subdomains += [s for s in stdout.splitlines() if s.strip()]

    def _amass(self) -> None:
        if not which("amass"):
            return
        out = f"{self.dirs['subdomains']}/amass.txt"
        run(["amass", "enum", "-passive", "-d", self.target, "-o", out], timeout=600)
        self.subdomains += read_lines(out)

    def _assetfinder(self) -> None:
        if not which("assetfinder"):
            return
        out = f"{self.dirs['subdomains']}/assetfinder.txt"
        rc, stdout, _ = run(["assetfinder", "--subs-only", self.target],
                            output_file=out, timeout=120)
        self.subdomains += [s for s in stdout.splitlines() if s.strip()]

    def _findomain(self) -> None:
        if not which("findomain"):
            return
        out = f"{self.dirs['subdomains']}/findomain.txt"
        rc, stdout, _ = run(["findomain", "-t", self.target, "-q"],
                            output_file=out, timeout=120)
        self.subdomains += [s for s in stdout.splitlines() if s.strip()]

    def _sublist3r(self) -> None:
        if not which("sublist3r"):
            return
        out = f"{self.dirs['subdomains']}/sublist3r.txt"
        run(["sublist3r", "-d", self.target, "-o", out, "-n"], timeout=300)
        self.subdomains += read_lines(out)

    def _crtsh(self) -> None:
        """Certificate Transparency log search via crt.sh (free, no API key)."""
        import json as _json
        out = f"{self.dirs['subdomains']}/crtsh.txt"
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        rc, stdout, _ = run(
            ["curl", "-s", "--max-time", "30", "--compressed", url],
            timeout=40,
        )
        if rc != 0 or not stdout.strip():
            logger.debug("crt.sh returned no data")
            return
        try:
            entries = _json.loads(stdout)
        except Exception:
            return
        subs = set()
        target_suffix = f".{self.target.lower()}"
        for entry in entries:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                d = line.strip().lstrip("*.").lower()
                if d.endswith(target_suffix) and d != self.target.lower():
                    subs.add(d)
        self.subdomains += list(subs)
        write_lines(out, sorted(subs))
        logger.info(f"  crt.sh: {len(subs)} subdomains")

    def _reverse_ip(self) -> None:
        """Resolve target IP and look for other domains sharing the same IP."""
        ip = resolve_ip(self.target)
        if not ip:
            return
        out = f"{self.dirs['recon']}/reverse_ip.txt"
        # Use HackTarget free reverse IP (curl, no key)
        rc, stdout, _ = run(
            ["curl", "-s", "--max-time", "15",
             f"https://api.hackertarget.com/reverseiplookup/?q={ip}"],
            timeout=20,
        )
        if rc == 0 and stdout and "error" not in stdout.lower():
            domains = [d.strip() for d in stdout.splitlines() if d.strip() and "API" not in d]
            write_lines(out, domains)
            logger.info(f"  Reverse IP ({ip}): {len(domains)} domains")

    def _dns_zone_transfer(self) -> None:
        """Attempt AXFR zone transfer against all NS servers."""
        if not which("dig"):
            return
        _, ns_out, _ = run(["dig", "+short", "NS", self.target], timeout=15)
        nameservers = [ns.strip().rstrip(".") for ns in ns_out.splitlines() if ns.strip()]
        if not nameservers:
            return

        out_file = f"{self.dirs['dns']}/zone_transfer.txt"
        for ns in nameservers:
            rc, out, _ = run(
                ["dig", "AXFR", self.target, f"@{ns}"],
                timeout=30,
            )
            if rc == 0 and out and "Transfer failed" not in out and "XFR size:" in out:
                Path(out_file).write_text(out)
                for line in out.splitlines():
                    parts = line.split()
                    if parts and parts[0].endswith(f".{self.target}."):
                        sub = parts[0].rstrip(".")
                        if sub not in self.subdomains:
                            self.subdomains.append(sub)
                self.findings.append(Finding(
                    severity="critical",
                    title="DNS Zone Transfer Allowed (AXFR)",
                    host=self.target,
                    detail=f"Nameserver {ns} allows full zone transfer – all DNS records exposed",
                    source="dns_axfr",
                ))
                logger.info(f"  AXFR: Zone transfer succeeded on {ns}!")
                break
            else:
                logger.debug(f"  AXFR: Transfer denied on {ns}")

    def _vhost_discovery(self) -> None:
        """Discover virtual hosts via Host header manipulation."""
        ip = resolve_ip(self.target)
        if not ip:
            return
        vhost_prefixes = [
            "dev", "staging", "stage", "test", "admin", "api", "app",
            "beta", "internal", "intranet", "portal", "demo", "old",
            "new", "v2", "cdn", "mail", "webmail", "m", "mobile",
        ]
        out_file = f"{self.dirs['recon']}/vhosts.txt"
        found = []

        rc_base, baseline, _ = run(
            ["curl", "-sk", "--max-time", "8",
             "-H", f"Host: nonexistent-{self.target}",
             f"https://{ip}"],
            timeout=12,
        )
        if rc_base != 0 or baseline is None:
            logger.debug("  Vhost baseline failed; skipping vhost discovery")
            return
        baseline_len = len(baseline)

        for prefix in vhost_prefixes:
            vhost = f"{prefix}.{self.target}"
            rc, body, _ = run(
                ["curl", "-sk", "--max-time", "5",
                 "-H", f"Host: {vhost}",
                 f"https://{ip}"],
                timeout=8,
            )
            if rc != 0 or not body:
                continue
            if abs(len(body) - baseline_len) > 100 and len(body) > 200:
                found.append(vhost)

        if found:
            write_lines(out_file, found)
            self.subdomains.extend(found)
            logger.info(f"  Vhosts found: {len(found)}")

    def _favicon_hash(self) -> None:
        """Download favicon and compute mmh3 hash for service fingerprinting."""
        hosts = self.live_hosts[:5] or [f"https://{self.target}"]
        out_file = f"{self.dirs['recon']}/favicon_hashes.txt"
        results = []

        import subprocess as _sp, base64
        for base in hosts:
            for path in ["/favicon.ico", "/assets/favicon.ico"]:
                try:
                    proc = _sp.run(
                        ["curl", "-sL", "--max-time", "10", "--output", "-", f"{base}{path}"],
                        capture_output=True, timeout=15,
                    )
                except Exception:
                    continue
                body = proc.stdout
                if not body or len(body) < 100:
                    continue
                try:
                    b64 = base64.encodebytes(body)
                    h = self._mmh3_hash(b64)
                    results.append(f"{base}: {h}")
                    for hr in self.host_records:
                        if base.endswith(hr.domain) or hr.domain in base:
                            hr.technologies.append(f"favicon:{h}")
                    break
                except Exception as exc:
                    logger.debug(f"  favicon hash failed for {base}: {exc}")

        if results:
            write_lines(out_file, results)
            logger.info(f"  Favicon hashes: {len(results)}")

    @staticmethod
    def _mmh3_hash(data: bytes) -> int:
        """Simple MurmurHash3 32-bit implementation for favicon hashing."""
        if isinstance(data, str):
            data = data.encode()
        length = len(data)
        c1, c2, seed = 0xcc9e2d51, 0x1b873593, 0
        h = seed
        rounded_end = (length & 0xfffffffc)
        for i in range(0, rounded_end, 4):
            k = (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24))
            k = (k * c1) & 0xffffffff
            k = ((k << 15) | (k >> 17)) & 0xffffffff
            k = (k * c2) & 0xffffffff
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xffffffff
            h = (h * 5 + 0xe6546b64) & 0xffffffff
        k = 0
        val = length & 0x03
        if val == 3:
            k = (data[rounded_end + 2] << 16)
        if val >= 2:
            k |= (data[rounded_end + 1] << 8)
        if val >= 1:
            k |= data[rounded_end]
            k = (k * c1) & 0xffffffff
            k = ((k << 15) | (k >> 17)) & 0xffffffff
            k = (k * c2) & 0xffffffff
            h ^= k
        h ^= length
        h ^= (h >> 16)
        h = (h * 0x85ebca6b) & 0xffffffff
        h ^= (h >> 13)
        h = (h * 0xc2b2ae35) & 0xffffffff
        h ^= (h >> 16)
        if h > 0x7fffffff:
            h -= 0x100000000
        return h

    def _google_dorks(self) -> None:
        """Generate Google dork queries for manual reconnaissance."""
        d = self.target
        dorks = [
            f'site:{d} filetype:pdf',
            f'site:{d} filetype:doc OR filetype:docx OR filetype:xls',
            f'site:{d} filetype:sql OR filetype:db OR filetype:bak',
            f'site:{d} filetype:log',
            f'site:{d} filetype:env',
            f'site:{d} filetype:xml',
            f'site:{d} filetype:conf OR filetype:cfg OR filetype:ini',
            f'site:{d} inurl:admin OR inurl:login OR inurl:dashboard',
            f'site:{d} inurl:api OR inurl:graphql OR inurl:swagger',
            f'site:{d} intitle:"index of"',
            f'site:{d} intext:"sql syntax" OR intext:"mysql_fetch"',
            f'site:{d} intext:"error" OR intext:"warning" OR intext:"fatal"',
            f'site:{d} ext:php intitle:phpinfo',
            f'site:{d} inurl:wp-content OR inurl:wp-includes',
            f'site:{d} inurl:".git" OR inurl:".env"',
            f'site:{d} "password" OR "passwd" OR "credentials"',
            f'site:{d} inurl:redirect OR inurl:return OR inurl:next',
            f'site:{d} inurl:upload OR inurl:file OR inurl:download',
            f'"{d}" site:pastebin.com OR site:ghostbin.com',
            f'"{d}" site:github.com OR site:gitlab.com',
            f'"{d}" intext:"api_key" OR intext:"apikey" OR intext:"secret"',
        ]
        self.google_dorks = dorks
        out_file = f"{self.dirs['recon']}/google_dorks.txt"
        write_lines(out_file, dorks)
        logger.info(f"  Google dorks: {len(dorks)} queries generated")

    def _deduplicate_subdomains(self) -> None:
        target = self.target.lower()
        suffix = f".{target}"
        unique = sorted({
            s.strip().lower()
            for s in self.subdomains
            if s.strip() and (s.strip().lower() == target or s.strip().lower().endswith(suffix))
        })
        self.subdomains = unique
        all_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        write_lines(all_file, unique)
        logger.info(f"Unique subdomains: {len(unique)}")

    # ─── HTTP PROBING ─────────────────────────────────────────────────────────

    def _httpx_probe(self) -> None:
        subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        # Bootstrap with main domain if nothing found
        if not Path(subs_file).exists() or not Path(subs_file).stat().st_size:
            write_lines(subs_file, [self.target])

        if not which("httpx"):
            logger.warning("httpx not found – basic HTTP check only")
            self._fallback_probe(subs_file)
            return

        out_txt  = f"{self.dirs['recon']}/live_hosts.txt"
        out_json = f"{self.dirs['recon']}/live_hosts.jsonl"

        # Collect live hosts with metadata
        run(
            [
                "httpx", "-l", subs_file,
                "-silent", "-title", "-tech-detect",
                "-status-code", "-content-length", "-server",
                "-follow-redirects", "-no-color",
                "-threads", str(self.threads),
                "-timeout", "10",
                "-retries", "2",
                "-o", out_txt,
            ],
            timeout=600,
        )
        run(
            [
                "httpx", "-l", subs_file,
                "-silent", "-title", "-tech-detect",
                "-status-code", "-content-length", "-server",
                "-follow-redirects", "-no-color",
                "-threads", str(self.threads),
                "-timeout", "10",
                "-retries", "2",
                "-json", "-o", out_json,
            ],
            timeout=600,
        )

        # Parse live URLs (first token of each line)
        for line in read_lines(out_txt):
            parts = line.split()
            if parts and parts[0].startswith("http"):
                self.live_hosts.append(parts[0])

        # Build HostRecord objects from JSON
        from .utils import parse_jsonl
        for row in parse_jsonl(out_json):
            url = row.get("url", "")
            if not url:
                continue
            domain = url.split("/")[2].split(":")[0]
            hr = HostRecord(
                domain=domain,
                ip=resolve_ip(domain),
                status=row.get("status-code", 0),
                title=row.get("title", ""),
                server=row.get("webserver", ""),
                technologies=row.get("tech", []),
                is_live=True,
            )
            self.host_records.append(hr)

        logger.info(f"Live hosts: {len(self.live_hosts)}")

    def _fallback_probe(self, subs_file: str) -> None:
        """Minimal curl-based probe when httpx is not installed."""
        for domain in read_lines(subs_file):
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "10", "--location", url],
                    timeout=15,
                )
                if rc == 0 and out:
                    self.live_hosts.append(url)
                    break

    # ─── PORT SCANNING ────────────────────────────────────────────────────────

    def _nmap(self) -> None:
        if not which("nmap"):
            logger.warning("nmap not found – skipping port scan")
            return

        out_txt  = f"{self.dirs['ports']}/nmap.txt"
        out_xml  = f"{self.dirs['ports']}/nmap.xml"
        out_grep = f"{self.dirs['ports']}/nmap.gnmap"

        run(
            [
                "nmap", "-sV", "-sC", "--top-ports", "1000",
                "-T4", "-oN", out_txt, "-oX", out_xml, "-oG", out_grep,
                self.target,
            ],
            timeout=600,
        )

        # Parse open ports from grep output
        for line in read_lines(out_grep):
            if "open" in line and not line.startswith("#"):
                self.ports_raw.append(line.strip())

        # Attach open-port list to every host record for the apex target
        for hr in self.host_records:
            if hr.domain == self.target:
                hr.open_ports = self.ports_raw

    def _masscan(self) -> None:
        if not which("masscan"):
            return
        out = f"{self.dirs['ports']}/masscan.txt"
        run(["masscan", self.target, "-p1-65535", "--rate=2000", "-oL", out],
            timeout=300)

    # ─── TECH / WAF ───────────────────────────────────────────────────────────

    def _whatweb(self) -> None:
        if not which("whatweb"):
            return
        out = f"{self.dirs['tech']}/whatweb.json"
        run(
            ["whatweb", "-a", "3", "--log-json", out,
             f"https://{self.target}", f"http://{self.target}"],
            timeout=120,
        )

    def _wafw00f(self) -> None:
        if not which("wafw00f"):
            return
        out = f"{self.dirs['recon']}/waf.txt"
        rc, stdout, _ = run(
            ["wafw00f", f"https://{self.target}"],
            output_file=out, timeout=60,
        )
        if stdout:
            self.waf = stdout[:500]

    # ─── ORCHESTRATOR ─────────────────────────────────────────────────────────

    def run(self) -> None:
        steps = [
            ("WHOIS",                  self._whois),
            ("DNS Records",            self._dns),
            ("DNS Zone Transfer",      self._dns_zone_transfer),
            ("Subfinder",              self._subfinder),
            ("Amass (passive)",        self._amass),
            ("Assetfinder",            self._assetfinder),
            ("Findomain",              self._findomain),
            ("Sublist3r",              self._sublist3r),
            ("crt.sh (CT logs)",       self._crtsh),
            ("Reverse IP lookup",      self._reverse_ip),
            # Virtual host discovery runs BEFORE dedup/httpx so new vhosts
            # end up in all_subdomains.txt and get probed by httpx.
            ("Virtual host discovery", self._vhost_discovery),
            ("Subdomain dedup",        self._deduplicate_subdomains),
            ("HTTP probe (httpx)",     self._httpx_probe),
            ("Favicon hash",           self._favicon_hash),
            ("Google dorks",           self._google_dorks),
            ("Port scan (nmap)",       self._nmap),
            ("Port scan (masscan)",    self._masscan),
            ("Tech detect (whatweb)",  self._whatweb),
            ("WAF detect (wafw00f)",   self._wafw00f),
            ("Extended recon",         self._extended_recon),
        ]
        for name, fn in steps:
            logger.info(f"  → {name}")
            try:
                fn()
            except Exception as exc:
                logger.error(f"    [!] {name}: {exc}")

    def _extended_recon(self) -> None:
        """Run extended-recon passes (ASN, Shodan InternetDB, SPF/DMARC, ...)."""
        from . import recon_extended
        out = recon_extended.extend_recon(
            target=self.target,
            dirs=self.dirs,
            live_hosts=self.live_hosts,
            host_records=self.host_records,
            subdomains=self.subdomains,
            threads=self.threads,
        )
        self.findings.extend(out.get("findings", []))
        new_subs = [s for s in out.get("extra_subdomains", []) if s not in self.subdomains]
        self.subdomains.extend(new_subs)
        self.asn_info = out.get("asn_info", {})
        self.shodan_info = out.get("shodan_info", {})
        self.geo_info = out.get("geo_info", {})
        self.http_versions = out.get("http_versions", {})
        if new_subs:
            all_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
            write_lines(all_file, sorted(set(self.subdomains)))
