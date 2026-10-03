"""
Vulnerability scanning: nuclei, nikto, SSL/TLS, directory brute-force,
CORS, security headers, subdomain takeover, open redirect, 403 bypass.
"""
import logging
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import which, run, read_lines, write_lines, parse_jsonl
from .models import Finding

logger = logging.getLogger("autoscan.vuln")

WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/opt/wordlists/common.txt",
]


def _first_wordlist() -> str | None:
    for p in WORDLISTS:
        if Path(p).exists():
            return p
    return None


class VulnScanner:
    """Phase 5 – Vulnerability scanning (accuracy over quantity)."""

    def __init__(self, target: str, dirs: dict, live_hosts: list, threads: int = 10):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads
        self.findings: list[Finding] = []

    def _targets_file(self) -> str:
        tf = f"{self.dirs['vuln']}/targets.txt"
        hosts = self.live_hosts or [f"https://{self.target}", f"http://{self.target}"]
        write_lines(tf, hosts)
        return tf

    # ─── Nuclei ───────────────────────────────────────────────────────────────

    def _nuclei(self) -> None:
        if not which("nuclei"):
            logger.warning("  nuclei not installed")
            return

        tf = self._targets_file()
        out_txt  = f"{self.dirs['nuclei']}/results.txt"
        out_json = f"{self.dirs['nuclei']}/results.jsonl"

        # Update templates
        run(["nuclei", "-update-templates", "-silent"], timeout=120)

        run(
            [
                "nuclei",
                "-l", tf,
                "-severity", "critical,high,medium,low,info",
                # Broad template categories
                "-tags", "cve,exposure,misconfig,sqli,xss,lfi,rce,ssrf,idor,redirect,takeover",
                "-o", out_txt,
                "-jsonl",
                "-output", out_json,
                "-silent",
                "-c", str(self.threads),
                "-timeout", "10",
                "-retries", "2",
                "-no-color",
            ],
            timeout=7200,  # generous timeout for large target sets
        )

        for row in parse_jsonl(out_json):
            info = row.get("info", {})
            sev = info.get("severity", "info").lower()
            self.findings.append(Finding(
                severity=sev,
                title=info.get("name", row.get("template-id", "?")),
                host=row.get("host", ""),
                detail=info.get("description", ""),
                source="nuclei",
                tags=(info.get("tags") or "").split(","),
                url=row.get("matched-at", row.get("host", "")),
                evidence=str(row.get("extracted-results", row.get("curl-command", ""))),
            ))

        logger.info(f"  Nuclei: {sum(1 for r in parse_jsonl(out_json))} findings")

    # ─── Nikto ────────────────────────────────────────────────────────────────

    def _nikto(self) -> None:
        if not which("nikto"):
            logger.warning("  nikto not installed")
            return

        targets = self.live_hosts[:5] or [f"https://{self.target}"]
        for i, host in enumerate(targets):
            out_txt  = f"{self.dirs['nikto']}/nikto_{i}.txt"
            out_json = f"{self.dirs['nikto']}/nikto_{i}.json"
            run(["nikto", "-h", host, "-o", out_txt,
                 "-Format", "txt", "-maxtime", "5m"], timeout=360)
            run(["nikto", "-h", host, "-o", out_json,
                 "-Format", "json", "-maxtime", "5m"], timeout=360)

        # Parse JSON outputs
        for p in Path(self.dirs["nikto"]).glob("*.json"):
            try:
                data = json.loads(p.read_text(errors="replace"))
                vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                for v in (vulns or []):
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"Nikto: {v.get('id', '?')}",
                        host=v.get("host", self.target),
                        detail=v.get("msg", v.get("description", str(v))),
                        source="nikto",
                        url=v.get("url", ""),
                    ))
            except Exception:
                pass

    # ─── SSL / TLS ─────────────────────────────────────────────────────────────

    def _ssl(self) -> None:
        out_dir = self.dirs["ssl"]

        if which("testssl.sh") or which("testssl"):
            binary = "testssl.sh" if which("testssl.sh") else "testssl"
            run(
                [binary,
                 "--jsonfile", f"{out_dir}/testssl.json",
                 "--logfile",  f"{out_dir}/testssl.log",
                 "--severity", "LOW",
                 "--color", "0",
                 f"{self.target}:443"],
                timeout=300,
            )
            # Parse findings
            p = Path(f"{out_dir}/testssl.json")
            if p.exists():
                try:
                    data = json.loads(p.read_text(errors="replace"))
                    for entry in data.get("findings", []):
                        sev_map = {"CRITICAL": "critical", "HIGH": "high",
                                   "MEDIUM": "medium", "LOW": "low",
                                   "INFO": "info", "OK": "info", "NOT ok": "medium"}
                        raw_sev = entry.get("severity", "INFO")
                        sev = sev_map.get(raw_sev.upper(), "info")
                        if sev in ("medium", "high", "critical"):
                            self.findings.append(Finding(
                                severity=sev,
                                title=f"SSL/TLS: {entry.get('id', '?')}",
                                host=self.target,
                                detail=entry.get("finding", ""),
                                source="testssl",
                            ))
                except Exception:
                    pass

        elif which("sslscan"):
            run(["sslscan", "--xml", f"{out_dir}/sslscan.xml", self.target],
                output_file=f"{out_dir}/sslscan.txt", timeout=120)

        elif which("openssl"):
            rc, out, err = run(
                ["openssl", "s_client", "-connect", f"{self.target}:443",
                 "-servername", self.target],
                stdin_data="", timeout=15,
            )
            Path(f"{out_dir}/openssl.txt").write_text(out + err)

    # ─── Directory brute-force ─────────────────────────────────────────────────

    def _dirbrute(self) -> None:
        wordlist = _first_wordlist()
        if not wordlist:
            logger.debug("  No wordlist – skipping dir brute")
            return

        targets = self.live_hosts[:3] or [f"https://{self.target}"]

        for i, host in enumerate(targets):
            out_file = f"{self.dirs['dirs']}/gobuster_{i}.txt"
            if which("gobuster"):
                run(
                    ["gobuster", "dir", "-u", host, "-w", wordlist,
                     "-o", out_file, "-t", str(self.threads),
                     "-q", "--no-error", "-b", "404,429"],
                    timeout=600,
                )
            elif which("ffuf"):
                run(
                    ["ffuf", "-w", f"{wordlist}:FUZZ",
                     "-u", f"{host}/FUZZ",
                     "-of", "json",
                     "-o", f"{self.dirs['dirs']}/ffuf_{i}.json",
                     "-t", str(self.threads), "-s",
                     "-fc", "404,429",
                     "-mc", "all"],
                    timeout=600,
                )
            elif which("feroxbuster"):
                run(
                    ["feroxbuster", "-u", host, "-w", wordlist,
                     "-o", out_file, "-t", str(self.threads),
                     "-q", "--no-state", "--filter-status", "404,429"],
                    timeout=600,
                )

    # ─── Security headers ──────────────────────────────────────────────────────

    def _headers(self) -> None:
        REQUIRED = {
            "strict-transport-security": ("high",   "HSTS not set – downgrade attack possible"),
            "content-security-policy":   ("medium",  "CSP missing – XSS risk increased"),
            "x-frame-options":           ("medium",  "Clickjacking protection missing"),
            "x-content-type-options":    ("low",     "MIME sniffing protection missing"),
            "referrer-policy":           ("info",    "Referrer-Policy not set"),
            "permissions-policy":        ("info",    "Permissions-Policy not set"),
        }
        targets = self.live_hosts[:5] or [f"https://{self.target}"]
        for host in targets:
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "10", "--location", host],
                timeout=15,
            )
            if rc != 0 or not out:
                continue
            out_lower = out.lower()
            # Check HTTPS redirection
            if host.startswith("http://"):
                if "location: https://" in out_lower:
                    pass  # good
                else:
                    self.findings.append(Finding(
                        severity="medium",
                        title="No HTTPS Redirect",
                        host=host,
                        detail="HTTP site does not redirect to HTTPS.",
                        source="headers",
                        url=host,
                    ))
            for header, (sev, msg) in REQUIRED.items():
                if header not in out_lower:
                    self.findings.append(Finding(
                        severity=sev,
                        title=f"Missing Header: {header}",
                        host=host,
                        detail=msg,
                        source="headers",
                        url=host,
                    ))
            # Server version disclosure
            for line in out.splitlines():
                if line.lower().startswith("server:"):
                    val = line.split(":", 1)[1].strip()
                    if re.search(r"\d+\.\d+", val):  # has version number
                        self.findings.append(Finding(
                            severity="low",
                            title="Server Version Disclosure",
                            host=host,
                            detail=f"Server header reveals version: {val}",
                            source="headers",
                            url=host,
                            evidence=val,
                        ))

    # ─── CORS ──────────────────────────────────────────────────────────────────

    def _cors(self) -> None:
        targets = self.live_hosts[:10] or [f"https://{self.target}"]
        for host in targets:
            rc, out, _ = run(
                ["curl", "-sI", "--max-time", "10",
                 "-H", "Origin: https://evil-attacker.com", host],
                timeout=15,
            )
            if rc != 0 or not out:
                continue
            out_lower = out.lower()
            if "access-control-allow-origin: https://evil-attacker.com" in out_lower:
                cred = "access-control-allow-credentials: true" in out_lower
                sev = "critical" if cred else "high"
                self.findings.append(Finding(
                    severity=sev,
                    title="CORS Misconfiguration – Reflects Arbitrary Origin",
                    host=host,
                    detail=(
                        "Server reflects attacker-controlled Origin in ACAO header"
                        + (" WITH credentials allowed – full account takeover possible." if cred
                           else " – sensitive data exposure possible.")
                    ),
                    source="cors",
                    url=host,
                ))
            elif "access-control-allow-origin: *" in out_lower:
                if "access-control-allow-credentials: true" in out_lower:
                    self.findings.append(Finding(
                        severity="high",
                        title="CORS Wildcard + Credentials (invalid but present)",
                        host=host,
                        detail="Wildcard ACAO with credentials is invalid per spec but may be exploitable in some browsers.",
                        source="cors",
                        url=host,
                    ))

    # ─── Subdomain takeover ────────────────────────────────────────────────────

    def _takeover(self) -> None:
        """Check for NXDOMAIN subdomains pointing to 3rd party services."""
        if not which("subjack") and not which("nuclei"):
            return
        if which("subjack"):
            subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt" \
                if Path(f"{self.dirs['subdomains']}/all_subdomains.txt").exists() \
                else None
            if subs_file:
                out = f"{self.dirs['vuln']}/takeover.txt"
                run(
                    ["subjack", "-w", subs_file, "-t", str(self.threads),
                     "-o", out, "-ssl"],
                    timeout=300,
                )
                for line in read_lines(out):
                    if "vulnerable" in line.lower() or "takeover" in line.lower():
                        self.findings.append(Finding(
                            severity="high",
                            title="Potential Subdomain Takeover",
                            host=line,
                            detail=f"Subdomain may be vulnerable to takeover: {line}",
                            source="subjack",
                        ))

    # ─── 403 Bypass ──────────────────────────────────────────────────────────

    def _bypass_403(self) -> None:
        """Try common 403 bypass techniques on forbidden paths."""
        targets = self.live_hosts[:3] or [f"https://{self.target}"]
        bypass_headers = [
            ["-H", "X-Original-URL: /"],
            ["-H", "X-Rewrite-URL: /"],
            ["-H", "X-Forwarded-For: 127.0.0.1"],
            ["-H", "X-Custom-IP-Authorization: 127.0.0.1"],
            ["-H", "X-Forwarded-Host: localhost"],
        ]

        for host in targets:
            # Check if base path is 403
            rc, out, _ = run(["curl", "-sI", "--max-time", "8", host], timeout=12)
            if not out or "403" not in out.splitlines()[0] if out.splitlines() else True:
                continue

            for extra in bypass_headers:
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8"] + extra + [host],
                    timeout=12,
                )
                first = out.splitlines()[0] if out and out.splitlines() else ""
                if "200" in first or "301" in first or "302" in first:
                    hdr = extra[1] if len(extra) > 1 else ""
                    self.findings.append(Finding(
                        severity="medium",
                        title=f"403 Bypass Possible via Header: {hdr.split(':')[0]}",
                        host=host,
                        detail=f"Adding header {hdr} bypasses 403 restriction on {host}",
                        source="403_bypass",
                        url=host,
                        evidence=hdr,
                    ))
                    break  # one finding per host is enough

    # ─── Open redirect ────────────────────────────────────────────────────────

    def _open_redirect(self) -> None:
        """Test common open redirect parameters."""
        REDIRECT_PARAMS = [
            "url", "redirect", "next", "return", "returnUrl", "goto",
            "dest", "destination", "redir", "redirect_uri", "callback",
            "continue", "target", "link", "to",
        ]
        CANARY = "https://evil-attacker.com"

        targets = self.live_hosts[:5] or [f"https://{self.target}"]

        for host in targets:
            for param in REDIRECT_PARAMS:
                test_url = f"{host}?{param}={CANARY}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "8", "--max-redirs", "0", test_url],
                    timeout=12,
                )
                if rc == 0 and out:
                    for line in out.splitlines():
                        if line.lower().startswith("location:") and "evil-attacker.com" in line.lower():
                            self.findings.append(Finding(
                                severity="medium",
                                title=f"Open Redirect via ?{param}=",
                                host=host,
                                detail=f"Parameter '{param}' redirects to arbitrary URL without validation.",
                                source="open_redirect",
                                url=test_url,
                                evidence=line.strip(),
                            ))
                            break

    # ─── Orchestrator ─────────────────────────────────────────────────────────

    def run(self) -> list:
        steps = [
            ("Security Headers",       self._headers),
            ("CORS",                   self._cors),
            ("SSL/TLS",                self._ssl),
            ("Nuclei",                 self._nuclei),
            ("Nikto",                  self._nikto),
            ("Directory Brute-force",  self._dirbrute),
            ("Subdomain Takeover",     self._takeover),
            ("403 Bypass",             self._bypass_403),
            ("Open Redirect",          self._open_redirect),
        ]
        for name, fn in steps:
            logger.info(f"  → {name}")
            try:
                fn()
            except Exception as exc:
                logger.error(f"    [!] {name}: {exc}")

        # Deduplicate findings by (title + host)
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.title, f.host)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        logger.info(f"  Vuln scan complete | {len(self.findings)} findings")
        return self.findings
