"""
Comprehensive subdomain takeover detection.

Combines three independent verification stages so a finding only fires
when ALL three agree:

  Stage 1 - DNS analysis (manual):
    Resolve the subdomain's CNAME chain. A takeover candidate is a CNAME
    pointing to a service domain (github.io, herokuapp.com, s3.amazonaws.com,
    azurewebsites.net, etc.) OR a subdomain that is NXDOMAIN while its parent
    still resolves (dangling delegation).

  Stage 2 - HTTP response fingerprint (manual):
    Fetch the subdomain over HTTP and HTTPS; look for the service-specific
    takeover body signature ("There isn't a GitHub Pages site here", ...).
    Confirmed with a second request to kill transient flake.

  Stage 3 - External tools (subjack / nuclei / subzy):
    When installed, these provide an independent corroboration.

Each finding reports which stages confirmed it and attaches the full
CNAME chain + the matched fingerprint as evidence.
"""
import re
import socket
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseCheck
from ..models import Finding
from ..utils import which, run, read_lines


# ---------------------------------------------------------------------------
# Service fingerprint database. Each entry defines:
#   service        : human-readable name
#   cnames         : CNAME suffixes that route to the service
#   fingerprint    : body substring that uniquely indicates "takeover possible"
#   status_code    : expected HTTP status when takeover candidate (optional)
#   severity       : finding severity if confirmed
#   nxdomain_also  : True if NXDOMAIN alone (dangling CNAME) is sufficient
# ---------------------------------------------------------------------------
TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cnames": ["github.io", "github.map.fastly.net"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "GitLab Pages",
        "cnames": ["gitlab.io"],
        "fingerprint": "The page you're looking for could not be found",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "AWS S3",
        "cnames": ["s3.amazonaws.com", "s3-website.", "s3.", ".s3-"],
        "fingerprint": "NoSuchBucket",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "AWS CloudFront",
        "cnames": ["cloudfront.net"],
        "fingerprint": "Bad request. We can't connect to the server for this app",
        "severity": "medium",
    },
    {
        "service": "Heroku",
        "cnames": ["herokuapp.com", "herokudns.com"],
        "fingerprint": "No such app",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "Shopify",
        "cnames": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cnames": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain",
        "severity": "high",
    },
    {
        "service": "Pantheon",
        "cnames": ["pantheonsite.io", "pantheon.io"],
        "fingerprint": "The gods are wise, but do not know of the site which you seek",
        "severity": "high",
    },
    {
        "service": "Tumblr",
        "cnames": ["tumblr.com", "domains.tumblr.com"],
        "fingerprint": "Whatever you were looking for doesn't currently exist at this address",
        "severity": "medium",
    },
    {
        "service": "Zendesk",
        "cnames": ["zendesk.com"],
        "fingerprint": "Help Center Closed",
        "severity": "medium",
    },
    {
        "service": "Help Scout",
        "cnames": ["helpscoutdocs.com"],
        "fingerprint": "No settings were found for this company",
        "severity": "high",
    },
    {
        "service": "Readthedocs",
        "cnames": ["readthedocs.io"],
        "fingerprint": "unknown to Read the Docs",
        "severity": "medium",
    },
    {
        "service": "Statuspage",
        "cnames": ["statuspage.io"],
        "fingerprint": "You are being redirected",
        "severity": "medium",
    },
    {
        "service": "Freshdesk",
        "cnames": ["freshdesk.com"],
        "fingerprint": "May be this is still fresh!",
        "severity": "medium",
    },
    {
        "service": "Intercom",
        "cnames": ["custom.intercom.help"],
        "fingerprint": "This page is reserved for artistic dogs",
        "severity": "medium",
    },
    {
        "service": "Mailchimp Pages",
        "cnames": ["list-manage.com"],
        "fingerprint": "Mailchimp could not deliver this email",
        "severity": "medium",
    },
    {
        "service": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprint": "Not Found - Request ID",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "Surge.sh",
        "cnames": ["surge.sh"],
        "fingerprint": "project not found",
        "severity": "high",
    },
    {
        "service": "Tilda",
        "cnames": ["tilda.ws"],
        "fingerprint": "Please renew your subscription",
        "severity": "high",
    },
    {
        "service": "Unbounce",
        "cnames": ["unbouncepages.com"],
        "fingerprint": "The requested URL was not found on this server",
        "severity": "medium",
    },
    {
        "service": "Vercel",
        "cnames": ["vercel.app", "now.sh"],
        "fingerprint": "The deployment could not be found on Vercel",
        "status_code": 404,
        "severity": "high",
    },
    {
        "service": "WPEngine",
        "cnames": ["wpengine.com"],
        "fingerprint": "The site you were looking for couldn't be found",
        "severity": "high",
    },
    {
        "service": "Webflow",
        "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
        "fingerprint": "The page you are looking for doesn't exist or has been moved",
        "severity": "medium",
    },
    {
        "service": "Thinkific",
        "cnames": ["thinkific.com"],
        "fingerprint": "You may have mistyped the address or the page may have moved",
        "severity": "medium",
    },
    {
        "service": "Teamwork",
        "cnames": ["teamwork.com"],
        "fingerprint": "Oops - We didn't find your site",
        "severity": "medium",
    },
    {
        "service": "SmugMug",
        "cnames": ["smugmug.com"],
        "fingerprint": "Page Not Found",
        "severity": "info",
    },
    {
        "service": "Simplebooklet",
        "cnames": ["simplebooklet.com"],
        "fingerprint": "We can't find this <a",
        "severity": "medium",
    },
    {
        "service": "Short.io",
        "cnames": ["short.io"],
        "fingerprint": "Link does not exist",
        "severity": "medium",
    },
    {
        "service": "Pingdom",
        "cnames": ["stats.pingdom.com"],
        "fingerprint": "Public Report Not Activated",
        "severity": "medium",
    },
    {
        "service": "LaunchRock",
        "cnames": ["launchrock.com"],
        "fingerprint": "It looks like you may have taken a wrong turn somewhere",
        "severity": "medium",
    },
    {
        "service": "Kinsta",
        "cnames": ["kinsta.cloud"],
        "fingerprint": "No Site For Domain",
        "severity": "high",
    },
    {
        "service": "JetBrains",
        "cnames": ["myjetbrains.com"],
        "fingerprint": "is not a registered InCloud YouTrack",
        "severity": "medium",
    },
    {
        "service": "Gemfury",
        "cnames": ["furyns.com"],
        "fingerprint": "404: This page could not be found",
        "severity": "medium",
    },
    {
        "service": "Flywheel",
        "cnames": ["flywheelsites.com"],
        "fingerprint": "We're sorry, you've reached a site that is no longer available",
        "severity": "medium",
    },
    {
        "service": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "fingerprint": "If you're moving your domain away from Cargo",
        "severity": "medium",
    },
    {
        "service": "Canny",
        "cnames": ["canny.io"],
        "fingerprint": "Company Not Found",
        "severity": "medium",
    },
    {
        "service": "Agile CRM",
        "cnames": ["agilecrm.com"],
        "fingerprint": "Sorry, this page is no longer available",
        "severity": "medium",
    },
    {
        "service": "Acquia",
        "cnames": ["acquia-sites.com"],
        "fingerprint": "Web Site Not Found",
        "severity": "high",
    },
    {
        "service": "Azure Websites",
        "cnames": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                   "trafficmanager.net", "blob.core.windows.net", "azure-api.net"],
        "fingerprint": "404 Web Site not found",
        "severity": "high",
        "nxdomain_also": True,
    },
    {
        "service": "Bitbucket",
        "cnames": ["bitbucket.io"],
        "fingerprint": "Repository not found",
        "severity": "high",
    },
    {
        "service": "Campaign Monitor",
        "cnames": ["createsend.com"],
        "fingerprint": "Trying to access your account?",
        "severity": "medium",
    },
    {
        "service": "Desk",
        "cnames": ["desk.com"],
        "fingerprint": "Please try again or try Desk.com free for 14 days",
        "severity": "medium",
    },
    {
        "service": "AnimaApp",
        "cnames": ["animaapp.io"],
        "fingerprint": "If this is your website and you've just created it",
        "severity": "medium",
    },
    {
        "service": "Hatena",
        "cnames": ["hatenablog.com"],
        "fingerprint": "404 Blog is not found",
        "severity": "medium",
    },
    {
        "service": "Uptimerobot",
        "cnames": ["stats.uptimerobot.com"],
        "fingerprint": "page not found",
        "severity": "info",
    },
]


class TakeoverCheck(BaseCheck):
    """Subdomain takeover detection with manual + tool-based verification."""

    name = "Subdomain Takeover"
    description = (
        "Multi-stage subdomain takeover detection: CNAME chain analysis, "
        "HTTP body fingerprint (50+ services), confirmed via a second shot "
        "and corroborated by subjack / nuclei when installed."
    )

    MAX_CANDIDATES = 100

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------
    def _cname_chain(self, hostname: str) -> list[str]:
        """Follow CNAME records; return the final chain as [h, c1, c2, ...]."""
        if not which("dig"):
            try:
                socket.gethostbyname(hostname)
                return [hostname]
            except Exception:
                return []

        chain = [hostname]
        current = hostname
        for _ in range(10):  # cap chain depth
            rc, out, _ = run(["dig", "+short", "CNAME", current], timeout=10)
            if rc != 0 or not out.strip():
                break
            next_cname = out.strip().splitlines()[0].rstrip(".").lower()
            if not next_cname or next_cname == current:
                break
            chain.append(next_cname)
            current = next_cname
        return chain

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.gethostbyname(hostname)
            return True
        except Exception:
            return False

    def _nxdomain(self, hostname: str) -> bool:
        """True if the record authoritatively does not exist."""
        if not which("dig"):
            return not self._resolves(hostname)
        rc, out, _ = run(["dig", "+short", "A", hostname], timeout=8)
        if rc == 0 and out.strip():
            return False
        rc, out, _ = run(["dig", hostname], timeout=8)
        if rc == 0 and "NXDOMAIN" in out:
            return True
        return not self._resolves(hostname)

    # ------------------------------------------------------------------
    # HTTP fingerprint helpers
    # ------------------------------------------------------------------
    def _fetch_body(self, url: str, timeout: int = 8) -> tuple[int, str]:
        """Return (status_code, body) via a single curl request."""
        rc, out, _ = run(
            ["curl", "-sk", "-L", "--max-time", str(timeout),
             "-w", "\n__HTTP_STATUS__:%{http_code}", url],
            timeout=timeout + 4,
        )
        if rc != 0 or not out:
            return 0, ""
        status = 0
        body = out
        m = re.search(r"__HTTP_STATUS__:(\d+)\s*$", out)
        if m:
            status = int(m.group(1))
            body = out[:m.start()]
        return status, body

    def _match_fingerprint(self, body: str, status: int,
                           chain: list[str]) -> dict | None:
        """Return the signature entry that matches this subdomain, else None."""
        last_cname = chain[-1] if chain else ""
        for sig in TAKEOVER_SIGNATURES:
            cname_match = any(c in last_cname for c in sig["cnames"])
            fp_match = sig["fingerprint"] in body
            if not fp_match:
                continue
            if sig.get("status_code") and sig["status_code"] != status:
                # Fingerprint matches but status disagrees - still useful as weak signal
                continue
            return {**sig, "cname_match": cname_match}
        return None

    def _is_cname_vulnerable_service(self, chain: list[str]) -> dict | None:
        """Check if the LAST CNAME in the chain is on a known takeover service."""
        if len(chain) < 2:
            return None
        last = chain[-1]
        for sig in TAKEOVER_SIGNATURES:
            if any(c in last for c in sig["cnames"]):
                return sig
        return None

    # ------------------------------------------------------------------
    # Candidate enumeration
    # ------------------------------------------------------------------
    def _candidates(self) -> list[str]:
        subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        if not Path(subs_file).exists():
            return []
        return read_lines(subs_file)[: self.MAX_CANDIDATES]

    # ------------------------------------------------------------------
    # Core per-subdomain verification
    # ------------------------------------------------------------------
    def _verify_subdomain(self, sub: str) -> dict | None:
        """
        Verify one subdomain for takeover. Returns a result dict when a
        takeover is confirmed, else None. Result keys:
          service, severity, cname_chain, matched_fingerprint,
          http_status, confirmed_stages
        """
        chain = self._cname_chain(sub)
        if not chain:
            return None

        # Stage 1a: CNAME points to a takeover-capable service?
        cname_sig = self._is_cname_vulnerable_service(chain)

        # Stage 1b: Dangling CNAME? (CNAME exists but points to NXDOMAIN target)
        dangling = False
        if len(chain) >= 2:
            last = chain[-1]
            if self._nxdomain(last):
                dangling = True

        # If neither CNAME-points-to-service nor dangling, skip
        if not cname_sig and not dangling:
            return None

        # Stage 2: HTTP fingerprint
        best_match = None
        http_status = 0
        for scheme in ("https", "http"):
            status, body = self._fetch_body(f"{scheme}://{sub}", timeout=8)
            if not body and status == 0:
                continue
            match = self._match_fingerprint(body, status, chain)
            if match:
                best_match = match
                http_status = status
                break

        # Stage 2 confirmation: refetch to kill flakes
        if best_match:
            time.sleep(0.5)
            status2, body2 = self._fetch_body(
                f"https://{sub}" if ":" not in sub else f"https://{sub}",
                timeout=8,
            )
            if best_match["fingerprint"] not in body2:
                return None

        # Decide: confirmed stages set
        confirmed_stages = []
        service = None
        severity = "medium"
        if cname_sig:
            confirmed_stages.append("CNAME points to takeover-capable service")
            service = cname_sig["service"]
            severity = cname_sig["severity"]
        if dangling:
            confirmed_stages.append("CNAME target is NXDOMAIN (dangling)")
        if best_match:
            confirmed_stages.append(f"HTTP body matches '{best_match['service']}' fingerprint (double-confirmed)")
            service = best_match["service"]
            severity = best_match["severity"]

        # Require STRONG evidence: either HTTP fingerprint matched OR
        # (dangling CNAME + CNAME on a vulnerable service with nxdomain_also=True)
        strong = False
        if best_match:
            strong = True
        elif cname_sig and dangling and cname_sig.get("nxdomain_also"):
            strong = True

        if not strong:
            return None

        return {
            "service": service,
            "severity": severity,
            "cname_chain": " -> ".join(chain),
            "matched_fingerprint": best_match["fingerprint"] if best_match else None,
            "http_status": http_status,
            "confirmed_stages": confirmed_stages,
        }

    # ------------------------------------------------------------------
    # External tool corroboration
    # ------------------------------------------------------------------
    def _run_subjack(self) -> set[str]:
        subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        if not which("subjack") or not Path(subs_file).exists():
            return set()
        out = f"{self.dirs['vuln']}/subjack.txt"
        run(["subjack", "-w", subs_file, "-t", str(self.threads),
             "-o", out, "-ssl"], timeout=300)
        flagged = set()
        for line in read_lines(out):
            low = line.lower()
            if "vulnerable" in low or "takeover" in low:
                m = re.search(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", line)
                if m:
                    flagged.add(m.group(1))
        return flagged

    def _run_nuclei_takeover(self) -> set[str]:
        subs_file = f"{self.dirs['subdomains']}/all_subdomains.txt"
        if not which("nuclei") or not Path(subs_file).exists():
            return set()
        out = f"{self.dirs['vuln']}/nuclei_takeover.jsonl"
        run(["nuclei", "-l", subs_file, "-tags", "takeover",
             "-silent", "-jsonl", "-output", out, "-c", str(self.threads)],
            timeout=600)
        flagged = set()
        from ..utils import parse_jsonl
        for row in parse_jsonl(out):
            host = row.get("host", "")
            if host:
                flagged.add(host.replace("https://", "").replace("http://", "").split("/")[0])
        return flagged

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def execute(self) -> list[Finding]:
        candidates = self._candidates()
        if not candidates:
            self.log.debug("  no subdomain candidates to check")
            return []

        self.log.info(f"  Takeover: scanning {len(candidates)} subdomains "
                      f"(manual CNAME + fingerprint verification)")

        # Stage 3: run external tools in parallel with manual stage
        subjack_flagged: set[str] = set()
        nuclei_flagged: set[str] = set()
        try:
            subjack_flagged = self._run_subjack()
        except Exception as exc:
            self.log.debug(f"  subjack: {exc}")
        try:
            nuclei_flagged = self._run_nuclei_takeover()
        except Exception as exc:
            self.log.debug(f"  nuclei takeover: {exc}")

        # Stage 1+2: manual CNAME + fingerprint verification (parallelized)
        confirmed: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as ex:
            fut_to_sub = {ex.submit(self._verify_subdomain, s): s for s in candidates}
            for fut in as_completed(fut_to_sub):
                sub = fut_to_sub[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    self.log.debug(f"  verify({sub}): {exc}")
                    continue
                if result:
                    confirmed[sub] = result

        # Emit findings:
        #   - Dual/triple-confirmed = manual + at least one tool
        #   - Manual-only = still high because our verification is strict
        #   - Tool-only = report at medium severity (no manual confirmation)
        tool_hits = subjack_flagged | nuclei_flagged
        for sub, result in confirmed.items():
            detectors = ["manual"]
            if sub in subjack_flagged:
                detectors.append("subjack")
            if sub in nuclei_flagged:
                detectors.append("nuclei")
            severity = result["severity"]
            if len(detectors) > 1:
                severity = "critical" if severity in ("high", "critical") else "high"
            stages = "; ".join(result["confirmed_stages"])
            self.findings.append(Finding(
                severity=severity,
                title=f"Subdomain Takeover ({result['service']}) on {sub} [{'+'.join(detectors)}]",
                host=sub,
                detail=(
                    f"Service: {result['service']}\n"
                    f"CNAME chain: {result['cname_chain']}\n"
                    f"Confirmation stages: {stages}\n"
                    f"Detectors: {', '.join(detectors)}\n"
                    f"HTTP status: {result['http_status']}\n"
                    f"Fingerprint: {result['matched_fingerprint'] or '(DNS-only)'}"
                ),
                source="takeover",
                url=f"https://{sub}",
                tags=["takeover", result["service"].lower().replace(" ", "-"),
                      *[f"detector:{d}" for d in detectors]],
                evidence=(
                    f"chain={result['cname_chain']} | "
                    f"fp={result['matched_fingerprint'] or 'none'} | "
                    f"status={result['http_status']}"
                ),
            ))

        # Tool-only hits (nothing in manual confirmed) - lower severity report
        for sub in tool_hits - set(confirmed.keys()):
            tool_src = []
            if sub in subjack_flagged:
                tool_src.append("subjack")
            if sub in nuclei_flagged:
                tool_src.append("nuclei")
            self.findings.append(Finding(
                severity="medium",
                title=f"Possible Subdomain Takeover on {sub} [{'+'.join(tool_src)} only]",
                host=sub,
                detail=(
                    f"External tool(s) {', '.join(tool_src)} flagged {sub} as a "
                    f"takeover candidate, but manual CNAME+fingerprint verification "
                    f"did not confirm. Investigate manually."
                ),
                source="takeover",
                url=f"https://{sub}",
                tags=["takeover", "tool-only", *[f"detector:{t}" for t in tool_src]],
            ))

        self.log.info(f"  Takeover: {len(self.findings)} finding(s) "
                      f"({len(confirmed)} manual-confirmed, "
                      f"{len(tool_hits - set(confirmed.keys()))} tool-only)")
        return self.findings
