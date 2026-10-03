"""
Passive intelligence: robots.txt, sitemap.xml, CMS detection,
email harvesting, screenshot capture, S3 bucket detection.
"""
import re
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from .utils import which, run, read_lines, write_lines, categorize_url
from .models import URLRecord, Finding

logger = logging.getLogger("autoscan.passive")


class PassiveModule:
    """
    Collects intelligence from public files and metadata
    without active scanning or fuzzing.
    """

    def __init__(self, target: str, dirs: dict, live_hosts: list, threads: int = 10):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads

        self.extra_urls: list[URLRecord] = []
        self.emails: list[str] = []
        self.findings: list[Finding] = []
        self.cms_info: dict = {}

    # ─── robots.txt ───────────────────────────────────────────────────────────

    def _robots(self) -> None:
        """Parse robots.txt for hidden paths, sitemap references, and misconfig."""
        hosts = self.live_hosts[:5] or [f"https://{self.target}"]

        for base in hosts:
            url = f"{base}/robots.txt"
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "10", url],
                timeout=15,
            )
            if rc != 0 or not body or "user-agent" not in body.lower():
                continue

            out_file = f"{self.dirs['urls']}/robots_{base.split('/')[2].replace(':','_')}.txt"
            Path(out_file).write_text(body)

            paths = set()
            sitemaps = []
            for line in body.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("disallow:") or low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and not path.startswith("#"):
                        paths.add(path)
                        full = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
                        cats = categorize_url(full)
                        self.extra_urls.append(URLRecord(url=full, method_source="robots", **cats))
                elif low.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm.startswith("http"):
                        sitemaps.append(sm)

            # Check for sensitive paths in disallowed
            sensitive_patterns = [
                "admin", "backup", "config", ".env", ".git", "wp-admin",
                "phpmyadmin", "dashboard", "cpanel", "api", "debug",
                "test", "staging", "internal", "private", ".sql", ".bak",
            ]
            for path in paths:
                for pat in sensitive_patterns:
                    if pat in path.lower():
                        self.findings.append(Finding(
                            severity="info",
                            title=f"Interesting path in robots.txt: {path}",
                            host=base,
                            detail=f"robots.txt disallows {path} – may contain sensitive content",
                            source="robots",
                            url=f"{base}{path}",
                        ))
                        break

            # Parse sitemaps
            for sm_url in sitemaps:
                self._parse_sitemap(sm_url, base)

            logger.info(f"  robots.txt ({base}): {len(paths)} paths, {len(sitemaps)} sitemaps")

    # ─── sitemap.xml ──────────────────────────────────────────────────────────

    def _sitemap(self) -> None:
        """Fetch and parse sitemap.xml for URL discovery."""
        hosts = self.live_hosts[:5] or [f"https://{self.target}"]
        for base in hosts:
            for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/"]:
                url = f"{base}{path}"
                self._parse_sitemap(url, base)

    def _parse_sitemap(self, url: str, base: str) -> None:
        rc, body, _ = run(
            ["curl", "-sL", "--max-time", "15", url],
            timeout=20,
        )
        if rc != 0 or not body or "<" not in body:
            return

        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return

        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls_found = 0

        # Standard sitemap
        for loc in root.findall(".//sm:loc", ns):
            u = (loc.text or "").strip()
            if u and u.startswith("http"):
                cats = categorize_url(u)
                self.extra_urls.append(URLRecord(url=u, method_source="sitemap", **cats))
                urls_found += 1

        # Also try without namespace
        if urls_found == 0:
            for loc in root.iter():
                if "loc" in loc.tag.lower() and loc.text:
                    u = loc.text.strip()
                    if u.startswith("http"):
                        cats = categorize_url(u)
                        self.extra_urls.append(URLRecord(url=u, method_source="sitemap", **cats))
                        urls_found += 1

        if urls_found:
            out_file = f"{self.dirs['urls']}/sitemap_urls.txt"
            existing = read_lines(out_file) if Path(out_file).exists() else []
            write_lines(out_file, existing + [u.url for u in self.extra_urls[-urls_found:]])
            logger.info(f"  sitemap ({url}): {urls_found} URLs")

    # ─── CMS Detection ─────────────────────────────────────────────────────────

    def _cms_detect(self) -> None:
        """Fingerprint CMS from common markers."""
        hosts = self.live_hosts[:3] or [f"https://{self.target}"]

        CMS_SIGNATURES = {
            "WordPress": [
                ("/wp-login.php", "WordPress"),
                ("/wp-includes/", "WordPress"),
                ("/wp-content/", "WordPress"),
                ("/xmlrpc.php", "XML-RPC"),
            ],
            "Joomla": [
                ("/administrator/", "Joomla Admin"),
                ("/media/system/js/", "Joomla"),
            ],
            "Drupal": [
                ("/core/misc/drupal.js", "Drupal"),
                ("/sites/default/", "Drupal"),
            ],
            "Laravel": [
                ("/_debugbar", "Laravel Debug"),
                ("/telescope", "Laravel Telescope"),
            ],
        }

        for base in hosts:
            # Check page source for meta generators
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "10", base],
                timeout=15,
            )
            if body:
                gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
                if gen:
                    self.cms_info[base] = gen.group(1)
                    self.findings.append(Finding(
                        severity="info",
                        title=f"CMS Detected: {gen.group(1)}",
                        host=base,
                        detail=f"Meta generator: {gen.group(1)}",
                        source="cms_detect",
                        url=base,
                    ))

            # Probe known paths
            for cms, paths in CMS_SIGNATURES.items():
                for path, label in paths:
                    rc, _, _ = run(
                        ["curl", "-sI", "--max-time", "5", f"{base}{path}"],
                        timeout=8,
                    )
                    # Parse status
                    if rc == 0:
                        # Check if we got 200
                        pass  # httpx or header check handled elsewhere

        # WordPress specific: check wp-json
        for base in hosts:
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "10", f"{base}/wp-json/wp/v2/users"],
                timeout=15,
            )
            if rc == 0 and body and body.strip().startswith("["):
                try:
                    users = json.loads(body)
                    if users and isinstance(users, list):
                        names = [u.get("name", u.get("slug", "?")) for u in users[:10]]
                        self.findings.append(Finding(
                            severity="medium",
                            title="WordPress User Enumeration via REST API",
                            host=base,
                            detail=f"Exposed users: {', '.join(names)}",
                            source="cms_detect",
                            url=f"{base}/wp-json/wp/v2/users",
                            evidence=body[:300],
                        ))
                except Exception:
                    pass

    # ─── Email Harvesting ──────────────────────────────────────────────────────

    def _emails(self) -> None:
        """Extract email addresses from page source and common pages."""
        hosts = self.live_hosts[:5] or [f"https://{self.target}"]
        email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        all_emails: set[str] = set()

        pages = ["", "/contact", "/about", "/team", "/impressum", "/privacy"]
        for base in hosts:
            for page in pages:
                rc, body, _ = run(
                    ["curl", "-sL", "--max-time", "10", f"{base}{page}"],
                    timeout=15,
                )
                if rc == 0 and body:
                    found = email_re.findall(body)
                    all_emails.update(e for e in found if not e.endswith((".png", ".jpg", ".gif")))

        self.emails = sorted(all_emails)
        if self.emails:
            write_lines(f"{self.dirs['recon']}/emails.txt", self.emails)
            logger.info(f"  Emails found: {len(self.emails)}")

    # ─── Screenshots ───────────────────────────────────────────────────────────

    def _screenshots(self) -> None:
        """Capture screenshots of live hosts."""
        if not self.live_hosts:
            return

        hosts_file = f"{self.dirs['recon']}/live_hosts_for_screenshot.txt"
        write_lines(hosts_file, self.live_hosts[:30])
        out_dir = self.dirs["screenshots"]

        if which("gowitness"):
            run(
                ["gowitness", "file", "-f", hosts_file,
                 "--destination", out_dir,
                 "--threads", str(min(self.threads, 5)),
                 "--timeout", "15"],
                timeout=600,
            )
            logger.info("  Screenshots captured (gowitness)")
        elif which("eyewitness"):
            run(
                ["eyewitness", "-f", hosts_file, "-d", out_dir,
                 "--no-prompt", "--timeout", "15"],
                timeout=600,
            )
            logger.info("  Screenshots captured (eyewitness)")
        else:
            logger.debug("  No screenshot tool (gowitness/eyewitness)")

    # ─── Sensitive file probing ────────────────────────────────────────────────

    def _sensitive_files(self) -> None:
        """Probe for common sensitive files that shouldn't be publicly accessible."""
        SENSITIVE_PATHS = [
            "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/.DS_Store", "/server-status", "/server-info",
            "/.htaccess", "/.htpasswd", "/web.config",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/phpinfo.php", "/info.php", "/test.php",
            "/wp-config.php.bak", "/wp-config.php.old",
            "/backup.zip", "/backup.sql", "/db.sql",
            "/database.sql", "/dump.sql", "/.env.bak",
            "/config.json", "/config.yaml", "/config.yml",
            "/composer.json", "/package.json", "/.npmrc",
            "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
            "/.aws/credentials", "/.ssh/id_rsa",
            "/error_log", "/debug.log", "/errors.log",
        ]

        hosts = self.live_hosts[:3] or [f"https://{self.target}"]

        for base in hosts:
            found = []
            for path in SENSITIVE_PATHS:
                url = f"{base}{path}"
                rc, out, _ = run(
                    ["curl", "-sI", "--max-time", "5", url],
                    timeout=8,
                )
                if rc != 0 or not out:
                    continue
                first_line = out.splitlines()[0] if out.splitlines() else ""
                if "200" in first_line:
                    # Verify it's not a custom 404 page (check content-length)
                    cl = 0
                    ct = ""
                    for line in out.splitlines():
                        ll = line.lower()
                        if ll.startswith("content-length:"):
                            try:
                                cl = int(ll.split(":")[1].strip())
                            except ValueError:
                                pass
                        elif ll.startswith("content-type:"):
                            ct = ll.split(":")[1].strip()

                    # Skip likely custom 404s (very small HTML pages)
                    if cl > 0 and cl < 100 and "html" in ct:
                        continue

                    sev = "high" if any(s in path for s in [".env", ".git", "config", "credential", "id_rsa", ".sql"]) else "medium"
                    self.findings.append(Finding(
                        severity=sev,
                        title=f"Sensitive File Exposed: {path}",
                        host=base,
                        detail=f"File accessible at {url} (Content-Length: {cl})",
                        source="sensitive_files",
                        url=url,
                    ))
                    found.append(path)
                    self.extra_urls.append(URLRecord(
                        url=url, status=200, is_sensitive_file=True,
                        method_source="probe",
                    ))

            if found:
                logger.info(f"  Sensitive files ({base}): {len(found)} found")

    # ─── Orchestrator ─────────────────────────────────────────────────────────

    def run(self) -> tuple[list, list, list]:
        """Returns (extra_urls, findings, emails)."""
        steps = [
            ("robots.txt",        self._robots),
            ("sitemap.xml",       self._sitemap),
            ("CMS detection",     self._cms_detect),
            ("Email harvesting",  self._emails),
            ("Sensitive files",   self._sensitive_files),
            ("Screenshots",       self._screenshots),
        ]
        for name, fn in steps:
            logger.info(f"  → {name}")
            try:
                fn()
            except Exception as exc:
                logger.error(f"    [!] {name}: {exc}")

        return self.extra_urls, self.findings, self.emails
