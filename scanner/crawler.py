"""
URL collection from live crawling and historical sources (Wayback, GAU).
Outputs categorized URL lists: live, wayback, JS files, login pages,
sensitive files, API endpoints.
"""
import logging
import re
import urllib.parse
from pathlib import Path
from .utils import which, run, read_lines, write_lines, categorize_url, parse_jsonl
from .models import URLRecord

logger = logging.getLogger("autoscan.crawler")

# ─── Wayback CDX helpers ──────────────────────────────────────────────────────

def _wayback_cdx_url(domain: str) -> str:
    """Build Wayback CDX API URL (no key, public endpoint)."""
    return (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        "&output=text"
        "&fl=original"
        "&collapse=urlkey"
        "&limit=5000"
    )


class CrawlerModule:
    """
    Phase 2 – URL discovery.
    Sources: GAU, Wayback CDX, hakrawler / katana / gospider (live).
    """

    def __init__(self, target: str, dirs: dict, live_hosts: list, threads: int = 10):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads

        self.raw_urls: set[str] = set()
        self.url_records: list[URLRecord] = []

    # ─── GAU (Get All URLs) ──────────────────────────────────────────────────

    def _gau(self) -> None:
        """
        gau fetches URLs from Wayback, CommonCrawl, OTX, URLScan.
        No API key needed for basic use.
        """
        if not which("gau"):
            logger.debug("gau not found")
            return

        out = f"{self.dirs['urls_wayback']}/gau.txt"
        rc, stdout, _ = run(
            ["gau", "--threads", str(self.threads), "--subs", "--blacklist",
             "ttf,woff,woff2,svg,eot,ico,png,jpg,jpeg,gif,css,mp4,mp3",
             self.target],
            output_file=out, timeout=600,
        )
        urls = [u.strip() for u in (stdout or "").splitlines() if u.strip().startswith("http")]
        if not urls:
            urls = read_lines(out)
        self.raw_urls.update(u for u in urls if self.target in u)
        logger.info(f"  GAU: {len(urls)} URLs")

    # ─── Wayback CDX (curl fallback) ─────────────────────────────────────────

    def _wayback_cdx(self) -> None:
        cdx_url = _wayback_cdx_url(self.target)
        out = f"{self.dirs['urls_wayback']}/wayback_cdx.txt"

        rc, stdout, _ = run(
            ["curl", "-s", "--max-time", "60", "--compressed", cdx_url],
            output_file=out, timeout=90,
        )

        if rc != 0 or not stdout.strip():
            logger.debug("Wayback CDX returned no data")
            return

        urls = [u.strip() for u in stdout.splitlines()
                if u.strip().startswith("http") and self.target in u]
        self.raw_urls.update(urls)
        logger.info(f"  Wayback CDX: {len(urls)} URLs")

    # ─── Live crawlers ────────────────────────────────────────────────────────

    def _hakrawler(self) -> None:
        if not which("hakrawler"):
            return
        targets = self.live_hosts[:10] if self.live_hosts else [f"https://{self.target}"]
        out = f"{self.dirs['urls_live']}/hakrawler.txt"
        # hakrawler reads targets from stdin
        stdin_data = "\n".join(targets)
        rc, stdout, _ = run(
            ["hakrawler", "-depth", "3", "-t", str(self.threads),
             "-insecure", "-subs"],
            stdin_data=stdin_data,
            output_file=out,
            timeout=300,
        )
        urls = [u.strip() for u in (stdout or "").splitlines() if u.strip().startswith("http")]
        self.raw_urls.update(urls)
        logger.info(f"  hakrawler: {len(urls)} URLs")

    def _katana(self) -> None:
        if not which("katana"):
            return
        targets = self.live_hosts[:5] if self.live_hosts else [f"https://{self.target}"]
        out = f"{self.dirs['urls_live']}/katana.txt"
        cmd = ["katana", "-silent", "-depth", "3", "-jc",
               "-c", str(self.threads), "-o", out]
        for t in targets:
            cmd.extend(["-u", t])
        rc, stdout, _ = run(cmd, timeout=400)
        urls = read_lines(out)
        self.raw_urls.update(u for u in urls if u.startswith("http"))
        logger.info(f"  katana: {len(urls)} URLs")

    def _gospider(self) -> None:
        if not which("gospider"):
            return
        targets = self.live_hosts[:5] if self.live_hosts else [f"https://{self.target}"]
        out_dir = f"{self.dirs['urls_live']}/gospider"
        Path(out_dir).mkdir(exist_ok=True)
        for i, t in enumerate(targets):
            run(
                ["gospider", "-s", t, "-o", out_dir, "-c", str(self.threads),
                 "-d", "3", "--no-redirect", "--quiet", "--js"],
                timeout=300,
            )
        # Collect URLs from output files
        for f in Path(out_dir).rglob("*"):
            if f.is_file():
                for line in read_lines(str(f)):
                    # gospider format: [xxx] - [url] - [found_url]
                    m = re.search(r"\] - \[(.+?)\]", line)
                    if m:
                        u = m.group(1).strip()
                        if u.startswith("http"):
                            self.raw_urls.add(u)
        logger.info(f"  gospider: crawled {len(targets)} targets")

    def _fallback_curl_crawl(self) -> None:
        """Basic URL extraction via curl + regex when no crawler is installed."""
        targets = self.live_hosts[:3] if self.live_hosts else [f"https://{self.target}"]
        url_regex = re.compile(
            r'(?:href|src|action|data-url|data-href)[=\s:]+["\']?(https?://[^\s\'"<>]+|/[^\s\'"<>]*)',
            re.I,
        )
        for base_url in targets:
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "15", base_url],
                timeout=20,
            )
            if rc == 0 and body:
                for match in url_regex.findall(body):
                    url = match.strip()
                    if url.startswith("/"):
                        parsed = urllib.parse.urlparse(base_url)
                        url = f"{parsed.scheme}://{parsed.netloc}{url}"
                    if url.startswith("http") and self.target in url:
                        self.raw_urls.add(url)

    # ─── URL probing with httpx ───────────────────────────────────────────────

    def _probe_urls(self) -> None:
        """Run httpx on collected URLs to get status codes and metadata."""
        if not self.raw_urls:
            return

        all_urls_file = f"{self.dirs['urls']}/all_raw.txt"
        write_lines(all_urls_file, sorted(self.raw_urls))

        if not which("httpx"):
            # Build basic URLRecord without probing
            for url in self.raw_urls:
                cats = categorize_url(url)
                self.url_records.append(URLRecord(url=url, method_source="wayback", **cats))
            return

        out_json = f"{self.dirs['urls']}/probed.jsonl"
        run(
            [
                "httpx", "-l", all_urls_file,
                "-silent", "-status-code", "-content-type",
                "-title", "-server", "-follow-redirects",
                "-threads", str(self.threads),
                "-timeout", "10", "-retries", "1",
                "-mc", "200,201,204,301,302,307,401,403,405",  # relevant codes only
                "-json", "-o", out_json,
            ],
            timeout=1200,
        )

        seen = set()
        for row in parse_jsonl(out_json):
            url = row.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            cats = categorize_url(url)
            self.url_records.append(URLRecord(
                url=url,
                status=row.get("status-code"),
                content_type=row.get("content-type", ""),
                title=row.get("title", ""),
                server=row.get("webserver", ""),
                redirect_to=row.get("location", ""),
                method_source="live",
                **cats,
            ))

        logger.info(f"  Probed URLs: {len(self.url_records)} live")

    # ─── Save categorized lists ───────────────────────────────────────────────

    def _save_categorized(self) -> None:
        categories = {
            "login_pages.txt":      [r.url for r in self.url_records if r.is_login],
            "js_files.txt":         [r.url for r in self.url_records if r.is_js],
            "sensitive_files.txt":  [r.url for r in self.url_records if r.is_sensitive_file],
            "api_endpoints.txt":    [r.url for r in self.url_records if r.is_api],
            "all_urls_200.txt":     [r.url for r in self.url_records if r.status == 200],
            "all_urls_403.txt":     [r.url for r in self.url_records if r.status == 403],
            "all_urls_redirect.txt":[r.url for r in self.url_records if r.status in (301, 302, 307)],
        }
        for fname, urls in categories.items():
            if urls:
                write_lines(f"{self.dirs['urls']}/{fname}", sorted(set(urls)))

        # Also write full URL list with statuses
        lines = [f"{r.status or '---'}\t{r.url}" for r in
                 sorted(self.url_records, key=lambda x: (x.status or 999, x.url))]
        write_lines(f"{self.dirs['urls']}/all_urls_with_status.txt", lines)

        logger.info(
            f"  URLs saved | total={len(self.url_records)}"
            f" | login={sum(r.is_login for r in self.url_records)}"
            f" | js={sum(r.is_js for r in self.url_records)}"
            f" | sensitive={sum(r.is_sensitive_file for r in self.url_records)}"
            f" | api={sum(r.is_api for r in self.url_records)}"
        )

    # ─── Orchestrator ─────────────────────────────────────────────────────────

    def run(self) -> list:
        steps = [
            ("GAU (multi-source URLs)",    self._gau),
            ("Wayback CDX",                self._wayback_cdx),
            ("hakrawler (live)",           self._hakrawler),
            ("katana (live)",              self._katana),
            ("gospider (live)",            self._gospider),
            ("curl fallback crawl",        self._fallback_curl_crawl),
            ("Probe URLs (httpx)",         self._probe_urls),
            ("Save categorized lists",     self._save_categorized),
        ]
        for name, fn in steps:
            logger.info(f"  → {name}")
            try:
                fn()
            except Exception as exc:
                logger.error(f"    [!] {name}: {exc}")

        return self.url_records
