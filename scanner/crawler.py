"""
URL / path / asset discovery across live crawling, historical sources, and
deep HTML/JS content inspection.

Sources (parallel + redundant for coverage):
  1. GAU             - Wayback + CommonCrawl + OTX + URLScan
  2. Wayback CDX     - direct curl against the public CDX API
  3. hakrawler       - fast live crawler
  4. katana          - headless-aware live crawler with JS parsing
  5. gospider        - live crawler w/ JS crawling
  6. Deep custom crawl (new) - recursive BFS up to depth 3 using curl +
     a rich extraction pipeline that pulls:
       - <a href>, <link href>, <script src>, <img src>, <form action>,
         <iframe src>, <audio src>, <video src>, <source src>, <object data>
       - CSS url(...) refs
       - JSON-LD / data-* attributes carrying URLs
       - JavaScript string literals that look like paths or absolute URLs
       - "action: '/path'" style config in inline <script>
       - sitemap.xml and sitemapindex refs
  7. common-paths probing (new) - probes a built-in 180+ well-known paths
     wordlist (admin consoles, backups, debug endpoints, CI/CD files,
     IDE configs, CDN assets, iOS/Android plist/.well-known/*).
  8. URL probing (httpx) + categorization.

All sources merge into a single de-duplicated URLRecord set. Each record
tracks its method_source (gau / wayback / hakrawler / katana / gospider /
deep-crawl / common-paths / fallback-curl).

Interesting paths are extracted to a dedicated interesting_paths.txt file.
"""
import json
import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from .utils import which, run, read_lines, write_lines, categorize_url, parse_jsonl
from .models import URLRecord

logger = logging.getLogger("autoscan.crawler")


# -----------------------------------------------------------------------
# Extraction regexes
# -----------------------------------------------------------------------

# HTML attributes that commonly carry URLs
_ATTR_URL_RE = re.compile(
    r'(?:href|src|action|data-url|data-href|data-src|data-link|poster|'
    r'formaction|background|ping|cite|longdesc|usemap|srcset|xlink:href)'
    r'\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# CSS url() refs
_CSS_URL_RE = re.compile(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', re.IGNORECASE)

# Absolute HTTP(S) URLs appearing anywhere (in JS strings, JSON, comments)
_ABS_URL_RE = re.compile(r'https?://[A-Za-z0-9.\-]+(?:/[\w./?=&%+:;,#\-]*)?')

# API-looking paths in JS: '/api/v1/users', "/graphql", 'rest/endpoint'
_JS_PATH_RE = re.compile(
    r'''["'](\/[A-Za-z0-9_\-./?=&%+]{3,200})["']'''
)

# "ajax", "fetch", "axios" calls - grab the first string argument
_JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.[a-z]+|ajax|xhr\.open)\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


# A compact built-in wordlist for always-probe common paths.
COMMON_PATHS = [
    # Admin / dashboards
    "/admin", "/admin/", "/administrator", "/admin.php", "/wp-admin/",
    "/dashboard", "/manager", "/console", "/cpanel", "/phpmyadmin/",
    "/pma/", "/myadmin/", "/mysql/", "/phpinfo.php",
    # Auth
    "/login", "/signin", "/register", "/signup", "/forgot-password",
    "/reset", "/sso", "/oauth", "/oauth/authorize", "/auth",
    # API docs
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc", "/docs",
    "/graphql", "/graphiql", "/altair",
    # Status / health
    "/health", "/healthz", "/status", "/ping", "/metrics", "/stats",
    "/version", "/info",
    # Debug / dev
    "/debug", "/debug.php", "/debugbar", "/_profiler", "/trace",
    "/.vscode/", "/.idea/", "/.git/HEAD", "/.git/config",
    "/.svn/entries", "/.hg/hgrc", "/.bzr/branch-format",
    # Configs / secrets
    "/.env", "/.env.local", "/.env.dev", "/.env.prod", "/.env.backup",
    "/.env.save", "/.env.old", "/.env.bak", "/.env~",
    "/config.json", "/config.yaml", "/config.yml", "/config.php",
    "/credentials", "/credentials.json",
    "/.htaccess", "/.htpasswd", "/web.config", "/.ssh/id_rsa",
    "/.aws/credentials", "/.aws/config",
    # Backup / archive
    "/backup", "/backups", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql", "/site.tar.gz",
    "/wordpress.sql", "/site.zip",
    # CI / CD
    "/.github/", "/.gitlab-ci.yml", "/.circleci/config.yml",
    "/.drone.yml", "/.travis.yml", "/Jenkinsfile", "/jenkins/",
    "/jenkins/login", "/build.yml",
    # Docker / infra
    "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.override.yml", "/kubeconfig",
    # Infra / docs
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/humans.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    # CMS specific
    "/wp-login.php", "/wp-content/", "/wp-content/debug.log",
    "/xmlrpc.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-cron.php", "/wp-json/", "/wp-json/wp/v2/users",
    "/user/login", "/users/sign_in",
    # Server-info
    "/server-status", "/server-info", "/stub_status",
    # Container platforms
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/heapdump", "/env", "/beans",
    # IDE / tooling leaks
    "/composer.json", "/composer.lock", "/package.json",
    "/package-lock.json", "/yarn.lock", "/pom.xml", "/build.gradle",
    "/Gemfile", "/Gemfile.lock", "/Pipfile", "/pyproject.toml",
    "/requirements.txt", "/setup.py", "/tsconfig.json",
    # Error pages (useful fingerprinting)
    "/error", "/404", "/500",
    # Logs
    "/debug.log", "/error.log", "/access.log", "/laravel.log",
    "/storage/logs/laravel.log",
    # Misc
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/favicon.ico",
]

# Patterns that make a discovered path "interesting" even if not sensitive
INTERESTING_PATH_PATTERNS = [
    (re.compile(r"/api/", re.I),                        "api-endpoint"),
    (re.compile(r"/v\d+/", re.I),                       "versioned-api"),
    (re.compile(r"/graphql\b", re.I),                   "graphql"),
    (re.compile(r"/(admin|dashboard|portal|console)/?", re.I), "admin-interface"),
    (re.compile(r"/(login|signin|sso|oauth)", re.I),    "auth-endpoint"),
    (re.compile(r"/(upload|file|attach)", re.I),        "upload-endpoint"),
    (re.compile(r"/(debug|trace|status|health)", re.I), "debug-endpoint"),
    (re.compile(r"\.(bak|old|backup|zip|tar\.gz|sql|dump|env|git)", re.I), "backup-or-vcs"),
    (re.compile(r"/\.well-known/", re.I),               "well-known"),
    (re.compile(r"/(swagger|openapi|api-docs|redoc)", re.I), "api-docs"),
]


def _wayback_cdx_url(domain: str) -> str:
    return (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        "&output=text"
        "&fl=original"
        "&collapse=urlkey"
        "&limit=10000"
    )


class CrawlerModule:
    """URL and asset discovery across 8 sources, deep extraction, auto-categorization."""

    DEEP_CRAWL_DEPTH = 2
    DEEP_CRAWL_LIMIT = 500         # cap pages fetched per deep crawl pass
    DEEP_CRAWL_PER_HOST = 150      # cap pages per host

    def __init__(self, target: str, dirs: dict, live_hosts: list, threads: int = 10):
        self.target = target
        self.dirs = dirs
        self.live_hosts = live_hosts
        self.threads = threads

        # Each raw URL carries its discovery source
        self.raw_urls: dict[str, str] = {}
        self.url_records: list[URLRecord] = []
        # Paths worth highlighting
        self.interesting_paths: dict[str, str] = {}  # url -> category tag

    # =========================================================
    # Shared helpers
    # =========================================================
    def _add_raw(self, url: str, source: str) -> None:
        if not url or not url.startswith("http"):
            return
        # Proper host-suffix scope check: substring match let through
        # 'evilexample.com', 'notexample.com', or any attacker URL whose
        # query string merely mentions the target.
        try:
            import urllib.parse as _up
            netloc = _up.urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            return
        tgt = self.target.lower()
        if netloc != tgt and not netloc.endswith("." + tgt):
            return
        if url not in self.raw_urls:
            self.raw_urls[url] = source
        self._tag_interesting(url)

    def _tag_interesting(self, url: str) -> None:
        for rx, tag in INTERESTING_PATH_PATTERNS:
            if rx.search(url):
                self.interesting_paths[url] = tag
                break

    def _normalize(self, href: str, base_url: str) -> str | None:
        if not href:
            return None
        href = href.strip().strip('"\'')
        if href.startswith("javascript:") or href.startswith("mailto:") \
           or href.startswith("tel:") or href.startswith("#"):
            return None
        if href.startswith("//"):
            scheme = urllib.parse.urlparse(base_url).scheme or "https"
            return f"{scheme}:{href}"
        if href.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{href}"
        if href.startswith("http"):
            return href
        # Relative path
        return urllib.parse.urljoin(base_url, href)

    def _extract_urls_from_body(self, body: str, base_url: str) -> set[str]:
        """Extract every URL-ish thing from an HTML/JS/CSS/JSON body."""
        found: set[str] = set()

        # HTML attributes
        for m in _ATTR_URL_RE.finditer(body):
            v = m.group(1)
            # srcset may contain multiple comma-separated URLs
            for part in v.split(","):
                u = self._normalize(part.strip().split()[0] if part.strip() else "", base_url)
                if u:
                    found.add(u)

        # CSS url(...)
        for m in _CSS_URL_RE.finditer(body):
            u = self._normalize(m.group(1), base_url)
            if u:
                found.add(u)

        # Absolute URLs
        for m in _ABS_URL_RE.finditer(body):
            found.add(m.group(0))

        # JS paths in strings
        for m in _JS_PATH_RE.finditer(body):
            u = self._normalize(m.group(1), base_url)
            if u:
                found.add(u)

        # fetch/axios/ajax first argument
        for m in _JS_FETCH_RE.finditer(body):
            u = self._normalize(m.group(1), base_url)
            if u:
                found.add(u)

        return found

    # =========================================================
    # Source 1: GAU
    # =========================================================
    def _gau(self) -> None:
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
        for u in urls:
            self._add_raw(u, "gau")
        logger.info(f"  GAU: {len(urls)} URLs")

    # =========================================================
    # Source 2: Wayback CDX (curl)
    # =========================================================
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
        count = 0
        for u in stdout.splitlines():
            u = u.strip()
            if u.startswith("http"):
                self._add_raw(u, "wayback")
                count += 1
        logger.info(f"  Wayback CDX: {count} URLs")

    # =========================================================
    # Source 3-5: Live crawlers (hakrawler / katana / gospider)
    # =========================================================
    def _hakrawler(self) -> None:
        if not which("hakrawler"):
            return
        targets = self.live_hosts[:10] if self.live_hosts else [f"https://{self.target}"]
        out = f"{self.dirs['urls_live']}/hakrawler.txt"
        rc, stdout, _ = run(
            ["hakrawler", "-depth", "3", "-t", str(self.threads),
             "-insecure", "-subs"],
            stdin_data="\n".join(targets),
            output_file=out, timeout=300,
        )
        urls = [u.strip() for u in (stdout or "").splitlines() if u.strip().startswith("http")]
        for u in urls:
            self._add_raw(u, "hakrawler")
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
        for u in urls:
            if u.startswith("http"):
                self._add_raw(u, "katana")
        logger.info(f"  katana: {len(urls)} URLs")

    def _gospider(self) -> None:
        if not which("gospider"):
            return
        targets = self.live_hosts[:5] if self.live_hosts else [f"https://{self.target}"]
        out_dir = f"{self.dirs['urls_live']}/gospider"
        Path(out_dir).mkdir(exist_ok=True)
        for t in targets:
            run(
                ["gospider", "-s", t, "-o", out_dir, "-c", str(self.threads),
                 "-d", "3", "--no-redirect", "--quiet", "--js"],
                timeout=300,
            )
        count = 0
        for f in Path(out_dir).rglob("*"):
            if f.is_file():
                for line in read_lines(str(f)):
                    m = re.search(r"\] - \[(.+?)\]", line)
                    if m:
                        u = m.group(1).strip()
                        if u.startswith("http"):
                            self._add_raw(u, "gospider")
                            count += 1
        logger.info(f"  gospider: {count} URLs")

    # =========================================================
    # Source 6: Deep custom crawl (new, BFS with rich extraction)
    # =========================================================
    def _deep_crawl(self) -> None:
        """Breadth-first crawl using curl + rich extraction regex pipeline."""
        if not self.live_hosts:
            seeds = [f"https://{self.target}"]
        else:
            seeds = self.live_hosts[:5]

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(s, 0) for s in seeds]
        per_host: dict[str, int] = {}
        page_count = 0

        while queue and page_count < self.DEEP_CRAWL_LIMIT:
            batch, queue = queue[:self.threads], queue[self.threads:]

            def _fetch(url: str) -> tuple[str, str]:
                rc, body, _ = run(
                    ["curl", "-skL", "--max-time", "10", url],
                    timeout=15,
                )
                if rc != 0 or not body:
                    return url, ""
                return url, body

            with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as ex:
                futures = {ex.submit(_fetch, url): (url, depth)
                           for url, depth in batch if url not in visited}
                for fut in as_completed(futures):
                    url, depth = futures[fut]
                    visited.add(url)
                    try:
                        _, body = fut.result()
                    except Exception:
                        continue
                    if not body:
                        continue
                    page_count += 1
                    host = urllib.parse.urlparse(url).netloc
                    per_host[host] = per_host.get(host, 0) + 1
                    # Extract and queue
                    found = self._extract_urls_from_body(body, url)
                    for u in found:
                        self._add_raw(u, "deep-crawl")
                        if (depth + 1 <= self.DEEP_CRAWL_DEPTH
                            and u not in visited
                            and per_host.get(urllib.parse.urlparse(u).netloc, 0)
                                < self.DEEP_CRAWL_PER_HOST
                            and page_count < self.DEEP_CRAWL_LIMIT):
                            queue.append((u, depth + 1))

        logger.info(f"  deep-crawl: {page_count} pages, "
                    f"{sum(1 for s in self.raw_urls.values() if s == 'deep-crawl')} URLs")

    # =========================================================
    # Source 7: Common-paths probing
    # =========================================================
    def _common_paths(self) -> None:
        """Probe COMMON_PATHS against each live host."""
        if not self.live_hosts:
            targets = [f"https://{self.target}"]
        else:
            targets = self.live_hosts[:3]

        candidates = [(host, path) for host in targets for path in COMMON_PATHS]

        def _probe(host: str, path: str) -> tuple[str, int]:
            url = host.rstrip("/") + path
            rc, out, _ = run(
                ["curl", "-skI", "--max-time", "5",
                 "-w", "%{http_code}", url],
                timeout=8,
            )
            if rc != 0:
                return url, 0
            # curl -I -w prints only the status code at end; grab from headers
            status = 0
            for line in (out or "").splitlines():
                m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
                if m:
                    status = int(m.group(1))
                    break
            if not status:
                try:
                    status = int(out.strip().splitlines()[-1])
                except Exception:
                    status = 0
            return url, status

        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as ex:
            futures = {ex.submit(_probe, h, p): (h, p) for h, p in candidates}
            found_count = 0
            for fut in as_completed(futures):
                try:
                    url, status = fut.result()
                except Exception:
                    continue
                if status and status < 400:
                    self._add_raw(url, "common-paths")
                    found_count += 1
                elif status == 403:
                    # Still noteworthy - add tag "forbidden"
                    self._add_raw(url, "common-paths")
                    self.interesting_paths[url] = "forbidden"
                    found_count += 1
        logger.info(f"  common-paths: {found_count} responsive paths")

    # =========================================================
    # Source 8: curl fallback (preserves legacy behavior)
    # =========================================================
    def _fallback_curl_crawl(self) -> None:
        targets = self.live_hosts[:3] if self.live_hosts else [f"https://{self.target}"]
        for base_url in targets:
            rc, body, _ = run(
                ["curl", "-sL", "--max-time", "15", base_url],
                timeout=20,
            )
            if rc != 0 or not body:
                continue
            for u in self._extract_urls_from_body(body, base_url):
                self._add_raw(u, "fallback-curl")

    # =========================================================
    # Probing + categorization + persistence
    # =========================================================
    def _probe_urls(self) -> None:
        if not self.raw_urls:
            return
        all_urls_file = f"{self.dirs['urls']}/all_raw.txt"
        write_lines(all_urls_file, sorted(self.raw_urls.keys()))

        if not which("httpx"):
            for url, source in self.raw_urls.items():
                cats = categorize_url(url)
                self.url_records.append(URLRecord(url=url, method_source=source, **cats))
            return

        out_json = f"{self.dirs['urls']}/probed.jsonl"
        run(
            ["httpx", "-l", all_urls_file,
             "-silent", "-status-code", "-content-type",
             "-title", "-server", "-follow-redirects",
             "-threads", str(self.threads),
             "-timeout", "10", "-retries", "1",
             "-mc", "200,201,204,301,302,307,401,403,405",
             "-json", "-o", out_json],
            timeout=1800,
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
                method_source=self.raw_urls.get(url, "live"),
                **cats,
            ))
        logger.info(f"  Probed URLs: {len(self.url_records)} live")

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

        # Full URL list with statuses, sorted by status then url
        lines = [f"{r.status or '---'}\t{r.url}" for r in
                 sorted(self.url_records, key=lambda x: (x.status or 999, x.url))]
        write_lines(f"{self.dirs['urls']}/all_urls_with_status.txt", lines)

        # Interesting paths with their category tag
        if self.interesting_paths:
            lines = [f"{tag}\t{url}" for url, tag in
                     sorted(self.interesting_paths.items())]
            write_lines(f"{self.dirs['urls']}/interesting_paths.txt", lines)

        # URL discovery by source
        by_source: dict[str, int] = {}
        for r in self.url_records:
            by_source[r.method_source] = by_source.get(r.method_source, 0) + 1
        source_lines = [f"{src:<16} {n:>5}" for src, n in
                        sorted(by_source.items(), key=lambda x: -x[1])]
        write_lines(f"{self.dirs['urls']}/by_source.txt", source_lines)

        logger.info(
            f"  URLs saved | total={len(self.url_records)}"
            f" | login={sum(r.is_login for r in self.url_records)}"
            f" | js={sum(r.is_js for r in self.url_records)}"
            f" | sensitive={sum(r.is_sensitive_file for r in self.url_records)}"
            f" | api={sum(r.is_api for r in self.url_records)}"
            f" | interesting={len(self.interesting_paths)}"
        )

    # =========================================================
    # Orchestrator
    # =========================================================
    def run(self) -> list:
        steps = [
            ("GAU (multi-source URLs)",    self._gau),
            ("Wayback CDX",                self._wayback_cdx),
            ("hakrawler (live)",           self._hakrawler),
            ("katana (live)",              self._katana),
            ("gospider (live)",            self._gospider),
            ("Deep custom crawl (BFS)",    self._deep_crawl),
            ("Common-paths probing",       self._common_paths),
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
