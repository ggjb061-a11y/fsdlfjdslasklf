"""Tests for the enhanced crawler extraction + helpers."""
import tempfile
import unittest
from unittest.mock import patch

from scanner.crawler import CrawlerModule, COMMON_PATHS, INTERESTING_PATH_PATTERNS
from scanner.utils import create_dirs


class TestWordlist(unittest.TestCase):
    def test_common_paths_has_variety(self):
        self.assertGreater(len(COMMON_PATHS), 150)
        for required in ["/admin", "/.env", "/.git/config", "/wp-admin/",
                          "/swagger.json", "/graphql", "/actuator/env",
                          "/.well-known/security.txt", "/robots.txt"]:
            self.assertIn(required, COMMON_PATHS)

    def test_no_duplicates(self):
        self.assertEqual(len(COMMON_PATHS), len(set(COMMON_PATHS)))


class TestInterestingPatterns(unittest.TestCase):
    def test_patterns_match_expected(self):
        tests = [
            ("https://x.com/api/v1/users", "api-endpoint"),
            ("https://x.com/graphql",      "graphql"),
            ("https://x.com/admin/users",  "admin-interface"),
            ("https://x.com/login",        "auth-endpoint"),
            ("https://x.com/upload",       "upload-endpoint"),
            ("https://x.com/debug",        "debug-endpoint"),
            ("https://x.com/backup.zip",   "backup-or-vcs"),
            ("https://x.com/.well-known/x","well-known"),
            ("https://x.com/swagger.json", "api-docs"),
        ]
        for url, expected in tests:
            matched = None
            for rx, tag in INTERESTING_PATH_PATTERNS:
                if rx.search(url):
                    matched = tag
                    break
            self.assertEqual(matched, expected, f"{url} -> {matched} (expected {expected})")


class TestExtraction(unittest.TestCase):
    def _crawler(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return CrawlerModule(target="example.com", dirs=dirs,
                             live_hosts=["https://example.com"], threads=1)

    def test_extract_from_html_attrs(self):
        c = self._crawler()
        html = '''
        <html>
          <a href="/path/one">one</a>
          <link href="/static/style.css">
          <script src="/js/app.js"></script>
          <img src="/img.png" data-src="/img@2x.png">
          <form action="/submit"></form>
          <iframe src="//example.com/frame"></iframe>
        </html>
        '''
        urls = c._extract_urls_from_body(html, "https://example.com/")
        self.assertIn("https://example.com/path/one", urls)
        self.assertIn("https://example.com/static/style.css", urls)
        self.assertIn("https://example.com/js/app.js", urls)
        self.assertIn("https://example.com/submit", urls)

    def test_extract_from_css(self):
        c = self._crawler()
        css = 'body { background: url("/img/bg.jpg"); font: url(/fonts/f.woff2); }'
        urls = c._extract_urls_from_body(css, "https://example.com/")
        self.assertIn("https://example.com/img/bg.jpg", urls)
        self.assertIn("https://example.com/fonts/f.woff2", urls)

    def test_extract_from_js(self):
        c = self._crawler()
        js = '''
        var apiUrl = "/api/v1/users";
        fetch('/api/v2/orders').then(r => r.json());
        axios.get("/api/v2/products");
        const path = '/internal/debug';
        '''
        urls = c._extract_urls_from_body(js, "https://example.com/")
        self.assertIn("https://example.com/api/v1/users", urls)
        self.assertIn("https://example.com/api/v2/orders", urls)
        self.assertIn("https://example.com/api/v2/products", urls)
        self.assertIn("https://example.com/internal/debug", urls)

    def test_extract_absolute_urls(self):
        c = self._crawler()
        text = '''
        See https://example.com/legacy/path for details.
        // Internal note: https://example.com/private/internal
        '''
        urls = c._extract_urls_from_body(text, "https://example.com/")
        self.assertIn("https://example.com/legacy/path", urls)
        self.assertIn("https://example.com/private/internal", urls)

    def test_skips_javascript_mailto_tel(self):
        c = self._crawler()
        html = '''
        <a href="javascript:alert(1)">x</a>
        <a href="mailto:x@example.com">email</a>
        <a href="tel:+123">call</a>
        <a href="#top">anchor</a>
        '''
        urls = c._extract_urls_from_body(html, "https://example.com/")
        self.assertFalse(any("javascript:" in u for u in urls))
        self.assertFalse(any("mailto:" in u for u in urls))
        self.assertFalse(any("tel:" in u for u in urls))

    def test_normalize_relative(self):
        c = self._crawler()
        self.assertEqual(
            c._normalize("sub/page", "https://example.com/dir/"),
            "https://example.com/dir/sub/page",
        )

    def test_normalize_scheme_relative(self):
        c = self._crawler()
        self.assertEqual(
            c._normalize("//example.com/x", "https://example.com/"),
            "https://example.com/x",
        )


class TestAddRawFilters(unittest.TestCase):
    def _crawler(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return CrawlerModule(target="example.com", dirs=dirs,
                             live_hosts=["https://example.com"], threads=1)

    def test_add_in_scope(self):
        c = self._crawler()
        c._add_raw("https://api.example.com/v1", "deep-crawl")
        self.assertIn("https://api.example.com/v1", c.raw_urls)
        self.assertEqual(c.raw_urls["https://api.example.com/v1"], "deep-crawl")

    def test_rejects_out_of_scope(self):
        c = self._crawler()
        c._add_raw("https://other.com/", "deep-crawl")
        self.assertNotIn("https://other.com/", c.raw_urls)

    def test_rejects_non_http(self):
        c = self._crawler()
        c._add_raw("javascript:alert(1)", "deep-crawl")
        c._add_raw("", "deep-crawl")
        self.assertEqual(c.raw_urls, {})

    def test_tag_interesting_on_add(self):
        c = self._crawler()
        c._add_raw("https://example.com/api/v1/users", "deep-crawl")
        self.assertEqual(c.interesting_paths["https://example.com/api/v1/users"],
                         "api-endpoint")


if __name__ == "__main__":
    unittest.main()
