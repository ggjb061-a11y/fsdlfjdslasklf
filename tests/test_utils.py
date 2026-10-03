"""Tests for scanner utility functions."""
import json
import tempfile
import unittest
from pathlib import Path

from scanner.utils import (
    categorize_url, read_lines, write_lines, parse_jsonl,
    create_dirs, set_proxy, get_proxy,
    LOGIN_PATTERNS, SENSITIVE_EXT, JS_EXT, API_PATTERN, STATIC_EXT,
)


class TestCategorizeURL(unittest.TestCase):
    def test_login_page(self):
        self.assertTrue(categorize_url("https://example.com/login")["is_login"])
        self.assertTrue(categorize_url("https://example.com/wp-admin/")["is_login"])
        self.assertTrue(categorize_url("https://example.com/user/signin")["is_login"])

    def test_js_file(self):
        self.assertTrue(categorize_url("https://example.com/app.js")["is_js"])
        self.assertTrue(categorize_url("https://example.com/app.js?v=1")["is_js"])
        self.assertFalse(categorize_url("https://example.com/app.json")["is_js"])

    def test_sensitive_file(self):
        self.assertTrue(categorize_url("https://example.com/.env")["is_sensitive_file"])
        self.assertTrue(categorize_url("https://example.com/backup.zip")["is_sensitive_file"])
        self.assertTrue(categorize_url("https://example.com/dump.sql")["is_sensitive_file"])
        self.assertFalse(categorize_url("https://example.com/index.html")["is_sensitive_file"])

    def test_api(self):
        self.assertTrue(categorize_url("https://example.com/api/v1/users")["is_api"])
        self.assertTrue(categorize_url("https://example.com/v2/data")["is_api"])
        self.assertTrue(categorize_url("https://example.com/graphql")["is_api"])

    def test_static(self):
        self.assertTrue(categorize_url("https://example.com/style.css")["is_static"])
        self.assertTrue(categorize_url("https://example.com/img.png")["is_static"])
        self.assertTrue(categorize_url("https://example.com/font.woff2")["is_static"])


class TestFileHelpers(unittest.TestCase):
    def test_read_write_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/test.txt"
            write_lines(path, ["a", "b", "c"])
            self.assertEqual(read_lines(path), ["a", "b", "c"])

    def test_read_nonexistent(self):
        self.assertEqual(read_lines("/nonexistent/path/xyz"), [])

    def test_read_strips_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/t.txt"
            Path(path).write_text("a\n\n  b  \n\n")
            self.assertEqual(read_lines(path), ["a", "b"])

    def test_parse_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/data.jsonl"
            Path(path).write_text(
                json.dumps({"a": 1}) + "\n" +
                json.dumps({"b": 2}) + "\n" +
                "malformed line\n" +
                json.dumps({"c": 3}) + "\n"
            )
            parsed = parse_jsonl(path)
            self.assertEqual(len(parsed), 3)
            self.assertEqual(parsed[0], {"a": 1})
            self.assertEqual(parsed[2], {"c": 3})

    def test_parse_jsonl_missing(self):
        self.assertEqual(parse_jsonl("/does/not/exist.jsonl"), [])


class TestCreateDirs(unittest.TestCase):
    def test_create_dirs_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            required_keys = [
                "base", "recon", "subdomains", "dns", "ports",
                "screenshots", "tech", "urls", "js", "js_files",
                "js_secrets", "methods", "vuln", "nuclei", "nikto",
                "ssl", "dirs", "reports",
            ]
            for key in required_keys:
                self.assertIn(key, dirs)
                self.assertTrue(Path(dirs[key]).exists(), f"{key} dir not created")

    def test_sanitizes_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "evil/../target")
            self.assertNotIn("..", dirs["base"])


class TestProxy(unittest.TestCase):
    def test_set_get_proxy(self):
        set_proxy("http://127.0.0.1:8080")
        self.assertEqual(get_proxy(), "http://127.0.0.1:8080")
        set_proxy(None)
        self.assertIsNone(get_proxy())


if __name__ == "__main__":
    unittest.main()
