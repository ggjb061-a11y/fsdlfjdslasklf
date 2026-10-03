"""Tests for the additional recon source modules (helpers + filters)."""
import unittest
from unittest.mock import patch

from scanner.recon_sources._helpers import filter_subs


class TestFilterSubs(unittest.TestCase):
    def test_keeps_in_scope(self):
        self.assertEqual(
            filter_subs(["api.example.com", "www.example.com"], "example.com"),
            {"api.example.com", "www.example.com"},
        )

    def test_rejects_out_of_scope(self):
        self.assertEqual(
            filter_subs(["other.com", "example.com.attacker.com"], "example.com"),
            set(),
        )

    def test_strips_wildcard(self):
        self.assertEqual(
            filter_subs(["*.example.com"], "example.com"),
            {"example.com"},
        )

    def test_strips_port(self):
        self.assertEqual(
            filter_subs(["api.example.com:443"], "example.com"),
            {"api.example.com"},
        )

    def test_strips_scheme(self):
        self.assertEqual(
            filter_subs(["https://api.example.com/path"], "example.com"),
            {"api.example.com"},
        )

    def test_lowercase(self):
        self.assertEqual(
            filter_subs(["API.Example.Com"], "example.com"),
            {"api.example.com"},
        )

    def test_rejects_invalid_chars(self):
        self.assertEqual(
            filter_subs(["bad space.example.com", "weird!.example.com"], "example.com"),
            set(),
        )


class TestSourceWiring(unittest.TestCase):
    """Each source should return a set, and tolerate network failures by returning empty."""

    def test_alienvault_handles_empty(self):
        from scanner.recon_sources.alienvault import fetch
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(-1, "", "timeout")):
            self.assertEqual(fetch("example.com"), set())

    def test_threatcrowd_handles_empty(self):
        from scanner.recon_sources.threatcrowd import fetch
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(-1, "", "")):
            self.assertEqual(fetch("example.com"), set())

    def test_rapiddns_parses_html(self):
        from scanner.recon_sources.rapiddns import fetch
        html = '''
        <table>
          <tr><td> api.example.com </td><td>1.2.3.4</td></tr>
          <tr><td> www.example.com </td><td>5.6.7.8</td></tr>
          <tr><td> other.com </td><td>9.9.9.9</td></tr>
        </table>
        '''
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, html, "")):
            result = fetch("example.com")
            self.assertIn("api.example.com", result)
            self.assertIn("www.example.com", result)
            self.assertNotIn("other.com", result)

    def test_hackertarget_hostsearch_parses_csv(self):
        from scanner.recon_sources.hackertarget_hostsearch import fetch
        body = "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n"
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, body, "")):
            result = fetch("example.com")
            self.assertIn("api.example.com", result)
            self.assertIn("www.example.com", result)

    def test_hackertarget_handles_rate_limit(self):
        from scanner.recon_sources.hackertarget_hostsearch import fetch
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, "API count exceeded", "")):
            self.assertEqual(fetch("example.com"), set())

    def test_alienvault_parses_passive_dns(self):
        from scanner.recon_sources.alienvault import fetch
        body = (
            '{"passive_dns": ['
            '{"hostname": "api.example.com"},'
            '{"hostname": "www.example.com"},'
            '{"hostname": "attacker.com"}'
            ']}'
        )
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, body, "")):
            result = fetch("example.com")
            self.assertEqual(result, {"api.example.com", "www.example.com"})

    def test_bufferover_parses_fdns(self):
        from scanner.recon_sources.bufferover import fetch
        body = '{"FDNS_A": ["1.2.3.4,api.example.com", "5.6.7.8,www.example.com"]}'
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, body, "")):
            result = fetch("example.com")
            self.assertIn("api.example.com", result)
            self.assertIn("www.example.com", result)

    def test_certspotter_parses_dns_names(self):
        from scanner.recon_sources.certspotter import fetch
        body = (
            '[{"dns_names": ["api.example.com", "www.example.com"]}, '
            '{"dns_names": ["*.example.com"]}]'
        )
        with patch("scanner.recon_sources._helpers.run",
                   return_value=(0, body, "")):
            result = fetch("example.com")
            self.assertIn("api.example.com", result)
            self.assertIn("www.example.com", result)


class TestJSMining(unittest.TestCase):
    def test_extracts_subdomains_from_js_file(self):
        import tempfile
        from pathlib import Path
        from scanner.recon_sources.js_mining import fetch

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "app.js"
            p.write_text(
                'const API = "https://api.example.com/v1";\n'
                'const CDN = "https://static.example.com";\n'
                'const SOCKET = "ws://notrelated.other.com";\n'
            )
            result = fetch("example.com", js_dir=tmp)
            self.assertIn("api.example.com", result)
            self.assertIn("static.example.com", result)
            self.assertNotIn("notrelated.other.com", result)


if __name__ == "__main__":
    unittest.main()
