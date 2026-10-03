"""Tests for individual vuln check modules."""
import tempfile
import unittest

from scanner.checks import (
    HeadersCheck, CORSCheck, SwaggerCheck, GraphQLCheck,
    CRLFCheck, HostHeaderCheck, CloudMetadataCheck,
    Bypass403Check, OpenRedirectCheck, DirBruteCheck,
    ALL_CHECKS,
)
from scanner.checks.base import BaseCheck
from scanner.utils import create_dirs


class TestChecksRegistry(unittest.TestCase):
    def test_all_checks_registered(self):
        self.assertGreaterEqual(len(ALL_CHECKS), 14)
        for cls in ALL_CHECKS:
            self.assertTrue(issubclass(cls, BaseCheck),
                            f"{cls.__name__} must subclass BaseCheck")
            self.assertTrue(cls.name, f"{cls.__name__} missing name")
            self.assertTrue(cls.description, f"{cls.__name__} missing description")

    def test_each_check_instantiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            for cls in ALL_CHECKS:
                kwargs = {}
                if cls is DirBruteCheck:
                    kwargs["wordlist"] = None
                check = cls(target="example.com", dirs=dirs,
                            live_hosts=["https://example.com"], threads=1, **kwargs)
                self.assertIsInstance(check, BaseCheck)
                self.assertEqual(check.findings, [])


class TestCheckStaticData(unittest.TestCase):
    def test_swagger_paths_contains_openapi(self):
        self.assertIn("/openapi.json", SwaggerCheck.API_PATHS)
        self.assertIn("/swagger.json", SwaggerCheck.API_PATHS)

    def test_graphql_paths(self):
        self.assertIn("/graphql", GraphQLCheck.GRAPHQL_PATHS)

    def test_crlf_payloads_present(self):
        self.assertGreater(len(CRLFCheck.PAYLOADS), 2)

    def test_cloud_metadata_covers_three_clouds(self):
        clouds = [c for c, _ in CloudMetadataCheck.METADATA_URLS]
        self.assertIn("AWS", clouds)
        self.assertIn("GCP", clouds)
        self.assertIn("Azure", clouds)

    def test_bypass403_has_headers_and_paths(self):
        self.assertGreater(len(Bypass403Check.BYPASS_HEADERS), 5)
        self.assertGreater(len(Bypass403Check.PATH_BYPASSES), 2)

    def test_open_redirect_params(self):
        self.assertIn("url", OpenRedirectCheck.REDIRECT_PARAMS)
        self.assertIn("redirect", OpenRedirectCheck.REDIRECT_PARAMS)

    def test_headers_required(self):
        self.assertIn("strict-transport-security", HeadersCheck.REQUIRED)
        self.assertIn("content-security-policy", HeadersCheck.REQUIRED)


class TestBaseCheck(unittest.TestCase):
    def test_hosts_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = HeadersCheck(target="example.com", dirs=dirs, live_hosts=[], threads=1)
            hosts = check._hosts(5)
            self.assertEqual(hosts, ["https://example.com"])

    def test_hosts_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            hosts_list = [f"https://sub{i}.example.com" for i in range(10)]
            check = HeadersCheck(target="example.com", dirs=dirs,
                                 live_hosts=hosts_list, threads=1)
            self.assertEqual(len(check._hosts(3)), 3)


if __name__ == "__main__":
    unittest.main()
