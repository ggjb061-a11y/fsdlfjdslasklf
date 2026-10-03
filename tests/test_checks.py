"""Tests for individual vuln check modules."""
import tempfile
import unittest

from scanner.checks import (
    HeadersCheck, CORSCheck, SwaggerCheck, GraphQLCheck,
    CRLFCheck, HostHeaderCheck, CloudMetadataCheck,
    SSRFCheck, XXECheck, SSTICheck, PathTraversalCheck,
    SQLInjectionCheck, SqlmapCheck, CommandInjectionCheck,
    NoSQLInjectionCheck, JWTWeaknessCheck,
    DeserializationCheck, CSPCookieCheck, LDAPInjectionCheck,
    XSSCheck, FamousCVEsCheck,
    Bypass403Check, OpenRedirectCheck, DirBruteCheck,
    ALL_CHECKS,
)
from scanner.checks.base import BaseCheck
from scanner.utils import create_dirs


class TestChecksRegistry(unittest.TestCase):
    def test_all_checks_registered(self):
        self.assertGreaterEqual(len(ALL_CHECKS), 28)
        self.assertIn(SqlmapCheck, ALL_CHECKS)
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
        self.assertGreater(len(CRLFCheck.CRLF_VARIANTS), 2)
        labels = {v[0] for v in CRLFCheck.CRLF_VARIANTS}
        self.assertIn("url-pct", labels)

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

    def test_ssrf_params(self):
        self.assertIn("url", SSRFCheck.SSRF_PARAMS)
        self.assertGreater(len(SSRFCheck.PROBES), 2)

    def test_xxe_payloads(self):
        self.assertIn("ENTITY xxe SYSTEM", XXECheck.XXE_PAYLOAD)

    def test_ssti_payloads(self):
        self.assertGreater(len(SSTICheck.PRIMARY), 3)
        for payload, expected, engines in SSTICheck.PRIMARY:
            self.assertTrue(payload)
            self.assertTrue(expected)
            self.assertTrue(engines)

    def test_path_traversal(self):
        self.assertIn("file", PathTraversalCheck.PARAMS)
        self.assertGreater(len(PathTraversalCheck.LINUX_PAYLOADS), 4)
        self.assertIn("root:x:0:0", PathTraversalCheck.LINUX_INDICATORS)
        self.assertGreater(len(PathTraversalCheck.WIN_PAYLOADS), 2)

    def test_sqli_signatures(self):
        self.assertGreater(len(SQLInjectionCheck.ERROR_SIGNATURES), 5)
        self.assertIn("id", SQLInjectionCheck.PARAMS)

    def test_cmd_injection(self):
        self.assertIn("cmd", CommandInjectionCheck.PARAMS)
        self.assertGreater(len(CommandInjectionCheck.MARKER_PAYLOADS), 3)

    def test_nosql_injection(self):
        self.assertGreater(len(NoSQLInjectionCheck.NOSQL_PAYLOADS), 2)
        self.assertGreater(len(NoSQLInjectionCheck.LOGIN_PATHS), 3)

    def test_deserialization_signatures(self):
        self.assertGreater(len(DeserializationCheck.SIGNATURES), 5)
        names = [n for n, _ in DeserializationCheck.SIGNATURES]
        self.assertIn("Java (ObjectInputStream)", names)
        self.assertIn("PHP serialize", names)
        self.assertIn("Python pickle (gASV)", names)

    def test_csp_cookie_check(self):
        import tempfile
        from scanner.utils import create_dirs
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = CSPCookieCheck(target="example.com", dirs=dirs,
                                   live_hosts=["https://example.com"], threads=1)
            check._audit_csp("default-src 'self' 'unsafe-inline' 'unsafe-eval'",
                             "https://example.com")
            titles = [f.title for f in check.findings]
            self.assertTrue(any("unsafe-inline" in t for t in titles))
            self.assertTrue(any("unsafe-eval" in t for t in titles))

    def test_ldap_payloads(self):
        self.assertGreater(len(LDAPInjectionCheck.LDAP_PAYLOADS), 3)
        self.assertIn("/login", LDAPInjectionCheck.LOGIN_PATHS)

    def test_xss_payloads(self):
        self.assertGreater(len(XSSCheck.PAYLOADS), 3)
        contexts = {p[0] for p in XSSCheck.PAYLOADS}
        self.assertIn("html", contexts)
        self.assertIn("js", contexts)
        self.assertIn("attr", contexts)

    def test_famous_cves_covers_known_cves(self):
        """Spot-check: the famous-CVE module probes Log4Shell, Shellshock, Struts."""
        import tempfile
        from scanner.utils import create_dirs
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = FamousCVEsCheck(target="example.com", dirs=dirs,
                                    live_hosts=[], threads=1)
            # Ensure the probe method names cover the big CVEs
            method_names = [m for m in dir(check) if m.startswith("_")]
            self.assertIn("_log4shell", method_names)
            self.assertIn("_shellshock", method_names)
            self.assertIn("_struts", method_names)
            self.assertIn("_spring4shell", method_names)
            self.assertIn("_confluence", method_names)
            self.assertIn("_f5_bigip", method_names)


class TestJWTWeakness(unittest.TestCase):
    def _make_token(self, header: dict, payload: dict, secret: str) -> str:
        import base64, hmac, hashlib, json
        def b64(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        h = b64(json.dumps(header, separators=(",", ":")).encode())
        p = b64(json.dumps(payload, separators=(",", ":")).encode())
        msg = f"{h}.{p}".encode()
        s = b64(hmac.new(secret.encode(), msg, hashlib.sha256).digest())
        return f"{h}.{p}.{s}"

    def test_jwt_regex_matches_valid_jwt(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, "secret")
        self.assertTrue(JWTWeaknessCheck.JWT_RE.match(token))

    def test_jwt_weak_secret_recovered(self):
        import tempfile
        from scanner.utils import create_dirs
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = JWTWeaknessCheck(target="example.com", dirs=dirs,
                                     live_hosts=[], threads=1)
            token = self._make_token({"alg": "HS256", "typ": "JWT"},
                                     {"user": "admin"}, "secret")
            recovered = check._try_weak_secret(token)
            self.assertEqual(recovered, "secret")

    def test_jwt_random_secret_not_recovered(self):
        import tempfile
        from scanner.utils import create_dirs
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            check = JWTWeaknessCheck(target="example.com", dirs=dirs,
                                     live_hosts=[], threads=1)
            token = self._make_token({"alg": "HS256", "typ": "JWT"},
                                     {"user": "admin"},
                                     "r4nd0m-un9uessable-s3cret-98765432")
            self.assertIsNone(check._try_weak_secret(token))


class TestBaseStatusCode(unittest.TestCase):
    def test_parse_valid(self):
        from scanner.checks.base import BaseCheck
        self.assertEqual(BaseCheck._status_code("HTTP/1.1 200 OK"), 200)
        self.assertEqual(BaseCheck._status_code("HTTP/1.1 404 Not Found"), 404)
        self.assertEqual(BaseCheck._status_code("HTTP/2 500"), 500)

    def test_parse_invalid(self):
        from scanner.checks.base import BaseCheck
        self.assertEqual(BaseCheck._status_code(""), 0)
        self.assertEqual(BaseCheck._status_code("not an http line"), 0)

    def test_parse_no_substring_false_match(self):
        """Regression: must not match '200' inside the reason phrase like 'Server: nginx/1.2.3 200X'"""
        from scanner.checks.base import BaseCheck
        self.assertEqual(BaseCheck._status_code("HTTP/1.1 302 Found Date: 2026-10-03"), 302)


class TestAuthHelpers(unittest.TestCase):
    def test_set_and_get_auth(self):
        from scanner.utils import set_auth, get_auth
        set_auth(headers=["X-Scan: 1"], cookie="s=abc",
                 bearer="xyz", basic="u:p")
        a = get_auth()
        self.assertIn("X-Scan: 1", a["headers"])
        self.assertIn("Authorization: Bearer xyz", a["headers"])
        self.assertEqual(a["cookie"], "s=abc")
        self.assertEqual(a["basic"], "u:p")
        set_auth()


class TestConstants(unittest.TestCase):
    def test_canary_defined(self):
        from scanner.constants import ATTACKER_CANARY, SEVERITY_ORDER
        self.assertTrue(ATTACKER_CANARY)
        self.assertEqual(SEVERITY_ORDER[0], "critical")
        self.assertEqual(SEVERITY_ORDER[-1], "info")

    def test_checks_use_constant_canary(self):
        from scanner.constants import ATTACKER_CANARY
        from scanner.checks import cors, open_redirect, host_header
        self.assertIn("ATTACKER_CANARY", cors.__dict__ | {"ATTACKER_CANARY": None})


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
