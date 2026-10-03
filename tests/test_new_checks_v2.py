"""Tests for the 8 new checks added in v4.1."""
import tempfile
import unittest
from unittest.mock import patch

from scanner.utils import create_dirs


class TestGraphQLDeep(unittest.TestCase):
    def test_class_metadata(self):
        from scanner.checks.graphql_deep import GraphQLDeepCheck
        self.assertEqual(GraphQLDeepCheck.name, "GraphQL Deep")
        self.assertIn("/graphql", GraphQLDeepCheck.PATHS)
        self.assertIn("users", GraphQLDeepCheck.SENSITIVE_FIELDS)
        self.assertIn("__schema", GraphQLDeepCheck.INTROSPECTION_QUERY)


class TestOpenAPIFuzzer(unittest.TestCase):
    def test_sample_value(self):
        from scanner.checks.openapi_fuzzer import OpenAPIFuzzerCheck
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            c = OpenAPIFuzzerCheck(target="example.com", dirs=dirs,
                                    live_hosts=["https://example.com"], threads=1)
            self.assertEqual(c._sample_value({"type": "integer"}), "1")
            self.assertEqual(c._sample_value({"type": "boolean"}), "true")
            self.assertEqual(c._sample_value({"type": "string"}), "test")

    def test_build_path_replaces_vars(self):
        from scanner.checks.openapi_fuzzer import OpenAPIFuzzerCheck
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            c = OpenAPIFuzzerCheck(target="example.com", dirs=dirs,
                                    live_hosts=["https://example.com"], threads=1)
            params = [
                {"name": "id", "in": "path", "schema": {"type": "integer"}},
                {"name": "limit", "in": "query", "schema": {"type": "integer"}},
            ]
            filled, query = c._build_path("/users/{id}", params)
            self.assertEqual(filled, "/users/1")
            self.assertEqual(query, {"limit": "1"})


class TestOAuthSAML(unittest.TestCase):
    def test_class_metadata(self):
        from scanner.checks.oauth_saml import OAuthSAMLCheck
        self.assertIn("/oauth/authorize", OAuthSAMLCheck.AUTHORIZE_PATHS)
        self.assertIn("/saml/metadata", OAuthSAMLCheck.SAML_METADATA_PATHS)
        self.assertEqual(OAuthSAMLCheck.OIDC_WELL_KNOWN,
                         "/.well-known/openid-configuration")


class TestSessionMgmt(unittest.TestCase):
    def test_shannon_entropy(self):
        from scanner.checks.session_mgmt import SessionMgmtCheck
        self.assertEqual(SessionMgmtCheck._shannon_entropy(""), 0.0)
        self.assertAlmostEqual(SessionMgmtCheck._shannon_entropy("aaaa"), 0.0)
        self.assertGreater(SessionMgmtCheck._shannon_entropy("abcdefghij"), 3.0)
        self.assertGreater(SessionMgmtCheck._shannon_entropy("Lx7y9pQ3kR"), 3.0)
        # Low entropy
        self.assertLess(SessionMgmtCheck._shannon_entropy("aaaaab"), 1.5)

    def test_parse_set_cookie(self):
        import tempfile
        from scanner.checks.session_mgmt import SessionMgmtCheck
        with tempfile.TemporaryDirectory() as tmp:
            dirs = create_dirs(tmp, "example.com")
            c = SessionMgmtCheck(target="example.com", dirs=dirs,
                                  live_hosts=[], threads=1)
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Set-Cookie: session=abc123; HttpOnly; Secure; Path=/; SameSite=Lax\r\n"
                "Set-Cookie: csrftoken=xyz; HttpOnly\r\n"
            )
            cookies = c._parse_set_cookie_lines(headers)
            self.assertEqual(len(cookies), 2)
            self.assertEqual(cookies[0][0], "session")
            self.assertEqual(cookies[0][1], "abc123")
            self.assertTrue(cookies[0][2].get("httponly"))
            self.assertTrue(cookies[0][2].get("secure"))

    def test_session_name_regex(self):
        from scanner.checks.session_mgmt import SessionMgmtCheck
        for n in ["sessionid", "PHPSESSID", "JSESSIONID", "auth_token"]:
            self.assertTrue(SessionMgmtCheck.SESSION_COOKIE_NAMES.search(n))
        for n in ["banner", "theme", "preference"]:
            self.assertFalse(SessionMgmtCheck.SESSION_COOKIE_NAMES.search(n))


class TestPrototypePollution(unittest.TestCase):
    def test_class_metadata(self):
        from scanner.checks.prototype_pollution import PrototypePollutionCheck
        self.assertGreater(len(PrototypePollutionCheck.PAYLOADS), 2)
        self.assertTrue(any("__proto__" in p for p in PrototypePollutionCheck.PAYLOADS))
        self.assertTrue(any("constructor" in p for p in PrototypePollutionCheck.PAYLOADS))


class TestMassAssignment(unittest.TestCase):
    def test_privileged_fields(self):
        from scanner.checks.mass_assignment import MassAssignmentCheck
        for k in ["role", "is_admin", "verified", "premium"]:
            self.assertIn(k, MassAssignmentCheck.PRIVILEGED_FIELDS)

    def test_target_paths(self):
        from scanner.checks.mass_assignment import MassAssignmentCheck
        self.assertIn("/api/register", MassAssignmentCheck.TARGET_PATHS)
        self.assertIn("/signup", MassAssignmentCheck.TARGET_PATHS)


class TestFormFuzzer(unittest.TestCase):
    def _check(self):
        from scanner.checks.form_fuzzer import FormFuzzerCheck
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return FormFuzzerCheck(target="example.com", dirs=dirs,
                                live_hosts=["https://example.com"], threads=1)

    def test_extract_forms(self):
        c = self._check()
        html = """
        <form action="/login" method="post">
          <input name="username" type="text">
          <input name="password" type="password">
        </form>
        <form action="/search" method="get">
          <input name="q" type="search">
        </form>
        """
        forms = c._extract_forms(html, "https://example.com/")
        self.assertEqual(len(forms), 2)
        self.assertEqual(forms[0]["action"], "https://example.com/login")
        names = [n for n, _t, _v in forms[0]["inputs"]]
        self.assertIn("username", names)
        self.assertIn("password", names)


class TestEmailHeaderInjection(unittest.TestCase):
    def _check(self):
        from scanner.checks.email_header_injection import EmailHeaderInjectionCheck
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dirs = create_dirs(tmp.name, "example.com")
        return EmailHeaderInjectionCheck(target="example.com", dirs=dirs,
                                          live_hosts=["https://example.com"], threads=1)

    def test_extracts_only_mail_forms(self):
        c = self._check()
        html = """
        <form action="/subscribe" method="post">
          <input name="email" type="email">
          <input name="name" type="text">
        </form>
        <form action="/search" method="get">
          <input name="q" type="search">
        </form>
        """
        forms = c._extract_mail_forms(html, "https://example.com/")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "https://example.com/subscribe")


class TestRegistry(unittest.TestCase):
    def test_all_8_registered(self):
        from scanner.checks import (
            ALL_CHECKS, GraphQLDeepCheck, OpenAPIFuzzerCheck, OAuthSAMLCheck,
            SessionMgmtCheck, PrototypePollutionCheck, MassAssignmentCheck,
            FormFuzzerCheck, EmailHeaderInjectionCheck,
        )
        for cls in (GraphQLDeepCheck, OpenAPIFuzzerCheck, OAuthSAMLCheck,
                     SessionMgmtCheck, PrototypePollutionCheck,
                     MassAssignmentCheck, FormFuzzerCheck,
                     EmailHeaderInjectionCheck):
            self.assertIn(cls, ALL_CHECKS)
        self.assertGreaterEqual(len(ALL_CHECKS), 42)


class TestLinkFinderExtraction(unittest.TestCase):
    def test_linkfinder_regex(self):
        from scanner.js_analyzer import LINKFINDER_RE
        content = '''
        const api = "/api/v1/users";
        const html = "/pages/profile.html";
        const absolute = "https://api.example.com/orders";
        var dot = "../admin/panel";
        '''
        matches = [m.group(1) for m in LINKFINDER_RE.finditer(content)]
        self.assertTrue(any("/api/v1/users" in m for m in matches))
        self.assertTrue(any("/pages/profile.html" in m for m in matches))
        self.assertTrue(any("api.example.com" in m for m in matches))


if __name__ == "__main__":
    unittest.main()
