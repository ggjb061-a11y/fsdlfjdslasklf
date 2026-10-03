"""Tests for input validation functions."""
import unittest

from scanner.validators import (
    validate_target, validate_webhook_url, is_private_host, ValidationError,
)


class TestValidateTarget(unittest.TestCase):
    def test_valid_hostname(self):
        self.assertEqual(validate_target("example.com"), "example.com")
        self.assertEqual(validate_target("sub.example.com"), "sub.example.com")
        self.assertEqual(validate_target("foo-bar.example.co.uk"), "foo-bar.example.co.uk")

    def test_valid_ip(self):
        self.assertEqual(validate_target("8.8.8.8"), "8.8.8.8")
        self.assertEqual(validate_target("::1"), "::1")

    def test_strips_whitespace(self):
        self.assertEqual(validate_target("  example.com  "), "example.com")

    def test_rejects_leading_dash(self):
        with self.assertRaises(ValidationError):
            validate_target("-oG")
        with self.assertRaises(ValidationError):
            validate_target("--help")

    def test_rejects_shell_meta(self):
        for bad in ["a;b", "a|b", "a$b", "a`b", "a&b", "a>b", "a<b",
                    "a(b", "a)b", "a*b", "a?b", "a[b", "a]b", "a{b",
                    "a!b", "a#b", "a b", "a\tb", "a/b", "a\\b"]:
            with self.assertRaises(ValidationError):
                validate_target(bad)

    def test_rejects_control_chars(self):
        with self.assertRaises(ValidationError):
            validate_target("ex\x00ample.com")
        with self.assertRaises(ValidationError):
            validate_target("ex\nample.com")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_target("")
        with self.assertRaises(ValidationError):
            validate_target("   ")


class TestValidateWebhookURL(unittest.TestCase):
    def test_valid_https(self):
        self.assertEqual(
            validate_webhook_url("https://hooks.slack.com/foo/bar"),
            "https://hooks.slack.com/foo/bar",
        )

    def test_rejects_file_scheme(self):
        with self.assertRaises(ValidationError):
            validate_webhook_url("file:///etc/passwd")

    def test_rejects_gopher_scheme(self):
        with self.assertRaises(ValidationError):
            validate_webhook_url("gopher://127.0.0.1:11211/_")

    def test_rejects_leading_dash(self):
        with self.assertRaises(ValidationError):
            validate_webhook_url("-oTouch")

    def test_rejects_at_prefix(self):
        with self.assertRaises(ValidationError):
            validate_webhook_url("@/etc/passwd")

    def test_rejects_private_ip(self):
        with self.assertRaises(ValidationError):
            validate_webhook_url("http://127.0.0.1/webhook")
        with self.assertRaises(ValidationError):
            validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(ValidationError):
            validate_webhook_url("http://10.0.0.1/webhook")

    def test_allow_private_flag(self):
        self.assertEqual(
            validate_webhook_url("http://127.0.0.1/x", allow_private=True),
            "http://127.0.0.1/x",
        )


class TestIsPrivateHost(unittest.TestCase):
    def test_loopback(self):
        self.assertTrue(is_private_host("127.0.0.1"))
        self.assertTrue(is_private_host("::1"))

    def test_link_local(self):
        self.assertTrue(is_private_host("169.254.169.254"))

    def test_rfc1918(self):
        self.assertTrue(is_private_host("10.0.0.1"))
        self.assertTrue(is_private_host("172.16.0.1"))
        self.assertTrue(is_private_host("192.168.1.1"))

    def test_public_not_private(self):
        self.assertFalse(is_private_host("8.8.8.8"))
        self.assertFalse(is_private_host("1.1.1.1"))

    def test_hostname_not_private(self):
        self.assertFalse(is_private_host("example.com"))


if __name__ == "__main__":
    unittest.main()
