"""Tests for the extended recon module (permutations, dorks, parsers)."""
import unittest

from scanner.recon_extended import permute_subdomains, TOP_100_SUBDOMAINS


class TestPermutations(unittest.TestCase):
    def test_permutation_generates_expected_names(self):
        existing = ["api.example.com", "www.example.com"]
        permuted = permute_subdomains(existing, "example.com")
        self.assertIn("api-dev.example.com", permuted)
        self.assertIn("dev-api.example.com", permuted)
        self.assertIn("api-staging.example.com", permuted)
        self.assertNotIn("api.example.com", permuted)
        self.assertNotIn("example.com", permuted)

    def test_empty_input_returns_empty(self):
        self.assertEqual(permute_subdomains([], "example.com"), [])

    def test_unrelated_subdomains_ignored(self):
        existing = ["foo.other.net", "api.example.com"]
        permuted = permute_subdomains(existing, "example.com")
        # foo should not appear because it's not under example.com
        self.assertFalse(any("foo-dev" in p for p in permuted))

    def test_wordlist_well_formed(self):
        self.assertEqual(len(TOP_100_SUBDOMAINS), len(set(TOP_100_SUBDOMAINS)))
        self.assertGreaterEqual(len(TOP_100_SUBDOMAINS), 100)
        self.assertIn("www", TOP_100_SUBDOMAINS)
        self.assertIn("api", TOP_100_SUBDOMAINS)
        self.assertIn("admin", TOP_100_SUBDOMAINS)


if __name__ == "__main__":
    unittest.main()
