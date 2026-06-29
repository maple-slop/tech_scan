import unittest

from tech_scan.normalize import http_fallback_url, normalize_target


class NormalizeTests(unittest.TestCase):
    def test_normalize_bare_domain_defaults_to_https(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_normalize_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")

    def test_http_fallback_only_for_https(self):
        self.assertEqual(http_fallback_url("https://example.com/a"), "http://example.com/a")
        self.assertIsNone(http_fallback_url("http://example.com/a"))


if __name__ == "__main__":
    unittest.main()
