import unittest

from tech_scan.normalize import expand_targets, normalize_target


class NormalizeTests(unittest.TestCase):
    def test_expand_bare_domain_to_http_and_https(self):
        self.assertEqual(
            [candidate.url for candidate in expand_targets("example.com")],
            ["http://example.com", "https://example.com"],
        )

    def test_expand_explicit_scheme_to_single_target(self):
        self.assertEqual(
            [candidate.url for candidate in expand_targets("http://example.com")],
            ["http://example.com"],
        )
        self.assertEqual(
            [candidate.url for candidate in expand_targets("https://example.com")],
            ["https://example.com"],
        )

    def test_expand_preserves_explicit_port_and_path(self):
        self.assertEqual(
            [candidate.url for candidate in expand_targets("https://example.com:8443/a/")],
            ["https://example.com:8443/a"],
        )

    def test_normalize_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            normalize_target("ftp://example.com")

    def test_bare_port_requires_scheme(self):
        with self.assertRaisesRegex(ValueError, "scheme is required"):
            expand_targets("example.com:8080")


if __name__ == "__main__":
    unittest.main()
