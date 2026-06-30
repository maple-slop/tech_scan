import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tech_scan.cache import ResponseCache
from tech_scan.models import FetchResult


def make_fetch(mode="requests"):
    return FetchResult(
        input="example.com",
        url="https://example.com",
        final_url="https://www.example.com",
        status=200,
        headers={"server": "Apache"},
        cookies={"session": "abc"},
        body='<html><script src="/app.js"></script></html>',
        mode=mode,
        browser_globals=["React", "__NEXT_DATA__"] if mode == "browser" else [],
        script_srcs=["https://www.example.com/app.js"] if mode == "browser" else ["/app.js"],
    )


class CacheTests(unittest.TestCase):
    def test_requests_observation_roundtrip(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", None, make_fetch())

                cached = cache.get("https://example.com", "requests", None, 86400)

            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertTrue(cached.cached)
            self.assertEqual(cached.final_url, "https://www.example.com")
            self.assertEqual(cached.status, 200)
            self.assertEqual(cached.headers, {"server": "Apache"})
            self.assertEqual(cached.cookies, {"session": "abc"})
            self.assertIn("/app.js", cached.script_srcs)

    def test_browser_observation_roundtrip(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "browser", None, make_fetch("browser"))

                cached = cache.get("https://example.com", "browser", None, 86400)

            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertEqual(cached.browser_globals, ["React", "__NEXT_DATA__"])
            self.assertEqual(cached.script_srcs, ["https://www.example.com/app.js"])

    def test_ttl_expiry_returns_none(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", None, make_fetch())
                cache.conn.execute(
                    "UPDATE fetch_observations SET updated_at = ?",
                    (int(time.time()) - 100,),
                )
                cache.conn.commit()

                self.assertIsNone(cache.get("https://example.com", "requests", None, 1))

    def test_provider_set_does_not_affect_cache_lookup(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", None, make_fetch())

                self.assertIsNotNone(cache.get("https://example.com", "requests", None, 86400))

    def test_mode_and_proxy_isolate_cache_rows(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", "http://proxy:8080", make_fetch())

                self.assertIsNone(cache.get("https://example.com", "requests", None, 86400))
                self.assertIsNone(cache.get("https://example.com", "browser", "http://proxy:8080", 86400))
                self.assertIsNotNone(
                    cache.get("https://example.com", "requests", "http://proxy:8080", 86400)
                )

    def test_tls_identity_isolates_cache_rows(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set(
                    "https://example.com",
                    "requests",
                    "http://proxy:8080",
                    make_fetch(),
                    "ca:/tmp/ca.pem",
                )

                self.assertIsNone(
                    cache.get(
                        "https://example.com",
                        "requests",
                        "http://proxy:8080",
                        86400,
                        "insecure",
                    )
                )
                self.assertIsNotNone(
                    cache.get(
                        "https://example.com",
                        "requests",
                        "http://proxy:8080",
                        86400,
                        "ca:/tmp/ca.pem",
                    )
                )


if __name__ == "__main__":
    unittest.main()
