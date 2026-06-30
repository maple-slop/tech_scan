import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tech_scan.cache import ResponseCache, is_cacheable_fetch
from tech_scan.models import FetchResult, ResourceObservation


def make_fetch(mode="requests"):
    document = ResourceObservation(
        id="document:0",
        kind="document",
        url="https://example.com",
        final_url="https://www.example.com",
        status=200,
        headers={"server": "Apache"},
        cookies={"session": "abc"},
        body='<html><script src="/app.js"></script></html>',
    )
    script = ResourceObservation(
        id="script:0",
        parent_id=document.id,
        kind="script",
        url="https://www.example.com/app.js",
        final_url="https://www.example.com/app.js",
        status=200,
        headers={"content-type": "application/javascript"},
        cookies={},
        body="React.version = '18.0.0'",
    )
    return FetchResult(
        input="example.com",
        url=document.url,
        final_url=document.final_url,
        status=document.status,
        headers=document.headers,
        cookies=document.cookies,
        body=document.body,
        mode=mode,
        browser_globals=["React", "__NEXT_DATA__"] if mode == "browser" else [],
        script_srcs=["https://www.example.com/app.js"],
        resources=[document, script],
        primary_resource_id=document.id,
    )


def make_primary_error_fetch(mode="browser"):
    error = "browser executable missing"
    document = ResourceObservation(
        id="document:0",
        kind="document",
        url="https://example.com",
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        error=error,
    )
    return FetchResult(
        input="example.com",
        url=document.url,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode=mode,
        error=error,
        resources=[document],
        primary_resource_id=document.id,
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
            self.assertIn("https://www.example.com/app.js", cached.script_srcs)
            self.assertEqual(cached.primary_resource.kind, "document")
            self.assertEqual(cached.script_resources[0].parent_id, cached.primary_resource_id)
            self.assertIn("React.version", cached.script_resources[0].body)

    def test_browser_observation_roundtrip(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "browser", None, make_fetch("browser"))

                cached = cache.get("https://example.com", "browser", None, 86400)

            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertEqual(cached.browser_globals, ["React", "__NEXT_DATA__"])
            self.assertEqual(cached.script_srcs, ["https://www.example.com/app.js"])

    def test_primary_fetcher_error_is_not_cacheable(self):
        self.assertFalse(is_cacheable_fetch(make_primary_error_fetch()))

        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "browser", None, make_primary_error_fetch())

                cached = cache.get("https://example.com", "browser", None, 86400)

            self.assertIsNone(cached)

    def test_stale_cached_primary_fetcher_error_is_ignored(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "browser", None, make_fetch("browser"))
                cache.conn.execute(
                    "UPDATE resources SET status = NULL, error = ? WHERE resource_id = ?",
                    ("old browser executable missing", "document:0"),
                )
                cache.conn.commit()

                cached = cache.get("https://example.com", "browser", None, 86400)

            self.assertIsNone(cached)

    def test_http_error_status_is_cacheable(self):
        fetch = make_fetch()
        document = ResourceObservation(
            id="document:0",
            kind="document",
            url="https://example.com",
            final_url="https://example.com",
            status=403,
            headers={"server": "cloudflare"},
            cookies={},
            body="Forbidden",
        )
        fetch = FetchResult(
            input=fetch.input,
            url=document.url,
            final_url=document.final_url,
            status=document.status,
            headers=document.headers,
            cookies=document.cookies,
            body=document.body,
            mode=fetch.mode,
            resources=[document],
            primary_resource_id=document.id,
        )

        self.assertTrue(is_cacheable_fetch(fetch))
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", None, fetch)

                cached = cache.get("https://example.com", "requests", None, 86400)

            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertEqual(cached.status, 403)

    def test_ttl_expiry_returns_none(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set("https://example.com", "requests", None, make_fetch())
                cache.conn.execute("UPDATE fetches SET updated_at = ?", (int(time.time()) - 100,))
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

    def test_browser_extension_identity_isolates_cache_rows(self):
        with TemporaryDirectory() as tmpdir:
            with ResponseCache(Path(tmpdir) / "results.db") as cache:
                cache.set(
                    "https://example.com",
                    "browser",
                    None,
                    make_fetch("browser"),
                    "default|extension:ubol:2026.628.2035",
                )

                self.assertIsNone(
                    cache.get(
                        "https://example.com",
                        "browser",
                        None,
                        86400,
                        "default|extension:none",
                    )
                )
                self.assertIsNotNone(
                    cache.get(
                        "https://example.com",
                        "browser",
                        None,
                        86400,
                        "default|extension:ubol:2026.628.2035",
                    )
                )


if __name__ == "__main__":
    unittest.main()
