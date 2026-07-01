import argparse
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tech_scan.diagnostics import Diagnostics
from tech_scan.models import FetchResult
from tech_scan.scanner import scan_input, scan_target as scan_concrete_target
from tech_scan.sanity import SanityResult


def args_for(db, refresh=False, mode="requests", verbosity=0):
    return argparse.Namespace(
        db=db,
        mode=mode,
        proxy=None,
        timeout=1,
        sanity_timeout=1,
        concurrency=1,
        cache_ttl=86400,
        refresh=refresh,
        output="jsonl",
        verbosity=verbosity,
        ca_bundle=None,
        insecure=False,
        no_browser_extension=False,
    )


def scan_target(raw_target, args, providers_requested, provider_names, browser_session=None):
    return scan_concrete_target(
        raw_target,
        f"https://{raw_target}",
        args,
        providers_requested,
        provider_names,
        browser_session,
    )


class CliCacheTests(unittest.TestCase):
    def setUp(self):
        self.sanity_patch = None
        self.sanity_mock = None
        self.set_sanity_result(
            SanityResult("ok", "example.com", (443,), open_ip="192.0.2.1", open_port=443)
        )

    def tearDown(self):
        if self.sanity_patch is not None:
            self.sanity_patch.stop()

    def set_sanity_result(self, result):
        if self.sanity_patch is not None:
            self.sanity_patch.stop()
        self.sanity_patch = patch(
            "tech_scan.scanner.check_target_ports",
            return_value=result,
        )
        self.sanity_mock = self.sanity_patch.start()

    def test_scan_input_expands_bare_domain_to_http_and_https(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetches = [
                FetchResult(
                    input="example.com",
                    url="http://example.com",
                    final_url="http://example.com",
                    status=200,
                    headers={},
                    cookies={},
                    body="http",
                    mode="requests",
                ),
                FetchResult(
                    input="example.com",
                    url="https://example.com",
                    final_url="https://example.com",
                    status=200,
                    headers={},
                    cookies={},
                    body="https",
                    mode="requests",
                ),
            ]

            with patch("tech_scan.scanner.fetch_requests", side_effect=fetches) as fetch_mock:
                results = scan_input("example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertEqual([result["url"] for result in results], ["http://example.com", "https://example.com"])
        self.assertEqual([call.args[1] for call in fetch_mock.call_args_list], ["http://example.com", "https://example.com"])

    def test_scan_input_preserves_concrete_url_when_http_redirects_to_https(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetches = [
                FetchResult(
                    input="example.com",
                    url="http://example.com",
                    final_url="https://example.com",
                    status=301,
                    headers={},
                    cookies={},
                    body="",
                    mode="requests",
                ),
                FetchResult(
                    input="example.com",
                    url="https://example.com",
                    final_url="https://example.com",
                    status=200,
                    headers={},
                    cookies={},
                    body="https",
                    mode="requests",
                ),
            ]

            with patch("tech_scan.scanner.fetch_requests", side_effect=fetches):
                results = scan_input("example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertEqual([result["url"] for result in results], ["http://example.com", "https://example.com"])
        self.assertEqual([result["final_url"] for result in results], ["https://example.com", "https://example.com"])

    def test_scan_input_explicit_scheme_uses_single_concrete_target(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="https://example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={},
                cookies={},
                body="https",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch) as fetch_mock:
                results = scan_input("https://example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://example.com")
        self.assertEqual(fetch_mock.call_args.args[1], "https://example.com")

    def test_scan_input_rejects_port_without_scheme(self):
        with TemporaryDirectory() as tmpdir:
            results = scan_input(
                "example.com:8080",
                args_for(Path(tmpdir) / "results.db"),
                ["builtin"],
                ["builtin"],
            )

        self.assertEqual(len(results), 1)
        self.assertIsNone(results[0]["url"])
        self.assertIn("scheme is required", results[0]["error"])

    def test_cached_fetch_is_reused_with_different_provider_set(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "Apache"},
                cookies={},
                body="",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch) as fetch_mock:
                first = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
                second = scan_target(
                    "example.com",
                    args_for(db),
                    ["all"],
                    ["builtin", "wappalyzergo"],
                )

            self.assertFalse(first["cached"])
            self.assertEqual(first["cache_lookup"], "miss")
            self.assertTrue(first["cache_stored"])
            self.assertEqual(first["cache_reason"], "http-status-200")
            self.assertTrue(second["cached"])
            self.assertEqual(second["cache_lookup"], "hit")
            self.assertIsNone(second["cache_stored"])
            self.assertIsNone(second["cache_reason"])
            self.assertEqual(fetch_mock.call_count, 1)
            self.assertEqual(second["providers"], ["builtin", "wappalyzergo"])

    def test_refresh_forces_new_fetch_write(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "Apache"},
                cookies={},
                body="",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch) as fetch_mock:
                scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
                refreshed = scan_target(
                    "example.com",
                    args_for(db, refresh=True),
                    ["builtin"],
                    ["builtin"],
                )

            self.assertFalse(refreshed["cached"])
            self.assertEqual(refreshed["cache_lookup"], "refresh")
            self.assertTrue(refreshed["cache_stored"])
            self.assertEqual(refreshed["cache_reason"], "http-status-200")
            self.assertEqual(fetch_mock.call_count, 2)

    def test_auto_mode_small_static_response_does_not_call_browser(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "example"},
                cookies={},
                body="<html><body>Example Domain</body></html>",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                with patch("tech_scan.scanner.fetch_browser_async") as browser_mock:
                    result = scan_target(
                        "example.com",
                        args_for(db, mode="auto"),
                        ["builtin"],
                        ["builtin"],
                    )

            self.assertEqual(result["mode"], "requests")
            browser_mock.assert_not_called()

    def test_browser_cache_identity_includes_chromium_path_env(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            first_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error="browser executable missing",
            )
            second_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "example"},
                cookies={},
                body="<html><body>Example Domain</body></html>",
                mode="browser",
            )
            args = args_for(db, mode="browser")

            with patch("tech_scan.scanner.fetch_browser_async", side_effect=[first_fetch, second_fetch]) as fetch_mock:
                with patch.dict("os.environ", {"CHROMIUM_PATH": "/old/chrome"}):
                    first = scan_target("example.com", args, ["builtin"], ["builtin"])
                with patch.dict("os.environ", {"CHROMIUM_PATH": "/new/chrome"}):
                    second = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertFalse(first["cached"])
            self.assertEqual(first["cache_lookup"], "miss")
            self.assertFalse(first["cache_stored"])
            self.assertEqual(first["cache_reason"], "local-client-error")
            self.assertFalse(second["cached"])
            self.assertEqual(fetch_mock.call_count, 2)
            self.assertEqual(second["status"], 200)

    def test_browser_fetcher_failure_is_not_cached(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            failed_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error="browser executable missing",
            )
            successful_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "example"},
                cookies={},
                body="<html><body>Example Domain</body></html>",
                mode="browser",
            )
            args = args_for(db, mode="browser")

            with patch("tech_scan.scanner.fetch_browser_async", side_effect=[failed_fetch, successful_fetch]) as fetch_mock:
                first = scan_target("example.com", args, ["builtin"], ["builtin"])
                second = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertFalse(first["cached"])
            self.assertEqual(first["cache_lookup"], "miss")
            self.assertFalse(first["cache_stored"])
            self.assertEqual(first["cache_reason"], "local-client-error")
            self.assertFalse(second["cached"])
            self.assertEqual(fetch_mock.call_count, 2)
            self.assertEqual(second["status"], 200)

    def test_redirect_status_response_is_cached_and_reported(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            redirect_fetch = FetchResult(
                input="https://example.com",
                url="https://example.com",
                final_url="https://example.com/login",
                status=301,
                headers={"location": "/login"},
                cookies={},
                body="",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=redirect_fetch) as fetch_mock:
                first = scan_input(
                    "https://example.com",
                    args_for(db),
                    ["builtin"],
                    ["builtin"],
                )[0]
                second = scan_input(
                    "https://example.com",
                    args_for(db),
                    ["builtin"],
                    ["builtin"],
                )[0]

        self.assertFalse(first["cached"])
        self.assertEqual(first["status"], 301)
        self.assertEqual(first["cache_lookup"], "miss")
        self.assertTrue(first["cache_stored"])
        self.assertEqual(first["cache_reason"], "http-status-301")
        self.assertTrue(second["cached"])
        self.assertEqual(second["status"], 301)
        self.assertEqual(second["cache_lookup"], "hit")
        self.assertIsNone(second["cache_stored"])
        self.assertEqual(fetch_mock.call_count, 1)

    def test_cross_host_redirect_block_is_cached_and_reported(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            blocked_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error="blocked cross-host redirect to https://idp.example.net/sso",
            )
            args = args_for(db, mode="browser")

            with patch("tech_scan.scanner.fetch_browser_async", return_value=blocked_fetch) as fetch_mock:
                first = scan_target("example.com", args, ["builtin"], ["builtin"])
                second = scan_target("example.com", args, ["builtin"], ["builtin"])

        self.assertFalse(first["cached"])
        self.assertEqual(first["cache_lookup"], "miss")
        self.assertTrue(first["cache_stored"])
        self.assertEqual(first["cache_reason"], "blocked-cross-host-redirect")
        self.assertTrue(second["cached"])
        self.assertEqual(second["cache_lookup"], "hit")
        self.assertEqual(fetch_mock.call_count, 1)

    def test_auto_mode_logs_browser_fallback_reason_at_verbosity_one(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            stderr = io.StringIO()
            args = args_for(db, mode="auto", verbosity=1)
            args._diagnostics = Diagnostics(verbosity=1, stream=stderr)
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=403,
                headers={},
                cookies={},
                body="blocked",
                mode="requests",
            )
            browser_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "example"},
                cookies={},
                body="<html><body>Example Domain</body></html>",
                mode="browser",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                with patch("tech_scan.scanner.fetch_browser_async", return_value=browser_fetch):
                    result = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertEqual(result["mode"], "browser")
            self.assertIn("auto switching fetcher", stderr.getvalue())
            self.assertIn("reason=blocking-status-403", stderr.getvalue())

    def test_auto_mode_logs_cdn_waf_browser_fallback_reason(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            stderr = io.StringIO()
            args = args_for(db, mode="auto", verbosity=1)
            args._diagnostics = Diagnostics(verbosity=1, stream=stderr)
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"cf-ray": "abc-TPE", "server": "cloudflare"},
                cookies={},
                body="<html><title>Just a moment...</title>/cdn-cgi/challenge-platform/</html>",
                mode="requests",
            )
            browser_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "example"},
                cookies={},
                body="<html><body>Example Domain</body></html>",
                mode="browser",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                with patch("tech_scan.scanner.fetch_browser_async", return_value=browser_fetch):
                    result = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertEqual(result["mode"], "browser")
            self.assertIn("reason=cdn-waf-challenge", stderr.getvalue())
            self.assertNotIn("browser_fallback_failed", str(result["observations"]))

    def test_auto_mode_warns_when_cdn_waf_fallback_browser_also_fails(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            args = args_for(db, mode="auto")
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=451,
                headers={"x-iinfo": "1-123"},
                cookies={},
                body="blocked",
                mode="requests",
            )
            browser_fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error="browser failed",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                with patch("tech_scan.scanner.fetch_browser_async", return_value=browser_fetch):
                    result = scan_target("example.com", args, ["builtin"], ["builtin"])

        self.assertEqual(result["mode"], "requests")
        self.assertIn(
            {
                "kind": "auto",
                "name": "browser_fallback_failed",
                "value": (
                    "requests looked blocked by CDN/WAF "
                    "(reason=cdn-waf-blocking-status-451); browser also failed: browser failed"
                ),
            },
            result["observations"],
        )

    def test_top_level_error_traceback_depends_on_verbosity(self):
        def fake_fetch_requests(*args, **kwargs):
            error = "connection failed"
            if kwargs.get("include_traceback"):
                error += "\nTraceback (most recent call last):\n  fake"
            return FetchResult(
                input="example.com",
                url="https://example.com",
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="requests",
                error=error,
            )

        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            with patch("tech_scan.scanner.fetch_requests", side_effect=fake_fetch_requests):
                quiet = scan_target(
                    "example.com",
                    args_for(db, mode="requests", verbosity=0),
                    ["builtin"],
                    ["builtin"],
                )
                verbose = scan_target(
                    "example.org",
                    args_for(db, mode="requests", verbosity=2),
                    ["builtin"],
                    ["builtin"],
                )

        self.assertNotIn("Traceback", quiet["error"])
        self.assertIn("Traceback (most recent call last):", verbose["error"])

    def test_verbosity_three_logs_cache_fetch_and_provider_details(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            stderr = io.StringIO()
            args = args_for(db, mode="requests", verbosity=3)
            args._diagnostics = Diagnostics(verbosity=3, stream=stderr)
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "Apache"},
                cookies={},
                body="",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                scan_target("example.com", args, ["builtin"], ["builtin"])

            logs = stderr.getvalue()
            self.assertIn("cache miss", logs)
            self.assertIn("fetch start", logs)
            self.assertIn("fetch end", logs)
            self.assertIn("cache write", logs)
            self.assertIn("reason=http-status-200", logs)
            self.assertIn("providers complete", logs)

    def test_cache_hit_bypasses_sanity_check(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={"server": "Apache"},
                cookies={},
                body="",
                mode="requests",
            )

            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
            self.sanity_mock.reset_mock()
            with patch("tech_scan.scanner.fetch_requests") as fetch_mock:
                result = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

            self.assertTrue(result["cached"])
            self.assertIsNotNone(result["cache_created_at"])
            self.assertIsNotNone(result["cache_updated_at"])
            self.sanity_mock.assert_not_called()
            fetch_mock.assert_not_called()

    def test_sanity_failure_skips_fetcher(self):
        self.set_sanity_result(
            SanityResult(
                "no-open-port",
                "example.com",
                (80, 443),
                error="sanity check failed: no open port for example.com on 80,443",
            )
        )
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            with patch("tech_scan.scanner.fetch_requests") as fetch_mock:
                result = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

            fetch_mock.assert_not_called()
            self.assertIsNone(result["status"])
            self.assertIn("sanity check failed", result["error"])
            again = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertTrue(again["cached"])
        self.assertEqual(again["error"], result["error"])
        self.assertEqual(self.sanity_mock.call_count, 1)

    def test_refresh_reruns_cached_sanity_failure(self):
        self.set_sanity_result(
            SanityResult(
                "no-open-port",
                "example.com",
                (80, 443),
                error="sanity check failed: no open port for example.com on 80,443",
            )
        )
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
            refreshed = scan_target(
                "example.com",
                args_for(db, refresh=True),
                ["builtin"],
                ["builtin"],
            )

        self.assertFalse(refreshed["cached"])
        self.assertEqual(self.sanity_mock.call_count, 2)

    def test_sanity_pass_calls_fetcher(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={},
                cookies={},
                body="ok",
                mode="requests",
            )
            with patch("tech_scan.scanner.fetch_requests", return_value=fetch) as fetch_mock:
                result = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

            self.assertEqual(result["status"], 200)
            fetch_mock.assert_called_once()

    def test_sanity_failure_logs_to_stderr_at_verbosity_one(self):
        stderr = io.StringIO()
        args = args_for(Path("/tmp/sanity-test.db"), verbosity=1)
        args._diagnostics = Diagnostics(verbosity=1, stream=stderr)
        self.set_sanity_result(
            SanityResult(
                "no-open-port",
                "example.com",
                (80, 443),
                error="sanity check failed: no open port for example.com on 80,443",
            )
        )
        with TemporaryDirectory() as tmpdir:
            args.db = Path(tmpdir) / "results.db"
            scan_target("example.com", args, ["builtin"], ["builtin"])

        self.assertIn("sanity skip fetcher", stderr.getvalue())

    def test_unrecognized_signature_headers_are_raw_observations(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={
                    "server": "WeirdServer/9.9",
                    "x-powered-by": "SomethingCustom",
                },
                cookies={},
                body="ok",
                mode="requests",
            )
            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                result = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertEqual(
            result["observations"],
            [
                {"kind": "header", "name": "Server", "value": "WeirdServer/9.9"},
                {"kind": "header", "name": "X-Powered-By", "value": "SomethingCustom"},
            ],
        )
        self.assertEqual(result["technologies"], [])

    def test_recognized_header_evidence_is_not_duplicated_as_observation(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = FetchResult(
                input="example.com",
                url="https://example.com",
                final_url="https://example.com",
                status=200,
                headers={
                    "server": "nginx",
                    "x-powered-by": "SomethingCustom",
                },
                cookies={},
                body="ok",
                mode="requests",
            )
            with patch("tech_scan.scanner.fetch_requests", return_value=fetch):
                result = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])

        self.assertEqual(
            result["observations"],
            [{"kind": "header", "name": "X-Powered-By", "value": "SomethingCustom"}],
        )
        self.assertEqual(result["technologies"][0]["name"], "nginx")
        self.assertIn("Server: nginx", result["technologies"][0]["evidence"])


if __name__ == "__main__":
    unittest.main()
