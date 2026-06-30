import argparse
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tech_scan.cli import scan_target
from tech_scan.diagnostics import Diagnostics
from tech_scan.models import FetchResult


def args_for(db, provider_data=None, refresh=False, mode="requests", verbosity=0):
    return argparse.Namespace(
        db=db,
        mode=mode,
        proxy=None,
        timeout=1,
        concurrency=1,
        cache_ttl=86400,
        refresh=refresh,
        output="jsonl",
        verbosity=verbosity,
        ca_bundle=None,
        insecure=False,
        no_browser_extension=False,
        wappalyzer_data=provider_data,
    )


class CliCacheTests(unittest.TestCase):
    def test_cached_fetch_is_reused_with_different_provider_set(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            data_path = Path(tmpdir) / "fingerprints_data.json"
            data_path.write_text(
                json.dumps({"apps": {"Apache": {"cats": [22], "headers": {"server": "Apache"}}}}),
                encoding="utf-8",
            )
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

            with patch("tech_scan.cli.fetch_requests", return_value=fetch) as fetch_mock:
                first = scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
                second = scan_target(
                    "example.com",
                    args_for(db, data_path),
                    ["wappalyzer_json"],
                    ["wappalyzer_json"],
                )

            self.assertFalse(first["cached"])
            self.assertTrue(second["cached"])
            self.assertEqual(fetch_mock.call_count, 1)
            self.assertEqual(second["technologies"][0]["provider"], "wappalyzer_json")

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

            with patch("tech_scan.cli.fetch_requests", return_value=fetch) as fetch_mock:
                scan_target("example.com", args_for(db), ["builtin"], ["builtin"])
                refreshed = scan_target(
                    "example.com",
                    args_for(db, refresh=True),
                    ["builtin"],
                    ["builtin"],
                )

            self.assertFalse(refreshed["cached"])
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

            with patch("tech_scan.cli.fetch_requests", return_value=fetch):
                with patch("tech_scan.cli.fetch_browser") as browser_mock:
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
                error="old browser missing",
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

            with patch("tech_scan.cli.fetch_browser", side_effect=[first_fetch, second_fetch]) as fetch_mock:
                with patch.dict("os.environ", {"CHROMIUM_PATH": "/old/chrome"}):
                    first = scan_target("example.com", args, ["builtin"], ["builtin"])
                with patch.dict("os.environ", {"CHROMIUM_PATH": "/new/chrome"}):
                    second = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertFalse(first["cached"])
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

            with patch("tech_scan.cli.fetch_browser", side_effect=[failed_fetch, successful_fetch]) as fetch_mock:
                first = scan_target("example.com", args, ["builtin"], ["builtin"])
                second = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertFalse(first["cached"])
            self.assertFalse(second["cached"])
            self.assertEqual(fetch_mock.call_count, 2)
            self.assertEqual(second["status"], 200)

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

            with patch("tech_scan.cli.fetch_requests", return_value=fetch):
                with patch("tech_scan.cli.fetch_browser", return_value=browser_fetch):
                    result = scan_target("example.com", args, ["builtin"], ["builtin"])

            self.assertEqual(result["mode"], "browser")
            self.assertIn("auto switching fetcher", stderr.getvalue())
            self.assertIn("reason=blocking-status-403", stderr.getvalue())

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
            with patch("tech_scan.cli.fetch_requests", side_effect=fake_fetch_requests):
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

            with patch("tech_scan.cli.fetch_requests", return_value=fetch):
                scan_target("example.com", args, ["builtin"], ["builtin"])

            logs = stderr.getvalue()
            self.assertIn("cache miss", logs)
            self.assertIn("fetch start", logs)
            self.assertIn("fetch end", logs)
            self.assertIn("cache write", logs)
            self.assertIn("providers complete", logs)


if __name__ == "__main__":
    unittest.main()
