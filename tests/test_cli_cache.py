import argparse
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tech_scan.cli import scan_target
from tech_scan.models import FetchResult


def args_for(db, provider_data=None, refresh=False):
    return argparse.Namespace(
        db=db,
        mode="requests",
        proxy=None,
        timeout=1,
        concurrency=1,
        cache_ttl=86400,
        refresh=refresh,
        output="jsonl",
        wappalyzergo_cmd=None,
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


if __name__ == "__main__":
    unittest.main()
