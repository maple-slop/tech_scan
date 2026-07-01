import argparse
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

from tech_scan.diagnostics import Diagnostics
from tech_scan.fetch_pipeline import FetchPipeline
from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.sanity import SanityResult


def args_for(db, refresh=False, mode="requests"):
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
        verbosity=0,
        ca_bundle=None,
        insecure=False,
        no_browser_extension=False,
    )


async def run_blocking_direct(func, *args, **kwargs):
    return func(*args, **kwargs)


def ok_sanity():
    return SanityResult("ok", "example.com", (443,), open_ip="192.0.2.1", open_port=443)


def document_fetch(mode="requests", url="https://example.com", status=200, error=None):
    return FetchResult(
        input="example.com",
        url=url,
        final_url=url if status else None,
        status=status,
        headers={"server": "example"},
        cookies={},
        body="ok" if not error else "",
        mode=mode,
        error=error,
    )


class FetchPipelineTests(unittest.IsolatedAsyncioTestCase):
    def pipeline(self, args):
        return FetchPipeline(args, None, run_blocking_direct, Diagnostics(0))

    async def test_cache_hit_returns_cached_fetch_and_hit_outcome(self):
        with TemporaryDirectory() as tmpdir:
            args = args_for(Path(tmpdir) / "results.db")
            fetch = document_fetch()

            with patch("tech_scan.fetch_pipeline.check_target_ports", return_value=ok_sanity()):
                with patch("tech_scan.fetch_pipeline.fetch_requests", return_value=fetch) as fetch_mock:
                    first, first_outcome = await self.pipeline(args).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )
                    second, second_outcome = await self.pipeline(args).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )

        self.assertFalse(first.cached)
        self.assertEqual(first_outcome.lookup, "miss")
        self.assertTrue(first_outcome.stored)
        self.assertEqual(first_outcome.reason, "http-status-200")
        self.assertTrue(second.cached)
        self.assertEqual(second_outcome.lookup, "hit")
        self.assertIsNone(second_outcome.stored)
        self.assertIsNone(second_outcome.reason)
        self.assertEqual(fetch_mock.call_count, 1)

    async def test_refresh_bypasses_cache_lookup_and_writes_fresh_fetch(self):
        with TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "results.db"
            fetch = document_fetch()

            with patch("tech_scan.fetch_pipeline.check_target_ports", return_value=ok_sanity()):
                with patch("tech_scan.fetch_pipeline.fetch_requests", return_value=fetch) as fetch_mock:
                    await self.pipeline(args_for(db)).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )
                    refreshed, outcome = await self.pipeline(args_for(db, refresh=True)).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )

        self.assertFalse(refreshed.cached)
        self.assertEqual(outcome.lookup, "refresh")
        self.assertTrue(outcome.stored)
        self.assertEqual(outcome.reason, "http-status-200")
        self.assertEqual(fetch_mock.call_count, 2)

    async def test_sanity_failure_is_cached_and_skips_fetcher(self):
        sanity = SanityResult(
            "no-open-port",
            "example.com",
            (443,),
            error="sanity check failed: no open port for example.com on 443",
        )
        with TemporaryDirectory() as tmpdir:
            args = args_for(Path(tmpdir) / "results.db")
            with patch("tech_scan.fetch_pipeline.check_target_ports", return_value=sanity):
                with patch("tech_scan.fetch_pipeline.fetch_requests") as fetch_mock:
                    fetch, outcome = await self.pipeline(args).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )

        self.assertIn("sanity check failed", fetch.error)
        self.assertEqual(fetch.resources[0].kind, "sanity")
        self.assertEqual(outcome.lookup, "miss")
        self.assertTrue(outcome.stored)
        self.assertEqual(outcome.reason, "sanity-no-open-port")
        fetch_mock.assert_not_called()

    async def test_browser_local_client_failure_is_not_cached(self):
        failed_fetch = document_fetch(
            mode="browser",
            url="https://example.com",
            status=None,
            error="browser executable missing",
        )
        with TemporaryDirectory() as tmpdir:
            args = args_for(Path(tmpdir) / "results.db", mode="browser")
            browser_mock = AsyncMock(return_value=failed_fetch)

            with patch("tech_scan.fetch_pipeline.check_target_ports", return_value=ok_sanity()):
                with patch("tech_scan.fetch_pipeline.fetch_browser_async", browser_mock):
                    fetch, outcome = await self.pipeline(args).fetch(
                        "browser",
                        "example.com",
                        "https://example.com",
                    )

        self.assertEqual(fetch.error, "browser executable missing")
        self.assertEqual(outcome.lookup, "miss")
        self.assertFalse(outcome.stored)
        self.assertEqual(outcome.reason, "local-client-error")

    async def test_same_host_redirect_alias_is_written(self):
        redirect = ResourceObservation(
            id="redirect:0",
            kind="redirect",
            url="http://example.com",
            final_url="https://example.com",
            status=301,
            headers={"location": "https://example.com"},
            cookies={},
            body="",
        )
        document = ResourceObservation(
            id="document:0",
            kind="document",
            url="http://example.com",
            final_url="https://example.com",
            status=200,
            headers={"server": "example"},
            cookies={},
            body="ok",
        )
        fetch = FetchResult(
            input="example.com",
            url=document.url,
            final_url=document.final_url,
            status=document.status,
            headers=document.headers,
            cookies=document.cookies,
            body=document.body,
            mode="requests",
            resources=[redirect, document],
            primary_resource_id=document.id,
        )

        with TemporaryDirectory() as tmpdir:
            args = args_for(Path(tmpdir) / "results.db")
            with patch("tech_scan.fetch_pipeline.check_target_ports", return_value=ok_sanity()):
                with patch("tech_scan.fetch_pipeline.fetch_requests", return_value=fetch) as fetch_mock:
                    first, first_outcome = await self.pipeline(args).fetch(
                        "requests",
                        "example.com",
                        "http://example.com",
                    )
                    second, second_outcome = await self.pipeline(args).fetch(
                        "requests",
                        "example.com",
                        "https://example.com",
                    )

        self.assertFalse(first.cached)
        self.assertTrue(first_outcome.stored)
        self.assertTrue(second.cached)
        self.assertEqual(second_outcome.lookup, "hit")
        self.assertEqual(fetch_mock.call_count, 1)
