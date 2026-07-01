from __future__ import annotations

import argparse
import asyncio
import time
from typing import Any, Awaitable, Callable

from .diagnostics import Diagnostics
from .fetchers.auto import (
    browser_fallback_reason,
    has_useful_response,
    is_cdn_waf_fallback_reason,
)
from .fetch_pipeline import CacheOutcome, FetchPipeline
from .fetchers.browser import AsyncBrowserPool
from .models import FetchResult
from .normalize import expand_targets
from .observations import browser_fallback_failed_observation, collect_header_observations
from .providers import build_providers, merge_findings


BlockingRunner = Callable[..., Awaitable[Any]]
ResultEmitter = Callable[[dict[str, Any]], None]


async def run_blocking_in_thread(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(func, *args, **kwargs)


async def run_blocking_direct(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return func(*args, **kwargs)


class ScanRunner:
    def __init__(
        self,
        args: argparse.Namespace,
        providers_requested: list[str],
        provider_names: list[str],
        browser_session: AsyncBrowserPool | None = None,
        run_blocking: BlockingRunner = run_blocking_in_thread,
    ):
        self.args = args
        self.providers_requested = providers_requested
        self.provider_names = provider_names
        self.diagnostics = getattr(args, "_diagnostics", None) or Diagnostics(
            getattr(args, "verbosity", 0)
        )
        self.providers = build_providers(providers_requested)
        self.fetch_pipeline = FetchPipeline(
            args,
            browser_session,
            run_blocking,
            self.diagnostics,
        )

    async def scan_input_async(
        self,
        raw_target: str,
        emit_result: ResultEmitter | None = None,
    ) -> list[dict[str, Any]]:
        raw_target = raw_target.strip()
        try:
            candidates = expand_targets(raw_target)
        except ValueError as exc:
            result = {
                "input": raw_target,
                "url": None,
                "final_url": None,
                "status": None,
                "mode": self.args.mode,
                "providers": self.provider_names,
                "cached": False,
                "cache_lookup": "not_applicable",
                "cache_stored": None,
                "cache_reason": None,
                "cache_created_at": None,
                "cache_updated_at": None,
                "observations": [],
                "technologies": [],
                "error": str(exc),
            }
            if emit_result:
                emit_result(result)
            return [result]

        results = []
        for candidate in candidates:
            result = await self.scan_target_async(candidate.input, candidate.url)
            results.append(result)
            if emit_result:
                emit_result(result)
        return results

    async def scan_target_async(self, raw_target: str, target: str) -> dict[str, Any]:
        findings = []
        fetch: FetchResult | None = None
        auto_observations: list[dict[str, str]] = []
        cache_outcomes: dict[str, CacheOutcome] = {}

        if self.args.mode in {"requests", "auto"}:
            fetch, cache_outcome = await self.fetch_pipeline.fetch(
                "requests",
                raw_target,
                target,
            )
            cache_outcomes["requests"] = cache_outcome
            findings = self._detect(fetch, "requests", target)

        fallback_reason = (
            browser_fallback_reason(fetch, len(findings))
            if (
                self.args.mode == "auto"
                and fetch is not None
                and not str(fetch.error or "").startswith("sanity check failed:")
            )
            else None
        )
        if self.args.mode == "browser" or (self.args.mode == "auto" and fallback_reason):
            if fallback_reason:
                self.diagnostics.log(
                    1,
                    f"auto switching fetcher: target={target} from=requests to=browser "
                    f"reason={fallback_reason}",
                )
            browser_fetch, cache_outcome = await self.fetch_pipeline.fetch(
                "browser",
                raw_target,
                target,
            )
            cache_outcomes["browser"] = cache_outcome
            if not browser_fetch.error:
                fetch = browser_fetch
                findings = self._detect(fetch, "browser", target)
            elif fetch is None:
                fetch = browser_fetch
            if (
                self.args.mode == "auto"
                and fallback_reason
                and is_cdn_waf_fallback_reason(fallback_reason)
                and (browser_fetch.error or not has_useful_response(browser_fetch))
            ):
                auto_observations.append(
                    browser_fallback_failed_observation(
                        fallback_reason,
                        browser_fetch,
                    )
                )

        assert fetch is not None
        merged = merge_findings(findings)
        primary = fetch.primary_resource
        observations = collect_header_observations(fetch, merged)
        observations.extend(auto_observations)
        cache_outcome = cache_outcomes.get(fetch.mode, CacheOutcome())
        return {
            "input": raw_target,
            "url": fetch.url,
            "final_url": fetch.final_url,
            "status": fetch.status,
            "mode": fetch.mode,
            "providers": self.provider_names,
            "cached": fetch.cached,
            "cache_lookup": cache_outcome.lookup,
            "cache_stored": cache_outcome.stored,
            "cache_reason": cache_outcome.reason,
            "cache_created_at": primary.cache_created_at,
            "cache_updated_at": primary.cache_updated_at,
            "observations": observations,
            "technologies": [finding.to_json() for finding in merged],
            "error": fetch.error,
        }

    def _detect(self, fetch: FetchResult, mode: str, target: str):
        findings = []
        provider_started = time.perf_counter()
        for provider in self.providers:
            findings.extend(provider.detect(fetch))
        self.diagnostics.log(
            3,
            f"providers complete: target={target} mode={mode} "
            f"providers={len(self.providers)} findings={len(findings)} "
            f"elapsed={time.perf_counter() - provider_started:.3f}s",
        )
        return findings


def scan_target(
    raw_target: str,
    target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: AsyncBrowserPool | None = None,
) -> dict[str, Any]:
    return asyncio.run(ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
        run_blocking_direct,
    ).scan_target_async(raw_target, target))


def scan_input(
    raw_target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: AsyncBrowserPool | None = None,
    emit_result: ResultEmitter | None = None,
) -> list[dict[str, Any]]:
    return asyncio.run(ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
        run_blocking_direct,
    ).scan_input_async(raw_target, emit_result))


async def scan_input_async(
    raw_target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: AsyncBrowserPool | None = None,
    emit_result: ResultEmitter | None = None,
) -> list[dict[str, Any]]:
    return await ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
    ).scan_input_async(raw_target, emit_result)
