from __future__ import annotations

import argparse
import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from .cache import ResponseCache, cache_disposition
from .cli_config import fetch_identity, requests_verify
from .diagnostics import Diagnostics
from .fetchers.auto import (
    browser_fallback_reason,
    has_useful_response,
    is_cdn_waf_fallback_reason,
)
from .fetchers.browser import AsyncBrowserPool, fetch_browser_async
from .fetchers.requests import fetch_requests
from .models import FetchResult, ResourceObservation
from .normalize import expand_targets
from .observations import browser_fallback_failed_observation, collect_header_observations
from .providers import build_providers, merge_findings
from .sanity import check_target_ports


BlockingRunner = Callable[..., Awaitable[Any]]


@dataclass
class CacheOutcome:
    lookup: str = "not_applicable"
    stored: bool | None = None
    reason: str | None = None


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
        self.browser_session = browser_session
        self.run_blocking = run_blocking
        self.diagnostics = getattr(args, "_diagnostics", None) or Diagnostics(
            getattr(args, "verbosity", 0)
        )
        self.providers = build_providers(providers_requested)

    async def scan_input_async(self, raw_target: str) -> list[dict[str, Any]]:
        raw_target = raw_target.strip()
        try:
            candidates = expand_targets(raw_target)
        except ValueError as exc:
            return [
                {
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
            ]

        return [
            await self.scan_target_async(candidate.input, candidate.url)
            for candidate in candidates
        ]

    async def scan_target_async(self, raw_target: str, target: str) -> dict[str, Any]:
        findings = []
        fetch: FetchResult | None = None
        auto_observations: list[dict[str, str]] = []
        cache_outcomes: dict[str, CacheOutcome] = {}

        with ResponseCache(self.args.db) as cache:
            async def cached_or_fetch(mode: str) -> FetchResult:
                cache_outcome = CacheOutcome(
                    lookup="refresh" if self.args.refresh else "miss"
                )
                cache_outcomes[mode] = cache_outcome
                identity = fetch_identity(self.args, mode)
                if not self.args.refresh:
                    cached_fetch = cache.get(
                        target,
                        mode,
                        self.args.proxy,
                        self.args.cache_ttl,
                        identity,
                    )
                    if cached_fetch:
                        cache_outcome.lookup = "hit"
                        primary = cached_fetch.primary_resource
                        self.diagnostics.log(
                            3,
                            f"cache hit: target={target} mode={mode} "
                            f"resource_created_at={primary.cache_created_at} "
                            f"resource_updated_at={primary.cache_updated_at}",
                        )
                        return cached_fetch
                    self.diagnostics.log(3, f"cache miss: target={target} mode={mode}")
                else:
                    self.diagnostics.log(3, f"cache bypass refresh: target={target} mode={mode}")
                sanity = await self.run_blocking(
                    check_target_ports,
                    raw_target,
                    target,
                    getattr(self.args, "sanity_timeout", 1.0),
                    diagnostics=self.diagnostics,
                    include_traceback=self.diagnostics.enabled(2),
                )
                if not sanity.ok:
                    self.diagnostics.log(
                        1,
                        f"sanity skip fetcher: target={target} mode={mode} "
                        f"status={sanity.status}",
                    )
                    sanity_resource = ResourceObservation(
                        id="sanity:0",
                        kind="sanity",
                        url=target,
                        final_url=None,
                        status=None,
                        headers={},
                        cookies={},
                        body="",
                        error=sanity.error,
                    )
                    sanity_fetch = FetchResult(
                        input=raw_target,
                        url=target,
                        final_url=None,
                        status=None,
                        headers={},
                        cookies={},
                        body="",
                        mode=mode,
                        error=sanity.error,
                        resources=[sanity_resource],
                        primary_resource_id=sanity_resource.id,
                    )
                    disposition = cache_disposition(sanity_fetch)
                    cache_outcome.reason = disposition.reason
                    if disposition.cacheable:
                        cache.set(target, mode, self.args.proxy, sanity_fetch, identity)
                        cache_outcome.stored = True
                        self.diagnostics.log(
                            3,
                            f"cache write: target={target} mode={mode} reason={disposition.reason}",
                        )
                    else:
                        cache_outcome.stored = False
                        self.diagnostics.log(
                            3,
                            f"cache drop: target={target} mode={mode} reason={disposition.reason}",
                        )
                    return sanity_fetch
                started = time.perf_counter()
                self.diagnostics.log(3, f"fetch start: target={target} mode={mode}")
                if mode == "browser":
                    fresh_fetch = await fetch_browser_async(
                        raw_target,
                        target,
                        self.args.timeout,
                        self.args.proxy,
                        self.browser_session,
                        self.args.insecure,
                        str(Path(self.args.ca_bundle).expanduser().resolve())
                        if self.args.ca_bundle
                        else None,
                        not getattr(self.args, "no_browser_extension", False),
                        diagnostics=self.diagnostics,
                        include_traceback=self.diagnostics.enabled(2),
                    )
                else:
                    fresh_fetch = await self.run_blocking(
                        fetch_requests,
                        raw_target,
                        target,
                        self.args.timeout,
                        self.args.proxy,
                        requests_verify(self.args.ca_bundle, self.args.insecure),
                        diagnostics=self.diagnostics,
                        include_traceback=self.diagnostics.enabled(2),
                    )
                elapsed = time.perf_counter() - started
                self.diagnostics.log(
                    3,
                    f"fetch end: target={target} mode={mode} status={fresh_fetch.status} "
                    f"error={bool(fresh_fetch.error)} elapsed={elapsed:.3f}s",
                )
                disposition = cache_disposition(fresh_fetch)
                cache_outcome.reason = disposition.reason
                if disposition.cacheable:
                    cache.set(target, mode, self.args.proxy, fresh_fetch, identity)
                    cache_outcome.stored = True
                    self.diagnostics.log(
                        3,
                        f"cache write: target={target} mode={mode} reason={disposition.reason}",
                    )
                else:
                    cache_outcome.stored = False
                    self.diagnostics.log(
                        3,
                        f"cache drop: target={target} mode={mode} reason={disposition.reason}",
                    )
                return fresh_fetch

            if self.args.mode in {"requests", "auto"}:
                fetch = await cached_or_fetch("requests")
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
                browser_fetch = await cached_or_fetch("browser")
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
) -> list[dict[str, Any]]:
    return asyncio.run(ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
        run_blocking_direct,
    ).scan_input_async(raw_target))


async def scan_input_async(
    raw_target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: AsyncBrowserPool | None = None,
) -> list[dict[str, Any]]:
    return await ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
    ).scan_input_async(raw_target)
