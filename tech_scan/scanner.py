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
from .fetch_pipeline import FetchExecutor
from .fetchers.browser import AsyncBrowserPool
from .models import CacheInfo, FetchObservation, Observation, ResolvedObservation, ScanResult, TechnologyResult
from .normalize import expand_targets
from .observations import (
    browser_fallback_failed_observation,
    cached_auto_fallback_skipped_observation,
    collect_header_observations,
)
from .providers import build_providers, merge_findings


BlockingRunner = Callable[..., Awaitable[Any]]
ResultEmitter = Callable[[ScanResult], None]


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
        if not hasattr(self.args, "cache"):
            self.args.cache = "refresh" if getattr(self.args, "refresh", False) else "use"
        self.providers = build_providers(providers_requested)
        self.fetch_executor = FetchExecutor(
            args,
            browser_session,
            run_blocking,
            self.diagnostics,
        )

    async def scan_input_async(
        self,
        raw_target: str,
        emit_result: ResultEmitter | None = None,
    ) -> list[ScanResult]:
        raw_target = raw_target.strip()
        try:
            candidates = expand_targets(raw_target)
        except ValueError as exc:
            result = ScanResult.validation_error(
                raw_target,
                self.args.mode,
                self.provider_names,
                str(exc),
                cache_policy=getattr(self.args, "cache", "use"),
            )
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

    async def scan_target_async(self, raw_target: str, target: str) -> ScanResult:
        findings = []
        resolved: ResolvedObservation | None = None
        auto_observations: list[Observation] = []

        if getattr(self.args, "cache", "use") == "only":
            sources = (
                ["requests", "browser"]
                if self.args.mode == "auto"
                else [self.args.mode]
            )
            resolved = self.fetch_executor.select_cache_only(raw_target, target, sources)
            findings = self._detect(resolved.observation, resolved.fetch_mode or "cache-only", target)
        elif self.args.mode in {"requests", "auto"}:
            resolved = await self.fetch_executor.resolve(
                "requests",
                raw_target,
                target,
            )
            findings = self._detect(resolved.observation, "requests", target)

        fallback_reason = self._fallback_reason(resolved.observation if resolved else None, len(findings))
        if self._should_run_browser(fallback_reason):
            if fallback_reason:
                self.diagnostics.log(
                    1,
                    f"auto switching fetcher: target={target} from=requests to=browser "
                    f"reason={fallback_reason}",
                )
            browser_resolved = await self._browser_fallback_resolve(
                raw_target,
                target,
                fallback_reason,
                resolved,
                auto_observations,
            )
            if browser_resolved is not None and not browser_resolved.observation.error:
                resolved = browser_resolved
                findings = self._detect(resolved.observation, "browser", target)
            elif browser_resolved is not None and resolved is None:
                resolved = browser_resolved
            if (
                browser_resolved is not None
                and
                self._should_warn_browser_fallback_failed(
                    fallback_reason,
                    browser_resolved.observation,
                )
            ):
                auto_observations.append(
                    browser_fallback_failed_observation(
                        fallback_reason,
                        browser_resolved.observation,
                    )
                )

        assert resolved is not None
        fetch = resolved.observation
        merged = merge_findings(findings)
        observations = collect_header_observations(fetch, merged)
        observations.extend(auto_observations)
        return ScanResult(
            input=raw_target,
            url=fetch.url,
            final_url=fetch.final_url,
            status=fetch.status,
            scan_mode=self.args.mode,
            fetch_mode=resolved.fetch_mode,
            providers=list(self.provider_names),
            cache=resolved.cache,
            observations=observations,
            technologies=[TechnologyResult.from_finding(finding) for finding in merged],
            error=fetch.error,
        )

    def _fallback_reason(self, fetch: FetchObservation | None, findings_count: int) -> str | None:
        if self.args.mode != "auto" or fetch is None:
            return None
        if str(fetch.error or "").startswith("sanity check failed:"):
            return None
        return browser_fallback_reason(fetch, findings_count)

    def _should_run_browser(self, fallback_reason: str | None) -> bool:
        return self.args.mode == "browser" or (
            self.args.mode == "auto" and fallback_reason is not None
        )

    def _should_warn_browser_fallback_failed(
        self,
        fallback_reason: str | None,
        browser_fetch: FetchObservation,
    ) -> bool:
        return (
            self.args.mode == "auto"
            and fallback_reason is not None
            and is_cdn_waf_fallback_reason(fallback_reason)
            and (browser_fetch.error is not None or not has_useful_response(browser_fetch))
        )

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

    async def _browser_fallback_resolve(
        self,
        raw_target: str,
        target: str,
        fallback_reason: str | None,
        requests_resolved: ResolvedObservation | None,
        auto_observations: list[Observation],
    ) -> ResolvedObservation | None:
        if (
            self.args.mode == "auto"
            and requests_resolved is not None
            and not requests_resolved.network_used
            and requests_resolved.cache.lookup == "hit"
        ):
            cached_browser = self.fetch_executor.get_cached("browser", target)
            if cached_browser is not None:
                self.diagnostics.log(
                    1,
                    f"auto using cached browser fallback: target={target} reason={fallback_reason}",
                )
                return cached_browser
            assert fallback_reason is not None
            self.diagnostics.log(
                1,
                f"auto skipped live browser fallback: target={target} "
                f"reason={fallback_reason} requests_cached=true browser_cache=miss",
            )
            auto_observations.append(cached_auto_fallback_skipped_observation(fallback_reason))
            return None

        return await self.fetch_executor.resolve(
            "browser",
            raw_target,
            target,
        )


def scan_target(
    raw_target: str,
    target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: AsyncBrowserPool | None = None,
) -> ScanResult:
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
) -> list[ScanResult]:
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
) -> list[ScanResult]:
    return await ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
    ).scan_input_async(raw_target, emit_result)
