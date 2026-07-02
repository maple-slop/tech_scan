from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from .cache import CacheStore, cache_disposition
from .cli_config import fetch_identity, requests_verify
from .diagnostics import Diagnostics
from .fetchers.browser import AsyncBrowserPool, fetch_browser_async
from .fetchers.requests import fetch_requests
from .models import CacheInfo, FetchObservation, ResolvedObservation, ResourceObservation
from .sanity import check_target_ports
from .url_policy import same_hostname


BlockingRunner = Callable[..., Awaitable[Any]]


def _redirect_alias_targets(source_url: str, fetch: FetchObservation) -> list[str]:
    aliases = []
    for resource in fetch.resources:
        if resource.kind != "redirect" or not resource.final_url:
            continue
        parsed = urlparse(resource.final_url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if resource.final_url == source_url:
            continue
        if not same_hostname(source_url, resource.final_url):
            continue
        if resource.final_url not in aliases:
            aliases.append(resource.final_url)
    return aliases


def _sanity_observation(raw_target: str, target: str, source: str, error: str | None) -> FetchObservation:
    sanity_resource = ResourceObservation(
        id="sanity:0",
        kind="sanity",
        url=target,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        error=error,
    )
    return FetchObservation(
        input=raw_target,
        url=target,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode=source,
        error=error,
        resources=[sanity_resource],
        primary_resource_id=sanity_resource.id,
    )


def _cache_only_miss(raw_target: str, target: str) -> FetchObservation:
    error = "cache-only miss; no cached fetch observation for target"
    resource = ResourceObservation(
        id="cache-only:0",
        kind="cache-only",
        url=target,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        error=error,
    )
    return FetchObservation(
        input=raw_target,
        url=target,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode="cache-only",
        error=error,
        resources=[resource],
        primary_resource_id=resource.id,
    )


def _has_2xx(fetch: FetchObservation | None) -> bool:
    return bool(fetch and fetch.status is not None and 200 <= fetch.status < 300)


class FetchExecutor:
    def __init__(
        self,
        args: argparse.Namespace,
        browser_session: AsyncBrowserPool | None,
        run_blocking: BlockingRunner,
        diagnostics: Diagnostics,
    ):
        self.args = args
        self.browser_session = browser_session
        self.run_blocking = run_blocking
        self.diagnostics = diagnostics
        if not hasattr(self.args, "cache"):
            self.args.cache = "refresh" if getattr(self.args, "refresh", False) else "use"

    async def fetch(self, source: str, raw_target: str, target: str) -> tuple[FetchObservation, CacheInfo]:
        resolved = await self.resolve(source, raw_target, target)
        return resolved.observation, resolved.cache

    async def resolve(self, source: str, raw_target: str, target: str) -> ResolvedObservation:
        cache_policy = getattr(self.args, "cache", "use")
        if cache_policy == "only":
            cached = self.get_cached(source, target)
            if cached is not None:
                return cached
            return ResolvedObservation(
                _cache_only_miss(raw_target, target),
                fetch_mode=None,
                cache=CacheInfo(
                    policy=cache_policy,
                    lookup="miss",
                    write="not_attempted",
                    reason="cache-only-miss",
                ),
                network_used=False,
            )

        if cache_policy == "use":
            cached = self.get_cached(source, target)
            if cached is not None:
                return cached
            self.diagnostics.log(3, f"cache miss: target={target} source={source}")
        elif cache_policy == "refresh":
            self.diagnostics.log(3, f"cache bypass refresh: target={target} source={source}")
        elif cache_policy == "off":
            self.diagnostics.log(3, f"cache disabled: target={target} source={source}")

        observation = await self._live_fetch(source, raw_target, target)
        cache = self._write_cache(source, target, observation)
        return ResolvedObservation(observation, source, cache, network_used=True)

    def get_cached(self, source: str, target: str) -> ResolvedObservation | None:
        cache_policy = getattr(self.args, "cache", "use")
        identity = fetch_identity(self.args, source)
        with CacheStore(self.args.db) as store:
            record = store.get(
                target,
                source,
                self.args.proxy,
                self.args.cache_ttl,
                identity,
            )
        if record is None:
            self.diagnostics.log(3, f"cache probe miss: target={target} source={source}")
            return None
        self.diagnostics.log(
            3,
            f"cache probe hit: target={target} source={source} "
            f"created_at={record.created_at} updated_at={record.updated_at}",
        )
        return ResolvedObservation(
            observation=record.observation,
            fetch_mode=source,
            cache=CacheInfo(
                policy=cache_policy,
                lookup="hit",
                write="not_attempted",
                created_at=record.created_at,
                updated_at=record.updated_at,
            ),
            network_used=False,
        )

    def select_cache_only(self, raw_target: str, target: str, sources: list[str]) -> ResolvedObservation:
        cache_policy = getattr(self.args, "cache", "use")
        if sources == ["requests", "browser"]:
            requests = self.get_cached("requests", target)
            browser = self.get_cached("browser", target)
            if browser and _has_2xx(browser.observation):
                return browser
            if requests:
                return requests
            if browser:
                return browser
        else:
            for source in sources:
                cached = self.get_cached(source, target)
                if cached:
                    return cached
        return ResolvedObservation(
            _cache_only_miss(raw_target, target),
            fetch_mode=None,
            cache=CacheInfo(
                policy=cache_policy,
                lookup="miss",
                write="not_attempted",
                reason="cache-only-miss",
            ),
            network_used=False,
        )

    async def _live_fetch(self, source: str, raw_target: str, target: str) -> FetchObservation:
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
                f"sanity skip fetcher: target={target} source={source} status={sanity.status}",
            )
            return _sanity_observation(raw_target, target, source, sanity.error)

        started = time.perf_counter()
        self.diagnostics.log(3, f"fetch start: target={target} source={source}")
        if source == "browser":
            fetch = await fetch_browser_async(
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
            fetch = await self.run_blocking(
                fetch_requests,
                raw_target,
                target,
                self.args.timeout,
                self.args.proxy,
                requests_verify(self.args.ca_bundle, self.args.insecure),
                diagnostics=self.diagnostics,
                include_traceback=self.diagnostics.enabled(2),
            )
        self.diagnostics.log(
            3,
            f"fetch end: target={target} source={source} status={fetch.status} "
            f"error={bool(fetch.error)} elapsed={time.perf_counter() - started:.3f}s",
        )
        return fetch

    def _write_cache(self, source: str, target: str, observation: FetchObservation) -> CacheInfo:
        policy = getattr(self.args, "cache", "use")
        disposition = cache_disposition(observation)
        lookup = "refresh" if policy == "refresh" else "bypass" if policy == "off" else "miss"
        if policy == "off":
            return CacheInfo(
                policy=policy,
                lookup=lookup,
                write="not_attempted",
                reason=disposition.reason,
            )
        if not disposition.cacheable:
            self.diagnostics.log(
                3,
                f"cache drop: target={target} source={source} reason={disposition.reason}",
            )
            return CacheInfo(
                policy=policy,
                lookup=lookup,
                write="dropped",
                reason=disposition.reason,
            )

        identity = fetch_identity(self.args, source)
        with CacheStore(self.args.db) as store:
            record = store.set(target, source, self.args.proxy, observation, identity)
            for alias in _redirect_alias_targets(target, observation):
                store.set(alias, source, self.args.proxy, observation, identity)
                self.diagnostics.log(
                    3,
                    f"cache alias write: source={target} alias={alias} fetch_source={source}",
                )
        assert record is not None
        self.diagnostics.log(
            3,
            f"cache write: target={target} source={source} reason={disposition.reason}",
        )
        return CacheInfo(
            policy=policy,
            lookup=lookup,
            write="stored",
            reason=disposition.reason,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )


FetchPipeline = FetchExecutor
