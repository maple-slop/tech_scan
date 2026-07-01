from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from .cache import ResponseCache, cache_disposition
from .cli_config import fetch_identity, requests_verify
from .diagnostics import Diagnostics
from .fetchers.browser import AsyncBrowserPool, fetch_browser_async
from .fetchers.requests import fetch_requests
from .models import FetchResult, ResourceObservation
from .sanity import check_target_ports
from .url_policy import same_hostname


BlockingRunner = Callable[..., Awaitable[Any]]


@dataclass
class CacheOutcome:
    lookup: str = "not_applicable"
    stored: bool | None = None
    reason: str | None = None


def _redirect_alias_targets(source_url: str, fetch: FetchResult) -> list[str]:
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


def _sanity_fetch(raw_target: str, target: str, mode: str, error: str | None) -> FetchResult:
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
    return FetchResult(
        input=raw_target,
        url=target,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode=mode,
        error=error,
        resources=[sanity_resource],
        primary_resource_id=sanity_resource.id,
    )


class FetchPipeline:
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

    async def fetch(self, mode: str, raw_target: str, target: str) -> tuple[FetchResult, CacheOutcome]:
        if mode == "null":
            return self._fetch_null(raw_target, target)

        outcome = CacheOutcome(lookup="refresh" if self.args.refresh else "miss")
        identity = fetch_identity(self.args, mode)

        with ResponseCache(self.args.db) as cache:
            if not self.args.refresh:
                cached_fetch = cache.get(
                    target,
                    mode,
                    self.args.proxy,
                    self.args.cache_ttl,
                    identity,
                )
                if cached_fetch:
                    outcome.lookup = "hit"
                    primary = cached_fetch.primary_resource
                    self.diagnostics.log(
                        3,
                        f"cache hit: target={target} mode={mode} "
                        f"resource_created_at={primary.cache_created_at} "
                        f"resource_updated_at={primary.cache_updated_at}",
                    )
                    return cached_fetch, outcome
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
                sanity_fetch = _sanity_fetch(raw_target, target, mode, sanity.error)
                self._apply_cache_disposition(cache, target, mode, sanity_fetch, identity, outcome)
                return sanity_fetch, outcome

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
            self._apply_cache_disposition(cache, target, mode, fresh_fetch, identity, outcome)
            return fresh_fetch, outcome

    def get_cached(self, mode: str, target: str) -> tuple[FetchResult | None, CacheOutcome]:
        identity = fetch_identity(self.args, mode)
        outcome = CacheOutcome(lookup="miss")
        with ResponseCache(self.args.db) as cache:
            cached_fetch = cache.get(
                target,
                mode,
                self.args.proxy,
                self.args.cache_ttl,
                identity,
            )
        if cached_fetch is None:
            self.diagnostics.log(3, f"cache probe miss: target={target} mode={mode}")
            return None, outcome
        outcome.lookup = "hit"
        primary = cached_fetch.primary_resource
        self.diagnostics.log(
            3,
            f"cache probe hit: target={target} mode={mode} "
            f"resource_created_at={primary.cache_created_at} "
            f"resource_updated_at={primary.cache_updated_at}",
        )
        return cached_fetch, outcome

    def _fetch_null(self, raw_target: str, target: str) -> tuple[FetchResult, CacheOutcome]:
        outcome = CacheOutcome(
            lookup="refresh" if self.args.refresh else "miss",
            stored=False,
            reason="null-cache-miss",
        )
        if self.args.refresh:
            self.diagnostics.log(3, f"null cache bypass refresh: target={target}")
            return self._null_cache_miss(raw_target, target), outcome

        requests_fetch, _ = self.get_cached("requests", target)
        browser_fetch, _ = self.get_cached("browser", target)
        cached_fetch = self._preferred_null_fetch(requests_fetch, browser_fetch)
        if cached_fetch:
            outcome.lookup = "hit"
            outcome.stored = None
            outcome.reason = None
            self.diagnostics.log(
                3,
                f"null cache selected: target={target} cached_mode={cached_fetch.mode}",
            )
            return replace(cached_fetch, mode="null"), outcome

        self.diagnostics.log(3, f"null cache miss: target={target}")
        return self._null_cache_miss(raw_target, target), outcome

    @staticmethod
    def _preferred_null_fetch(
        requests_fetch: FetchResult | None,
        browser_fetch: FetchResult | None,
    ) -> FetchResult | None:
        if browser_fetch and browser_fetch.status is not None and 200 <= browser_fetch.status < 300:
            return browser_fetch
        return requests_fetch or browser_fetch

    def _null_cache_miss(self, raw_target: str, target: str) -> FetchResult:
        error = "null fetch mode cache miss; no cached fetch observation for target"
        resource = ResourceObservation(
            id="null:0",
            kind="null",
            url=target,
            final_url=None,
            status=None,
            headers={},
            cookies={},
            body="",
            error=error,
        )
        return FetchResult(
            input=raw_target,
            url=target,
            final_url=None,
            status=None,
            headers={},
            cookies={},
            body="",
            mode="null",
            error=error,
            resources=[resource],
            primary_resource_id=resource.id,
        )

    def _apply_cache_disposition(
        self,
        cache: ResponseCache,
        target: str,
        mode: str,
        fetch: FetchResult,
        identity: str,
        outcome: CacheOutcome,
    ) -> None:
        disposition = cache_disposition(fetch)
        outcome.reason = disposition.reason
        if disposition.cacheable:
            cache.set(target, mode, self.args.proxy, fetch, identity)
            for alias in _redirect_alias_targets(target, fetch):
                cache.set(alias, mode, self.args.proxy, fetch, identity)
                self.diagnostics.log(
                    3,
                    f"cache alias write: source={target} alias={alias} mode={mode}",
                )
            outcome.stored = True
            self.diagnostics.log(
                3,
                f"cache write: target={target} mode={mode} reason={disposition.reason}",
            )
        else:
            outcome.stored = False
            self.diagnostics.log(
                3,
                f"cache drop: target={target} mode={mode} reason={disposition.reason}",
            )
