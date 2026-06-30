from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from .cache import ResponseCache, cache_disposition
from .cli_config import fetch_identity, requests_verify
from .diagnostics import Diagnostics
from .fetchers.auto import browser_fallback_reason
from .fetchers.browser import BrowserSession, fetch_browser
from .fetchers.requests import fetch_requests
from .models import FetchResult, ResourceObservation
from .normalize import expand_targets
from .observations import collect_header_observations
from .providers import build_providers, merge_findings
from .sanity import check_target_ports


class ScanRunner:
    def __init__(
        self,
        args: argparse.Namespace,
        providers_requested: list[str],
        provider_names: list[str],
        browser_session: BrowserSession | None = None,
    ):
        self.args = args
        self.providers_requested = providers_requested
        self.provider_names = provider_names
        self.browser_session = browser_session
        self.diagnostics = getattr(args, "_diagnostics", None) or Diagnostics(
            getattr(args, "verbosity", 0)
        )
        self.providers = build_providers(providers_requested)

    def scan_input(self, raw_target: str) -> list[dict[str, Any]]:
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
                    "cache_created_at": None,
                    "cache_updated_at": None,
                    "observations": [],
                    "technologies": [],
                    "error": str(exc),
                }
            ]

        return [
            self.scan_target(candidate.input, candidate.url)
            for candidate in candidates
        ]

    def scan_target(self, raw_target: str, target: str) -> dict[str, Any]:
        findings = []
        fetch: FetchResult | None = None

        with ResponseCache(self.args.db) as cache:
            def cached_or_fetch(mode: str) -> FetchResult:
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
                sanity = check_target_ports(
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
                    if disposition.cacheable:
                        cache.set(target, mode, self.args.proxy, sanity_fetch, identity)
                        self.diagnostics.log(
                            3,
                            f"cache write: target={target} mode={mode} reason={disposition.reason}",
                        )
                    else:
                        self.diagnostics.log(
                            3,
                            f"cache drop: target={target} mode={mode} reason={disposition.reason}",
                        )
                    return sanity_fetch
                started = time.perf_counter()
                self.diagnostics.log(3, f"fetch start: target={target} mode={mode}")
                if mode == "browser":
                    fresh_fetch = fetch_browser(
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
                    fresh_fetch = fetch_requests(
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
                if disposition.cacheable:
                    cache.set(target, mode, self.args.proxy, fresh_fetch, identity)
                    self.diagnostics.log(
                        3,
                        f"cache write: target={target} mode={mode} reason={disposition.reason}",
                    )
                else:
                    self.diagnostics.log(
                        3,
                        f"cache drop: target={target} mode={mode} reason={disposition.reason}",
                    )
                return fresh_fetch

            if self.args.mode in {"requests", "auto"}:
                fetch = cached_or_fetch("requests")
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
                browser_fetch = cached_or_fetch("browser")
                if not browser_fetch.error:
                    fetch = browser_fetch
                    findings = self._detect(fetch, "browser", target)
                elif fetch is None:
                    fetch = browser_fetch

        assert fetch is not None
        merged = merge_findings(findings)
        primary = fetch.primary_resource
        return {
            "input": raw_target,
            "url": fetch.url,
            "final_url": fetch.final_url,
            "status": fetch.status,
            "mode": fetch.mode,
            "providers": self.provider_names,
            "cached": fetch.cached,
            "cache_created_at": primary.cache_created_at,
            "cache_updated_at": primary.cache_updated_at,
            "observations": collect_header_observations(fetch, merged),
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
    browser_session: BrowserSession | None = None,
) -> dict[str, Any]:
    return ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
    ).scan_target(raw_target, target)


def scan_input(
    raw_target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: BrowserSession | None = None,
) -> list[dict[str, Any]]:
    return ScanRunner(
        args,
        providers_requested,
        provider_names,
        browser_session,
    ).scan_input(raw_target)
