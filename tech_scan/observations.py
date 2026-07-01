from __future__ import annotations

from collections.abc import Iterable

from .models import FetchResult, Finding, Observation


HEADER_DISPLAY_NAMES = {
    "cf-ray": "CF-Ray",
    "server": "Server",
    "via": "Via",
    "x-0-status": "X-0-Status",
    "x-0-t": "X-0-T",
    "x-0-version": "X-0-Version",
    "x-akamai": "X-Akamai",
    "x-amz-cf-id": "X-Amz-Cf-Id",
    "x-amz-id-2": "X-Amz-Id-2",
    "x-amz-request-id": "X-Amz-Request-Id",
    "x-application-context": "X-Application-Context",
    "x-aspnet-version": "X-AspNet-Version",
    "x-bubble-capacity-limit": "X-Bubble-Capacity-Limit",
    "x-bubble-capacity-used": "X-Bubble-Capacity-Used",
    "x-bubble-perf": "X-Bubble-Perf",
    "x-cdn": "X-CDN",
    "x-generator": "X-Generator",
    "x-iinfo": "X-IInfo",
    "x-litespeed-cache": "X-LiteSpeed-Cache",
    "x-nf-request-id": "X-NF-Request-ID",
    "x-now-trace": "X-Now-Trace",
    "x-powered-by": "X-Powered-By",
    "x-turbo-charged-by": "X-Turbo-Charged-By",
    "x-vercel-cache": "X-Vercel-Cache",
    "x-vercel-id": "X-Vercel-Id",
}


OBSERVED_HEADERS = set(HEADER_DISPLAY_NAMES)


def _is_observed_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in OBSERVED_HEADERS or lowered.startswith(("x-vercel-", "x-now-"))


def header_display_name(name: str) -> str:
    lowered = name.lower()
    return HEADER_DISPLAY_NAMES.get(
        lowered,
        "-".join(part.capitalize() for part in lowered.split("-")),
    )


def collect_header_observations(
    fetch: FetchResult,
    findings: Iterable[Finding],
) -> list[Observation]:
    evidence = {
        item
        for finding in findings
        for item in finding.evidence
    }
    observations: list[Observation] = []
    for name, value in fetch.headers.items():
        if not value or not _is_observed_header(name):
            continue
        display_name = header_display_name(name)
        if f"{display_name}: {value}" in evidence:
            continue
        observations.append(Observation(kind="header", name=display_name, value=value))
    return observations


def browser_fallback_failed_observation(
    fallback_reason: str,
    browser_fetch: FetchResult,
) -> Observation:
    error = browser_fetch.error or "no useful browser response"
    return Observation(
        kind="auto",
        name="browser_fallback_failed",
        value=(
            "requests looked blocked by CDN/WAF "
            f"(reason={fallback_reason}); browser also failed: {error}"
        ),
    )
