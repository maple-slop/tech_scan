from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .cache import ResponseCache, default_db_path
from .fetchers import BrowserSession, fetch_browser, fetch_requests, should_try_browser
from .models import FetchResult
from .normalize import normalize_target
from .output import format_result
from .providers import build_providers, merge_findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect website technologies for domains read from stdin. "
            "Defaults to human-readable output; use --output jsonl for one JSON object per input line."
        ),
        epilog=(
            "Examples: "
            "printf 'example.com\\n' | tech-scan; "
            "tech-scan --provider all --wappalyzer-data fingerprints_data.json < domains.txt"
        ),
    )
    wappalyzer_data_env = os.environ.get("WAPPALYZER_DATA")
    parser.add_argument(
        "--db",
        type=Path,
        default=default_db_path(),
        help=(
            "SQLite response-cache path. Stores fetched observations, not provider results. "
            "Default: ${XDG_CACHE_HOME:-~/.cache}/tech_scan/results.db."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["requests", "browser", "auto"],
        default="auto",
        help=(
            "Fetch mode. requests uses a browser-like HTTP request; browser uses Playwright; "
            "auto tries requests first and falls back to browser for sparse/blocked/JS-heavy pages. "
            "Default: auto."
        ),
    )
    parser.add_argument(
        "--proxy",
        help=(
            "Proxy URL for fetching, for example http://127.0.0.1:8080 or socks5://127.0.0.1:9050. "
            "Proxy is part of the response-cache key."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="Per-target fetch timeout in seconds. Default: 15.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=8,
        help="Number of targets to scan concurrently. Default: 8.",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=86400,
        help=(
            "Seconds before a cached fetch observation expires. "
            "Use a negative value to never expire cached rows. Default: 86400."
        ),
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore cached fetch observations and overwrite them with fresh responses.",
    )
    parser.add_argument(
        "--output",
        choices=["human", "jsonl"],
        default="human",
        help=(
            "Output format. human prints colorized multi-line blocks; jsonl prints one JSON object "
            "per input line. Default: human."
        ),
    )
    parser.add_argument(
        "--provider",
        action="append",
        choices=["builtin", "wappalyzergo", "wappalyzer_json", "all"],
        default=None,
        help=(
            "Detection provider. Repeatable. builtin is curated local rules; "
            "wappalyzer_json uses fingerprints_data.json; wappalyzergo uses an external wrapper; "
            "all enables builtin plus configured optional providers. Default: builtin."
        ),
    )
    parser.add_argument(
        "--wappalyzergo-cmd",
        default=os.environ.get("WAPPALYZERGO_CMD"),
        help=(
            "Command for an optional stdin/stdout JSON wrapper around projectdiscovery/wappalyzergo. "
            "Can also be set with WAPPALYZERGO_CMD."
        ),
    )
    parser.add_argument(
        "--wappalyzer-data",
        type=Path,
        default=Path(wappalyzer_data_env) if wappalyzer_data_env else None,
        help=(
            "Path to Wappalyzer fingerprints_data.json for the Python-native wappalyzer_json provider. "
            "Can also be set with WAPPALYZER_DATA."
        ),
    )
    return parser.parse_args(argv)


def resolve_provider_names(
    requested: list[str],
    wappalyzergo_cmd: str | None,
    wappalyzer_data: Path | str | None = None,
) -> list[str]:
    if "all" in requested:
        names = {"builtin"}
        if wappalyzergo_cmd:
            names.add("wappalyzergo")
        if wappalyzer_data:
            names.add("wappalyzer_json")
        return sorted(names)
    return sorted(set(requested))


def scan_target(
    raw_target: str,
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    browser_session: BrowserSession | None = None,
) -> dict[str, Any]:
    raw_target = raw_target.strip()
    try:
        target = normalize_target(raw_target)
    except ValueError as exc:
        return {
            "input": raw_target,
            "url": None,
            "status": None,
            "mode": args.mode,
            "providers": provider_names,
            "cached": False,
            "technologies": [],
            "error": str(exc),
        }

    providers = build_providers(providers_requested, args.wappalyzergo_cmd, args.wappalyzer_data)
    findings = []
    fetch: FetchResult | None = None

    with ResponseCache(args.db) as cache:
        def cached_or_fetch(mode: str) -> FetchResult:
            if not args.refresh:
                cached_fetch = cache.get(target, mode, args.proxy, args.cache_ttl)
                if cached_fetch:
                    return cached_fetch
            if mode == "browser":
                fresh_fetch = fetch_browser(
                    raw_target,
                    target,
                    args.timeout,
                    args.proxy,
                    browser_session,
                )
            else:
                fresh_fetch = fetch_requests(raw_target, target, args.timeout, args.proxy)
            cache.set(target, mode, args.proxy, fresh_fetch)
            return fresh_fetch

        if args.mode in {"requests", "auto"}:
            fetch = cached_or_fetch("requests")
            for provider in providers:
                findings.extend(provider.detect(fetch))

        if args.mode == "browser" or (
            args.mode == "auto" and fetch is not None and should_try_browser(fetch, len(findings))
        ):
            browser_fetch = cached_or_fetch("browser")
            if not browser_fetch.error:
                fetch = browser_fetch
                findings = []
                for provider in providers:
                    findings.extend(provider.detect(fetch))
            elif fetch is None:
                fetch = browser_fetch

    assert fetch is not None
    merged = merge_findings(findings)
    result = {
        "input": raw_target,
        "url": fetch.final_url or fetch.url,
        "status": fetch.status,
        "mode": fetch.mode,
        "providers": provider_names,
        "cached": fetch.cached,
        "technologies": [finding.to_json() for finding in merged],
        "error": fetch.error,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    providers_requested = args.provider or ["builtin"]
    provider_names = resolve_provider_names(
        providers_requested,
        args.wappalyzergo_cmd,
        args.wappalyzer_data,
    )
    if (
        "wappalyzergo" in providers_requested
        and "all" not in providers_requested
        and not args.wappalyzergo_cmd
    ):
        print(
            "error: --provider wappalyzergo requires --wappalyzergo-cmd or WAPPALYZERGO_CMD",
            file=sys.stderr,
        )
        return 2
    if (
        "wappalyzer_json" in providers_requested
        and "all" not in providers_requested
        and not args.wappalyzer_data
    ):
        print(
            "error: --provider wappalyzer_json requires --wappalyzer-data or WAPPALYZER_DATA",
            file=sys.stderr,
        )
        return 2
    if args.wappalyzer_data and not args.wappalyzer_data.exists():
        print(f"error: --wappalyzer-data does not exist: {args.wappalyzer_data}", file=sys.stderr)
        return 2
    if args.concurrency < 1:
        print("error: --concurrency must be >= 1", file=sys.stderr)
        return 2

    targets = [line.strip() for line in sys.stdin if line.strip()]
    browser_session = BrowserSession(args.proxy) if args.mode in {"browser", "auto"} else None
    try:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if browser_session is not None:
            for target in targets:
                result = scan_target(
                    target,
                    args,
                    providers_requested,
                    provider_names,
                    browser_session,
                )
                print(format_result(result, args.output, color), flush=True)
                if args.output == "human":
                    print(flush=True)
            return 0

        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = [
                executor.submit(
                    scan_target,
                    target,
                    args,
                    providers_requested,
                    provider_names,
                    browser_session,
                )
                for target in targets
            ]
            for future in futures:
                print(format_result(future.result(), args.output, color), flush=True)
                if args.output == "human":
                    print(flush=True)
    finally:
        if browser_session is not None:
            browser_session.close()
    return 0
