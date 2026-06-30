from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .cache import ResponseCache, default_db_path, is_cacheable_fetch
from .diagnostics import Diagnostics
from .fetchers import (
    BrowserSession,
    browser_fallback_reason,
    browser_extension_identity,
    chromium_executable_path,
    fetch_browser,
    fetch_requests,
)
from .models import FetchResult
from .normalize import normalize_target
from .output import format_result
from .providers import build_providers, merge_findings
from .sanity import check_target_ports


def ca_bundle_env_default() -> Path | None:
    for name in ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"]:
        value = os.environ.get(name)
        if value:
            return Path(value).expanduser()
    return None


def tls_identity(ca_bundle: Path | None, insecure: bool) -> str:
    if insecure:
        return "insecure"
    if ca_bundle:
        return f"ca:{ca_bundle.expanduser().resolve()}"
    return "default"


def requests_verify(ca_bundle: Path | None, insecure: bool) -> bool | str | None:
    if insecure:
        return False
    if ca_bundle:
        return str(ca_bundle.expanduser().resolve())
    return None


def chromium_identity() -> str:
    executable_path = chromium_executable_path()
    if executable_path:
        return f"chromium:{Path(executable_path).expanduser().resolve()}"
    return "chromium:playwright-default"


def fetch_identity(args: argparse.Namespace, mode: str) -> str:
    parts = [tls_identity(args.ca_bundle, args.insecure)]
    if mode == "browser":
        parts.append(browser_extension_identity(not getattr(args, "no_browser_extension", False)))
        parts.append(chromium_identity())
    return "|".join(parts)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect website technologies for domains read from stdin. "
            "Defaults to human-readable output; use --output jsonl for one JSON object per input line."
        ),
        epilog=(
            "Examples: "
            "printf 'example.com\\n' | tech-scan; "
            "tech-scan --provider all < domains.txt"
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
        "--ca-bundle",
        type=Path,
        default=ca_bundle_env_default(),
        help=(
            "CA bundle path for proxied/TLS fetching. Defaults from REQUESTS_CA_BUNDLE, "
            "then CURL_CA_BUNDLE, then SSL_CERT_FILE. Requests mode uses this directly; "
            "browser mode passes it to Chromium as best-effort environment."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Useful for intercepting proxies such as mitmproxy.",
    )
    parser.add_argument(
        "--no-browser-extension",
        action="store_true",
        help="Disable the vendored uBlock Origin Lite extension in browser mode.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="Per-target fetch timeout in seconds. Default: 15.",
    )
    parser.add_argument(
        "--sanity-timeout",
        type=float,
        default=1.0,
        help="Per-IP/port TCP sanity-check timeout before fresh fetches. Default: 1.0.",
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
        "--verbosity",
        type=int,
        choices=range(4),
        default=0,
        metavar="{0,1,2,3}",
        help=(
            "Diagnostic verbosity. 0: short errors only; 1: fetcher switch and redirects; "
            "2: include tracebacks for live top-level fetch failures; 3: detailed diagnostics. "
            "Default: 0."
        ),
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
            "wappalyzergo uses vendored projectdiscovery/wappalyzergo fingerprints; "
            "wappalyzer_json uses an explicit fingerprints_data.json; "
            "all enables builtin and wappalyzergo plus configured optional providers. Default: builtin."
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
    wappalyzer_data: Path | str | None = None,
) -> list[str]:
    if "all" in requested:
        names = {"builtin", "wappalyzergo"}
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

    providers = build_providers(providers_requested, args.wappalyzer_data)
    findings = []
    fetch: FetchResult | None = None
    diagnostics = getattr(args, "_diagnostics", None) or Diagnostics(getattr(args, "verbosity", 0))

    with ResponseCache(args.db) as cache:
        def cached_or_fetch(mode: str) -> FetchResult:
            identity = fetch_identity(args, mode)
            if not args.refresh:
                cached_fetch = cache.get(
                    target,
                    mode,
                    args.proxy,
                    args.cache_ttl,
                    identity,
                )
                if cached_fetch:
                    diagnostics.log(3, f"cache hit: target={target} mode={mode}")
                    return cached_fetch
                diagnostics.log(3, f"cache miss: target={target} mode={mode}")
            else:
                diagnostics.log(3, f"cache bypass refresh: target={target} mode={mode}")
            sanity = check_target_ports(
                raw_target,
                target,
                getattr(args, "sanity_timeout", 1.0),
                diagnostics=diagnostics,
                include_traceback=diagnostics.enabled(2),
            )
            if not sanity.ok:
                diagnostics.log(
                    1,
                    f"sanity skip fetcher: target={target} mode={mode} "
                    f"status={sanity.status}",
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
                    error=sanity.error,
                )
            started = time.perf_counter()
            diagnostics.log(3, f"fetch start: target={target} mode={mode}")
            if mode == "browser":
                fresh_fetch = fetch_browser(
                    raw_target,
                    target,
                    args.timeout,
                    args.proxy,
                    browser_session,
                    args.insecure,
                    str(args.ca_bundle.expanduser().resolve()) if args.ca_bundle else None,
                    not getattr(args, "no_browser_extension", False),
                    diagnostics=diagnostics,
                    include_traceback=diagnostics.enabled(2),
                )
            else:
                fresh_fetch = fetch_requests(
                    raw_target,
                    target,
                    args.timeout,
                    args.proxy,
                    requests_verify(args.ca_bundle, args.insecure),
                    diagnostics=diagnostics,
                    include_traceback=diagnostics.enabled(2),
                )
            elapsed = time.perf_counter() - started
            diagnostics.log(
                3,
                f"fetch end: target={target} mode={mode} status={fresh_fetch.status} "
                f"error={bool(fresh_fetch.error)} elapsed={elapsed:.3f}s",
            )
            if is_cacheable_fetch(fresh_fetch):
                cache.set(target, mode, args.proxy, fresh_fetch, identity)
                diagnostics.log(3, f"cache write: target={target} mode={mode}")
            else:
                diagnostics.log(3, f"cache drop: target={target} mode={mode} reason=fetch-error")
            return fresh_fetch

        if args.mode in {"requests", "auto"}:
            fetch = cached_or_fetch("requests")
            provider_started = time.perf_counter()
            for provider in providers:
                findings.extend(provider.detect(fetch))
            diagnostics.log(
                3,
                f"providers complete: target={target} mode=requests "
                f"providers={len(providers)} findings={len(findings)} "
                f"elapsed={time.perf_counter() - provider_started:.3f}s",
            )

        fallback_reason = (
            browser_fallback_reason(fetch, len(findings))
            if (
                args.mode == "auto"
                and fetch is not None
                and not str(fetch.error or "").startswith("sanity check failed:")
            )
            else None
        )
        if args.mode == "browser" or (args.mode == "auto" and fallback_reason):
            if fallback_reason:
                diagnostics.log(
                    1,
                    f"auto switching fetcher: target={target} from=requests to=browser "
                    f"reason={fallback_reason}",
                )
            browser_fetch = cached_or_fetch("browser")
            if not browser_fetch.error:
                fetch = browser_fetch
                findings = []
                provider_started = time.perf_counter()
                for provider in providers:
                    findings.extend(provider.detect(fetch))
                diagnostics.log(
                    3,
                    f"providers complete: target={target} mode=browser "
                    f"providers={len(providers)} findings={len(findings)} "
                    f"elapsed={time.perf_counter() - provider_started:.3f}s",
                )
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


def print_result(result: dict[str, Any], output: str, color: bool) -> None:
    print(format_result(result, output, color), flush=True)
    if output == "human":
        print(flush=True)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args._diagnostics = Diagnostics(args.verbosity)
    providers_requested = args.provider or ["builtin"]
    provider_names = resolve_provider_names(
        providers_requested,
        args.wappalyzer_data,
    )
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
    if args.ca_bundle and args.insecure:
        print("error: --ca-bundle cannot be used with --insecure", file=sys.stderr)
        return 2
    if args.ca_bundle:
        args.ca_bundle = args.ca_bundle.expanduser()
        if not args.ca_bundle.exists():
            print(f"error: --ca-bundle does not exist: {args.ca_bundle}", file=sys.stderr)
            return 2

    targets = [line.strip() for line in sys.stdin if line.strip()]
    browser_session = (
        BrowserSession(
            args.proxy,
            ignore_https_errors=args.insecure,
            ca_bundle=str(args.ca_bundle.resolve()) if args.ca_bundle else None,
            enable_extension=not getattr(args, "no_browser_extension", False),
            diagnostics=args._diagnostics,
            include_traceback=args.verbosity >= 2,
        )
        if args.mode in {"browser", "auto"}
        else None
    )
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
                print_result(result, args.output, color)
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
            for future in as_completed(futures):
                print_result(future.result(), args.output, color)
    finally:
        if browser_session is not None:
            browser_session.close()
    return 0
