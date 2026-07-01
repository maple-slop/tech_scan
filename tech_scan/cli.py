from __future__ import annotations

import argparse
import asyncio
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .cache import default_db_path
from .cli_config import ca_bundle_env_default
from .diagnostics import Diagnostics
from .fetchers.browser import AsyncBrowserPool
from .output import format_result
from .scanner import scan_input, scan_input_async


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect website technologies for domains read from stdin. "
            "Defaults to human-readable output; use --output jsonl for one JSON object per scanned URL."
        ),
        epilog=(
            "Examples: "
            "printf 'example.com\\n' | tech-scan; "
            "tech-scan --provider all < domains.txt"
        ),
    )
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
        default=10,
        help="Per-target fetch timeout in seconds. Default: 10.",
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
            "per scanned URL. Bare domains scan both HTTP and HTTPS. Default: human."
        ),
    )
    parser.add_argument(
        "--provider",
        action="append",
        choices=["builtin", "wappalyzergo", "all"],
        default=None,
        help=(
            "Detection provider. Repeatable. builtin is curated local rules; "
            "wappalyzergo uses vendored projectdiscovery/wappalyzergo fingerprints; "
            "all enables builtin and wappalyzergo. Default: builtin."
        ),
    )
    return parser.parse_args(argv)


def resolve_provider_names(
    requested: list[str],
) -> list[str]:
    if "all" in requested:
        return ["builtin", "wappalyzergo"]
    return sorted(set(requested))


def print_result(result: dict[str, Any], output: str, color: bool) -> None:
    print(format_result(result, output, color), flush=True)
    if output == "human":
        print(flush=True)


async def main_browser_async(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    color: bool,
) -> int:
    semaphore = asyncio.Semaphore(args.concurrency)
    async with AsyncBrowserPool(
        args.proxy,
        args.concurrency,
        ignore_https_errors=args.insecure,
        ca_bundle=str(args.ca_bundle.resolve()) if args.ca_bundle else None,
        enable_extension=not getattr(args, "no_browser_extension", False),
        diagnostics=args._diagnostics,
        include_traceback=args.verbosity >= 2,
    ) as browser_pool:
        async def run_target(target: str) -> list[dict[str, Any]]:
            async with semaphore:
                args._diagnostics.log(3, f"async scan start: target={target}")
                results = await scan_input_async(
                    target,
                    args,
                    providers_requested,
                    provider_names,
                    browser_pool,
                )
                args._diagnostics.log(3, f"async scan end: target={target}")
                return results

        tasks = [asyncio.create_task(run_target(target)) for target in targets]
        for task in asyncio.as_completed(tasks):
            for result in await task:
                print_result(result, args.output, color)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args._diagnostics = Diagnostics(args.verbosity)
    providers_requested = args.provider or ["builtin"]
    provider_names = resolve_provider_names(
        providers_requested,
    )
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
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if args.mode in {"browser", "auto"}:
        return asyncio.run(
            main_browser_async(
                targets,
                args,
                providers_requested,
                provider_names,
                color,
            )
        )

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(
                scan_input,
                target,
                args,
                providers_requested,
                provider_names,
                None,
            )
            for target in targets
        ]
        for future in as_completed(futures):
            for result in future.result():
                print_result(result, args.output, color)
    return 0
