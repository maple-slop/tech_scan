from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .cache import ResponseCache, default_db_path
from .fetch import fetch_browser, fetch_requests, should_try_browser
from .models import FetchResult
from .normalize import normalize_target
from .providers import build_providers, merge_findings


RESET = "\033[0m"
COLORS = {
    "dim": "\033[2m",
    "green": "\033[32m",
    "bright_green": "\033[1;32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS[color]}{text}{RESET}"


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
                fresh_fetch = fetch_browser(raw_target, target, args.timeout, args.proxy)
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


def format_jsonl(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True)


def origin_display_url(result: dict[str, Any]) -> str:
    for value in [result.get("url"), result.get("input")]:
        if not value:
            continue
        text = str(value)
        parsed = urlparse(text if "://" in text else f"https://{text}")
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/"
    return "<unknown>"


def status_color(status: object, error: object) -> str:
    if error:
        return "red"
    try:
        code = int(status)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "yellow"
    if 200 <= code < 400:
        return "green"
    if 400 <= code < 500:
        return "yellow"
    return "red"


def confidence_color(confidence: object) -> str:
    try:
        score = int(confidence)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "dim"
    if score >= 90:
        return "bright_green"
    if score >= 75:
        return "green"
    if score >= 50:
        return "yellow"
    return "dim"


def evidence_color(evidence: object) -> str:
    text = str(evidence).lower()
    strong_markers = [
        "header",
        "cookie",
        "csrf",
        "viewstate",
        "state field",
        "wappalyzer header",
        "wappalyzer cookie",
        "wappalyzer meta",
        "wappalyzer script",
    ]
    weak_markers = [
        "url suffix",
        "implied",
        "generic",
        "no evidence",
    ]
    if any(marker in text for marker in strong_markers):
        return "green"
    if any(marker in text for marker in weak_markers):
        return "dim"
    if any(marker in text for marker in ["body", "html", "script", "meta", "global", "js", "marker"]):
        return "yellow"
    return "yellow"


def format_human(result: dict[str, Any], color: bool = True) -> str:
    technologies = result.get("technologies") or []
    tech_names = [str(tech.get("name", "")) for tech in technologies if tech.get("name")]
    summary = ", ".join(tech_names) if tech_names else "no technologies"
    display_url = origin_display_url(result)
    status = result.get("status")
    error = result.get("error")
    status_text = str(status) if status is not None else "no status"
    status_style = status_color(status, error)

    lines = [
        " ".join(
            [
                colorize(str(display_url), "bold", color),
                colorize(status_text, status_style, color),
                colorize(summary, "cyan", color),
            ]
        )
    ]
    lines.extend(
        [
            f"  input: {result.get('input')}",
            f"  url: {result.get('url')}",
            f"  status: {colorize(status_text, status_style, color)}",
            f"  mode: {result.get('mode')}",
            f"  providers: {', '.join(result.get('providers') or [])}",
            f"  cached: {result.get('cached')}",
            f"  error: {colorize(str(error), 'red', color) if error else None}",
        ]
    )

    if not technologies:
        lines.append("  technologies: none")
        return "\n".join(lines)

    lines.append("  technologies:")
    for index, tech in enumerate(technologies, start=1):
        name = colorize(str(tech.get("name")), "bold", color)
        confidence = tech.get("confidence")
        confidence_text = colorize(str(confidence), confidence_color(confidence), color)
        lines.append(
            "  "
            f"{index}. {name}: dimension={tech.get('dimension')}, "
            f"provider={tech.get('provider')}, confidence={confidence_text}"
        )
        evidence = tech.get("evidence") or []
        if evidence:
            for item in evidence:
                lines.append(f"     evidence: {colorize(str(item), evidence_color(item), color)}")
        else:
            lines.append(f"     evidence: {colorize('none', evidence_color('no evidence'), color)}")
    return "\n".join(lines)


def format_result(result: dict[str, Any], output: str, color: bool) -> str:
    if output == "jsonl":
        return format_jsonl(result)
    return format_human(result, color=color)


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
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(scan_target, target, args, providers_requested, provider_names)
            for target in targets
        ]
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        for future in futures:
            print(format_result(future.result(), args.output, color), flush=True)
            if args.output == "human":
                print(flush=True)
    return 0
