from __future__ import annotations

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from .fetchers.browser import AsyncBrowserPool
from .scanner import scan_input, scan_input_async


ResultPrinter = Callable[[dict[str, Any]], None]


def _log_interrupted(args: argparse.Namespace) -> None:
    diagnostics = getattr(args, "_diagnostics", None)
    if diagnostics:
        diagnostics.log(1, "scan interrupted; cancelling pending work")


def run_requests(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    print_result: ResultPrinter,
) -> int:
    executor = ThreadPoolExecutor(max_workers=args.concurrency)
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
    try:
        for future in as_completed(futures):
            for result in future.result():
                print_result(result)
    except KeyboardInterrupt:
        _log_interrupted(args)
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        return 130
    executor.shutdown(wait=True)
    return 0


async def run_browser_or_auto(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    print_result: ResultPrinter,
) -> int:
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks: list[asyncio.Task[list[dict[str, Any]]]] = []

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
        try:
            for task in asyncio.as_completed(tasks):
                for result in await task:
                    print_result(result)
        except (asyncio.CancelledError, KeyboardInterrupt):
            _log_interrupted(args)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return 130
    return 0
