from __future__ import annotations

import argparse
import asyncio
import queue
import threading
from typing import Any, Callable

from .fetchers.browser import AsyncBrowserPool
from .scanner import scan_input, scan_input_async


ResultPrinter = Callable[[dict[str, Any]], None]


def _log_interrupted(args: argparse.Namespace) -> None:
    diagnostics = getattr(args, "_diagnostics", None)
    if diagnostics:
        diagnostics.log(1, "scan interrupted; cancelling pending work")


def _print_ready(args: argparse.Namespace, result: dict[str, Any], print_result: ResultPrinter) -> None:
    diagnostics = getattr(args, "_diagnostics", None)
    if diagnostics:
        diagnostics.log(
            3,
            f"result ready: target={result.get('url')} "
            f"cached={str(bool(result.get('cached'))).lower()} "
            f"providers={','.join(result.get('providers') or [])}",
        )
    print_result(result)


def run_requests(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    print_result: ResultPrinter,
) -> int:
    stop_event = threading.Event()
    task_queue: queue.Queue[str | None] = queue.Queue()
    result_queue: queue.Queue[tuple[BaseException | None, dict[str, Any] | None, bool]] = queue.Queue()

    for target in targets:
        task_queue.put(target)
    worker_count = min(args.concurrency, len(targets)) if targets else 0
    for _ in range(worker_count):
        task_queue.put(None)

    def worker() -> None:
        while not stop_event.is_set():
            target = task_queue.get()
            if target is None:
                return
            try:
                scan_input(
                    target,
                    args,
                    providers_requested,
                    provider_names,
                    None,
                    emit_result=lambda result: result_queue.put((None, result, False)),
                )
                result_queue.put((None, None, True))
            except BaseException as exc:
                result_queue.put((exc, None, True))

    workers = [
        threading.Thread(target=worker, name=f"tech-scan-request-{index}", daemon=True)
        for index in range(worker_count)
    ]
    for worker_thread in workers:
        worker_thread.start()

    completed = 0
    try:
        while completed < len(targets):
            try:
                error, result, done = result_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if error is not None:
                if isinstance(error, KeyboardInterrupt):
                    raise error
                raise error
            if result is not None:
                _print_ready(args, result, print_result)
            if done:
                completed += 1
    except KeyboardInterrupt:
        _log_interrupted(args)
        stop_event.set()
        return 130
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
        async def run_target(target: str) -> None:
            async with semaphore:
                args._diagnostics.log(3, f"async scan start: target={target}")
                await scan_input_async(
                    target,
                    args,
                    providers_requested,
                    provider_names,
                    browser_pool,
                    emit_result=lambda result: _print_ready(args, result, print_result),
                )
                args._diagnostics.log(3, f"async scan end: target={target}")

        tasks = [asyncio.create_task(run_target(target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await task
        except (asyncio.CancelledError, KeyboardInterrupt):
            _log_interrupted(args)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return 130
    return 0
