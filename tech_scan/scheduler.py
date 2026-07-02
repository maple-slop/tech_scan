from __future__ import annotations

import argparse
import asyncio
import queue
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from .fetchers.browser import AsyncBrowserPool
from .models import ScanResult
from .scanner import scan_input, scan_input_async


SchedulerResult = ScanResult | Mapping[str, Any]
ResultPrinter = Callable[[SchedulerResult], None]


@dataclass(frozen=True)
class WorkerMessage:
    error: BaseException | None = None
    result: SchedulerResult | None = None
    done: bool = False


REQUEST_WORKER_JOIN_TIMEOUT = 0.2


def _log_interrupted(args: argparse.Namespace) -> None:
    diagnostics = getattr(args, "_diagnostics", None)
    if diagnostics and not getattr(args, "_interrupted_logged", False):
        args._interrupted_logged = True
        diagnostics.log(1, "scan interrupted; cancelling pending work")


def _result_json(result: SchedulerResult) -> dict[str, Any]:
    if isinstance(result, ScanResult):
        return result.to_json()
    return dict(result)


def _print_ready(args: argparse.Namespace, result: SchedulerResult, print_result: ResultPrinter) -> None:
    result_json = _result_json(result)
    diagnostics = getattr(args, "_diagnostics", None)
    if diagnostics:
        cache = result_json.get("cache") or {}
        diagnostics.log(
            3,
            f"result ready: target={result_json.get('url')} "
            f"cache.lookup={cache.get('lookup')} "
            f"providers={','.join(result_json.get('providers') or [])}",
        )
    print_result(result)


class RequestScheduler:
    def __init__(
        self,
        targets: list[str],
        args: argparse.Namespace,
        providers_requested: list[str],
        provider_names: list[str],
        print_result: ResultPrinter,
    ):
        self.targets = targets
        self.args = args
        self.providers_requested = providers_requested
        self.provider_names = provider_names
        self.print_result = print_result
        self.stop_event = threading.Event()
        self.task_queue: queue.Queue[str | None] = queue.Queue()
        self.result_queue: queue.Queue[WorkerMessage] = queue.Queue()
        self.worker_count = min(args.concurrency, len(targets)) if targets else 0
        self.workers = [
            threading.Thread(
                target=self._worker,
                name=f"tech-scan-request-{index}",
                daemon=True,
            )
            for index in range(self.worker_count)
        ]

    def run(self) -> int:
        self._enqueue_targets()
        for worker in self.workers:
            worker.start()

        completed = 0
        try:
            while completed < len(self.targets):
                try:
                    message = self.result_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if message.error is not None:
                    if isinstance(message.error, KeyboardInterrupt):
                        raise message.error
                    self._request_stop()
                    self._join_workers()
                    raise message.error
                if self.stop_event.is_set():
                    continue
                if message.result is not None:
                    _print_ready(self.args, message.result, self.print_result)
                if message.done:
                    completed += 1
        except KeyboardInterrupt:
            _log_interrupted(self.args)
            self._request_stop()
            self._join_workers()
            return 130
        self._join_workers()
        return 0

    def _enqueue_targets(self) -> None:
        for target in self.targets:
            self.task_queue.put(target)
        self._enqueue_sentinels()

    def _enqueue_sentinels(self) -> None:
        for _ in range(self.worker_count):
            self.task_queue.put(None)

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            target = self.task_queue.get()
            if target is None or self.stop_event.is_set():
                return
            try:
                scan_input(
                    target,
                    self.args,
                    self.providers_requested,
                    self.provider_names,
                    None,
                    emit_result=self._emit_result,
                )
                self._put_message(WorkerMessage(done=True))
            except BaseException as exc:
                if isinstance(exc, KeyboardInterrupt):
                    self.stop_event.set()
                    self._put_message(WorkerMessage(error=exc, done=True), force=True)
                else:
                    self._put_message(WorkerMessage(error=exc, done=True))

    def _emit_result(self, result: SchedulerResult) -> None:
        self._put_message(WorkerMessage(result=result))

    def _put_message(self, message: WorkerMessage, force: bool = False) -> None:
        if force or not self.stop_event.is_set():
            self.result_queue.put(message)

    def _request_stop(self) -> None:
        self.stop_event.set()
        self._drain_pending_targets()
        self._enqueue_sentinels()

    def _drain_pending_targets(self) -> None:
        while True:
            try:
                self.task_queue.get_nowait()
            except queue.Empty:
                return

    def _join_workers(self) -> None:
        for worker in self.workers:
            worker.join(timeout=REQUEST_WORKER_JOIN_TIMEOUT)


def run_requests(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    print_result: ResultPrinter,
) -> int:
    return RequestScheduler(
        targets,
        args,
        providers_requested,
        provider_names,
        print_result,
    ).run()


async def run_browser_or_auto(
    targets: list[str],
    args: argparse.Namespace,
    providers_requested: list[str],
    provider_names: list[str],
    print_result: ResultPrinter,
) -> int:
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks: list[asyncio.Task[None]] = []
    shutdown_requested = False

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
            nonlocal shutdown_requested
            try:
                async with semaphore:
                    if shutdown_requested:
                        return
                    args._diagnostics.log(3, f"async scan start: target={target}")
                    await scan_input_async(
                        target,
                        args,
                        providers_requested,
                        provider_names,
                        browser_pool,
                        emit_result=lambda result: (
                            None
                            if shutdown_requested
                            else _print_ready(args, result, print_result)
                        ),
                    )
                    args._diagnostics.log(3, f"async scan end: target={target}")
            except BaseException:
                shutdown_requested = True
                raise

        tasks = [asyncio.create_task(run_target(target)) for target in targets]
        try:
            for task in asyncio.as_completed(tasks):
                await task
        except (asyncio.CancelledError, KeyboardInterrupt):
            shutdown_requested = True
            _log_interrupted(args)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return 130
    return 0
