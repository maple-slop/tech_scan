from __future__ import annotations

import asyncio
from contextlib import ExitStack
from importlib import resources
import os
import shutil
import tempfile

from tech_scan.diagnostics import Diagnostics, exception_with_traceback, short_exception
from tech_scan.models import FetchResult

from .headers import BROWSER_HEADERS
from .browser_capture import capture_browser_page, maybe_await

UBOL_PACKAGE = "tech_scan.fetchers.data.ubol"
UBOL_VERSION = "2026.628.2035"


def chromium_executable_path() -> str | None:
    env_path = os.environ.get("CHROMIUM_PATH")
    if env_path:
        return env_path
    if os.access("/usr/bin/chromium", os.X_OK):
        return "/usr/bin/chromium"
    return None


def ubol_extension_path() -> str:
    return str(resources.files(UBOL_PACKAGE))


def browser_extension_identity(enabled: bool) -> str:
    return f"extension:ubol:{UBOL_VERSION}" if enabled else "extension:none"


def _browser_launch_args(
    proxy: str | None,
    ca_bundle: str | None,
    ignore_https_errors: bool,
    enable_extension: bool,
    diagnostics: Diagnostics | None = None,
) -> dict[str, object]:
    launch_args: dict[str, object] = {"headless": True}
    executable_path = chromium_executable_path()
    if executable_path:
        launch_args["executable_path"] = executable_path
        if diagnostics:
            diagnostics.log(3, f"browser launch executable_path={executable_path}")
    elif enable_extension:
        launch_args["channel"] = "chromium"
        if diagnostics:
            diagnostics.log(3, "browser launch channel=chromium")
    elif diagnostics:
        diagnostics.log(3, "browser launch using Playwright default browser")
    if proxy:
        launch_args["proxy"] = {"server": proxy}
    if ca_bundle:
        env = dict(os.environ)
        env["SSL_CERT_FILE"] = ca_bundle
        env["REQUESTS_CA_BUNDLE"] = ca_bundle
        env["CURL_CA_BUNDLE"] = ca_bundle
        launch_args["env"] = env
    if enable_extension and ignore_https_errors:
        launch_args["ignore_https_errors"] = True
    return launch_args


class AsyncBrowserPool:
    def __init__(
        self,
        proxy: str | None,
        concurrency: int,
        ignore_https_errors: bool = False,
        ca_bundle: str | None = None,
        enable_extension: bool = True,
        diagnostics: Diagnostics | None = None,
        include_traceback: bool = False,
    ):
        self.proxy = proxy
        self.concurrency = max(1, concurrency)
        self.ignore_https_errors = ignore_https_errors
        self.ca_bundle = ca_bundle
        self.enable_extension = enable_extension
        self.diagnostics = diagnostics
        self.include_traceback = include_traceback
        self._playwright = None
        self._browser = None
        self._contexts: list[object] = []
        self._context_queue: asyncio.Queue[object] | None = None
        self._startup_error: str | None = None
        self._start_lock = asyncio.Lock()
        self._profile_dirs: list[str] = []
        self._resources = ExitStack()

    async def _ensure_started(self) -> str | None:
        if self._browser is not None or self._contexts or self._startup_error is not None:
            return self._startup_error
        async with self._start_lock:
            if self._browser is not None or self._contexts or self._startup_error is not None:
                return self._startup_error
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                if self.diagnostics:
                    self.diagnostics.exception(2, "playwright import failed", exc)
                self._startup_error = (
                    exception_with_traceback(
                        exc,
                        "Playwright is not installed; install tech-scan[browser]",
                    )
                    if self.include_traceback
                    else "Playwright is not installed; install tech-scan[browser]"
                )
                return self._startup_error

            launch_args = _browser_launch_args(
                self.proxy,
                self.ca_bundle,
                self.ignore_https_errors,
                self.enable_extension,
                self.diagnostics,
            )
            try:
                if self.diagnostics:
                    self.diagnostics.log(
                        3,
                        f"async browser launch start: extension={self.enable_extension} "
                        f"proxy={self.proxy} concurrency={self.concurrency}",
                    )
                self._playwright = await async_playwright().start()
                if self.enable_extension:
                    extension_path = self._resources.enter_context(
                        resources.as_file(resources.files(UBOL_PACKAGE))
                    )
                    args = [
                        f"--disable-extensions-except={extension_path}",
                        f"--load-extension={extension_path}",
                    ]
                    self._context_queue = asyncio.Queue()
                    for _ in range(self.concurrency):
                        profile_dir = tempfile.mkdtemp(prefix="tech-scan-chromium-")
                        self._profile_dirs.append(profile_dir)
                        context = await self._playwright.chromium.launch_persistent_context(
                            profile_dir,
                            args=args,
                            extra_http_headers=BROWSER_HEADERS,
                            **launch_args,
                        )
                        self._contexts.append(context)
                        await self._context_queue.put(context)
                    if self.diagnostics:
                        self.diagnostics.log(3, f"async browser persistent contexts ready: {len(self._contexts)}")
                    return None
                self._browser = await self._playwright.chromium.launch(**launch_args)
                if self.diagnostics:
                    self.diagnostics.log(3, "async browser launch ready")
                return None
            except Exception as exc:
                await self.close()
                if self.diagnostics:
                    self.diagnostics.exception(2, "browser launch failed", exc)
                self._startup_error = (
                    exception_with_traceback(exc) if self.include_traceback else short_exception(exc)
                )
                return self._startup_error

    async def _context_for_fetch(self) -> tuple[object | None, bool]:
        if self.enable_extension:
            if self._context_queue is None:
                return None, False
            context = await self._context_queue.get()
            return context, False
        context_args: dict[str, object] = {"extra_http_headers": BROWSER_HEADERS}
        if self.ignore_https_errors:
            context_args["ignore_https_errors"] = True
        return await self._browser.new_context(**context_args), True

    async def fetch(self, target_input: str, url: str, timeout: float) -> FetchResult:
        error = await self._ensure_started()
        if error:
            return FetchResult(
                input=target_input,
                url=url,
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error=str(error),
            )

        context = None
        close_context = False
        try:
            if self.diagnostics:
                self.diagnostics.log(3, f"async browser fetch start: {url} timeout={timeout}")
            context, close_context = await self._context_for_fetch()
            if context is None:
                raise RuntimeError("browser context is not available")
            if self.enable_extension and hasattr(context, "clear_cookies"):
                await maybe_await(context.clear_cookies())
            return await capture_browser_page(
                context,
                target_input,
                url,
                timeout,
                self.diagnostics,
                self.include_traceback,
            )
        except Exception as exc:
            if self.diagnostics:
                self.diagnostics.exception(2, f"browser fetch failed: {url}", exc)
            error_text = (
                exception_with_traceback(exc) if self.include_traceback else short_exception(exc)
            )
            return FetchResult(
                input=target_input,
                url=url,
                final_url=None,
                status=None,
                headers={},
                cookies={},
                body="",
                mode="browser",
                error=error_text,
            )
        finally:
            if context is not None:
                if close_context:
                    await maybe_await(context.close())
                elif self._context_queue is not None:
                    await self._context_queue.put(context)

    async def close(self) -> None:
        while self._context_queue is not None and not self._context_queue.empty():
            try:
                self._context_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        for context in self._contexts:
            try:
                await maybe_await(context.close())
            except Exception:
                pass
        self._contexts = []
        if self._browser is not None:
            await maybe_await(self._browser.close())
            self._browser = None
        if self._playwright is not None:
            await maybe_await(self._playwright.stop())
            self._playwright = None
        self._resources.close()
        for profile_dir in self._profile_dirs:
            shutil.rmtree(profile_dir, ignore_errors=True)
        self._profile_dirs = []

    async def __aenter__(self) -> "AsyncBrowserPool":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()


async def fetch_browser_async(
    target_input: str,
    url: str,
    timeout: float,
    proxy: str | None,
    browser_pool: AsyncBrowserPool | None = None,
    ignore_https_errors: bool = False,
    ca_bundle: str | None = None,
    enable_extension: bool = True,
    diagnostics: Diagnostics | None = None,
    include_traceback: bool = False,
) -> FetchResult:
    if browser_pool is not None:
        return await browser_pool.fetch(target_input, url, timeout)
    async with AsyncBrowserPool(
        proxy,
        1,
        ignore_https_errors,
        ca_bundle,
        enable_extension,
        diagnostics,
        include_traceback,
    ) as pool:
        return await pool.fetch(target_input, url, timeout)
