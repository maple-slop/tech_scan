from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import ExitStack
from importlib import resources
import inspect
import os
import shutil
import tempfile
from urllib.parse import urlparse

from tech_scan.diagnostics import Diagnostics, exception_with_traceback, short_exception
from tech_scan.models import FetchResult, ResourceObservation

from .headers import BROWSER_HEADERS
from tech_scan.url_policy import same_hostname

UBOL_PACKAGE = "tech_scan.fetchers.data.ubol"
UBOL_VERSION = "2026.628.2035"
MAX_RESOURCE_BODY_BYTES = 1024 * 1024
TEXT_RESOURCE_TYPES = {"document", "script", "stylesheet", "xhr", "fetch"}
TEXT_CONTENT_MARKERS = [
    "text/",
    "javascript",
    "json",
    "xml",
    "html",
    "css",
]


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


def _value(obj: object, name: str, default: object = None) -> object:
    value = getattr(obj, name, default)
    return value() if callable(value) else value


def _headers(response: object) -> dict[str, str]:
    raw = _value(response, "headers", {})
    if isinstance(raw, Mapping):
        return {str(key).lower(): str(value) for key, value in raw.items()}
    return {}


def _resource_type(response: object) -> str:
    request = _value(response, "request")
    resource_type = _value(request, "resource_type", None) if request is not None else None
    return str(resource_type or "other")


def _is_http_url(url: str) -> bool:
    return urlparse(url).scheme in {"http", "https"}


def _is_text_resource(kind: str, headers: dict[str, str]) -> bool:
    content_type = headers.get("content-type", "").lower()
    return kind in TEXT_RESOURCE_TYPES or any(marker in content_type for marker in TEXT_CONTENT_MARKERS)


def _resource_id(kind: str, counters: dict[str, int]) -> str:
    index = counters.get(kind, 0)
    counters[kind] = index + 1
    return f"{kind}:{index}"


async def _maybe_await(value: object) -> object:
    if inspect.isawaitable(value):
        return await value
    return value


async def _async_response_body(
    response: object,
    kind: str,
    headers: dict[str, str],
    diagnostics: Diagnostics | None = None,
) -> tuple[str, str | None]:
    if not _is_text_resource(kind, headers):
        return "", None
    try:
        raw = await _maybe_await(_value(response, "body", b""))
        if isinstance(raw, str):
            raw_bytes = raw.encode("utf-8", errors="replace")
        else:
            raw_bytes = bytes(raw or b"")
        if len(raw_bytes) > MAX_RESOURCE_BODY_BYTES:
            raw_bytes = raw_bytes[:MAX_RESOURCE_BODY_BYTES]
        return raw_bytes.decode("utf-8", errors="replace"), None
    except Exception as exc:
        if diagnostics:
            diagnostics.exception(2, f"browser resource body failed: {str(_value(response, 'url', ''))}", exc)
        return "", short_exception(exc)


async def _async_resource_from_browser_response(
    resource_id: str,
    response: object,
    parent_id: str | None,
    diagnostics: Diagnostics | None = None,
) -> ResourceObservation | None:
    url = str(_value(response, "url", ""))
    if not _is_http_url(url):
        return None
    kind = _resource_type(response)
    headers = _headers(response)
    body, error = await _async_response_body(response, kind, headers, diagnostics)
    status = _value(response, "status", None)
    return ResourceObservation(
        id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=url,
        status=int(status) if status is not None else None,
        headers=headers,
        cookies={},
        body=body,
        error=error,
    )


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

        blocked_redirect: dict[str, str] = {}
        context = None
        close_context = False
        page = None
        try:
            if self.diagnostics:
                self.diagnostics.log(3, f"async browser fetch start: {url} timeout={timeout}")
            context, close_context = await self._context_for_fetch()
            if context is None:
                raise RuntimeError("browser context is not available")
            if self.enable_extension and hasattr(context, "clear_cookies"):
                await _maybe_await(context.clear_cookies())
            page = await context.new_page()
            observed_responses: list[object] = []

            def record_response(response: object) -> None:
                observed_responses.append(response)

            async def limit_main_frame_redirects(route: object, request: object) -> None:
                request_url = request.url
                is_navigation = await _maybe_await(request.is_navigation_request())
                if (
                    is_navigation
                    and request.frame == page.main_frame
                    and not same_hostname(url, request_url)
                ):
                    blocked_redirect["url"] = request_url
                    if self.diagnostics:
                        self.diagnostics.log(
                            1,
                            f"browser redirect blocked: {url} -> {request_url} "
                            f"(cross-host)",
                        )
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            await page.route("**/*", limit_main_frame_redirects)
            page.on("response", record_response)
            response = await page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            body = await page.content()
            globals_result = await page.evaluate(
                """() => Object.keys(window).filter((k) =>
                    /React|Vue|Angular|__NEXT|__NUXT|Svelte|jQuery|webpack/i.test(k)
                )"""
            )
            script_srcs = await page.evaluate(
                """() => Array.from(document.scripts)
                    .map((script) => script.src)
                    .filter(Boolean)"""
            )
            cookies = {
                cookie["name"]: cookie.get("value", "")
                for cookie in await context.cookies()
            }
            headers: Mapping[str, str] = response.headers if response else {}
            status = response.status if response else None
            final_url = page.url
            document = ResourceObservation(
                id="document:0",
                kind="document",
                url=url,
                final_url=final_url,
                status=status,
                headers={k.lower(): v for k, v in headers.items()},
                cookies=cookies,
                body=body or "",
            )
            resources_list = [document]
            counters: dict[str, int] = {"document": 1}
            for observed in observed_responses:
                observed_url = str(_value(observed, "url", ""))
                observed_kind = _resource_type(observed)
                if observed_kind == "document" and observed_url == final_url:
                    continue
                resource = await _async_resource_from_browser_response(
                    _resource_id(observed_kind, counters),
                    observed,
                    document.id,
                    self.diagnostics,
                )
                if resource is not None:
                    resources_list.append(resource)
                    if self.diagnostics:
                        self.diagnostics.log(
                            3,
                            f"browser resource observed: kind={resource.kind} "
                            f"status={resource.status} url={resource.url}",
                        )
            if self.diagnostics:
                self.diagnostics.log(
                    3,
                    f"async browser fetch end: {url} status={document.status} "
                    f"final_url={document.final_url} resources={len(resources_list)}",
                )
            return FetchResult(
                input=target_input,
                url=document.url,
                final_url=document.final_url,
                status=document.status,
                headers=document.headers,
                cookies=document.cookies,
                body=document.body,
                mode="browser",
                browser_globals=list(globals_result or []),
                script_srcs=list(script_srcs or []),
                resources=resources_list,
                primary_resource_id=document.id,
            )
        except Exception as exc:
            if self.diagnostics:
                self.diagnostics.exception(2, f"browser fetch failed: {url}", exc)
            error_text = (
                exception_with_traceback(exc) if self.include_traceback else short_exception(exc)
            )
            if blocked_redirect.get("url"):
                message = f"blocked cross-host redirect to {blocked_redirect['url']}"
                error_text = (
                    exception_with_traceback(exc, message)
                    if self.include_traceback
                    else message
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
            if page is not None and hasattr(page, "close"):
                await _maybe_await(page.close())
            if context is not None:
                if close_context:
                    await _maybe_await(context.close())
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
                await _maybe_await(context.close())
            except Exception:
                pass
        self._contexts = []
        if self._browser is not None:
            await _maybe_await(self._browser.close())
            self._browser = None
        if self._playwright is not None:
            await _maybe_await(self._playwright.stop())
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
