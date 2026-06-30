from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
from importlib import resources
import os
import shutil
import tempfile
import threading
import traceback
from urllib.parse import urlparse

from tech_scan.models import FetchResult, ResourceObservation

from .headers import BROWSER_HEADERS
from .requests import same_hostname

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


def _format_exception(exc: BaseException, message: str | None = None) -> str:
    prefix = message if message is not None else str(exc)
    return f"{prefix}\n{traceback.format_exc()}"


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


def _response_body(response: object, kind: str, headers: dict[str, str]) -> tuple[str, str | None]:
    if not _is_text_resource(kind, headers):
        return "", None
    try:
        raw = _value(response, "body", b"")
        if isinstance(raw, str):
            raw_bytes = raw.encode("utf-8", errors="replace")
        else:
            raw_bytes = bytes(raw or b"")
        if len(raw_bytes) > MAX_RESOURCE_BODY_BYTES:
            raw_bytes = raw_bytes[:MAX_RESOURCE_BODY_BYTES]
        return raw_bytes.decode("utf-8", errors="replace"), None
    except Exception as exc:
        return "", _format_exception(exc)


def _resource_from_browser_response(
    resource_id: str,
    response: object,
    parent_id: str | None,
) -> ResourceObservation | None:
    url = str(_value(response, "url", ""))
    if not _is_http_url(url):
        return None
    kind = _resource_type(response)
    headers = _headers(response)
    body, error = _response_body(response, kind, headers)
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


def _resource_id(kind: str, counters: dict[str, int]) -> str:
    index = counters.get(kind, 0)
    counters[kind] = index + 1
    return f"{kind}:{index}"


class BrowserSession:
    def __init__(
        self,
        proxy: str | None,
        ignore_https_errors: bool = False,
        ca_bundle: str | None = None,
        enable_extension: bool = True,
    ):
        self.proxy = proxy
        self.ignore_https_errors = ignore_https_errors
        self.ca_bundle = ca_bundle
        self.enable_extension = enable_extension
        self._playwright = None
        self._browser = None
        self._context = None
        self._startup_error: str | None = None
        self._lock = threading.Lock()
        self._profile_dir: str | None = None
        self._resources = ExitStack()

    def _ensure_browser(self) -> tuple[object | None, object | None]:
        if self._browser is not None or self._context is not None or self._startup_error is not None:
            return self._context or self._browser, self._startup_error
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            self._startup_error = _format_exception(
                exc,
                "Playwright is not installed; install tech-scan[browser]",
            )
            return None, self._startup_error

        launch_args: dict[str, object] = {"headless": True}
        executable_path = chromium_executable_path()
        if executable_path:
            launch_args["executable_path"] = executable_path
        elif self.enable_extension:
            launch_args["channel"] = "chromium"
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}
        if self.ca_bundle:
            env = dict(os.environ)
            env["SSL_CERT_FILE"] = self.ca_bundle
            env["REQUESTS_CA_BUNDLE"] = self.ca_bundle
            env["CURL_CA_BUNDLE"] = self.ca_bundle
            launch_args["env"] = env
        if self.enable_extension and self.ignore_https_errors:
            launch_args["ignore_https_errors"] = True

        try:
            self._playwright = sync_playwright().start()
            if self.enable_extension:
                extension_path = self._resources.enter_context(
                    resources.as_file(resources.files(UBOL_PACKAGE))
                )
                self._profile_dir = tempfile.mkdtemp(prefix="tech-scan-chromium-")
                args = [
                    f"--disable-extensions-except={extension_path}",
                    f"--load-extension={extension_path}",
                ]
                self._context = self._playwright.chromium.launch_persistent_context(
                    self._profile_dir,
                    args=args,
                    extra_http_headers=BROWSER_HEADERS,
                    **launch_args,
                )
                return self._context, None
            self._browser = self._playwright.chromium.launch(**launch_args)
            return self._browser, None
        except Exception as exc:
            self.close()
            self._startup_error = _format_exception(exc)
            return None, self._startup_error

    def fetch(self, target_input: str, url: str, timeout: float) -> FetchResult:
        with self._lock:
            browser_or_context, error = self._ensure_browser()
            if error or browser_or_context is None:
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
            page = None
            try:
                if self.enable_extension:
                    context = browser_or_context
                    if hasattr(context, "clear_cookies"):
                        context.clear_cookies()
                else:
                    context_args: dict[str, object] = {"extra_http_headers": BROWSER_HEADERS}
                    if self.ignore_https_errors:
                        context_args["ignore_https_errors"] = True
                    context = browser_or_context.new_context(**context_args)
                page = context.new_page()
                observed_responses: list[object] = []

                def record_response(response: object) -> None:
                    observed_responses.append(response)

                def limit_main_frame_redirects(route: object, request: object) -> None:
                    request_url = request.url
                    if (
                        request.is_navigation_request()
                        and request.frame == page.main_frame
                        and not same_hostname(url, request_url)
                    ):
                        blocked_redirect["url"] = request_url
                        route.abort("blockedbyclient")
                        return
                    route.continue_()

                page.route("**/*", limit_main_frame_redirects)
                page.on("response", record_response)
                response = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                body = page.content()
                globals_result = page.evaluate(
                    """() => Object.keys(window).filter((k) =>
                        /React|Vue|Angular|__NEXT|__NUXT|Svelte|jQuery|webpack/i.test(k)
                    )"""
                )
                script_srcs = page.evaluate(
                    """() => Array.from(document.scripts)
                        .map((script) => script.src)
                        .filter(Boolean)"""
                )
                cookies = {
                    cookie["name"]: cookie.get("value", "")
                    for cookie in context.cookies()
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
                    resource = _resource_from_browser_response(
                        _resource_id(observed_kind, counters),
                        observed,
                        document.id,
                    )
                    if resource is not None:
                        resources_list.append(resource)
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
                error_text = _format_exception(exc)
                if blocked_redirect.get("url"):
                    error_text = _format_exception(
                        exc,
                        f"blocked cross-host redirect to {blocked_redirect['url']}",
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
                    page.close()
                if context is not None and not self.enable_extension:
                    context.close()

    def close(self) -> None:
        if self._context is not None:
            self._context.close()
            self._context = None
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None
        self._resources.close()
        if self._profile_dir is not None:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None

    def __enter__(self) -> BrowserSession:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def fetch_browser(
    target_input: str,
    url: str,
    timeout: float,
    proxy: str | None,
    browser_session: BrowserSession | None = None,
    ignore_https_errors: bool = False,
    ca_bundle: str | None = None,
    enable_extension: bool = True,
) -> FetchResult:
    if browser_session is not None:
        return browser_session.fetch(target_input, url, timeout)
    with BrowserSession(proxy, ignore_https_errors, ca_bundle, enable_extension) as session:
        return session.fetch(target_input, url, timeout)
