from __future__ import annotations

from collections.abc import Mapping
import os
import threading

from tech_scan.models import FetchResult

from .headers import BROWSER_HEADERS
from .requests import same_hostname


def chromium_executable_path() -> str | None:
    env_path = os.environ.get("CHROMIUM_PATH")
    if env_path:
        return env_path
    if os.access("/usr/bin/chromium", os.X_OK):
        return "/usr/bin/chromium"
    return None


class BrowserSession:
    def __init__(self, proxy: str | None):
        self.proxy = proxy
        self._playwright = None
        self._browser = None
        self._startup_error: str | None = None
        self._lock = threading.Lock()

    def _ensure_browser(self) -> tuple[object | None, object | None]:
        if self._browser is not None or self._startup_error is not None:
            return self._browser, self._startup_error
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self._startup_error = "Playwright is not installed; install tech-scan[browser]"
            return None, self._startup_error

        launch_args: dict[str, object] = {"headless": True}
        executable_path = chromium_executable_path()
        if executable_path:
            launch_args["executable_path"] = executable_path
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(**launch_args)
            return self._browser, None
        except Exception as exc:
            self.close()
            self._startup_error = str(exc)
            return None, self._startup_error

    def fetch(self, target_input: str, url: str, timeout: float) -> FetchResult:
        with self._lock:
            browser, error = self._ensure_browser()
            if error or browser is None:
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
                context = browser.new_context(extra_http_headers=BROWSER_HEADERS)
                page = context.new_page()

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
                return FetchResult(
                    input=target_input,
                    url=url,
                    final_url=final_url,
                    status=status,
                    headers={k.lower(): v for k, v in headers.items()},
                    cookies=cookies,
                    body=body or "",
                    mode="browser",
                    browser_globals=list(globals_result or []),
                    script_srcs=list(script_srcs or []),
                )
            except Exception as exc:
                error_text = str(exc)
                if blocked_redirect.get("url"):
                    error_text = f"blocked cross-host redirect to {blocked_redirect['url']}"
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
                    context.close()

    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

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
) -> FetchResult:
    if browser_session is not None:
        return browser_session.fetch(target_input, url, timeout)
    with BrowserSession(proxy) as session:
        return session.fetch(target_input, url, timeout)
