from __future__ import annotations

from collections.abc import Mapping
import os
import re
import threading
from urllib.parse import urljoin, urlparse

import requests

from .models import FetchResult
from .normalize import http_fallback_url


BROWSER_HEADERS = {
    "Sec-Ch-Ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/149.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=0, i",
}


def _cookie_dict(cookies: requests.cookies.RequestsCookieJar) -> dict[str, str]:
    return {cookie.name: cookie.value for cookie in cookies}


def extract_script_srcs(body: str) -> list[str]:
    return [
        match.group(2)
        for match in re.finditer(
            r"<script\b[^>]*\bsrc\s*=\s*([\"'])(.*?)\1", body, re.I | re.S
        )
    ]


def same_hostname(first_url: str, second_url: str) -> bool:
    return (urlparse(first_url).hostname or "").lower() == (
        urlparse(second_url).hostname or ""
    ).lower()


def redirect_target(current_url: str, location: str | None) -> str | None:
    if not location:
        return None
    return urljoin(current_url, location)


def is_redirect_status(status_code: int) -> bool:
    return status_code in {301, 302, 303, 307, 308}


def fetch_requests(
    target_input: str, url: str, timeout: float, proxy: str | None
) -> FetchResult:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    session = requests.Session()

    last_error: str | None = None
    for candidate in [url, http_fallback_url(url)]:
        if not candidate:
            continue
        try:
            current_url = candidate
            response = None
            for _ in range(10):
                response = session.get(
                    current_url,
                    headers=BROWSER_HEADERS,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=False,
                )
                next_url = redirect_target(current_url, response.headers.get("location"))
                if not is_redirect_status(response.status_code) or not next_url:
                    break
                if not same_hostname(candidate, next_url):
                    break
                current_url = next_url
            if response is None:
                raise requests.RequestException("request failed")
            body = response.text or ""
            return FetchResult(
                input=target_input,
                url=candidate,
                final_url=response.url,
                status=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                cookies=_cookie_dict(response.cookies),
                body=body,
                mode="requests",
                script_srcs=extract_script_srcs(body),
            )
        except requests.RequestException as exc:
            last_error = str(exc)

    return FetchResult(
        input=target_input,
        url=url,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode="requests",
        error=last_error or "request failed",
    )


def should_try_browser(fetch: FetchResult, findings_count: int) -> bool:
    if fetch.error:
        return True
    if fetch.status in {403, 429, 503}:
        return True
    body = fetch.body.strip()
    if len(body) < 700:
        return True
    lower = body.lower()
    spa_markers = [
        '<div id="root"',
        '<div id="app"',
        "__next",
        "__nuxt",
        "window.__",
        "please enable javascript",
    ]
    return findings_count == 0 and any(marker in lower for marker in spa_markers)


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
