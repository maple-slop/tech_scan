from __future__ import annotations

from collections.abc import Mapping
import re

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
            response = session.get(
                candidate,
                headers=BROWSER_HEADERS,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=True,
            )
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


def fetch_browser(
    target_input: str, url: str, timeout: float, proxy: str | None
) -> FetchResult:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return FetchResult(
            input=target_input,
            url=url,
            final_url=None,
            status=None,
            headers={},
            cookies={},
            body="",
            mode="browser",
            error="Playwright is not installed; install tech-scan[browser]",
        )

    launch_args: dict[str, object] = {"headless": True}
    if proxy:
        launch_args["proxy"] = {"server": proxy}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_args)
            page = browser.new_page(extra_http_headers=BROWSER_HEADERS)
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
                for cookie in page.context.cookies()
            }
            headers: Mapping[str, str] = response.headers if response else {}
            status = response.status if response else None
            final_url = page.url
            browser.close()
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
    except PlaywrightError as exc:
        return FetchResult(
            input=target_input,
            url=url,
            final_url=None,
            status=None,
            headers={},
            cookies={},
            body="",
            mode="browser",
            error=str(exc),
        )
