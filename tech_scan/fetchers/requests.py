from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests

from tech_scan.models import FetchResult
from tech_scan.normalize import http_fallback_url

from .headers import BROWSER_HEADERS


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
