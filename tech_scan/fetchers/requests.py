from __future__ import annotations

import re
import warnings
from urllib.parse import urljoin, urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

from tech_scan.diagnostics import Diagnostics, exception_with_traceback, short_exception
from tech_scan.models import FetchResult, ResourceObservation

from .adblock import is_blocked_script_url
from .headers import BROWSER_HEADERS

MAX_SCRIPT_RESOURCES = 25
MAX_SCRIPT_BODY_BYTES = 1024 * 1024


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


def _limited_text(response: requests.Response, max_bytes: int | None = None) -> str:
    content = response.content if hasattr(response, "content") else None
    if content is None:
        text = response.text or ""
        content = text.encode(response.encoding or "utf-8", errors="replace")
    if max_bytes is not None and len(content) > max_bytes:
        content = content[:max_bytes]
    encoding = response.encoding or "utf-8"
    return content.decode(encoding, errors="replace")


def _get_with_same_host_redirects(
    session: requests.Session,
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    request_kwargs: dict[str, object],
    diagnostics: Diagnostics | None = None,
) -> requests.Response:
    current_url = url
    response = None
    for _ in range(10):
        if request_kwargs.get("verify") is False:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                response = session.get(
                    current_url,
                    headers=BROWSER_HEADERS,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=False,
                    **request_kwargs,
                )
        else:
            response = session.get(
                current_url,
                headers=BROWSER_HEADERS,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=False,
                **request_kwargs,
            )
        next_url = redirect_target(current_url, response.headers.get("location"))
        if not is_redirect_status(response.status_code) or not next_url:
            break
        if not same_hostname(url, next_url):
            if diagnostics:
                diagnostics.log(
                    1,
                    f"requests redirect stopped: {current_url} -> {next_url} "
                    f"(cross-host)",
                )
            break
        if diagnostics:
            diagnostics.log(1, f"requests redirect: {current_url} -> {next_url}")
        current_url = next_url
    if response is None:
        raise requests.RequestException("request failed")
    return response


def _resource_from_response(
    resource_id: str,
    kind: str,
    url: str,
    response: requests.Response,
    parent_id: str | None = None,
    max_body_bytes: int | None = None,
) -> ResourceObservation:
    return ResourceObservation(
        id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=response.url,
        status=response.status_code,
        headers={k.lower(): v for k, v in response.headers.items()},
        cookies=_cookie_dict(response.cookies),
        body=_limited_text(response, max_body_bytes),
    )


def _error_resource(
    resource_id: str,
    kind: str,
    url: str,
    error: str,
    parent_id: str | None = None,
) -> ResourceObservation:
    return ResourceObservation(
        id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        error=error,
    )


def fetch_requests(
    target_input: str,
    url: str,
    timeout: float,
    proxy: str | None,
    verify: bool | str | None = None,
    diagnostics: Diagnostics | None = None,
    include_traceback: bool = False,
) -> FetchResult:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    session = requests.Session()
    request_kwargs = {}
    if verify is not None:
        request_kwargs["verify"] = verify

    try:
        if diagnostics:
            diagnostics.log(3, f"requests fetch start: {url}")
        response = _get_with_same_host_redirects(
            session,
            url,
            timeout,
            proxies,
            request_kwargs,
            diagnostics,
        )
        document = _resource_from_response("document:0", "document", url, response)
        if diagnostics:
            diagnostics.log(
                3,
                f"requests fetch end: {url} status={document.status} "
                f"final_url={document.final_url}",
            )
        body = document.body
        script_srcs = extract_script_srcs(body)
        resources = [document]
        base_url = response.url or url
        for index, src in enumerate(script_srcs[:MAX_SCRIPT_RESOURCES]):
            script_url = urljoin(base_url, src)
            if is_blocked_script_url(script_url):
                if diagnostics:
                    diagnostics.log(3, f"requests script skipped by adblock: {script_url}")
                continue
            resource_id = f"script:{index}"
            try:
                if diagnostics:
                    diagnostics.log(3, f"requests script fetch start: {script_url}")
                script_response = _get_with_same_host_redirects(
                    session,
                    script_url,
                    timeout,
                    proxies,
                    request_kwargs,
                    diagnostics,
                )
                resources.append(
                    _resource_from_response(
                        resource_id,
                        "script",
                        script_url,
                        script_response,
                        parent_id=document.id,
                        max_body_bytes=MAX_SCRIPT_BODY_BYTES,
                    )
                )
                if diagnostics:
                    diagnostics.log(3, f"requests script fetch end: {script_url}")
            except requests.RequestException as exc:
                if diagnostics:
                    diagnostics.exception(2, f"requests script fetch failed: {script_url}", exc)
                resources.append(
                    _error_resource(
                        resource_id,
                        "script",
                        script_url,
                        short_exception(exc),
                        parent_id=document.id,
                    )
                )
        return FetchResult(
            input=target_input,
            url=document.url,
            final_url=document.final_url,
            status=document.status,
            headers=document.headers,
            cookies=document.cookies,
            body=body,
            mode="requests",
            script_srcs=[urljoin(base_url, src) for src in script_srcs],
            resources=resources,
            primary_resource_id=document.id,
        )
    except requests.RequestException as exc:
        if diagnostics:
            diagnostics.exception(2, f"requests fetch failed: {url}", exc)
        error = exception_with_traceback(exc) if include_traceback else short_exception(exc)

    error_resource = _error_resource("document:0", "document", url, error or "request failed")
    return FetchResult(
        input=target_input,
        url=url,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        mode="requests",
        error=error or "request failed",
        resources=[error_resource],
        primary_resource_id=error_resource.id,
    )
