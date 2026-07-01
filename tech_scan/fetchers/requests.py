from __future__ import annotations

import warnings
from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

from tech_scan.diagnostics import Diagnostics, exception_with_traceback, short_exception
from tech_scan.html_extract import extract_script_srcs
from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.url_policy import redirect_target, same_hostname

from .adblock import is_blocked_script_url
from .headers import REQUESTS_HEADERS
from .resources import (
    is_redirect_status,
    limited_text_from_bytes_or_text,
    make_error_resource,
    make_redirect_resource,
    make_resource,
)

MAX_SCRIPT_RESOURCES = 25
MAX_SCRIPT_BODY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class RedirectFetch:
    response: requests.Response
    redirects: list[ResourceObservation]


def _cookie_dict(cookies: requests.cookies.RequestsCookieJar) -> dict[str, str]:
    return {cookie.name: cookie.value for cookie in cookies}


def _response_text(response: requests.Response, max_bytes: int | None = None) -> str:
    content = response.content if hasattr(response, "content") else None
    return limited_text_from_bytes_or_text(
        content=content,
        text=response.text or "",
        encoding=response.encoding or "utf-8",
        max_bytes=max_bytes,
    )


def _get_with_same_host_redirects(
    session: requests.Session,
    url: str,
    timeout: float,
    proxies: dict[str, str] | None,
    request_kwargs: dict[str, object],
    diagnostics: Diagnostics | None = None,
) -> RedirectFetch:
    current_url = url
    response = None
    redirects: list[ResourceObservation] = []
    for _ in range(10):
        if request_kwargs.get("verify") is False:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                response = session.get(
                    current_url,
                    headers=REQUESTS_HEADERS,
                    timeout=timeout,
                    proxies=proxies,
                    allow_redirects=False,
                    **request_kwargs,
                )
        else:
            response = session.get(
                current_url,
                headers=REQUESTS_HEADERS,
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
        redirects.append(
            make_redirect_resource(
                resource_id=f"redirect:{len(redirects)}",
                url=current_url,
                next_url=next_url,
                status=response.status_code,
                headers=response.headers,
                cookies=_cookie_dict(response.cookies),
            )
        )
        if diagnostics:
            diagnostics.log(1, f"requests redirect: {current_url} -> {next_url}")
        current_url = next_url
    if response is None:
        raise requests.RequestException("request failed")
    return RedirectFetch(response=response, redirects=redirects)


def _resource_from_response(
    resource_id: str,
    kind: str,
    url: str,
    response: requests.Response,
    parent_id: str | None = None,
    max_body_bytes: int | None = None,
) -> ResourceObservation:
    return make_resource(
        resource_id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=response.url,
        status=response.status_code,
        headers=response.headers,
        cookies=_cookie_dict(response.cookies),
        body=_response_text(response, max_body_bytes),
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
        redirect_fetch = _get_with_same_host_redirects(
            session,
            url,
            timeout,
            proxies,
            request_kwargs,
            diagnostics,
        )
        response = redirect_fetch.response
        document = _resource_from_response("document:0", "document", url, response)
        if diagnostics:
            diagnostics.log(
                3,
                f"requests fetch end: {url} status={document.status} "
                f"final_url={document.final_url}",
            )
        body = document.body
        script_srcs = extract_script_srcs(body)
        resources = [*redirect_fetch.redirects, document]
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
                script_fetch = _get_with_same_host_redirects(
                    session,
                    script_url,
                    timeout,
                    proxies,
                    request_kwargs,
                    diagnostics,
                )
                script_response = script_fetch.response
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
                    make_error_resource(
                        resource_id=resource_id,
                        kind="script",
                        url=script_url,
                        error=short_exception(exc),
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

    error_resource = make_error_resource("document:0", "document", url, error or "request failed")
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
