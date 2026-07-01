from __future__ import annotations

from collections.abc import Mapping
import inspect
from urllib.parse import urlparse

from tech_scan.diagnostics import Diagnostics, exception_with_traceback, short_exception
from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.url_policy import redirect_target, same_hostname

from .resources import (
    is_redirect_status,
    limited_text_from_bytes_or_text,
    make_redirect_resource,
    make_resource,
    normalize_headers,
)


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


def _value(obj: object, name: str, default: object = None) -> object:
    value = getattr(obj, name, default)
    return value() if callable(value) else value


def _resource_type(response: object) -> str:
    request = _value(response, "request")
    resource_type = _value(request, "resource_type", None) if request is not None else None
    return str(resource_type or "other")


def _is_http_url(url: str) -> bool:
    return urlparse(url).scheme in {"http", "https"}


def _browser_resource_kind(response: object, final_url: str | None = None) -> str:
    kind = _resource_type(response)
    status = _value(response, "status", None)
    url = str(_value(response, "url", ""))
    if (
        kind == "document"
        and is_redirect_status(status)
        and (final_url is None or url != final_url)
    ):
        return "redirect"
    return kind


def _is_text_resource(kind: str, headers: dict[str, str]) -> bool:
    content_type = headers.get("content-type", "").lower()
    return kind in TEXT_RESOURCE_TYPES or any(marker in content_type for marker in TEXT_CONTENT_MARKERS)


def _resource_id(kind: str, counters: dict[str, int]) -> str:
    index = counters.get(kind, 0)
    counters[kind] = index + 1
    return f"{kind}:{index}"


async def maybe_await(value: object) -> object:
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
        raw = await maybe_await(_value(response, "body", b""))
        if isinstance(raw, str):
            raw_bytes = raw.encode("utf-8", errors="replace")
        else:
            raw_bytes = bytes(raw or b"")
        return limited_text_from_bytes_or_text(
            raw_bytes,
            encoding="utf-8",
            max_bytes=MAX_RESOURCE_BODY_BYTES,
        ), None
    except Exception as exc:
        if diagnostics:
            diagnostics.exception(2, f"browser resource body failed: {str(_value(response, 'url', ''))}", exc)
        return "", short_exception(exc)


async def _async_resource_from_browser_response(
    resource_id: str,
    response: object,
    parent_id: str | None,
    final_page_url: str,
    diagnostics: Diagnostics | None = None,
) -> ResourceObservation | None:
    url = str(_value(response, "url", ""))
    if not _is_http_url(url):
        return None
    kind = _browser_resource_kind(response, final_page_url)
    headers = normalize_headers(_value(response, "headers", {}))
    body, error = await _async_response_body(response, kind, headers, diagnostics)
    status = _value(response, "status", None)
    status_int = int(status) if status is not None else None
    if kind == "redirect":
        return make_redirect_resource(
            resource_id=resource_id,
            url=url,
            next_url=redirect_target(url, headers.get("location")) or url,
            status=status_int,
            headers=headers,
            cookies={},
            parent_id=parent_id,
        )
    return make_resource(
        resource_id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=url,
        status=status_int,
        headers=headers,
        cookies={},
        body=body,
        error=error,
    )


async def capture_browser_page(
    context: object,
    target_input: str,
    url: str,
    timeout: float,
    diagnostics: Diagnostics | None = None,
    include_traceback: bool = False,
) -> FetchResult:
    blocked_redirect: dict[str, str] = {}
    page = None
    try:
        page = await context.new_page()
        observed_responses: list[object] = []

        def record_response(response: object) -> None:
            observed_responses.append(response)

        async def limit_main_frame_redirects(route: object, request: object) -> None:
            request_url = request.url
            is_navigation = await maybe_await(request.is_navigation_request())
            if (
                is_navigation
                and request.frame == page.main_frame
                and not same_hostname(url, request_url)
            ):
                blocked_redirect["url"] = request_url
                if diagnostics:
                    diagnostics.log(
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
        headers: Mapping[object, object] = response.headers if response else {}
        status = response.status if response else None
        final_url = page.url
        document = make_resource(
            resource_id="document:0",
            kind="document",
            url=url,
            final_url=final_url,
            status=status,
            headers=headers,
            cookies=cookies,
            body=body or "",
        )
        resources_list = [document]
        counters: dict[str, int] = {"document": 1}
        for observed in observed_responses:
            observed_url = str(_value(observed, "url", ""))
            observed_kind = _browser_resource_kind(observed, final_url)
            if observed_kind == "document" and observed_url == final_url:
                continue
            resource = await _async_resource_from_browser_response(
                _resource_id(observed_kind, counters),
                observed,
                document.id,
                final_url,
                diagnostics,
            )
            if resource is not None:
                resources_list.append(resource)
                if diagnostics:
                    diagnostics.log(
                        3,
                        f"browser resource observed: kind={resource.kind} "
                        f"status={resource.status} url={resource.url}",
                    )
        if diagnostics:
            diagnostics.log(
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
        if diagnostics:
            diagnostics.exception(2, f"browser fetch failed: {url}", exc)
        error_text = (
            exception_with_traceback(exc) if include_traceback else short_exception(exc)
        )
        if blocked_redirect.get("url"):
            message = f"blocked cross-host redirect to {blocked_redirect['url']}"
            error_text = (
                exception_with_traceback(exc, message)
                if include_traceback
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
            await maybe_await(page.close())
