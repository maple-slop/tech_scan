from __future__ import annotations

import re

from tech_scan.models import FetchResult


def looks_js_required(body: str) -> bool:
    lower = body.lower()
    markers = [
        "please enable javascript",
        "enable javascript",
        "requires javascript",
        "javascript is required",
        "you need to enable javascript",
    ]
    return any(marker in lower for marker in markers)


def looks_spa_shell(body: str, script_srcs: list[str]) -> bool:
    lower = body.lower()
    has_mount = any(
        marker in lower
        for marker in [
            '<div id="root"',
            "<div id='root'",
            '<div id="app"',
            "<div id='app'",
        ]
    )
    has_framework_marker = any(
        marker in lower
        for marker in [
            "__next_data__",
            "__nuxt__",
            "/_next/",
            "/_nuxt/",
        ]
    )
    script_count = len(script_srcs) or lower.count("<script")
    visible_text = re.sub(r"<(script|style)\b.*?</\1>", "", lower, flags=re.I | re.S)
    visible_text = re.sub(r"<[^>]+>", " ", visible_text)
    visible_text = re.sub(r"\s+", " ", visible_text).strip()
    is_thin_shell = len(visible_text) < 300 and script_count > 0
    return has_framework_marker or (has_mount and is_thin_shell)


def has_useful_response(fetch: FetchResult) -> bool:
    return bool(fetch.status or fetch.headers or fetch.body.strip())


def should_try_browser(fetch: FetchResult, findings_count: int) -> bool:
    return browser_fallback_reason(fetch, findings_count) is not None


def browser_fallback_reason(fetch: FetchResult, findings_count: int) -> str | None:
    if fetch.error:
        return "request-error"
    if fetch.status in {401, 403, 429, 503}:
        return f"blocking-status-{fetch.status}"
    if not has_useful_response(fetch):
        return "empty-response"
    body = fetch.body.strip()
    if looks_js_required(body):
        return "javascript-required"
    if findings_count == 0 and looks_spa_shell(body, fetch.script_srcs):
        return "spa-shell-without-findings"
    return None
