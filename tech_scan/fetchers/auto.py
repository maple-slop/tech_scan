from __future__ import annotations

import re

from tech_scan.models import FetchResult


BLOCKING_STATUSES = {401, 403, 406, 409, 418, 429, 451, 503}
CDN_WAF_HEADER_NAMES = {
    "cf-ray",
    "x-akamai",
    "x-amz-cf-id",
    "x-cdn",
    "x-iinfo",
    "x-nf-request-id",
    "x-now-trace",
    "x-vercel-cache",
    "x-vercel-id",
}
CDN_WAF_HEADER_PREFIXES = ("x-vercel-", "x-akamai-", "cf-")
CDN_WAF_VALUE_MARKERS = [
    "akamai",
    "big-ip",
    "cloudflare",
    "cloudfront",
    "fastly",
    "imperva",
    "incapsula",
    "netlify",
    "sucuri",
    "varnish",
    "vercel",
]
CDN_WAF_BODY_MARKERS = [
    "/cdn-cgi/challenge-platform/",
    "__cf_chl_",
    "attention required",
    "bot detection",
    "captcha",
    "cf-browser-verification",
    "checking your browser",
    "cloudflare ray id",
    "ddos protection",
    "enable cookies",
    "incapsula incident id",
    "just a moment",
    "perimeterx",
    "please stand by",
    "request blocked",
    "the request could not be satisfied",
    "unusual traffic",
    "verify you are human",
    "web application firewall",
    "you have been blocked",
    "your access to this site has been limited",
]


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


def has_cdn_waf_signal(fetch: FetchResult) -> bool:
    for name, value in fetch.headers.items():
        lowered_name = name.lower()
        lowered_value = str(value).lower()
        if lowered_name in CDN_WAF_HEADER_NAMES:
            return True
        if lowered_name.startswith(CDN_WAF_HEADER_PREFIXES):
            return True
        if lowered_name in {"server", "via"} and any(
            marker in lowered_value for marker in CDN_WAF_VALUE_MARKERS
        ):
            return True
    return False


def looks_cdn_waf_challenge(fetch: FetchResult) -> bool:
    lower = (fetch.body or "").lower()
    return any(marker in lower for marker in CDN_WAF_BODY_MARKERS)


def is_cdn_waf_fallback_reason(reason: str | None) -> bool:
    return bool(reason and reason.startswith("cdn-waf-"))


def browser_fallback_reason(fetch: FetchResult, findings_count: int) -> str | None:
    if fetch.error:
        return "request-error"
    cdn_waf_signal = has_cdn_waf_signal(fetch)
    if cdn_waf_signal and fetch.status in BLOCKING_STATUSES:
        return f"cdn-waf-blocking-status-{fetch.status}"
    if fetch.status in {401, 403, 429, 503}:
        return f"blocking-status-{fetch.status}"
    if not has_useful_response(fetch):
        return "empty-response"
    if cdn_waf_signal and not (fetch.body or "").strip():
        return "cdn-waf-empty-response"
    body = fetch.body.strip()
    if cdn_waf_signal and looks_cdn_waf_challenge(fetch):
        return "cdn-waf-challenge"
    if looks_js_required(body):
        return "javascript-required"
    if findings_count == 0 and looks_spa_shell(body, fetch.script_srcs):
        return "spa-shell-without-findings"
    return None
