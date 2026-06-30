from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlparse

from tech_scan.models import (
    DIM_BACKEND,
    DIM_CDN_WAF_SERVER,
    DIM_FRONTEND,
    FetchResult,
    Finding,
)

from .base import Provider


@dataclass(frozen=True)
class DetectionContext:
    body: str
    body_with_scripts: str
    cookie_names: list[str]
    cookie_pairs: list[tuple[str, str]]
    browser_globals: list[str]
    urls: list[str]
    embedded_urls: list[str]


Detector = Callable[[FetchResult, DetectionContext], list[str]]


@dataclass(frozen=True)
class Rule:
    name: str
    dimension: str
    confidence: int
    detect: Detector


HEADER_NAMES = {
    "cf-ray": "CF-Ray",
    "server": "Server",
    "via": "Via",
    "x-akamai": "X-Akamai",
    "x-amz-cf-id": "X-Amz-Cf-Id",
    "x-application-context": "X-Application-Context",
    "x-aspnet-version": "X-AspNet-Version",
    "x-powered-by": "X-Powered-By",
}


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


def header_detector(header: str, pattern: str) -> Detector:
    regex = _compile(pattern)
    header_key = header.lower()
    display_name = HEADER_NAMES.get(header_key, header)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        value = fetch.headers.get(header_key, "")
        if value and regex.search(value):
            return [f"{display_name}: {value}"]
        return []

    return detect


def cookie_name_detector(pattern: str) -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        evidence = []
        for name in context.cookie_names:
            if regex.search(name) or regex.search(f"\n{name}\n"):
                evidence.append(f"cookie: {name}")
        return evidence

    return detect


def cookie_value_detector(pattern: str, evidence: str) -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        cookie_pairs = "\n".join(
            f"{name}={value}" for name, value in context.cookie_pairs
        )
        return [evidence] if regex.search(cookie_pairs) else []

    return detect


def body_detector(pattern: str, evidence: str, include_scripts: bool = False) -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        haystack = context.body_with_scripts if include_scripts else context.body
        return [evidence] if regex.search(haystack) else []

    return detect


def global_detector(pattern: str) -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        return [
            f"window global: {name}"
            for name in context.browser_globals
            if regex.search(name)
        ]

    return detect


def url_detector(pattern: str, prefix: str = "url") -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        return [f"{prefix}: {url}" for url in context.urls if regex.search(url)]

    return detect


def embedded_url_detector(pattern: str) -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        return [
            f"same-host embedded url: {url}"
            for url in context.embedded_urls
            if regex.search(url)
        ]

    return detect


RULES = [
    Rule("Cloudflare", DIM_CDN_WAF_SERVER, 95, header_detector("server", r"cloudflare")),
    Rule("Cloudflare", DIM_CDN_WAF_SERVER, 90, header_detector("cf-ray", r".+")),
    Rule("Akamai", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"akamai|ghost")),
    Rule("Akamai", DIM_CDN_WAF_SERVER, 80, header_detector("x-akamai", r".+")),
    Rule("Fastly", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"fastly")),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"cloudfront")),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, header_detector("x-amz-cf-id", r".+")),
    Rule("Varnish", DIM_CDN_WAF_SERVER, 85, header_detector("via", r"varnish")),
    Rule("nginx", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"nginx")),
    Rule("Apache", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"apache")),
    Rule("Microsoft IIS", DIM_CDN_WAF_SERVER, 95, header_detector("server", r"microsoft-iis|iis")),
    Rule("LiteSpeed", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"litespeed")),
    Rule("Envoy", DIM_CDN_WAF_SERVER, 85, header_detector("server", r"envoy")),
    Rule("HAProxy", DIM_CDN_WAF_SERVER, 80, header_detector("server", r"haproxy")),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"phusion passenger")),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, header_detector("x-powered-by", r"phusion passenger(?:\(r\))?")),
    Rule("React", DIM_FRONTEND, 80, body_detector(r"react(?:\.production)?(?:\.min)?\.js|data-reactroot|react-dom", "react script/html marker", True)),
    Rule("React", DIM_FRONTEND, 75, global_detector(r"React")),
    Rule("Vue.js", DIM_FRONTEND, 80, body_detector(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|data-v-[a-f0-9]+|__vue__", "vue script/html marker", True)),
    Rule("Vue.js", DIM_FRONTEND, 75, global_detector(r"Vue")),
    Rule("Angular", DIM_FRONTEND, 80, body_detector(r"angular(?:\.min)?\.js|ng-version|ng-app", "angular script/html marker", True)),
    Rule("Angular", DIM_FRONTEND, 75, global_detector(r"Angular")),
    Rule("Svelte", DIM_FRONTEND, 75, body_detector(r"__svelte|svelte-[a-z0-9]+", "svelte marker", True)),
    Rule("Svelte", DIM_FRONTEND, 75, global_detector(r"Svelte")),
    Rule("Next.js", DIM_FRONTEND, 90, body_detector(r"/_next/|__NEXT_DATA__|window\.__NEXT", "next.js marker", True)),
    Rule("Next.js", DIM_FRONTEND, 75, global_detector(r"__NEXT")),
    Rule("Nuxt", DIM_FRONTEND, 90, body_detector(r"/_nuxt/|__NUXT__|window\.__NUXT", "nuxt marker", True)),
    Rule("Nuxt", DIM_FRONTEND, 75, global_detector(r"__NUXT")),
    Rule("Gatsby", DIM_FRONTEND, 85, body_detector(r"___gatsby|gatsby-browser|gatsby-focus-wrapper", "gatsby marker", True)),
    Rule("jQuery", DIM_FRONTEND, 80, body_detector(r"jquery(?:-[0-9.]+)?(?:\.min)?\.js|window\.jQuery", "jquery script/global", True)),
    Rule("jQuery", DIM_FRONTEND, 75, global_detector(r"jQuery")),
    Rule("ASP.NET", DIM_BACKEND, 95, header_detector("x-aspnet-version", r".+")),
    Rule("ASP.NET", DIM_BACKEND, 90, header_detector("x-powered-by", r"\basp\.net\b")),
    Rule("ASP.NET", DIM_BACKEND, 90, cookie_name_detector(r"ASP\.NET_SessionId")),
    Rule("ASP.NET", DIM_BACKEND, 70, url_detector(r"\.aspx?(?:[/?#]|$)")),
    Rule("ASP.NET", DIM_BACKEND, 60, embedded_url_detector(r"\.aspx?(?:[/?#]|$)")),
    Rule("ASP.NET Web Forms", DIM_BACKEND, 95, body_detector(r"name=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']|id=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']", "web forms state field")),
    Rule("ASP.NET Web Forms", DIM_BACKEND, 90, body_detector(r"(WebResource|ScriptResource)\.axd(?:[?\"'])", "web forms resource handler")),
    Rule("ASP.NET MVC/Core", DIM_BACKEND, 85, body_detector(r"__RequestVerificationToken", "asp.net antiforgery token")),
    Rule("ASP.NET Core", DIM_BACKEND, 90, header_detector("server", r"\bkestrel\b")),
    Rule("ASP.NET Core", DIM_BACKEND, 85, cookie_name_detector(r"\.AspNetCore\.")),
    Rule("Classic ASP", DIM_BACKEND, 85, cookie_name_detector(r"ASPSESSIONID[A-Z0-9]*")),
    Rule("Classic ASP", DIM_BACKEND, 65, url_detector(r"\.asp(?:[/?#]|$)")),
    Rule("Classic ASP", DIM_BACKEND, 55, embedded_url_detector(r"\.asp(?:[/?#]|$)")),
    Rule("Java", DIM_BACKEND, 70, cookie_name_detector(r"(^|\n)JSESSIONID($|\n)")),
    Rule("Spring", DIM_BACKEND, 90, body_detector(r"Whitelabel Error Page|springframework|Spring Boot", "spring marker")),
    Rule("Spring", DIM_BACKEND, 80, header_detector("x-application-context", r".+")),
    Rule("Spring Security", DIM_BACKEND, 80, body_detector(r"name=[\"']_csrf[\"']|csrfParameterName|csrfHeaderName", "spring csrf marker")),
    Rule("Java EE/Jakarta EE", DIM_BACKEND, 80, body_detector(r"javax\.|jakarta\.|JavaServer Faces|jsf", "java ee marker")),
    Rule("JavaServer Faces", DIM_BACKEND, 90, body_detector(r"javax\.faces\.ViewState|jakarta\.faces\.ViewState", "jsf view state")),
    Rule("JavaServer Faces", DIM_BACKEND, 85, body_detector(r"PrimeFaces|RichFaces|IceFaces|javax\.faces|jakarta\.faces", "jsf component marker")),
    Rule("JavaServer Faces", DIM_BACKEND, 70, url_detector(r"\.xhtml(?:[/?#]|$)")),
    Rule("JavaServer Faces", DIM_BACKEND, 60, embedded_url_detector(r"\.xhtml(?:[/?#]|$)")),
    Rule("JSP", DIM_BACKEND, 85, body_detector(r"\.jsp(?:x)?(?:\b|[?\"'])|JSP Page|JasperException", "jsp marker")),
    Rule("JSP", DIM_BACKEND, 70, url_detector(r"\.jspx?(?:[/?#]|$)")),
    Rule("JSP", DIM_BACKEND, 60, embedded_url_detector(r"\.jspx?(?:[/?#]|$)")),
    Rule("Java Servlet", DIM_BACKEND, 70, url_detector(r"\.(do|action)(?:[/?#]|$)")),
    Rule("Java Servlet", DIM_BACKEND, 60, embedded_url_detector(r"\.(do|action)(?:[/?#]|$)")),
    Rule("Apache Tomcat", DIM_BACKEND, 90, header_detector("server", r"tomcat|coyote")),
    Rule("Jetty", DIM_BACKEND, 90, header_detector("server", r"jetty")),
    Rule("JBoss/WildFly", DIM_BACKEND, 90, header_detector("server", r"jboss|wildfly")),
    Rule("PHP", DIM_BACKEND, 90, header_detector("x-powered-by", r"php")),
    Rule("PHP", DIM_BACKEND, 85, cookie_name_detector(r"PHPSESSID")),
    Rule("PHP", DIM_BACKEND, 70, url_detector(r"\.php(?:[/?#]|$)")),
    Rule("PHP", DIM_BACKEND, 60, embedded_url_detector(r"\.php(?:[/?#]|$)")),
    Rule("Laravel", DIM_BACKEND, 90, cookie_name_detector(r"laravel_session|XSRF-TOKEN")),
    Rule("Laravel", DIM_BACKEND, 80, body_detector(r"name=[\"']_token[\"']", "laravel csrf field")),
    Rule("Laravel", DIM_BACKEND, 85, cookie_value_detector(r"(?im)^(laravel_session|XSRF-TOKEN)=((eyJpdiI6)|(%7B%22iv%22))", "laravel encrypted cookie")),
    Rule("Laravel", DIM_BACKEND, 80, body_detector(r"Laravel|Whoops, looks like something went wrong|Illuminate\\", "laravel error/debug marker")),
    Rule("Django", DIM_BACKEND, 85, cookie_name_detector(r"(^|\n)(csrftoken|sessionid)($|\n)")),
    Rule("Django", DIM_BACKEND, 85, body_detector(r"name=[\"']csrfmiddlewaretoken[\"']", "django csrf marker")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, cookie_name_detector(r"(^|\n)(_[a-z0-9]+_session|_session_id)($|\n)")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, header_detector("server", r"mod_(?:rails|rack)")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, header_detector("x-powered-by", r"mod_(?:rails|rack)")),
    Rule("Ruby on Rails", DIM_BACKEND, 70, body_detector(r"<meta[^>]+name=[\"']csrf-param[\"'][^>]+content=[\"']authenticity_token[\"']|<meta[^>]+content=[\"']authenticity_token[\"'][^>]+name=[\"']csrf-param[\"']", "rails csrf param meta")),
    Rule("Ruby on Rails", DIM_BACKEND, 65, body_detector(r"/assets/application-[a-z0-9]{32}\.js", "rails asset pipeline script")),
    Rule("Ruby on Rails", DIM_BACKEND, 75, global_detector(r"ReactOnRails|__REACT_ON_RAILS_EVENT_HANDLERS_RAN_ONCE__|_rails_loaded")),
    Rule("Express", DIM_BACKEND, 90, header_detector("x-powered-by", r"express")),
]


URL_ATTRS = {"href", "src", "action", "formaction"}


def _same_hostname(first_url: str, second_url: str) -> bool:
    return (urlparse(first_url).hostname or "").lower() == (
        urlparse(second_url).hostname or ""
    ).lower()


def _extract_attr_urls(body: str) -> list[str]:
    urls: list[str] = []
    for tag in re.finditer(r"<[a-zA-Z][^>]*>", body, re.I | re.S):
        attrs = tag.group(0)
        for attr in re.finditer(
            r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])(.*?)\2",
            attrs,
            re.I | re.S,
        ):
            if attr.group(1).lower() in URL_ATTRS:
                urls.append(attr.group(3))
    return urls


def _same_host_embedded_urls(fetch: FetchResult, body: str) -> list[str]:
    base_url = fetch.final_url or fetch.url
    if not base_url:
        return []
    candidates = [*_extract_attr_urls(body), *fetch.script_srcs]
    for resource in fetch.resources:
        if resource.url and resource.kind != "document":
            candidates.append(resource.url)

    seen: set[str] = set()
    urls: list[str] = []
    for candidate in candidates:
        if not candidate or candidate.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, candidate)
        if not _same_hostname(base_url, absolute):
            continue
        if absolute not in seen:
            seen.add(absolute)
            urls.append(absolute)
    return urls


class BuiltinProvider(Provider):
    name = "builtin"

    def detect(self, fetch: FetchResult) -> list[Finding]:
        findings: dict[tuple[str, str], Finding] = {}
        body = fetch.body or ""
        context = DetectionContext(
            body=body,
            body_with_scripts="\n".join([body, *fetch.script_bodies]),
            cookie_names=list(fetch.cookies.keys()),
            cookie_pairs=list(fetch.cookies.items()),
            browser_globals=list(fetch.browser_globals),
            urls=[url for url in [fetch.url, fetch.final_url] if url],
            embedded_urls=_same_host_embedded_urls(fetch, body),
        )

        for rule in RULES:
            evidence = rule.detect(fetch, context)
            if not evidence:
                continue

            key = (rule.name.lower(), rule.dimension)
            existing = findings.get(key)
            if existing:
                existing.confidence = max(existing.confidence, rule.confidence)
                for item in evidence:
                    if item not in existing.evidence:
                        existing.evidence.append(item)
            else:
                findings[key] = Finding(
                    name=rule.name,
                    dimension=rule.dimension,
                    provider=self.name,
                    confidence=rule.confidence,
                    evidence=list(dict.fromkeys(evidence)),
                )
        return list(findings.values())
