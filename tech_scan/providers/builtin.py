from __future__ import annotations

import re
from dataclasses import dataclass
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
class Rule:
    name: str
    dimension: str
    confidence: int
    evidence: str
    header: str | None = None
    header_pattern: str | None = None
    cookie_pattern: str | None = None
    cookie_value_pattern: str | None = None
    body_pattern: str | None = None
    global_pattern: str | None = None
    url_pattern: str | None = None
    embedded_url_pattern: str | None = None


RULES = [
    Rule("Cloudflare", DIM_CDN_WAF_SERVER, 95, "cloudflare header", "server", r"cloudflare"),
    Rule("Cloudflare", DIM_CDN_WAF_SERVER, 90, "cf-ray header", "cf-ray", r".+"),
    Rule("Akamai", DIM_CDN_WAF_SERVER, 90, "akamai header", "server", r"akamai|ghost"),
    Rule("Akamai", DIM_CDN_WAF_SERVER, 80, "akamai cache header", "x-akamai", r".+"),
    Rule("Fastly", DIM_CDN_WAF_SERVER, 90, "fastly header", "server", r"fastly"),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, "cloudfront header", "server", r"cloudfront"),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, "x-amz-cf header", "x-amz-cf-id", r".+"),
    Rule("Varnish", DIM_CDN_WAF_SERVER, 85, "varnish header", "via", r"varnish"),
    Rule("nginx", DIM_CDN_WAF_SERVER, 90, "server header", "server", r"nginx"),
    Rule("Apache", DIM_CDN_WAF_SERVER, 90, "server header", "server", r"apache"),
    Rule("Microsoft IIS", DIM_CDN_WAF_SERVER, 95, "server header", "server", r"microsoft-iis|iis"),
    Rule("LiteSpeed", DIM_CDN_WAF_SERVER, 90, "server header", "server", r"litespeed"),
    Rule("Envoy", DIM_CDN_WAF_SERVER, 85, "server header", "server", r"envoy"),
    Rule("HAProxy", DIM_CDN_WAF_SERVER, 80, "haproxy marker", "server", r"haproxy"),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, "passenger server header", "server", r"phusion passenger"),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, "passenger x-powered-by header", "x-powered-by", r"phusion passenger(?:\(r\))?"),
    Rule("React", DIM_FRONTEND, 80, "react script/html marker", body_pattern=r"react(?:\.production)?(?:\.min)?\.js|data-reactroot|react-dom"),
    Rule("React", DIM_FRONTEND, 75, "window global", global_pattern=r"React"),
    Rule("Vue.js", DIM_FRONTEND, 80, "vue script/html marker", body_pattern=r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|data-v-[a-f0-9]+|__vue__"),
    Rule("Vue.js", DIM_FRONTEND, 75, "window global", global_pattern=r"Vue"),
    Rule("Angular", DIM_FRONTEND, 80, "angular script/html marker", body_pattern=r"angular(?:\.min)?\.js|ng-version|ng-app"),
    Rule("Angular", DIM_FRONTEND, 75, "window global", global_pattern=r"Angular"),
    Rule("Svelte", DIM_FRONTEND, 75, "svelte marker", body_pattern=r"__svelte|svelte-[a-z0-9]+"),
    Rule("Svelte", DIM_FRONTEND, 75, "window global", global_pattern=r"Svelte"),
    Rule("Next.js", DIM_FRONTEND, 90, "next.js marker", body_pattern=r"/_next/|__NEXT_DATA__|window\.__NEXT"),
    Rule("Next.js", DIM_FRONTEND, 75, "window global", global_pattern=r"__NEXT"),
    Rule("Nuxt", DIM_FRONTEND, 90, "nuxt marker", body_pattern=r"/_nuxt/|__NUXT__|window\.__NUXT"),
    Rule("Nuxt", DIM_FRONTEND, 75, "window global", global_pattern=r"__NUXT"),
    Rule("Gatsby", DIM_FRONTEND, 85, "gatsby marker", body_pattern=r"___gatsby|gatsby-browser|gatsby-focus-wrapper"),
    Rule("jQuery", DIM_FRONTEND, 80, "jquery script/global", body_pattern=r"jquery(?:-[0-9.]+)?(?:\.min)?\.js|window\.jQuery"),
    Rule("jQuery", DIM_FRONTEND, 75, "window global", global_pattern=r"jQuery"),
    Rule("ASP.NET", DIM_BACKEND, 95, "asp.net header", "x-aspnet-version", r".+"),
    Rule("ASP.NET", DIM_BACKEND, 90, "asp.net cookie", cookie_pattern=r"ASP\.NET_SessionId"),
    Rule("ASP.NET", DIM_BACKEND, 70, "asp.net url suffix", url_pattern=r"\.aspx?(?:[/?#]|$)"),
    Rule("ASP.NET", DIM_BACKEND, 60, "same-host embedded asp.net url suffix", embedded_url_pattern=r"\.aspx?(?:[/?#]|$)"),
    Rule("ASP.NET Web Forms", DIM_BACKEND, 95, "web forms state field", body_pattern=r"name=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']|id=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']"),
    Rule("ASP.NET Web Forms", DIM_BACKEND, 90, "web forms resource handler", body_pattern=r"(WebResource|ScriptResource)\.axd(?:[?\"'])"),
    Rule("ASP.NET MVC/Core", DIM_BACKEND, 85, "asp.net antiforgery token", body_pattern=r"__RequestVerificationToken"),
    Rule("ASP.NET Core", DIM_BACKEND, 95, "asp.net core header", "x-powered-by", r"asp\.net"),
    Rule("ASP.NET Core", DIM_BACKEND, 85, "asp.net core cookie", cookie_pattern=r"\.AspNetCore\."),
    Rule("Classic ASP", DIM_BACKEND, 85, "classic asp session cookie", cookie_pattern=r"ASPSESSIONID[A-Z0-9]*"),
    Rule("Classic ASP", DIM_BACKEND, 65, "classic asp url suffix", url_pattern=r"\.asp(?:[/?#]|$)"),
    Rule("Classic ASP", DIM_BACKEND, 55, "same-host embedded classic asp url suffix", embedded_url_pattern=r"\.asp(?:[/?#]|$)"),
    Rule("Java", DIM_BACKEND, 70, "java session cookie", cookie_pattern=r"(^|\n)JSESSIONID($|\n)"),
    Rule("Spring", DIM_BACKEND, 90, "spring marker", body_pattern=r"Whitelabel Error Page|springframework|Spring Boot"),
    Rule("Spring", DIM_BACKEND, 80, "spring cookie/header", "x-application-context", r".+"),
    Rule("Spring Security", DIM_BACKEND, 80, "spring csrf marker", body_pattern=r"name=[\"']_csrf[\"']|csrfParameterName|csrfHeaderName"),
    Rule("Java EE/Jakarta EE", DIM_BACKEND, 80, "java ee marker", body_pattern=r"javax\.|jakarta\.|JavaServer Faces|jsf"),
    Rule("JavaServer Faces", DIM_BACKEND, 90, "jsf view state", body_pattern=r"javax\.faces\.ViewState|jakarta\.faces\.ViewState"),
    Rule("JavaServer Faces", DIM_BACKEND, 85, "jsf component marker", body_pattern=r"PrimeFaces|RichFaces|IceFaces|javax\.faces|jakarta\.faces"),
    Rule("JavaServer Faces", DIM_BACKEND, 70, "jsf xhtml url suffix", url_pattern=r"\.xhtml(?:[/?#]|$)"),
    Rule("JavaServer Faces", DIM_BACKEND, 60, "same-host embedded jsf xhtml url suffix", embedded_url_pattern=r"\.xhtml(?:[/?#]|$)"),
    Rule("JSP", DIM_BACKEND, 85, "jsp marker", body_pattern=r"\.jsp(?:x)?(?:\b|[?\"'])|JSP Page|JasperException"),
    Rule("JSP", DIM_BACKEND, 70, "jsp url suffix", url_pattern=r"\.jspx?(?:[/?#]|$)"),
    Rule("JSP", DIM_BACKEND, 60, "same-host embedded jsp url suffix", embedded_url_pattern=r"\.jspx?(?:[/?#]|$)"),
    Rule("Java Servlet", DIM_BACKEND, 70, "servlet-style action url", url_pattern=r"\.(do|action)(?:[/?#]|$)"),
    Rule("Java Servlet", DIM_BACKEND, 60, "same-host embedded servlet-style action url", embedded_url_pattern=r"\.(do|action)(?:[/?#]|$)"),
    Rule("Apache Tomcat", DIM_BACKEND, 90, "tomcat header", "server", r"tomcat|coyote"),
    Rule("Jetty", DIM_BACKEND, 90, "jetty header", "server", r"jetty"),
    Rule("JBoss/WildFly", DIM_BACKEND, 90, "jboss/wildfly marker", "server", r"jboss|wildfly"),
    Rule("PHP", DIM_BACKEND, 90, "php header", "x-powered-by", r"php"),
    Rule("PHP", DIM_BACKEND, 85, "php cookie", cookie_pattern=r"PHPSESSID"),
    Rule("PHP", DIM_BACKEND, 70, "php url suffix", url_pattern=r"\.php(?:[/?#]|$)"),
    Rule("PHP", DIM_BACKEND, 60, "same-host embedded php url suffix", embedded_url_pattern=r"\.php(?:[/?#]|$)"),
    Rule("Laravel", DIM_BACKEND, 90, "laravel cookie", cookie_pattern=r"laravel_session|XSRF-TOKEN"),
    Rule("Laravel", DIM_BACKEND, 80, "laravel csrf field", body_pattern=r"name=[\"']_token[\"']"),
    Rule("Laravel", DIM_BACKEND, 85, "laravel encrypted cookie", cookie_value_pattern=r"(?im)^(laravel_session|XSRF-TOKEN)=((eyJpdiI6)|(%7B%22iv%22))"),
    Rule("Laravel", DIM_BACKEND, 80, "laravel error/debug marker", body_pattern=r"Laravel|Whoops, looks like something went wrong|Illuminate\\"),
    Rule("Django", DIM_BACKEND, 85, "django cookie", cookie_pattern=r"(^|\n)(csrftoken|sessionid)($|\n)"),
    Rule("Django", DIM_BACKEND, 85, "django csrf marker", body_pattern=r"name=[\"']csrfmiddlewaretoken[\"']"),
    Rule("Ruby on Rails", DIM_BACKEND, 85, "rails session cookie", cookie_pattern=r"(^|\n)(_[a-z0-9]+_session|_session_id)($|\n)"),
    Rule("Ruby on Rails", DIM_BACKEND, 85, "rails rack header", "server", r"mod_(?:rails|rack)"),
    Rule("Ruby on Rails", DIM_BACKEND, 85, "rails rack x-powered-by header", "x-powered-by", r"mod_(?:rails|rack)"),
    Rule("Ruby on Rails", DIM_BACKEND, 70, "rails csrf param meta", body_pattern=r"<meta[^>]+name=[\"']csrf-param[\"'][^>]+content=[\"']authenticity_token[\"']|<meta[^>]+content=[\"']authenticity_token[\"'][^>]+name=[\"']csrf-param[\"']"),
    Rule("Ruby on Rails", DIM_BACKEND, 65, "rails asset pipeline script", body_pattern=r"/assets/application-[a-z0-9]{32}\.js"),
    Rule("Ruby on Rails", DIM_BACKEND, 75, "rails window global", global_pattern=r"ReactOnRails|__REACT_ON_RAILS_EVENT_HANDLERS_RAN_ONCE__|_rails_loaded"),
    Rule("Express", DIM_BACKEND, 90, "express header", "x-powered-by", r"express"),
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
        body_with_scripts = "\n".join([body, *fetch.script_bodies])
        cookie_names = "\n".join(fetch.cookies.keys())
        cookie_pairs = "\n".join(f"{name}={value}" for name, value in fetch.cookies.items())
        globals_text = "\n".join(fetch.browser_globals)
        urls = "\n".join(url for url in [fetch.url, fetch.final_url] if url)
        embedded_urls = _same_host_embedded_urls(fetch, body)

        for rule in RULES:
            matched = False
            if rule.header and rule.header_pattern:
                value = fetch.headers.get(rule.header.lower(), "")
                matched = bool(re.search(rule.header_pattern, value, re.I))
            if not matched and rule.cookie_pattern:
                matched = bool(re.search(rule.cookie_pattern, cookie_names, re.I))
            if not matched and rule.cookie_value_pattern:
                matched = bool(re.search(rule.cookie_value_pattern, cookie_pairs, re.I))
            if not matched and rule.body_pattern:
                haystack = body_with_scripts if rule.dimension == DIM_FRONTEND else body
                matched = bool(re.search(rule.body_pattern, haystack, re.I))
            if not matched and rule.global_pattern:
                matched = bool(re.search(rule.global_pattern, globals_text, re.I))
            if not matched and rule.url_pattern:
                matched = bool(re.search(rule.url_pattern, urls, re.I))
            if not matched and rule.embedded_url_pattern:
                matched = any(
                    re.search(rule.embedded_url_pattern, url, re.I)
                    for url in embedded_urls
                )
            if not matched:
                continue

            key = (rule.name.lower(), rule.dimension)
            existing = findings.get(key)
            if existing:
                existing.confidence = max(existing.confidence, rule.confidence)
                if rule.evidence not in existing.evidence:
                    existing.evidence.append(rule.evidence)
            else:
                findings[key] = Finding(
                    name=rule.name,
                    dimension=rule.dimension,
                    provider=self.name,
                    confidence=rule.confidence,
                    evidence=[rule.evidence],
                )
        return list(findings.values())
