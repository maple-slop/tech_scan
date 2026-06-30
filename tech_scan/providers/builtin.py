from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

from tech_scan.html_extract import extract_meta, extract_url_attrs
from tech_scan.models import (
    DIM_BACKEND,
    DIM_CDN_WAF_SERVER,
    DIM_FRONTEND,
    FetchResult,
    Finding,
)
from tech_scan.observations import header_display_name
from tech_scan.url_policy import same_hostname

from .base import Provider


@dataclass(frozen=True)
class DetectionContext:
    body: str
    body_with_scripts: str
    cookie_names: list[str]
    cookie_pairs: list[tuple[str, str]]
    browser_globals: list[str]
    meta: dict[str, list[str]]
    urls: list[str]
    embedded_urls: list[str]


Detector = Callable[[FetchResult, DetectionContext], list[str]]


@dataclass(frozen=True)
class Rule:
    name: str
    dimension: str
    confidence: int
    detect: Detector


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


def header_detector(header: str, pattern: str) -> Detector:
    regex = _compile(pattern)
    header_key = header.lower()
    display_name = header_display_name(header_key)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        value = fetch.headers.get(header_key, "")
        if value and regex.search(value):
            return [f"{display_name}: {value}"]
        return []

    return detect


def meta_detector(name: str, pattern: str, evidence: str | None = None) -> Detector:
    regex = _compile(pattern)
    meta_key = name.lower()

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        values = context.meta.get(meta_key, [])
        if not any(regex.search(value) for value in values):
            return []
        return [evidence or f"meta {meta_key}"]

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
    Rule("Vercel", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^(now|vercel)$")),
    Rule("Vercel", DIM_CDN_WAF_SERVER, 90, header_detector("x-vercel-id", r".+")),
    Rule("Vercel", DIM_CDN_WAF_SERVER, 85, header_detector("x-vercel-cache", r".+")),
    Rule("Vercel", DIM_CDN_WAF_SERVER, 85, header_detector("x-now-trace", r".+")),
    Rule("Netlify", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^netlify")),
    Rule("Netlify", DIM_CDN_WAF_SERVER, 90, header_detector("x-nf-request-id", r".+")),
    Rule("Heroku", DIM_CDN_WAF_SERVER, 85, header_detector("via", r"[\d.-]+ vegur$")),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"cloudfront")),
    Rule("AWS CloudFront", DIM_CDN_WAF_SERVER, 90, header_detector("x-amz-cf-id", r".+")),
    Rule("Amazon S3", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^amazons3$")),
    Rule("Amazon S3", DIM_CDN_WAF_SERVER, 90, header_detector("x-amz-request-id", r".+")),
    Rule("Amazon S3", DIM_CDN_WAF_SERVER, 85, header_detector("x-amz-id-2", r".+")),
    Rule("Varnish", DIM_CDN_WAF_SERVER, 85, header_detector("via", r"varnish")),
    Rule("nginx", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"nginx")),
    Rule("OpenResty", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"openresty")),
    Rule("Tengine", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"tengine")),
    Rule("Apache", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"apache")),
    Rule("Microsoft IIS", DIM_CDN_WAF_SERVER, 95, header_detector("server", r"microsoft-iis|iis")),
    Rule("LiteSpeed", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"litespeed")),
    Rule("LiteSpeed Cache", DIM_CDN_WAF_SERVER, 90, header_detector("x-litespeed-cache", r".+")),
    Rule("LiteSpeed Cache", DIM_CDN_WAF_SERVER, 85, header_detector("x-turbo-charged-by", r"litespeed")),
    Rule("Caddy", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^caddy$")),
    Rule("lighttpd", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"lighttpd|lighty")),
    Rule("Envoy", DIM_CDN_WAF_SERVER, 85, header_detector("server", r"envoy")),
    Rule("HAProxy", DIM_CDN_WAF_SERVER, 80, header_detector("server", r"haproxy")),
    Rule("gunicorn", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"gunicorn")),
    Rule("Werkzeug", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"werkzeug")),
    Rule("CherryPy", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"cherrypy")),
    Rule("WebLogic", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"weblogic")),
    Rule("OpenGSE", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^gse$")),
    Rule("Imperva", DIM_CDN_WAF_SERVER, 90, header_detector("x-cdn", r"^imperva")),
    Rule("Imperva", DIM_CDN_WAF_SERVER, 90, header_detector("x-iinfo", r".+")),
    Rule("F5 BIG-IP", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"^big-?ip$")),
    Rule("F5 BIG-IP", DIM_CDN_WAF_SERVER, 90, cookie_name_detector(r"(?i)(lastmrh_session|mrhsession|bigipserver|f5_fullwt|f5_st)")),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, header_detector("server", r"phusion passenger")),
    Rule("Phusion Passenger", DIM_CDN_WAF_SERVER, 90, header_detector("x-powered-by", r"phusion passenger(?:\(r\))?")),
    Rule("React", DIM_FRONTEND, 80, body_detector(r"react(?:\.production)?(?:\.min)?\.js|data-reactroot|react-dom", "react script/html marker", True)),
    Rule("React", DIM_FRONTEND, 75, global_detector(r"React")),
    Rule("Vue.js", DIM_FRONTEND, 80, body_detector(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|data-v-[a-f0-9]+|__vue__", "vue script/html marker", True)),
    Rule("Vue.js", DIM_FRONTEND, 75, global_detector(r"Vue")),
    Rule("Angular", DIM_FRONTEND, 80, body_detector(r"angular(?:\.min)?\.js|ng-version|ng-app", "angular script/html marker", True)),
    Rule("Angular", DIM_FRONTEND, 75, global_detector(r"Angular")),
    Rule("AngularJS", DIM_FRONTEND, 85, body_detector(r"<(?:div|html)[^>]+ng-app=|<ng-app|angular(?:\.min)?\.js", "angularjs marker", True)),
    Rule("AngularJS", DIM_FRONTEND, 75, global_detector(r"^angular$|angular\.version")),
    Rule("Alpine.js", DIM_FRONTEND, 80, body_detector(r"\bx-data\b|alpine(?:\.min)?\.js", "alpine marker", True)),
    Rule("Alpine.js", DIM_FRONTEND, 75, global_detector(r"Alpine")),
    Rule("Astro", DIM_FRONTEND, 85, meta_detector("generator", r"^astro\s+v?[\d.]+", "astro generator meta")),
    Rule("Astro", DIM_FRONTEND, 75, global_detector(r"Astro")),
    Rule("Stimulus", DIM_FRONTEND, 80, body_detector(r"data-controller=", "stimulus controller marker")),
    Rule("htmx", DIM_FRONTEND, 80, body_detector(r"htmx(?:\.min)?\.js|htmx\.org@", "htmx script marker", True)),
    Rule("htmx", DIM_FRONTEND, 75, global_detector(r"^htmx$")),
    Rule("Polymer", DIM_FRONTEND, 80, body_detector(r"<polymer-[^>]+|/polymer\.html|polymer\.js", "polymer marker", True)),
    Rule("Polymer", DIM_FRONTEND, 75, global_detector(r"Polymer")),
    Rule("Svelte", DIM_FRONTEND, 75, body_detector(r"__svelte|svelte-[a-z0-9]+", "svelte marker", True)),
    Rule("Svelte", DIM_FRONTEND, 75, global_detector(r"Svelte")),
    Rule("SvelteKit", DIM_FRONTEND, 85, meta_detector("generator", r"sveltekit", "sveltekit generator meta")),
    Rule("Next.js", DIM_FRONTEND, 90, body_detector(r"/_next/|__NEXT_DATA__|window\.__NEXT", "next.js marker", True)),
    Rule("Next.js", DIM_FRONTEND, 75, global_detector(r"__NEXT")),
    Rule("Nuxt", DIM_FRONTEND, 90, body_detector(r"/_nuxt/|__NUXT__|window\.__NUXT", "nuxt marker", True)),
    Rule("Nuxt", DIM_FRONTEND, 75, global_detector(r"__NUXT")),
    Rule("Remix", DIM_FRONTEND, 80, global_detector(r"__remixContext")),
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
    Rule("Java", DIM_BACKEND, 75, header_detector("server", r"apache-coyote|jetty|weblogic|gse")),
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
    Rule("Apache Tomcat", DIM_BACKEND, 90, header_detector("x-powered-by", r"\btomcat\b")),
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
    Rule("Django", DIM_BACKEND, 85, cookie_name_detector(r"(^|\n)django_language($|\n)")),
    Rule("Python", DIM_BACKEND, 80, header_detector("server", r"(^|\s)python(?:/|$)")),
    Rule("Python", DIM_BACKEND, 80, header_detector("server", r"werkzeug|gunicorn|cherrypy")),
    Rule("Flask", DIM_BACKEND, 90, header_detector("server", r"werkzeug")),
    Rule("Ruby", DIM_BACKEND, 80, header_detector("server", r"mongrel|ruby(?:/|$)")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, cookie_name_detector(r"(^|\n)(_[a-z0-9]+_session|_session_id)($|\n)")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, header_detector("server", r"mod_(?:rails|rack)")),
    Rule("Ruby on Rails", DIM_BACKEND, 85, header_detector("x-powered-by", r"mod_(?:rails|rack)")),
    Rule("Ruby on Rails", DIM_BACKEND, 70, body_detector(r"<meta[^>]+name=[\"']csrf-param[\"'][^>]+content=[\"']authenticity_token[\"']|<meta[^>]+content=[\"']authenticity_token[\"'][^>]+name=[\"']csrf-param[\"']", "rails csrf param meta")),
    Rule("Ruby on Rails", DIM_BACKEND, 65, body_detector(r"/assets/application-[a-z0-9]{32}\.js", "rails asset pipeline script")),
    Rule("Ruby on Rails", DIM_BACKEND, 75, global_detector(r"ReactOnRails|__REACT_ON_RAILS_EVENT_HANDLERS_RAN_ONCE__|_rails_loaded")),
    Rule("Express", DIM_BACKEND, 90, header_detector("x-powered-by", r"express")),
    Rule("Node.js", DIM_BACKEND, 80, header_detector("x-powered-by", r"node\.?js")),
    Rule("Koa", DIM_BACKEND, 90, header_detector("x-powered-by", r"^koa$")),
    Rule("Hono", DIM_BACKEND, 90, header_detector("x-powered-by", r"^hono$")),
    Rule("Sails.js", DIM_BACKEND, 90, header_detector("x-powered-by", r"^sails(?:$|[^a-z0-9])")),
    Rule("Sails.js", DIM_BACKEND, 85, cookie_name_detector(r"sails\.sid")),
    Rule("total.js", DIM_BACKEND, 90, header_detector("x-powered-by", r"^total\.js")),
    Rule("Bun", DIM_BACKEND, 90, header_detector("x-powered-by", r"^bun$")),
    Rule("Symfony", DIM_BACKEND, 85, cookie_name_detector(r"sf_redirect")),
    Rule("Symfony", DIM_BACKEND, 75, global_detector(r"Sfjs")),
    Rule("CodeIgniter", DIM_BACKEND, 85, cookie_name_detector(r"ci_(csrf_token|session)")),
    Rule("CodeIgniter", DIM_BACKEND, 80, body_detector(r"name=[\"']ci_csrf_token[\"']", "codeigniter csrf marker")),
    Rule("CakePHP", DIM_BACKEND, 85, cookie_name_detector(r"cakephp")),
    Rule("CakePHP", DIM_BACKEND, 80, meta_detector("application-name", r"cakephp", "cakephp application meta")),
    Rule("Yii", DIM_BACKEND, 85, cookie_name_detector(r"yii_csrf_token")),
    Rule("Yii", DIM_BACKEND, 80, body_detector(r"yii\.(?:validation|activeform)\.js|name=[\"']yii_csrf_token[\"']", "yii marker", True)),
    Rule("Livewire", DIM_BACKEND, 85, body_detector(r"\bwire:[a-z-]+|livewire(?:\.min)?\.js", "livewire marker", True)),
    Rule("Adobe ColdFusion", DIM_BACKEND, 85, cookie_name_detector(r"(CFID|CFTOKEN)")),
    Rule("Adobe ColdFusion", DIM_BACKEND, 80, body_detector(r"\.cfm(?:[?\"']|$)|/cfajax/", "coldfusion marker", True)),
]


IMPLIED_BACKENDS = {
    "Apache Tomcat": ("Java", 50),
    "CakePHP": ("PHP", 50),
    "CodeIgniter": ("PHP", 50),
    "Django": ("Python", 50),
    "Express": ("Node.js", 50),
    "Flask": ("Python", 50),
    "Hono": ("Node.js", 50),
    "Jetty": ("Java", 50),
    "Koa": ("Node.js", 50),
    "Laravel": ("PHP", 50),
    "Livewire": ("PHP", 50),
    "Ruby on Rails": ("Ruby", 50),
    "Sails.js": ("Node.js", 50),
    "Spring": ("Java", 50),
    "Symfony": ("PHP", 50),
    "Yii": ("PHP", 50),
}


def _same_host_embedded_urls(fetch: FetchResult, body: str) -> list[str]:
    base_url = fetch.final_url or fetch.url
    if not base_url:
        return []
    candidates = [*extract_url_attrs(body), *fetch.script_srcs]
    for resource in fetch.resources:
        if resource.url and resource.kind != "document":
            candidates.append(resource.url)

    seen: set[str] = set()
    urls: list[str] = []
    for candidate in candidates:
        if not candidate or candidate.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, candidate)
        if not same_hostname(base_url, absolute):
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
            meta=extract_meta(body),
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

        for source, (implied_name, confidence) in IMPLIED_BACKENDS.items():
            source_key = (source.lower(), DIM_BACKEND)
            implied_key = (implied_name.lower(), DIM_BACKEND)
            if source_key not in findings or implied_key in findings:
                continue
            findings[implied_key] = Finding(
                name=implied_name,
                dimension=DIM_BACKEND,
                provider=self.name,
                confidence=confidence,
                evidence=[f"implied by: {source}"],
            )
        return list(findings.values())
