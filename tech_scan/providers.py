from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import (
    DIM_BACKEND,
    DIM_CDN_WAF_SERVER,
    DIM_FRONTEND,
    FetchResult,
    Finding,
)


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
    Rule("ASP.NET Web Forms", DIM_BACKEND, 95, "web forms state field", body_pattern=r"name=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']|id=[\"']__(VIEWSTATE|EVENTVALIDATION|VIEWSTATEGENERATOR)[\"']"),
    Rule("ASP.NET Web Forms", DIM_BACKEND, 90, "web forms resource handler", body_pattern=r"(WebResource|ScriptResource)\.axd(?:[?\"'])"),
    Rule("ASP.NET MVC/Core", DIM_BACKEND, 85, "asp.net antiforgery token", body_pattern=r"__RequestVerificationToken"),
    Rule("ASP.NET Core", DIM_BACKEND, 95, "asp.net core header", "x-powered-by", r"asp\.net"),
    Rule("ASP.NET Core", DIM_BACKEND, 85, "asp.net core cookie", cookie_pattern=r"\.AspNetCore\."),
    Rule("Classic ASP", DIM_BACKEND, 85, "classic asp session cookie", cookie_pattern=r"ASPSESSIONID[A-Z0-9]*"),
    Rule("Classic ASP", DIM_BACKEND, 65, "classic asp url suffix", url_pattern=r"\.asp(?:[/?#]|$)"),
    Rule("Java", DIM_BACKEND, 70, "java session cookie", cookie_pattern=r"(^|\n)JSESSIONID($|\n)"),
    Rule("Spring", DIM_BACKEND, 90, "spring marker", body_pattern=r"Whitelabel Error Page|springframework|Spring Boot"),
    Rule("Spring", DIM_BACKEND, 80, "spring cookie/header", "x-application-context", r".+"),
    Rule("Spring Security", DIM_BACKEND, 80, "spring csrf marker", body_pattern=r"name=[\"']_csrf[\"']|csrfParameterName|csrfHeaderName"),
    Rule("Java EE/Jakarta EE", DIM_BACKEND, 80, "java ee marker", body_pattern=r"javax\.|jakarta\.|JavaServer Faces|jsf"),
    Rule("JavaServer Faces", DIM_BACKEND, 90, "jsf view state", body_pattern=r"javax\.faces\.ViewState|jakarta\.faces\.ViewState"),
    Rule("JavaServer Faces", DIM_BACKEND, 85, "jsf component marker", body_pattern=r"PrimeFaces|RichFaces|IceFaces|javax\.faces|jakarta\.faces"),
    Rule("JavaServer Faces", DIM_BACKEND, 70, "jsf xhtml url suffix", url_pattern=r"\.xhtml(?:[/?#]|$)"),
    Rule("JSP", DIM_BACKEND, 85, "jsp marker", body_pattern=r"\.jsp(?:x)?(?:\b|[?\"'])|JSP Page|JasperException"),
    Rule("JSP", DIM_BACKEND, 70, "jsp url suffix", url_pattern=r"\.jspx?(?:[/?#]|$)"),
    Rule("Java Servlet", DIM_BACKEND, 70, "servlet-style action url", url_pattern=r"\.(do|action)(?:[/?#]|$)"),
    Rule("Apache Tomcat", DIM_BACKEND, 90, "tomcat header", "server", r"tomcat|coyote"),
    Rule("Jetty", DIM_BACKEND, 90, "jetty header", "server", r"jetty"),
    Rule("JBoss/WildFly", DIM_BACKEND, 90, "jboss/wildfly marker", "server", r"jboss|wildfly"),
    Rule("PHP", DIM_BACKEND, 90, "php header", "x-powered-by", r"php"),
    Rule("PHP", DIM_BACKEND, 85, "php cookie", cookie_pattern=r"PHPSESSID"),
    Rule("PHP", DIM_BACKEND, 70, "php url suffix", url_pattern=r"\.php(?:[/?#]|$)"),
    Rule("Laravel", DIM_BACKEND, 90, "laravel cookie", cookie_pattern=r"laravel_session|XSRF-TOKEN"),
    Rule("Laravel", DIM_BACKEND, 85, "laravel csrf field", body_pattern=r"name=[\"']_token[\"']|<meta[^>]+name=[\"']csrf-token[\"']"),
    Rule("Laravel", DIM_BACKEND, 85, "laravel encrypted cookie", cookie_value_pattern=r"(?im)^(laravel_session|XSRF-TOKEN)=((eyJpdiI6)|(%7B%22iv%22))"),
    Rule("Laravel", DIM_BACKEND, 80, "laravel error/debug marker", body_pattern=r"Laravel|Whoops, looks like something went wrong|Illuminate\\"),
    Rule("Django", DIM_BACKEND, 85, "django cookie", cookie_pattern=r"(^|\n)(csrftoken|sessionid)($|\n)"),
    Rule("Django", DIM_BACKEND, 85, "django csrf marker", body_pattern=r"name=[\"']csrfmiddlewaretoken[\"']"),
    Rule("Ruby on Rails", DIM_BACKEND, 85, "rails session cookie", cookie_pattern=r"(^|\n)_[a-z0-9]+_session($|\n)"),
    Rule("Ruby on Rails", DIM_BACKEND, 80, "rails csrf meta", body_pattern=r"<meta[^>]+name=[\"']csrf-token[\"']"),
    Rule("Express", DIM_BACKEND, 90, "express header", "x-powered-by", r"express"),
]


class Provider:
    name: str

    def detect(self, fetch: FetchResult) -> list[Finding]:
        raise NotImplementedError


class BuiltinProvider(Provider):
    name = "builtin"

    def detect(self, fetch: FetchResult) -> list[Finding]:
        findings: dict[tuple[str, str], Finding] = {}
        body = fetch.body or ""
        cookie_names = "\n".join(fetch.cookies.keys())
        cookie_pairs = "\n".join(f"{name}={value}" for name, value in fetch.cookies.items())
        globals_text = "\n".join(fetch.browser_globals)
        urls = "\n".join(url for url in [fetch.url, fetch.final_url] if url)

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
                matched = bool(re.search(rule.body_pattern, body, re.I))
            if not matched and rule.global_pattern:
                matched = bool(re.search(rule.global_pattern, globals_text, re.I))
            if not matched and rule.url_pattern:
                matched = bool(re.search(rule.url_pattern, urls, re.I))
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


WAPPALYZER_DIMENSION_MAP = {
    "cdn": DIM_CDN_WAF_SERVER,
    "caching": DIM_CDN_WAF_SERVER,
    "load balancers": DIM_CDN_WAF_SERVER,
    "reverse proxy": DIM_CDN_WAF_SERVER,
    "reverse proxies": DIM_CDN_WAF_SERVER,
    "web server extensions": DIM_CDN_WAF_SERVER,
    "web servers": DIM_CDN_WAF_SERVER,
    "javascript frameworks": DIM_FRONTEND,
    "javascript libraries": DIM_FRONTEND,
    "ui frameworks": DIM_FRONTEND,
    "web frameworks": DIM_BACKEND,
    "programming languages": DIM_BACKEND,
}


WAPPALYZER_CATEGORY_ID_MAP = {
    12: DIM_FRONTEND,  # JavaScript frameworks
    59: DIM_FRONTEND,  # JavaScript libraries
    66: DIM_FRONTEND,  # UI frameworks
    18: DIM_BACKEND,  # Web frameworks
    27: DIM_BACKEND,  # Programming languages
    22: DIM_CDN_WAF_SERVER,  # Web servers
    31: DIM_CDN_WAF_SERVER,  # CDN
    23: DIM_CDN_WAF_SERVER,  # Caching
    64: DIM_CDN_WAF_SERVER,  # Reverse proxies
    67: DIM_CDN_WAF_SERVER,  # Load balancers
}


WAF_ALLOWLIST = {
    "akamai bot manager",
    "aws waf",
    "cloudflare bot management",
    "cloudflare firewall rules",
    "imperva",
    "incapsula",
    "sucuri firewall",
    "wordfence",
}


@dataclass(frozen=True)
class WappalyzerPattern:
    pattern: str
    confidence: int


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_wappalyzer_pattern(value: object) -> WappalyzerPattern:
    raw = str(value or "")
    parts = raw.split(r"\;")
    pattern = parts[0]
    confidence = 100
    for part in parts[1:]:
        if part.startswith("confidence:"):
            try:
                confidence = int(part.split(":", 1)[1])
            except ValueError:
                confidence = 100
    return WappalyzerPattern(pattern=pattern, confidence=max(0, min(confidence, 100)))


def _pattern_matches(pattern: WappalyzerPattern, haystack: str) -> bool:
    if pattern.pattern == "":
        return True
    try:
        return bool(re.search(pattern.pattern, haystack, re.I))
    except re.error:
        return pattern.pattern.lower() in haystack.lower()


def _extract_script_srcs(body: str) -> list[str]:
    srcs: list[str] = []
    for match in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*([\"'])(.*?)\1", body, re.I | re.S):
        srcs.append(match.group(2))
    return srcs


def _extract_meta(body: str) -> dict[str, list[str]]:
    meta: dict[str, list[str]] = {}
    for match in re.finditer(r"<meta\b([^>]*)>", body, re.I | re.S):
        attrs = {
            attr.group(1).lower(): attr.group(3)
            for attr in re.finditer(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*([\"'])(.*?)\2", match.group(1))
        }
        name = attrs.get("name") or attrs.get("property") or attrs.get("http-equiv")
        content = attrs.get("content", "")
        if name:
            meta.setdefault(name.lower(), []).append(content)
    return meta


class WappalyzerJsonProvider(Provider):
    name = "wappalyzer_json"

    def __init__(self, data_path: Path | str):
        self.data_path = Path(data_path)
        with self.data_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.apps: dict[str, dict[str, object]] = data.get("apps", data) if isinstance(data, dict) else {}
        self.categories = data.get("categories", {}) if isinstance(data, dict) else {}

    def detect(self, fetch: FetchResult) -> list[Finding]:
        matched: dict[str, Finding] = {}
        body = fetch.body or ""
        script_srcs = fetch.script_srcs or _extract_script_srcs(body)
        meta = _extract_meta(body)

        for app_name, app in self.apps.items():
            if not isinstance(app, dict):
                continue
            finding = self._detect_app(app_name, app, fetch, body, script_srcs, meta)
            if finding:
                matched[app_name] = finding

        for app_name in list(matched):
            self._add_implied(app_name, matched, set())

        return list(matched.values())

    def _detect_app(
        self,
        app_name: str,
        app: dict[str, object],
        fetch: FetchResult,
        body: str,
        script_srcs: list[str],
        meta: dict[str, list[str]],
    ) -> Finding | None:
        dimension = self._dimension_for_app(app_name, app)
        if not dimension:
            return None

        evidence: list[str] = []
        confidence = 0
        confidence = max(confidence, self._match_keyed_patterns(
            app.get("headers"), fetch.headers, "wappalyzer header", evidence
        ))
        confidence = max(confidence, self._match_keyed_patterns(
            app.get("cookies"), fetch.cookies, "wappalyzer cookie", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.get("html"), [body], "wappalyzer html", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.get("scriptSrc"), script_srcs, "wappalyzer scriptSrc", evidence
        ))
        confidence = max(confidence, self._match_keyed_patterns(
            app.get("meta"), meta, "wappalyzer meta", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.get("js"), fetch.browser_globals, "wappalyzer js", evidence
        ))

        if not evidence:
            return None

        return Finding(
            name=app_name,
            dimension=dimension,
            provider=self.name,
            confidence=confidence or 100,
            evidence=evidence,
        )

    def _dimension_for_app(self, app_name: str, app: dict[str, object]) -> str | None:
        categories = app.get("cats") or app.get("categories") or []
        for category in _as_list(categories):
            dimension = self._dimension_for_category(category)
            if dimension:
                return dimension
        security_name = app_name.lower()
        return DIM_CDN_WAF_SERVER if security_name in WAF_ALLOWLIST else None

    def _dimension_for_category(self, category: object) -> str | None:
        if isinstance(category, int):
            return WAPPALYZER_CATEGORY_ID_MAP.get(category)
        if isinstance(category, str) and category.isdigit():
            category_id = int(category)
            if category_id in WAPPALYZER_CATEGORY_ID_MAP:
                return WAPPALYZER_CATEGORY_ID_MAP[category_id]
            category_data = self.categories.get(category) or self.categories.get(category_id)
            if isinstance(category_data, dict):
                return WAPPALYZER_DIMENSION_MAP.get(str(category_data.get("name", "")).lower())
        return WAPPALYZER_DIMENSION_MAP.get(str(category).lower())

    def _match_keyed_patterns(
        self,
        raw_patterns: object,
        values: dict[str, object],
        evidence_prefix: str,
        evidence: list[str],
    ) -> int:
        if not isinstance(raw_patterns, dict):
            return 0
        values_lc = {str(key).lower(): value for key, value in values.items()}
        confidence = 0
        for raw_key, raw_value in raw_patterns.items():
            key = str(raw_key).lower()
            if key not in values_lc:
                continue
            haystacks = values_lc[key] if isinstance(values_lc[key], list) else [values_lc[key]]
            for pattern_value in _as_list(raw_value):
                pattern = parse_wappalyzer_pattern(pattern_value)
                if any(_pattern_matches(pattern, str(haystack)) for haystack in haystacks):
                    confidence = max(confidence, pattern.confidence)
                    evidence_item = f"{evidence_prefix}: {raw_key}"
                    if evidence_item not in evidence:
                        evidence.append(evidence_item)
        return confidence

    def _match_text_patterns(
        self,
        raw_patterns: object,
        haystacks: list[str],
        evidence_item: str,
        evidence: list[str],
    ) -> int:
        confidence = 0
        for pattern_value in _as_list(raw_patterns):
            pattern = parse_wappalyzer_pattern(pattern_value)
            if any(_pattern_matches(pattern, haystack) for haystack in haystacks):
                confidence = max(confidence, pattern.confidence)
                if evidence_item not in evidence:
                    evidence.append(evidence_item)
        return confidence

    def _add_implied(self, app_name: str, matched: dict[str, Finding], seen: set[str]) -> None:
        if app_name in seen:
            return
        seen.add(app_name)
        app = self.apps.get(app_name)
        if not isinstance(app, dict):
            return
        for implied_value in _as_list(app.get("implies")):
            implied = parse_wappalyzer_pattern(implied_value).pattern
            implied_app = self.apps.get(implied)
            if not isinstance(implied_app, dict) or implied in matched:
                continue
            dimension = self._dimension_for_app(implied, implied_app)
            if not dimension:
                continue
            matched[implied] = Finding(
                name=implied,
                dimension=dimension,
                provider=self.name,
                confidence=parse_wappalyzer_pattern(implied_value).confidence,
                evidence=[f"wappalyzer implied by: {app_name}"],
            )
            self._add_implied(implied, matched, seen)


class WappalyzerGoProvider(Provider):
    name = "wappalyzergo"

    def __init__(self, command: str):
        self.command = command

    def detect(self, fetch: FetchResult) -> list[Finding]:
        payload = {
            "url": fetch.final_url or fetch.url,
            "headers": fetch.headers,
            "body": fetch.body,
        }
        try:
            proc = subprocess.run(
                [self.command],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=True,
                timeout=20,
            )
            raw = json.loads(proc.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return []

        return self._parse_output(raw)

    def _parse_output(self, raw: object) -> list[Finding]:
        technologies: Iterable[dict[str, object]]
        if isinstance(raw, dict) and isinstance(raw.get("technologies"), list):
            technologies = raw["technologies"]  # type: ignore[assignment]
        elif isinstance(raw, list):
            technologies = raw  # type: ignore[assignment]
        else:
            return []

        findings: list[Finding] = []
        for tech in technologies:
            if not isinstance(tech, dict):
                continue
            categories = tech.get("categories") or tech.get("category") or []
            if isinstance(categories, str):
                categories = [categories]
            dimension = None
            for category in categories:
                mapped = WAPPALYZER_DIMENSION_MAP.get(str(category).lower())
                if mapped:
                    dimension = mapped
                    break
            if not dimension:
                continue
            name = str(tech.get("name") or "").strip()
            if not name:
                continue
            confidence = int(tech.get("confidence") or 80)
            findings.append(
                Finding(
                    name=name,
                    dimension=dimension,
                    provider=self.name,
                    confidence=max(0, min(confidence, 100)),
                    evidence=["wappalyzergo provider"],
                )
            )
        return findings


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.name.lower(), finding.dimension)
        existing = merged.get(key)
        if not existing:
            merged[key] = Finding(
                name=finding.name,
                dimension=finding.dimension,
                provider=finding.provider,
                confidence=finding.confidence,
                evidence=list(finding.evidence),
            )
            continue
        existing.confidence = max(existing.confidence, finding.confidence)
        providers = set(existing.provider.split(","))
        providers.add(finding.provider)
        existing.provider = ",".join(sorted(providers))
        for evidence in finding.evidence:
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)
    return sorted(merged.values(), key=lambda item: (item.dimension, item.name.lower()))


def build_providers(
    provider_names: list[str],
    wappalyzergo_cmd: str | None,
    wappalyzer_data: Path | str | None = None,
) -> list[Provider]:
    enabled: list[Provider] = []
    names = {"builtin", "wappalyzergo", "wappalyzer_json"} if "all" in provider_names else set(provider_names)
    if "builtin" in names:
        enabled.append(BuiltinProvider())
    if "wappalyzer_json" in names and wappalyzer_data:
        enabled.append(WappalyzerJsonProvider(wappalyzer_data))
    if "wappalyzergo" in names and wappalyzergo_cmd:
        enabled.append(WappalyzerGoProvider(wappalyzergo_cmd))
    return enabled
