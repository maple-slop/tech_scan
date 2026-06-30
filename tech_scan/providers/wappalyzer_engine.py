from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from selectolax.parser import HTMLParser

from tech_scan.html_extract import extract_meta, extract_script_srcs
from tech_scan.models import (
    DIM_BACKEND,
    DIM_CDN_WAF_SERVER,
    DIM_FRONTEND,
    FetchResult,
    Finding,
)

from .base import Provider


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
    12: DIM_FRONTEND,
    59: DIM_FRONTEND,
    66: DIM_FRONTEND,
    18: DIM_BACKEND,
    27: DIM_BACKEND,
    22: DIM_CDN_WAF_SERVER,
    31: DIM_CDN_WAF_SERVER,
    23: DIM_CDN_WAF_SERVER,
    64: DIM_CDN_WAF_SERVER,
    67: DIM_CDN_WAF_SERVER,
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
class _WappalyzerPattern:
    pattern: str
    confidence: int


@dataclass(frozen=True)
class _DomContext:
    parser: HTMLParser | None


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _parse_wappalyzer_pattern(value: object) -> _WappalyzerPattern:
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
    return _WappalyzerPattern(pattern=pattern, confidence=max(0, min(confidence, 100)))


def _pattern_matches(pattern: _WappalyzerPattern, haystack: str) -> bool:
    if pattern.pattern == "":
        return True
    try:
        return bool(re.search(pattern.pattern, haystack, re.I))
    except re.error:
        return pattern.pattern.lower() in haystack.lower()


def _dom_context(body: str) -> _DomContext:
    if not body:
        return _DomContext(None)
    try:
        return _DomContext(HTMLParser(body))
    except Exception:
        return _DomContext(None)


def _node_text(node: object) -> str:
    text_method = getattr(node, "text", None)
    if not callable(text_method):
        return ""
    try:
        return str(text_method(separator=" ", strip=True))
    except TypeError:
        return str(text_method())


def _node_attributes(node: object) -> dict[str, str]:
    raw = getattr(node, "attributes", None)
    if not isinstance(raw, dict):
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items()}


class _WappalyzerFingerprintProvider(Provider):
    def __init__(
        self,
        data_path: Path | str | None = None,
        data: dict[str, Any] | None = None,
        provider_name: str = "wappalyzer",
    ):
        self.name = provider_name
        self.data_path = Path(data_path) if data_path is not None else None
        if data is None:
            if self.data_path is None:
                raise ValueError("data_path or data is required")
            with self.data_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        self.apps: dict[str, dict[str, object]] = data.get("apps", data) if isinstance(data, dict) else {}
        self.categories = data.get("categories", {}) if isinstance(data, dict) else {}

    def detect(self, fetch: FetchResult) -> list[Finding]:
        matched: dict[str, Finding] = {}
        body = fetch.body or ""
        script_srcs = fetch.script_srcs or extract_script_srcs(body)
        script_bodies = fetch.script_bodies
        meta = extract_meta(body)
        dom = _dom_context(body)

        for app_name, app in self.apps.items():
            if not isinstance(app, dict):
                continue
            finding = self._detect_app(app_name, app, fetch, body, script_srcs, script_bodies, meta, dom)
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
        script_bodies: list[str],
        meta: dict[str, list[str]],
        dom: _DomContext,
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
            app.get("js"), [*fetch.browser_globals, *script_bodies], "wappalyzer js", evidence
        ))
        confidence = max(confidence, self._match_dom_patterns(
            app.get("dom"), dom, evidence
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
                pattern = _parse_wappalyzer_pattern(pattern_value)
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
            pattern = _parse_wappalyzer_pattern(pattern_value)
            if any(_pattern_matches(pattern, haystack) for haystack in haystacks):
                confidence = max(confidence, pattern.confidence)
                if evidence_item and evidence_item not in evidence:
                    evidence.append(evidence_item)
        return confidence

    def _match_dom_patterns(
        self,
        raw_patterns: object,
        dom: _DomContext,
        evidence: list[str],
    ) -> int:
        if dom.parser is None or not isinstance(raw_patterns, dict):
            return 0

        confidence = 0
        for raw_selector, raw_tests in raw_patterns.items():
            if not isinstance(raw_tests, dict):
                continue
            selector = str(raw_selector)
            try:
                nodes = list(dom.parser.css(selector))
            except Exception:
                continue
            if not nodes:
                continue

            selector_confidence = 0
            for test_name, test_value in raw_tests.items():
                key = str(test_name)
                if key == "properties":
                    continue
                if key == "exists":
                    pattern = _parse_wappalyzer_pattern(test_value)
                    selector_confidence = max(selector_confidence, pattern.confidence)
                elif key == "text":
                    selector_confidence = max(
                        selector_confidence,
                        self._match_text_patterns(
                            test_value,
                            [_node_text(node) for node in nodes],
                            "",
                            [],
                        ),
                    )
                elif key == "attributes":
                    selector_confidence = max(
                        selector_confidence,
                        self._match_dom_attributes(test_value, nodes),
                    )
                else:
                    selector_confidence = max(
                        selector_confidence,
                        self._match_dom_attributes({key: test_value}, nodes),
                    )

            if selector_confidence:
                confidence = max(confidence, selector_confidence)
                evidence_item = f"wappalyzer dom: {selector}"
                if evidence_item not in evidence:
                    evidence.append(evidence_item)
        return confidence

    def _match_dom_attributes(
        self,
        raw_patterns: object,
        nodes: list[object],
    ) -> int:
        if not isinstance(raw_patterns, dict):
            return 0

        confidence = 0
        for raw_attr, raw_value in raw_patterns.items():
            attr = str(raw_attr).lower()
            for pattern_value in _as_list(raw_value):
                pattern = _parse_wappalyzer_pattern(pattern_value)
                for node in nodes:
                    attributes = _node_attributes(node)
                    if attr in attributes and _pattern_matches(pattern, attributes[attr]):
                        confidence = max(confidence, pattern.confidence)
                        break
        return confidence

    def _add_implied(self, app_name: str, matched: dict[str, Finding], seen: set[str]) -> None:
        if app_name in seen:
            return
        seen.add(app_name)
        app = self.apps.get(app_name)
        if not isinstance(app, dict):
            return
        for implied_value in _as_list(app.get("implies")):
            implied_pattern = _parse_wappalyzer_pattern(implied_value)
            implied = implied_pattern.pattern
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
                confidence=implied_pattern.confidence,
                evidence=[f"wappalyzer implied by: {app_name}"],
            )
            self._add_implied(implied, matched, seen)
