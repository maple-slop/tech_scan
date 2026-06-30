from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    def __init__(
        self,
        data_path: Path | str | None = None,
        data: dict[str, Any] | None = None,
        provider_name: str | None = None,
    ):
        if provider_name:
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
            implied_pattern = parse_wappalyzer_pattern(implied_value)
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
