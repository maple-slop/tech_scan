from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tech_scan.models import (
    DIM_BACKEND,
    DIM_CDN_WAF_SERVER,
    DIM_CMS,
    DIM_FRONTEND,
    FetchResult,
    Finding,
)

from .base import Provider
from .regex_compile import SearchablePattern, compile_regex_or_none
from .signals import DetectionSignals, node_attributes, node_text


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
    "cms": DIM_CMS,
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
    1: DIM_CMS,
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
class _CompiledPattern:
    pattern: str
    confidence: int
    regex: SearchablePattern | None = None

    @classmethod
    def from_value(cls, value: object) -> "_CompiledPattern":
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
        regex = None
        if pattern:
            regex = compile_regex_or_none(pattern)
        return cls(
            pattern=pattern,
            confidence=max(0, min(confidence, 100)),
            regex=regex,
        )

    def matches(self, haystack: str) -> bool:
        if self.pattern == "":
            return True
        if self.regex is not None:
            return bool(self.regex.search(haystack))
        return self.pattern.lower() in haystack.lower()


@dataclass(frozen=True)
class _CompiledKeyedPatterns:
    raw_key: str
    key: str
    patterns: list[_CompiledPattern]


@dataclass(frozen=True)
class _CompiledDomTest:
    kind: str
    key: str | None
    patterns: list[_CompiledPattern]


@dataclass(frozen=True)
class _CompiledDomRule:
    selector: str
    tests: list[_CompiledDomTest]


@dataclass(frozen=True)
class _CompiledImply:
    name: str
    confidence: int


@dataclass
class _CompiledApp:
    name: str
    dimension: str
    headers: list[_CompiledKeyedPatterns] = field(default_factory=list)
    cookies: list[_CompiledKeyedPatterns] = field(default_factory=list)
    meta: list[_CompiledKeyedPatterns] = field(default_factory=list)
    html: list[_CompiledPattern] = field(default_factory=list)
    script_src: list[_CompiledPattern] = field(default_factory=list)
    js: list[_CompiledPattern] = field(default_factory=list)
    dom: list[_CompiledDomRule] = field(default_factory=list)
    implies: list[_CompiledImply] = field(default_factory=list)

    @property
    def has_cheap_patterns(self) -> bool:
        return bool(self.headers or self.cookies or self.meta)

    @property
    def has_expensive_patterns(self) -> bool:
        return bool(self.html or self.script_src or self.js or self.dom)

    @property
    def has_only_expensive_patterns(self) -> bool:
        return self.has_expensive_patterns and not self.has_cheap_patterns


def _as_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


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
        self.compiled_apps: dict[str, _CompiledApp] = {}
        self.header_index: dict[str, set[str]] = defaultdict(set)
        self.cookie_index: dict[str, set[str]] = defaultdict(set)
        self.meta_index: dict[str, set[str]] = defaultdict(set)
        self.script_src_apps: set[str] = set()
        self.html_apps: set[str] = set()
        self.js_apps: set[str] = set()
        self.dom_apps: set[str] = set()
        self.expensive_only_apps: set[str] = set()
        self._compile_apps()

    def detect(self, fetch: FetchResult) -> list[Finding]:
        matched: dict[str, Finding] = {}
        signals = DetectionSignals.from_fetch(fetch)
        candidates = self._candidate_apps(signals)

        for app_name in sorted(candidates):
            app = self.compiled_apps.get(app_name)
            if app is None:
                continue
            finding = self._detect_app(app, signals)
            if finding:
                matched[app_name] = finding

        for app_name in list(matched):
            self._add_implied(app_name, matched, set())

        return list(matched.values())

    def _compile_apps(self) -> None:
        for app_name, app in self.apps.items():
            if not isinstance(app, dict):
                continue
            dimension = self._dimension_for_app(app_name, app)
            if not dimension:
                continue
            compiled = _CompiledApp(
                name=app_name,
                dimension=dimension,
                headers=self._compile_keyed_patterns(app.get("headers")),
                cookies=self._compile_keyed_patterns(app.get("cookies")),
                meta=self._compile_keyed_patterns(app.get("meta")),
                html=self._compile_text_patterns(app.get("html")),
                script_src=self._compile_text_patterns(app.get("scriptSrc")),
                js=self._compile_text_patterns(app.get("js")),
                dom=self._compile_dom_rules(app.get("dom")),
                implies=self._compile_implies(app.get("implies")),
            )
            self.compiled_apps[app_name] = compiled
            for keyed in compiled.headers:
                self.header_index[keyed.key].add(app_name)
            for keyed in compiled.cookies:
                self.cookie_index[keyed.key].add(app_name)
            for keyed in compiled.meta:
                self.meta_index[keyed.key].add(app_name)
            if compiled.script_src:
                self.script_src_apps.add(app_name)
            if compiled.html:
                self.html_apps.add(app_name)
            if compiled.js:
                self.js_apps.add(app_name)
            if compiled.dom:
                self.dom_apps.add(app_name)
            if compiled.has_only_expensive_patterns:
                self.expensive_only_apps.add(app_name)

    def _compile_keyed_patterns(self, raw_patterns: object) -> list[_CompiledKeyedPatterns]:
        if not isinstance(raw_patterns, dict):
            return []
        compiled = []
        for raw_key, raw_value in raw_patterns.items():
            patterns = self._compile_text_patterns(raw_value)
            if patterns:
                compiled.append(
                    _CompiledKeyedPatterns(
                        raw_key=str(raw_key),
                        key=str(raw_key).lower(),
                        patterns=patterns,
                    )
                )
        return compiled

    def _compile_text_patterns(self, raw_patterns: object) -> list[_CompiledPattern]:
        return [_CompiledPattern.from_value(value) for value in _as_list(raw_patterns)]

    def _compile_implies(self, raw_implies: object) -> list[_CompiledImply]:
        implies = []
        for value in _as_list(raw_implies):
            pattern = _CompiledPattern.from_value(value)
            if pattern.pattern:
                implies.append(_CompiledImply(name=pattern.pattern, confidence=pattern.confidence))
        return implies

    def _compile_dom_rules(self, raw_patterns: object) -> list[_CompiledDomRule]:
        if not isinstance(raw_patterns, dict):
            return []

        rules = []
        for raw_selector, raw_tests in raw_patterns.items():
            if not isinstance(raw_tests, dict):
                continue
            tests: list[_CompiledDomTest] = []
            for test_name, test_value in raw_tests.items():
                key = str(test_name)
                if key == "properties":
                    continue
                if key == "exists":
                    tests.append(
                        _CompiledDomTest(
                            kind="exists",
                            key=None,
                            patterns=[_CompiledPattern.from_value(test_value)],
                        )
                    )
                elif key == "text":
                    tests.append(
                        _CompiledDomTest(
                            kind="text",
                            key=None,
                            patterns=self._compile_text_patterns(test_value),
                        )
                    )
                elif key == "attributes":
                    if isinstance(test_value, dict):
                        for raw_attr, raw_value in test_value.items():
                            tests.append(
                                _CompiledDomTest(
                                    kind="attribute",
                                    key=str(raw_attr).lower(),
                                    patterns=self._compile_text_patterns(raw_value),
                                )
                            )
                else:
                    tests.append(
                        _CompiledDomTest(
                            kind="attribute",
                            key=key.lower(),
                            patterns=self._compile_text_patterns(test_value),
                        )
                    )
            if tests:
                rules.append(_CompiledDomRule(selector=str(raw_selector), tests=tests))
        return rules

    def _candidate_apps(self, signals: DetectionSignals) -> set[str]:
        candidates: set[str] = set(self.expensive_only_apps)
        for name in signals.headers:
            candidates.update(self.header_index.get(name, ()))
        for name in signals.cookies:
            candidates.update(self.cookie_index.get(name, ()))
        for name in signals.meta:
            candidates.update(self.meta_index.get(name, ()))
        if signals.script_srcs:
            candidates.update(self.script_src_apps)
        return candidates

    def _detect_app(
        self,
        app: _CompiledApp,
        signals: DetectionSignals,
    ) -> Finding | None:
        evidence: list[str] = []
        confidence = 0
        confidence = max(confidence, self._match_keyed_patterns(
            app.headers, signals.headers, "wappalyzer header", evidence
        ))
        confidence = max(confidence, self._match_keyed_patterns(
            app.cookies, signals.cookies, "wappalyzer cookie", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.html, [signals.body], "wappalyzer html", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.script_src, signals.script_srcs, "wappalyzer scriptSrc", evidence
        ))
        confidence = max(confidence, self._match_keyed_patterns(
            app.meta, signals.meta, "wappalyzer meta", evidence
        ))
        confidence = max(confidence, self._match_text_patterns(
            app.js, [*signals.browser_globals, *signals.script_bodies], "wappalyzer js", evidence
        ))
        confidence = max(confidence, self._match_dom_patterns(
            app.dom, signals, evidence
        ))

        if not evidence:
            return None

        return Finding(
            name=app.name,
            dimension=app.dimension,
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
        patterns_by_key: list[_CompiledKeyedPatterns],
        values: dict[str, object],
        evidence_prefix: str,
        evidence: list[str],
    ) -> int:
        confidence = 0
        for keyed in patterns_by_key:
            if keyed.key not in values:
                continue
            haystacks = values[keyed.key] if isinstance(values[keyed.key], list) else [values[keyed.key]]
            for pattern in keyed.patterns:
                if any(pattern.matches(str(haystack)) for haystack in haystacks):
                    confidence = max(confidence, pattern.confidence)
                    evidence_item = f"{evidence_prefix}: {keyed.raw_key}"
                    if evidence_item not in evidence:
                        evidence.append(evidence_item)
        return confidence

    def _match_text_patterns(
        self,
        patterns: list[_CompiledPattern],
        haystacks: list[str],
        evidence_item: str,
        evidence: list[str],
    ) -> int:
        confidence = 0
        for pattern in patterns:
            if any(pattern.matches(haystack) for haystack in haystacks):
                confidence = max(confidence, pattern.confidence)
                if evidence_item and evidence_item not in evidence:
                    evidence.append(evidence_item)
        return confidence

    def _match_dom_patterns(
        self,
        rules: list[_CompiledDomRule],
        signals: DetectionSignals,
        evidence: list[str],
    ) -> int:
        dom_parser = signals.dom_parser
        if dom_parser is None:
            return 0

        confidence = 0
        for rule in rules:
            try:
                nodes = list(dom_parser.css(rule.selector))
            except Exception:
                continue
            if not nodes:
                continue

            selector_confidence = 0
            for test in rule.tests:
                if test.kind == "exists":
                    selector_confidence = max(
                        selector_confidence,
                        max((pattern.confidence for pattern in test.patterns), default=0),
                    )
                elif test.kind == "text":
                    selector_confidence = max(
                        selector_confidence,
                        self._match_text_patterns(
                            test.patterns,
                            [node_text(node) for node in nodes],
                            "",
                            [],
                        ),
                    )
                elif test.kind == "attribute" and test.key is not None:
                    selector_confidence = max(
                        selector_confidence,
                        self._match_dom_attributes(test.key, test.patterns, nodes),
                    )

            if selector_confidence:
                confidence = max(confidence, selector_confidence)
                evidence_item = f"wappalyzer dom: {rule.selector}"
                if evidence_item not in evidence:
                    evidence.append(evidence_item)
        return confidence

    def _match_dom_attributes(
        self,
        attr: str,
        patterns: list[_CompiledPattern],
        nodes: list[object],
    ) -> int:
        confidence = 0
        for pattern in patterns:
            for node in nodes:
                attributes = node_attributes(node)
                if attr in attributes and pattern.matches(attributes[attr]):
                    confidence = max(confidence, pattern.confidence)
                    break
        return confidence

    def _add_implied(self, app_name: str, matched: dict[str, Finding], seen: set[str]) -> None:
        if app_name in seen:
            return
        seen.add(app_name)
        app = self.compiled_apps.get(app_name)
        if app is None:
            return
        for implied_pattern in app.implies:
            implied = implied_pattern.name
            implied_app = self.compiled_apps.get(implied)
            if implied_app is None or implied in matched:
                continue
            matched[implied] = Finding(
                name=implied,
                dimension=implied_app.dimension,
                provider=self.name,
                confidence=implied_pattern.confidence,
                evidence=[f"wappalyzer implied by: {app_name}"],
            )
            self._add_implied(implied, matched, seen)
