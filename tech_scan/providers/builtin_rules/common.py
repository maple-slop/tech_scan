from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.observations import header_display_name

from ..regex_compile import SearchablePattern, compile_regex
from ..signals import DetectionSignals


DetectionContext = DetectionSignals


Detector = Callable[[FetchResult, DetectionContext], list[str]]


@dataclass(frozen=True)
class Rule:
    name: str
    dimension: str
    confidence: int
    detect: Detector


def _compile(pattern: str) -> SearchablePattern:
    return compile_regex(pattern)


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


def _is_successful_resource(resource: ResourceObservation) -> bool:
    return not resource.error and (resource.status is None or 200 <= resource.status < 400)


def _source_url(resource: ResourceObservation) -> str:
    return resource.final_url or resource.url


def script_body_detector(pattern: str, evidence_label: str = "script body") -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        return [
            f"{evidence_label}: {_source_url(resource)}"
            for resource in context.script_resources
            if _is_successful_resource(resource)
            and resource.body
            and regex.search(resource.body)
        ]

    return detect


def script_url_detector(pattern: str, evidence_label: str = "script url") -> Detector:
    regex = _compile(pattern)

    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        return [
            f"{evidence_label}: {_source_url(resource)}"
            for resource in context.script_resources
            if _is_successful_resource(resource)
            and _source_url(resource)
            and regex.search(_source_url(resource))
        ]

    return detect


def any_detector(*detectors: Detector) -> Detector:
    def detect(fetch: FetchResult, context: DetectionContext) -> list[str]:
        evidence: list[str] = []
        for detector in detectors:
            for item in detector(fetch, context):
                if item not in evidence:
                    evidence.append(item)
        return evidence

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
