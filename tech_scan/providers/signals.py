from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from tech_scan.html_extract import extract_meta, extract_script_srcs, extract_url_attrs
from tech_scan.models import FetchResult, ResourceObservation
from tech_scan.url_policy import same_hostname


def _parse_dom(body: str) -> HTMLParser | None:
    if not body:
        return None
    try:
        return HTMLParser(body)
    except Exception:
        return None


def node_text(node: object) -> str:
    text_method = getattr(node, "text", None)
    if not callable(text_method):
        return ""
    try:
        return str(text_method(separator=" ", strip=True))
    except TypeError:
        return str(text_method())


def node_attributes(node: object) -> dict[str, str]:
    raw = getattr(node, "attributes", None)
    if not isinstance(raw, dict):
        return {}
    return {str(key).lower(): "" if value is None else str(value) for key, value in raw.items()}


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


@dataclass
class DetectionSignals:
    body: str
    body_with_scripts: str
    headers: dict[str, str]
    cookies: dict[str, str]
    script_resources: list[ResourceObservation]
    text_resources: list[ResourceObservation]
    cookie_names: list[str]
    cookie_pairs: list[tuple[str, str]]
    browser_globals: list[str]
    meta: dict[str, list[str]]
    script_srcs: list[str]
    script_bodies: list[str]
    urls: list[str]
    embedded_urls: list[str]
    _dom_parser: HTMLParser | None = field(default=None, init=False, repr=False)
    _dom_loaded: bool = field(default=False, init=False, repr=False)

    @classmethod
    def from_fetch(cls, fetch: FetchResult) -> "DetectionSignals":
        body = fetch.body or ""
        script_bodies = fetch.script_bodies
        return cls(
            body=body,
            body_with_scripts="\n".join([body, *script_bodies]),
            headers={str(key).lower(): str(value) for key, value in fetch.headers.items()},
            cookies={str(key).lower(): str(value) for key, value in fetch.cookies.items()},
            script_resources=fetch.script_resources,
            text_resources=[
                resource
                for resource in fetch.resources
                if resource.kind in {"document", "script", "stylesheet", "xhr", "fetch"}
            ],
            cookie_names=list(fetch.cookies.keys()),
            cookie_pairs=list(fetch.cookies.items()),
            browser_globals=list(fetch.browser_globals),
            meta=extract_meta(body),
            script_srcs=fetch.script_srcs or extract_script_srcs(body),
            script_bodies=script_bodies,
            urls=[url for url in [fetch.url, fetch.final_url] if url],
            embedded_urls=_same_host_embedded_urls(fetch, body),
        )

    @property
    def dom_parser(self) -> HTMLParser | None:
        if not self._dom_loaded:
            self._dom_parser = _parse_dom(self.body)
            self._dom_loaded = True
        return self._dom_parser
