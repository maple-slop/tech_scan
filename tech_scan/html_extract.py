from __future__ import annotations

from selectolax.parser import HTMLParser


def _parse(body: str) -> HTMLParser | None:
    if not body:
        return None
    try:
        return HTMLParser(body)
    except Exception:
        return None


def _attrs(node: object) -> dict[str, str]:
    raw = getattr(node, "attributes", None)
    if not isinstance(raw, dict):
        return {}
    return {
        str(name).lower(): "" if value is None else str(value)
        for name, value in raw.items()
    }


def extract_attrs(tag_attrs: str) -> dict[str, str]:
    parser = _parse(f"<x {tag_attrs}></x>")
    if parser is None:
        return {}
    node = parser.css_first("x")
    return _attrs(node) if node is not None else {}


def extract_script_srcs(body: str) -> list[str]:
    parser = _parse(body)
    if parser is None:
        return []
    urls: list[str] = []
    for node in parser.css("script"):
        src = _attrs(node).get("src")
        if src:
            urls.append(src)
    return urls


def extract_meta(body: str) -> dict[str, list[str]]:
    parser = _parse(body)
    if parser is None:
        return {}
    meta: dict[str, list[str]] = {}
    for node in parser.css("meta"):
        attrs = _attrs(node)
        name = attrs.get("name") or attrs.get("property") or attrs.get("http-equiv")
        content = attrs.get("content", "")
        if name:
            meta.setdefault(name.lower(), []).append(content)
    return meta


def extract_url_attrs(
    body: str,
    attr_names: tuple[str, ...] | None = None,
) -> list[str]:
    wanted = attr_names or ("href", "src", "action", "formaction")
    parser = _parse(body)
    if parser is None:
        return []
    urls: list[str] = []
    for node in parser.css("*"):
        attrs = _attrs(node)
        for name in wanted:
            value = attrs.get(name)
            if value:
                urls.append(value)
    return urls
