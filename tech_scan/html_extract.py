from __future__ import annotations

import re


ATTR_NAME = r"[a-zA-Z_:][-a-zA-Z0-9_:.]*"
QUOTED_ATTR_RE = re.compile(
    rf"({ATTR_NAME})\s*=\s*([\"'])(.*?)\2",
    re.I | re.S,
)


def extract_attrs(tag_attrs: str) -> dict[str, str]:
    return {
        match.group(1).lower(): match.group(3)
        for match in QUOTED_ATTR_RE.finditer(tag_attrs)
    }


def extract_script_srcs(body: str) -> list[str]:
    return [
        attrs["src"]
        for attrs in (
            extract_attrs(match.group(1))
            for match in re.finditer(r"<script\b([^>]*)>", body, re.I | re.S)
        )
        if attrs.get("src")
    ]


def extract_meta(body: str) -> dict[str, list[str]]:
    meta: dict[str, list[str]] = {}
    for match in re.finditer(r"<meta\b([^>]*)>", body, re.I | re.S):
        attrs = extract_attrs(match.group(1))
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
    urls: list[str] = []
    for match in re.finditer(r"<[a-zA-Z][^>]*>", body, re.I | re.S):
        attrs = extract_attrs(match.group(0))
        for name in wanted:
            value = attrs.get(name)
            if value:
                urls.append(value)
    return urls
