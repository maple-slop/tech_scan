from __future__ import annotations

from urllib.parse import urljoin, urlparse


def same_hostname(first_url: str, second_url: str) -> bool:
    return (urlparse(first_url).hostname or "").lower() == (
        urlparse(second_url).hostname or ""
    ).lower()


def redirect_target(current_url: str, location: str | None) -> str | None:
    if not location:
        return None
    return urljoin(current_url, location)
