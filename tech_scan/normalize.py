from __future__ import annotations

from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    target = raw.strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("missing host")
    return target.rstrip("/")


def http_fallback_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    return parsed._replace(scheme="http").geturl()
