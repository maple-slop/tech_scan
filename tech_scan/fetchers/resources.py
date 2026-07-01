from __future__ import annotations

from collections.abc import Mapping

from tech_scan.models import ResourceObservation


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def is_redirect_status(status: object) -> bool:
    return status in REDIRECT_STATUSES


def normalize_headers(headers: Mapping[object, object] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def limited_text_from_bytes_or_text(
    content: bytes | None,
    text: str | None = None,
    encoding: str | None = None,
    max_bytes: int | None = None,
) -> str:
    if content is None:
        content = (text or "").encode(encoding or "utf-8", errors="replace")
    if max_bytes is not None and len(content) > max_bytes:
        content = content[:max_bytes]
    return content.decode(encoding or "utf-8", errors="replace")


def make_resource(
    resource_id: str,
    kind: str,
    url: str,
    final_url: str | None,
    status: int | None,
    headers: Mapping[object, object] | None,
    cookies: Mapping[str, str] | None,
    body: str,
    parent_id: str | None = None,
    error: str | None = None,
) -> ResourceObservation:
    return ResourceObservation(
        id=resource_id,
        parent_id=parent_id,
        kind=kind,
        url=url,
        final_url=final_url,
        status=status,
        headers=normalize_headers(headers),
        cookies=dict(cookies or {}),
        body=body,
        error=error,
    )


def make_error_resource(
    resource_id: str,
    kind: str,
    url: str,
    error: str,
    parent_id: str | None = None,
) -> ResourceObservation:
    return make_resource(
        resource_id=resource_id,
        kind=kind,
        url=url,
        final_url=None,
        status=None,
        headers={},
        cookies={},
        body="",
        parent_id=parent_id,
        error=error,
    )


def make_redirect_resource(
    resource_id: str,
    url: str,
    next_url: str,
    status: int | None,
    headers: Mapping[object, object] | None,
    cookies: Mapping[str, str] | None,
    parent_id: str | None = None,
) -> ResourceObservation:
    return make_resource(
        resource_id=resource_id,
        kind="redirect",
        url=url,
        final_url=next_url,
        status=status,
        headers=headers,
        cookies=cookies,
        body="",
        parent_id=parent_id,
    )
