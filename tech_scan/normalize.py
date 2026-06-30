from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class TargetCandidate:
    input: str
    url: str


def _validate_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("missing host")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    return target.rstrip("/")


def expand_targets(raw: str) -> list[TargetCandidate]:
    target = raw.strip()
    if not target:
        raise ValueError("empty target")
    if "://" in target:
        return [TargetCandidate(target, _validate_url(target))]

    host_part = target.split("/", 1)[0]
    if ":" in host_part:
        raise ValueError(
            "scheme is required when a port is provided; use "
            f"http://{target} or https://{target}"
        )
    return [
        TargetCandidate(target, _validate_url(f"http://{target}")),
        TargetCandidate(target, _validate_url(f"https://{target}")),
    ]
