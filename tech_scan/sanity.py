from __future__ import annotations

import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .diagnostics import Diagnostics, exception_with_traceback, short_exception


SCHEME_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class PortTarget:
    host: str
    ports: tuple[int, ...]


@dataclass(frozen=True)
class SanityResult:
    status: str
    host: str
    ports: tuple[int, ...]
    open_ip: str | None = None
    open_port: int | None = None
    error: str | None = None
    traceback: str | None = None
    attempts: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def derive_port_target(raw_input: str, normalized_url: str) -> PortTarget:
    parsed = urlparse(normalized_url)
    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if port is not None:
        return PortTarget(host, (port,))
    if parsed.scheme not in SCHEME_PORTS:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme}")
    return PortTarget(host, (SCHEME_PORTS[parsed.scheme],))


def _dedupe_address_infos(address_infos: list[tuple]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    results: list[tuple[str, int]] = []
    for info in address_infos:
        sockaddr = info[4]
        ip = str(sockaddr[0])
        port = int(sockaddr[1])
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            results.append(key)
    return results


def check_target_ports(
    raw_input: str,
    normalized_url: str,
    timeout: float,
    diagnostics: Diagnostics | None = None,
    include_traceback: bool = False,
) -> SanityResult:
    try:
        target = derive_port_target(raw_input, normalized_url)
    except ValueError as exc:
        error = f"sanity check failed: invalid port target: {exc}"
        return SanityResult(
            "invalid-port",
            "",
            (),
            error=exception_with_traceback(exc, error) if include_traceback else error,
            traceback=exception_with_traceback(exc, error),
        )

    attempts: list[str] = []
    address_infos: list[tuple] = []
    for port in target.ports:
        try:
            resolved = socket.getaddrinfo(
                target.host,
                port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            address_infos.extend(resolved)
            if diagnostics:
                diagnostics.log(1, f"sanity resolved: host={target.host} port={port} records={len(resolved)}")
        except socket.gaierror as exc:
            if diagnostics:
                diagnostics.exception(2, f"sanity DNS failed: host={target.host} port={port}", exc)
            error = f"sanity check failed: DNS resolution failed for {target.host}: {exc}"
            return SanityResult(
                "dns-error",
                target.host,
                target.ports,
                error=exception_with_traceback(exc, error) if include_traceback else error,
                traceback=exception_with_traceback(exc, error),
                attempts=tuple(attempts),
            )

    for ip, port in _dedupe_address_infos(address_infos):
        attempt = f"{ip}:{port}"
        attempts.append(attempt)
        if diagnostics:
            diagnostics.log(3, f"sanity connect start: {attempt}")
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                if diagnostics:
                    diagnostics.log(1, f"sanity open port: host={target.host} ip={ip} port={port}")
                return SanityResult(
                    "ok",
                    target.host,
                    target.ports,
                    open_ip=ip,
                    open_port=port,
                    attempts=tuple(attempts),
                )
        except OSError as exc:
            if diagnostics:
                diagnostics.log(3, f"sanity connect failed: {attempt}: {short_exception(exc)}")

    ports_text = ",".join(str(port) for port in target.ports)
    error = f"sanity check failed: no open port for {target.host} on {ports_text}"
    if diagnostics:
        diagnostics.log(1, error)
    return SanityResult(
        "no-open-port",
        target.host,
        target.ports,
        error=error,
        attempts=tuple(attempts),
    )
