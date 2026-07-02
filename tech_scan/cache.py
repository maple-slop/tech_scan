from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FetchObservation, ResourceObservation


FETCH_PROFILE_VERSION = "v8"


@dataclass(frozen=True)
class CacheDisposition:
    cacheable: bool
    reason: str


@dataclass(frozen=True)
class CacheRecord:
    observation: FetchObservation
    created_at: int
    updated_at: int


LOCAL_CLIENT_ERROR_MARKERS = [
    "playwright is not installed",
    "browser executable",
    "executable doesn't exist",
    "chromium",
    "chrome for testing",
    "browser launch",
    "launch_persistent_context",
    "new_context",
    "persistent context",
    "user data dir",
]


def cache_disposition(fetch: FetchObservation) -> CacheDisposition:
    primary = fetch.primary_resource
    if primary.status is not None:
        return CacheDisposition(True, f"http-status-{primary.status}")
    if not fetch.error and not primary.error:
        return CacheDisposition(True, "resource-observation")

    error = str(fetch.error or primary.error or "").lower()
    if primary.kind == "sanity":
        if "no open port" in error:
            return CacheDisposition(True, "sanity-no-open-port")
        if "dns resolution failed" in error:
            return CacheDisposition(True, "sanity-dns-error")
        if "invalid port target" in error:
            return CacheDisposition(True, "sanity-invalid-port")
        return CacheDisposition(True, "sanity-error")
    if "blocked cross-host redirect" in error:
        return CacheDisposition(True, "blocked-cross-host-redirect")
    if any(marker in error for marker in LOCAL_CLIENT_ERROR_MARKERS):
        return CacheDisposition(False, "local-client-error")
    if fetch.mode == "browser":
        return CacheDisposition(False, "browser-client-error")
    if fetch.mode == "requests":
        return CacheDisposition(True, "requests-error")
    return CacheDisposition(False, "fetch-error")


def is_cacheable_fetch(fetch: FetchObservation) -> bool:
    return cache_disposition(fetch).cacheable


def default_db_path() -> Path:
    cache_home = os.environ.get("XDG_CACHE_HOME")
    base = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    return base / "tech_scan" / "results.db"


def _resource_to_json(resource: ResourceObservation) -> dict[str, Any]:
    return {
        "id": resource.id,
        "kind": resource.kind,
        "url": resource.url,
        "final_url": resource.final_url,
        "status": resource.status,
        "headers": resource.headers,
        "cookies": resource.cookies,
        "body": resource.body,
        "parent_id": resource.parent_id,
        "error": resource.error,
    }


def _resource_from_json(data: dict[str, Any], created_at: int, updated_at: int) -> ResourceObservation:
    return ResourceObservation(
        id=str(data["id"]),
        kind=str(data["kind"]),
        url=str(data["url"]),
        final_url=data.get("final_url"),
        status=data.get("status"),
        headers={str(key): str(value) for key, value in (data.get("headers") or {}).items()},
        cookies={str(key): str(value) for key, value in (data.get("cookies") or {}).items()},
        body=str(data.get("body") or ""),
        parent_id=data.get("parent_id"),
        error=data.get("error"),
        cache_created_at=created_at,
        cache_updated_at=updated_at,
    )


def _observation_to_json(fetch: FetchObservation) -> dict[str, Any]:
    return {
        "input": fetch.input,
        "url": fetch.url,
        "final_url": fetch.final_url,
        "status": fetch.status,
        "headers": fetch.headers,
        "cookies": fetch.cookies,
        "body": fetch.body,
        "mode": fetch.mode,
        "error": fetch.error,
        "browser_globals": fetch.browser_globals,
        "script_srcs": fetch.script_srcs,
        "resources": [_resource_to_json(resource) for resource in fetch.resources],
        "primary_resource_id": fetch.primary_resource_id,
    }


def _observation_from_json(data: dict[str, Any], target: str, created_at: int, updated_at: int) -> FetchObservation:
    resources = [
        _resource_from_json(resource, created_at, updated_at)
        for resource in data.get("resources") or []
    ]
    primary_resource_id = data.get("primary_resource_id")
    primary = next(
        (resource for resource in resources if resource.id == primary_resource_id),
        resources[0] if resources else None,
    )
    if primary is None:
        primary = ResourceObservation(
            id="document:0",
            kind="document",
            url=target,
            final_url=data.get("final_url"),
            status=data.get("status"),
            headers={str(key): str(value) for key, value in (data.get("headers") or {}).items()},
            cookies={str(key): str(value) for key, value in (data.get("cookies") or {}).items()},
            body=str(data.get("body") or ""),
            error=data.get("error"),
            cache_created_at=created_at,
            cache_updated_at=updated_at,
        )
        resources = [primary]
        primary_resource_id = primary.id
    script_srcs = data.get("script_srcs") or [
        resource.url for resource in resources if resource.kind == "script"
    ]
    return FetchObservation(
        input=target,
        url=target,
        final_url=primary.final_url,
        status=primary.status,
        headers=primary.headers,
        cookies=primary.cookies,
        body=primary.body,
        mode=str(data.get("mode") or ""),
        error=primary.error,
        browser_globals=[str(item) for item in data.get("browser_globals") or []],
        script_srcs=[str(item) for item in script_srcs],
        resources=resources,
        primary_resource_id=str(primary_resource_id) if primary_resource_id else None,
    )


class CacheStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fetch_records (
                cache_key TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                source TEXT NOT NULL,
                proxy TEXT,
                identity TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                observation_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CacheStore":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @staticmethod
    def key(target: str, source: str, proxy: str | None, identity: str | None = None) -> str:
        return "|".join([target, source, proxy or "", identity or "", FETCH_PROFILE_VERSION])

    def get(
        self,
        target: str,
        source: str,
        proxy: str | None,
        ttl: int,
        identity: str | None = None,
    ) -> CacheRecord | None:
        key = self.key(target, source, proxy, identity)
        row = self.conn.execute(
            """
            SELECT observation_json, created_at, updated_at
            FROM fetch_records
            WHERE cache_key = ?
            """,
            (key,),
        ).fetchone()
        if not row:
            return None
        observation_json, created_at, updated_at = row
        if ttl >= 0 and int(time.time()) - int(updated_at) > ttl:
            return None
        observation = _observation_from_json(
            json.loads(observation_json),
            target,
            int(created_at),
            int(updated_at),
        )
        return CacheRecord(observation, int(created_at), int(updated_at))

    def set(
        self,
        target: str,
        source: str,
        proxy: str | None,
        fetch: FetchObservation,
        identity: str | None = None,
    ) -> CacheRecord | None:
        if not cache_disposition(fetch).cacheable:
            return None
        now = int(time.time())
        key = self.key(target, source, proxy, identity)
        existing = self.conn.execute(
            "SELECT created_at FROM fetch_records WHERE cache_key = ?",
            (key,),
        ).fetchone()
        created_at = int(existing[0]) if existing else now
        self.conn.execute(
            """
            INSERT INTO fetch_records (
                cache_key, target, source, proxy, identity, profile_version,
                observation_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                target = excluded.target,
                source = excluded.source,
                proxy = excluded.proxy,
                identity = excluded.identity,
                profile_version = excluded.profile_version,
                observation_json = excluded.observation_json,
                updated_at = excluded.updated_at
            """,
            (
                key,
                target,
                source,
                proxy,
                identity or "",
                FETCH_PROFILE_VERSION,
                json.dumps(_observation_to_json(fetch), sort_keys=True),
                created_at,
                now,
            ),
        )
        self.conn.commit()
        record = self.get(target, source, proxy, -1, identity)
        assert record is not None
        return record
