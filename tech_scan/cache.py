from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .models import FetchResult, ResourceObservation


FETCH_PROFILE_VERSION = "v4"


def default_db_path() -> Path:
    cache_home = os.environ.get("XDG_CACHE_HOME")
    base = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    return base / "tech_scan" / "results.db"


class ResponseCache:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fetches (
                cache_key TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                proxy TEXT,
                profile_version TEXT NOT NULL,
                primary_resource_id TEXT NOT NULL,
                browser_globals_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resources (
                cache_key TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                parent_id TEXT,
                kind TEXT NOT NULL,
                url TEXT NOT NULL,
                final_url TEXT,
                status INTEGER,
                headers_json TEXT NOT NULL,
                cookies_json TEXT NOT NULL,
                body TEXT NOT NULL,
                error TEXT,
                PRIMARY KEY (cache_key, resource_id)
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resource_links (
                cache_key TEXT NOT NULL,
                parent_resource_id TEXT NOT NULL,
                child_resource_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                position INTEGER NOT NULL,
                PRIMARY KEY (cache_key, parent_resource_id, child_resource_id, relation)
            )
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> ResponseCache:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @staticmethod
    def key(target: str, mode: str, proxy: str | None, tls_identity: str | None = None) -> str:
        return "|".join([target, mode, proxy or "", tls_identity or "", FETCH_PROFILE_VERSION])

    def get(
        self,
        target: str,
        mode: str,
        proxy: str | None,
        ttl: int,
        tls_identity: str | None = None,
    ) -> FetchResult | None:
        key = self.key(target, mode, proxy, tls_identity)
        row = self.conn.execute(
            """
            SELECT
                primary_resource_id, browser_globals_json, updated_at
            FROM fetches
            WHERE cache_key = ?
            """,
            (key,),
        ).fetchone()
        if not row:
            return None

        (
            primary_resource_id,
            browser_globals_json,
            updated_at,
        ) = row
        if ttl >= 0 and int(time.time()) - int(updated_at) > ttl:
            return None

        resource_rows = self.conn.execute(
            """
            SELECT
                resource_id, parent_id, kind, url, final_url, status,
                headers_json, cookies_json, body, error
            FROM resources
            WHERE cache_key = ?
            ORDER BY resource_id
            """,
            (key,),
        ).fetchall()
        resources = [
            ResourceObservation(
                id=resource_id,
                parent_id=parent_id,
                kind=kind,
                url=url,
                final_url=final_url,
                status=status,
                headers=json.loads(headers_json),
                cookies=json.loads(cookies_json),
                body=body,
                error=error,
            )
            for (
                resource_id,
                parent_id,
                kind,
                url,
                final_url,
                status,
                headers_json,
                cookies_json,
                body,
                error,
            ) in resource_rows
        ]
        primary = next(
            (resource for resource in resources if resource.id == primary_resource_id),
            resources[0] if resources else None,
        )
        if primary is None:
            return None
        script_srcs = [resource.url for resource in resources if resource.kind == "script"]
        return FetchResult(
            input=target,
            url=primary.url,
            final_url=primary.final_url,
            status=primary.status,
            headers=primary.headers,
            cookies=primary.cookies,
            body=primary.body,
            mode=mode,
            error=primary.error,
            browser_globals=json.loads(browser_globals_json),
            script_srcs=script_srcs,
            resources=resources,
            primary_resource_id=primary_resource_id,
            cached=True,
        )

    def set(
        self,
        target: str,
        mode: str,
        proxy: str | None,
        fetch: FetchResult,
        tls_identity: str | None = None,
    ) -> None:
        now = int(time.time())
        key = self.key(target, mode, proxy, tls_identity)
        primary = fetch.primary_resource
        resources = fetch.resources or [primary]
        self.conn.execute(
            """
            INSERT INTO fetches (
                cache_key, target, mode, proxy, profile_version, primary_resource_id,
                browser_globals_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                target = excluded.target,
                mode = excluded.mode,
                proxy = excluded.proxy,
                profile_version = excluded.profile_version,
                primary_resource_id = excluded.primary_resource_id,
                browser_globals_json = excluded.browser_globals_json,
                updated_at = excluded.updated_at
            """,
            (
                key,
                target,
                mode,
                proxy,
                FETCH_PROFILE_VERSION,
                primary.id,
                json.dumps(fetch.browser_globals),
                now,
                now,
            ),
        )
        self.conn.execute("DELETE FROM resource_links WHERE cache_key = ?", (key,))
        self.conn.execute("DELETE FROM resources WHERE cache_key = ?", (key,))
        for resource in resources:
            self.conn.execute(
                """
                INSERT INTO resources (
                    cache_key, resource_id, parent_id, kind, url, final_url, status,
                    headers_json, cookies_json, body, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    resource.id,
                    resource.parent_id,
                    resource.kind,
                    resource.url,
                    resource.final_url,
                    resource.status,
                    json.dumps(resource.headers, sort_keys=True),
                    json.dumps(resource.cookies, sort_keys=True),
                    resource.body,
                    resource.error,
                ),
            )
        for index, resource in enumerate(resources):
            if resource.parent_id:
                self.conn.execute(
                    """
                    INSERT INTO resource_links (
                        cache_key, parent_resource_id, child_resource_id, relation, position
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (key, resource.parent_id, resource.id, resource.kind, index),
                )
        self.conn.commit()


ResultCache = ResponseCache
