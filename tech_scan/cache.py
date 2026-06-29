from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .models import FetchResult


FETCH_PROFILE_VERSION = "v2"


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
            CREATE TABLE IF NOT EXISTS fetch_observations (
                cache_key TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                proxy TEXT,
                profile_version TEXT NOT NULL,
                requested_url TEXT NOT NULL,
                final_url TEXT,
                status INTEGER,
                headers_json TEXT NOT NULL,
                cookies_json TEXT NOT NULL,
                body TEXT NOT NULL,
                browser_globals_json TEXT NOT NULL,
                script_srcs_json TEXT NOT NULL,
                error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
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
    def key(target: str, mode: str, proxy: str | None) -> str:
        return "|".join([target, mode, proxy or "", FETCH_PROFILE_VERSION])

    def get(self, target: str, mode: str, proxy: str | None, ttl: int) -> FetchResult | None:
        key = self.key(target, mode, proxy)
        row = self.conn.execute(
            """
            SELECT
                requested_url, final_url, status, headers_json, cookies_json, body,
                browser_globals_json, script_srcs_json, error, updated_at
            FROM fetch_observations
            WHERE cache_key = ?
            """,
            (key,),
        ).fetchone()
        if not row:
            return None

        (
            requested_url,
            final_url,
            status,
            headers_json,
            cookies_json,
            body,
            browser_globals_json,
            script_srcs_json,
            error,
            updated_at,
        ) = row
        if ttl >= 0 and int(time.time()) - int(updated_at) > ttl:
            return None

        return FetchResult(
            input=target,
            url=requested_url,
            final_url=final_url,
            status=status,
            headers=json.loads(headers_json),
            cookies=json.loads(cookies_json),
            body=body,
            mode=mode,
            error=error,
            browser_globals=json.loads(browser_globals_json),
            script_srcs=json.loads(script_srcs_json),
            cached=True,
        )

    def set(self, target: str, mode: str, proxy: str | None, fetch: FetchResult) -> None:
        now = int(time.time())
        key = self.key(target, mode, proxy)
        self.conn.execute(
            """
            INSERT INTO fetch_observations (
                cache_key, target, mode, proxy, profile_version, requested_url,
                final_url, status, headers_json, cookies_json, body,
                browser_globals_json, script_srcs_json, error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                requested_url = excluded.requested_url,
                final_url = excluded.final_url,
                status = excluded.status,
                headers_json = excluded.headers_json,
                cookies_json = excluded.cookies_json,
                body = excluded.body,
                browser_globals_json = excluded.browser_globals_json,
                script_srcs_json = excluded.script_srcs_json,
                error = excluded.error,
                updated_at = excluded.updated_at
            """,
            (
                key,
                target,
                mode,
                proxy,
                FETCH_PROFILE_VERSION,
                fetch.url,
                fetch.final_url,
                fetch.status,
                json.dumps(fetch.headers, sort_keys=True),
                json.dumps(fetch.cookies, sort_keys=True),
                fetch.body,
                json.dumps(fetch.browser_globals),
                json.dumps(fetch.script_srcs),
                fetch.error,
                now,
                now,
            ),
        )
        self.conn.commit()


ResultCache = ResponseCache
