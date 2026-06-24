"""
SQLite-backed TTL cache for Crucible.

Two tables, both keyed for cheap fast lookups by a single composite key:

  pipeline_result_cache  → full per-seed standard-pipeline result dict.
                           Hit when re-running the same seed under the same
                           settings profile within TTL → saves the 30+ external
                           API calls a fresh pipeline run would have made.

  api_call_cache         → per-source / per-query response payloads for
                           individually expensive external calls (Shodan,
                           VirusTotal, urlscan, CT lookups, etc.) so the
                           savings apply even when the pipeline result itself
                           is stale.

The cache is opportunistic: a cache miss (or read error) always falls back to
a live fetch. A write failure never breaks the request.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

# Cache lives in <project root>/data/ — sibling of src/. mkdir-on-import so
# a fresh checkout (or fresh `data/` after .gitignore tightening) doesn't
# trip the connect() with a missing-directory error.
_DATA_DIR = Path(__file__).parent.parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = _DATA_DIR / "crucible_cache.sqlite"
_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_result_cache (
    seed         TEXT NOT NULL,
    settings_key TEXT NOT NULL,
    completed_at INTEGER NOT NULL,
    result_json  TEXT NOT NULL,
    PRIMARY KEY (seed, settings_key)
);
CREATE INDEX IF NOT EXISTS idx_pipeline_completed_at
    ON pipeline_result_cache(completed_at);

CREATE TABLE IF NOT EXISTS api_call_cache (
    source        TEXT NOT NULL,
    query         TEXT NOT NULL,
    fetched_at    INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    PRIMARY KEY (source, query)
);
CREATE INDEX IF NOT EXISTS idx_api_call_fetched_at
    ON api_call_cache(fetched_at);
"""


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(str(_DB_PATH), isolation_level=None)


def _init() -> None:
    with _lock, _conn() as c:
        c.executescript(_SCHEMA)


_init()


def settings_key(ct_sources: set | list | None, features: set | list | None) -> str:
    """Stable hash of the CT-source + feature toggle profile, used as part of the
    cache key so a result fetched with one settings profile is never reused for
    a stricter / looser one."""
    def _norm(x):
        return sorted({s.strip().lower() for s in (x or []) if s and s.strip()})
    payload = json.dumps({"ct": _norm(ct_sources), "feat": _norm(features)})
    return hashlib.sha1(payload.encode()).hexdigest()[:16]


def get_pipeline_result(seed: str, settings_hash: str, max_age_hours: float) -> dict | None:
    cutoff = int(time.time()) - int(max_age_hours * 3600)
    seed_norm = seed.lower().strip()
    try:
        with _lock, _conn() as c:
            row = c.execute(
                "SELECT result_json, completed_at FROM pipeline_result_cache "
                "WHERE seed = ? AND settings_key = ? AND completed_at >= ?",
                (seed_norm, settings_hash, cutoff),
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    try:
        result = json.loads(row[0])
        result["_cache_hit"] = True
        result["_cached_at"] = row[1]
        return result
    except Exception:
        return None


def put_pipeline_result(seed: str, settings_hash: str, result: dict) -> None:
    if not result or result.get("_cache_hit"):
        return  # don't re-write a cache-hit result back into cache
    try:
        payload = json.dumps(result, default=str)
        with _lock, _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO pipeline_result_cache "
                "(seed, settings_key, completed_at, result_json) VALUES (?,?,?,?)",
                (seed.lower().strip(), settings_hash, int(time.time()), payload),
            )
    except Exception:
        pass  # cache write failures must never fail the actual request


async def cached_api_call(source: str, query: str, max_age_hours: float,
                          fetch_fn: Callable[[], Awaitable[Any]]) -> Any:
    """Wrap an async fetcher with a SQLite TTL cache.

    Use only for the heavy paid / rate-limited sources (Shodan, VT, urlscan,
    CT). Cheap unauthenticated calls (DoH, freeipapi) shouldn't go through
    here — the SQLite hop costs more than the call."""
    cutoff = int(time.time()) - int(max_age_hours * 3600)
    try:
        with _lock, _conn() as c:
            row = c.execute(
                "SELECT response_json FROM api_call_cache "
                "WHERE source = ? AND query = ? AND fetched_at >= ?",
                (source, query, cutoff),
            ).fetchone()
        if row:
            return json.loads(row[0])
    except Exception:
        pass  # fall through to a live fetch

    result = await fetch_fn()
    try:
        payload = json.dumps(result, default=str)
        with _lock, _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO api_call_cache "
                "(source, query, fetched_at, response_json) VALUES (?,?,?,?)",
                (source, query, int(time.time()), payload),
            )
    except Exception:
        pass
    return result


def stats() -> dict:
    try:
        with _lock, _conn() as c:
            n_pipe = c.execute("SELECT COUNT(*) FROM pipeline_result_cache").fetchone()[0]
            n_api  = c.execute("SELECT COUNT(*) FROM api_call_cache").fetchone()[0]
            newest_pipe = c.execute(
                "SELECT MAX(completed_at) FROM pipeline_result_cache").fetchone()[0]
            newest_api = c.execute(
                "SELECT MAX(fetched_at) FROM api_call_cache").fetchone()[0]
    except Exception as e:
        return {"error": str(e)}
    return {
        "pipeline_results_cached": n_pipe,
        "api_calls_cached": n_api,
        "newest_pipeline_at": newest_pipe,
        "newest_api_call_at": newest_api,
    }


def purge_older_than(hours: float) -> dict:
    """Drop entries older than `hours`. Use to keep the SQLite file from
    ballooning over months of use."""
    cutoff = int(time.time()) - int(hours * 3600)
    try:
        with _lock, _conn() as c:
            n1 = c.execute(
                "DELETE FROM pipeline_result_cache WHERE completed_at < ?",
                (cutoff,),
            ).rowcount
            n2 = c.execute(
                "DELETE FROM api_call_cache WHERE fetched_at < ?",
                (cutoff,),
            ).rowcount
            c.execute("VACUUM")
    except Exception as e:
        return {"error": str(e)}
    return {"pipeline_results_purged": n1, "api_calls_purged": n2}
