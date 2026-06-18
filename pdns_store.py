"""
crucible.pdns_store
===================

SQLite-backed self-tracking passive-DNS index. Every Crucible scan inserts the
(domain, ip, source, observed_at) tuples it observed into a local store; future
scans can then surface "we ourselves observed this IP at these times" alongside
external sources (VT / OTX / CIRCL / Mnemonic / live DNS / URLScan).

Why
---
External passive-DNS feeds have coverage gaps — Cloudflare-Universal-SSL hosts
often don't surface in any CT log, and free-tier passive-DNS sources rarely
return a `last_seen` timestamp for them. Self-tracking compounds value over
time: every scan you run becomes a passive-DNS sensor for itself, building
your private history of the domains and infrastructure you care about.

Schema
------
    pdns_observations
        id           PK
        domain       lowercased
        ip
        record_type  A / AAAA / etc. (uppercase, optional)
        source       'dns_current' | 'virustotal' | 'urlscan' | 'otx_pdns'
                     | 'circl_pdns' | 'mnemonic_pdns' | … or custom
        observed_at  ISO-8601 UTC ("YYYY-MM-DDTHH:MM:SSZ")
        scan_id      FK -> scan_runs.scan_id (nullable for bulk imports)
        UNIQUE(domain, ip, source, observed_at)   ← idempotent inserts

    scan_runs
        scan_id      uuid hex
        seed         the seed input the scan was launched with
        started_at   ISO-8601 UTC
        completed_at ISO-8601 UTC (null while scan in flight)

Both tables are created on first call via `init_db()` — no manual migration
required. Path is configurable via the CRUCIBLE_PDNS_DB env var; default is
a sibling of this module file.

Public surface (everything else is private)
-------------------------------------------
    init_db()
    start_scan(seed)              → scan_id
    finish_scan(scan_id)
    record_observations(scan_id, domain, [{ip, source, observed_at?,
                                            record_type?}])  → inserted count
    query_domain_history(domain)  → [{ip, first_observed, last_observed,
                                       sources, scan_count}]
    query_scans_for_seed(seed, limit=50)
    query_scan_state(scan_id)     → full state for the diff engine
"""

from __future__ import annotations

import datetime as _dt
import os
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Iterable, Optional


_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "crucible_pdns.sqlite",
)
DB_PATH = os.environ.get("CRUCIBLE_PDNS_DB", _DEFAULT_PATH)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pdns_observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    ip           TEXT NOT NULL,
    record_type  TEXT,
    source       TEXT NOT NULL,
    observed_at  TEXT NOT NULL,
    scan_id      TEXT,
    UNIQUE(domain, ip, source, observed_at)
);
CREATE INDEX IF NOT EXISTS idx_obs_domain ON pdns_observations(domain);
CREATE INDEX IF NOT EXISTS idx_obs_ip     ON pdns_observations(ip);
CREATE INDEX IF NOT EXISTS idx_obs_scan   ON pdns_observations(scan_id);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id      TEXT PRIMARY KEY,
    seed         TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_run_seed ON scan_runs(seed);
"""


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    try:
        # WAL keeps reads non-blocking during concurrent scans.
        conn.execute("PRAGMA journal_mode = WAL;")
        yield conn
    finally:
        conn.close()


_INITIALISED = False


def init_db() -> None:
    """Create tables if missing. Idempotent — cheap to call on every operation."""
    global _INITIALISED
    if _INITIALISED:
        return
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()
    _INITIALISED = True


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

def start_scan(seed: str) -> str:
    """Open a new scan_run row and return its scan_id."""
    init_db()
    sid = uuid.uuid4().hex
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scan_runs (scan_id, seed, started_at) VALUES (?, ?, ?)",
            (sid, (seed or "").lower(), _iso_now()),
        )
        conn.commit()
    return sid


def finish_scan(scan_id: str) -> None:
    """Mark a scan_run as completed. Safe to call multiple times (overwrites
    completed_at) — useful if the pipeline retries or backfills."""
    if not scan_id:
        return
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_runs SET completed_at = ? WHERE scan_id = ?",
            (_iso_now(), scan_id),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Observation recording
# ---------------------------------------------------------------------------

def record_observations(
    scan_id: str,
    domain: str,
    observations: Iterable[dict],
) -> int:
    """Insert observations for a (scan, domain). Idempotent on the UNIQUE
    constraint — re-inserting the same (domain, ip, source, observed_at) is a
    no-op. Returns the number of rows actually inserted (post-dedup)."""
    if not observations or not domain:
        return 0
    init_db()
    domain_lc = domain.lower()
    fallback_ts = _iso_now()
    rows = []
    for o in observations:
        ip = (o.get("ip") or "").strip()
        if not ip:
            continue
        rows.append((
            domain_lc,
            ip,
            ((o.get("record_type") or "").upper() or None),
            (o.get("source") or "unknown"),
            (o.get("observed_at") or fallback_ts),
            scan_id or None,
        ))
    if not rows:
        return 0
    with _connect() as conn:
        cur = conn.executemany(
            """INSERT OR IGNORE INTO pdns_observations
                   (domain, ip, record_type, source, observed_at, scan_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        conn.commit()
        return cur.rowcount


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def query_domain_history(domain: str) -> list:
    """Aggregated per-IP history for a domain across every scan ever recorded.

    Returns rows of:
        {ip, first_observed, last_observed, sources, scan_count}
    sorted by last_observed (newest first)."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT ip,
                      MIN(observed_at) AS first_observed,
                      MAX(observed_at) AS last_observed,
                      GROUP_CONCAT(DISTINCT source) AS sources,
                      COUNT(DISTINCT scan_id) AS scan_count
                 FROM pdns_observations
                 WHERE domain = ?
                 GROUP BY ip
                 ORDER BY MAX(observed_at) DESC""",
            ((domain or "").lower(),),
        ).fetchall()
    return [
        {
            "ip": r[0],
            "first_observed": r[1],
            "last_observed": r[2],
            "sources": sorted((r[3] or "").split(",")) if r[3] else [],
            "scan_count": r[4],
        }
        for r in rows
    ]


def query_scans_for_seed(seed: str, limit: int = 50) -> list:
    """Most recent scans of `seed`, newest first."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT scan_id, seed, started_at, completed_at
                 FROM scan_runs
                 WHERE seed = ?
                 ORDER BY started_at DESC
                 LIMIT ?""",
            ((seed or "").lower(), limit),
        ).fetchall()
    return [
        {"scan_id": r[0], "seed": r[1],
         "started_at": r[2], "completed_at": r[3]}
        for r in rows
    ]


def query_scan_state(scan_id: str) -> Optional[dict]:
    """Snapshot of everything one scan recorded — used by the diff engine."""
    if not scan_id:
        return None
    init_db()
    with _connect() as conn:
        run = conn.execute(
            """SELECT seed, started_at, completed_at
                 FROM scan_runs WHERE scan_id = ?""",
            (scan_id,),
        ).fetchone()
        if not run:
            return None
        obs = conn.execute(
            """SELECT ip, record_type, source, observed_at
                 FROM pdns_observations
                 WHERE scan_id = ?
                 ORDER BY ip, source""",
            (scan_id,),
        ).fetchall()
    return {
        "scan_id": scan_id,
        "seed": run[0],
        "started_at": run[1],
        "completed_at": run[2],
        "observations": [
            {"ip": o[0], "record_type": o[1],
             "source": o[2], "observed_at": o[3]}
            for o in obs
        ],
    }
