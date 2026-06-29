"""
crucible.actor_profiles
=======================

SQLite-backed actor / campaign profiles modelled on standard CTI-firm
attribution practice (MISP, MITRE ATT&CK Groups, Mandiant). A profile
aggregates evidence over time and carries the metadata an analyst expects
to keep on an attribution-target: aliases, motivation, origin, target
sectors, first/last-seen, references, and a structured evidence timeline.

Schema
------
    actor_profiles
        id              PK (kebab-slug, generated from name if not given)
        name            primary display name
        aliases         JSON list of other names this actor goes by
        notes           markdown free-form analyst notes
        severity        'critical' | 'high' | 'medium' | 'low' | ''
        tags            JSON list of free-form tags
        motivation      'state-sponsored' | 'financial' | 'hacktivism'
                        | 'ideological' | 'unknown' | '' | (free text)
        origin_country  ISO-2 / free text
        first_seen      ISO date (best-effort)
        last_seen       ISO date (best-effort)
        targets         JSON list of {sector, region, org} strings
        created_at      ISO-8601 UTC
        updated_at      ISO-8601 UTC

    actor_evidence
        id              PK
        profile_id      FK -> actor_profiles.id (ON DELETE CASCADE)
        evidence        JSON blob
        source          'finding' | 'hunt_match' | 'manual' | etc.
        source_seed     the domain/IP this evidence was observed against
        seen_at         ISO-8601 UTC
        category        'ioc' | 'ttp' | 'infra' | 'tooling' | 'human'
                        | 'news' | 'misc' | ''
        confidence      'high' | 'medium' | 'low' | ''
        tags            JSON list of analyst tags

    actor_references
        id              PK
        profile_id      FK -> actor_profiles.id (ON DELETE CASCADE)
        title           short label
        url             external link (Mandiant report, blog, tweet, MITRE)
        source          'vendor-report' | 'news' | 'social' | 'mitre'
                        | 'misc' | (free text)
        notes           one-liner about why this reference matters
        added_at        ISO-8601 UTC

Public surface
--------------
    init_db()
    create_profile(name, **fields) → id
    list_profiles() → [dict, ...]
    get_profile(id) → {profile, evidence:[...], references:[...]} | None
    update_profile(id, **fields)
    delete_profile(id)
    attribute_evidence(profile_id, evidence, source, source_seed,
                       category, confidence, tags) → id
    detach_evidence(evidence_id)
    list_references(profile_id) → [dict, ...]
    add_reference(profile_id, title, url, source='', notes='') → id
    delete_reference(reference_id)
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sqlite3
from contextlib import contextmanager


_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "crucible_actors.sqlite",
)
os.makedirs(os.path.dirname(_DEFAULT_PATH), exist_ok=True)
DB_PATH = os.environ.get("CRUCIBLE_ACTORS_DB", _DEFAULT_PATH)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS actor_profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    aliases         TEXT NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    motivation      TEXT NOT NULL DEFAULT '',
    origin_country  TEXT NOT NULL DEFAULT '',
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    targets         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id   TEXT NOT NULL REFERENCES actor_profiles(id) ON DELETE CASCADE,
    evidence     TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'manual',
    source_seed  TEXT NOT NULL DEFAULT '',
    seen_at      TEXT NOT NULL,
    category     TEXT NOT NULL DEFAULT '',
    confidence   TEXT NOT NULL DEFAULT '',
    tags         TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS actor_references (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id  TEXT NOT NULL REFERENCES actor_profiles(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    url         TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    added_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_profile  ON actor_evidence(profile_id);
CREATE INDEX IF NOT EXISTS idx_evidence_seen     ON actor_evidence(seen_at);
CREATE INDEX IF NOT EXISTS idx_references_profile ON actor_references(profile_id);
"""

# Idempotent migration map — columns that may need to be added on
# existing DBs created before the schema grew. Each tuple is
# (table, column, sqlite_type_with_default).
_MIGRATIONS = [
    ("actor_profiles", "aliases",        "TEXT NOT NULL DEFAULT '[]'"),
    ("actor_profiles", "motivation",     "TEXT NOT NULL DEFAULT ''"),
    ("actor_profiles", "origin_country", "TEXT NOT NULL DEFAULT ''"),
    ("actor_profiles", "first_seen",     "TEXT NOT NULL DEFAULT ''"),
    ("actor_profiles", "last_seen",      "TEXT NOT NULL DEFAULT ''"),
    ("actor_profiles", "targets",        "TEXT NOT NULL DEFAULT '[]'"),
    ("actor_evidence", "category",       "TEXT NOT NULL DEFAULT ''"),
    ("actor_evidence", "confidence",     "TEXT NOT NULL DEFAULT ''"),
    ("actor_evidence", "tags",           "TEXT NOT NULL DEFAULT '[]'"),
]


def _columns(c: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in c.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10.0)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA foreign_keys = ON")
        yield c
    finally:
        c.close()


def init_db() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA)
        # Run additive migrations for any older DB that doesn't yet
        # have the newer columns. ADD COLUMN is idempotent-via-guard:
        # check pragma first to keep the call sqlite-safe.
        for table, col, decl in _MIGRATIONS:
            if col not in _columns(c, table):
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except sqlite3.OperationalError:
                    pass


# ── Profiles ──────────────────────────────────────────────────────────

def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s or "actor"


def _unique_id(base_slug: str) -> str:
    with _conn() as c:
        if not c.execute(
            "SELECT 1 FROM actor_profiles WHERE id = ?", (base_slug,)
        ).fetchone():
            return base_slug
        n = 2
        while c.execute(
            "SELECT 1 FROM actor_profiles WHERE id = ?", (f"{base_slug}-{n}",)
        ).fetchone():
            n += 1
        return f"{base_slug}-{n}"


def _coerce_list(v) -> list:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        # Accept comma- or newline-separated strings from form inputs.
        return [s.strip() for s in re.split(r"[,\n]", v) if s.strip()]
    return []


def create_profile(name: str, *,
                   aliases: list | str | None = None,
                   notes: str = "",
                   severity: str = "",
                   tags: list | str | None = None,
                   motivation: str = "",
                   origin_country: str = "",
                   first_seen: str = "",
                   last_seen: str = "",
                   targets: list | str | None = None,
                   profile_id: str | None = None) -> str:
    if not name or not name.strip():
        raise ValueError("name is required")
    init_db()
    pid = profile_id or _unique_id(_slugify(name))
    now = _now()
    with _conn() as c:
        c.execute(
            "INSERT INTO actor_profiles "
            "(id, name, aliases, notes, severity, tags, motivation, "
            " origin_country, first_seen, last_seen, targets, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (pid, name.strip(),
             json.dumps(_coerce_list(aliases)),
             notes or "", severity or "",
             json.dumps(_coerce_list(tags)),
             motivation or "", origin_country or "",
             first_seen or "", last_seen or "",
             json.dumps(_coerce_list(targets)),
             now, now),
        )
    return pid


def _row_to_profile(row: sqlite3.Row) -> dict:
    keys = row.keys()
    def jget(field: str, default):
        return json.loads(row[field] or default) if field in keys else json.loads(default)
    def sget(field: str, default=""):
        return (row[field] if field in keys else default) or default
    return {
        "id":             row["id"],
        "name":           row["name"],
        "aliases":        jget("aliases", "[]"),
        "notes":          row["notes"],
        "severity":       row["severity"],
        "tags":           jget("tags", "[]"),
        "motivation":     sget("motivation"),
        "origin_country": sget("origin_country"),
        "first_seen":     sget("first_seen"),
        "last_seen":      sget("last_seen"),
        "targets":        jget("targets", "[]"),
        "created_at":     row["created_at"],
        "updated_at":     row["updated_at"],
    }


def list_profiles() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT p.*, "
            " (SELECT COUNT(*) FROM actor_evidence e "
            "  WHERE e.profile_id = p.id) AS evidence_count, "
            " (SELECT MAX(seen_at) FROM actor_evidence e "
            "  WHERE e.profile_id = p.id) AS last_evidence_at, "
            " (SELECT COUNT(*) FROM actor_references r "
            "  WHERE r.profile_id = p.id) AS reference_count "
            "FROM actor_profiles p ORDER BY updated_at DESC"
        ).fetchall()
    out = []
    for r in rows:
        p = _row_to_profile(r)
        p["evidence_count"]   = int(r["evidence_count"] or 0)
        p["last_evidence_at"] = r["last_evidence_at"] or ""
        p["reference_count"]  = int(r["reference_count"] or 0)
        out.append(p)
    return out


def get_profile(profile_id: str) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM actor_profiles WHERE id = ?", (profile_id,)
        ).fetchone()
        if not row:
            return None
        evidence = [
            {
                "id":           int(e["id"]),
                "evidence":     json.loads(e["evidence"]),
                "source":       e["source"],
                "source_seed":  e["source_seed"],
                "seen_at":      e["seen_at"],
                "category":     e["category"] if "category" in e.keys() else "",
                "confidence":   e["confidence"] if "confidence" in e.keys() else "",
                "tags":         json.loads(e["tags"] or "[]") if "tags" in e.keys() else [],
            }
            for e in c.execute(
                "SELECT * FROM actor_evidence WHERE profile_id = ? "
                "ORDER BY seen_at DESC",
                (profile_id,),
            ).fetchall()
        ]
        references = [
            {
                "id":       int(r["id"]),
                "title":    r["title"],
                "url":      r["url"],
                "source":   r["source"],
                "notes":    r["notes"],
                "added_at": r["added_at"],
            }
            for r in c.execute(
                "SELECT * FROM actor_references WHERE profile_id = ? "
                "ORDER BY added_at DESC",
                (profile_id,),
            ).fetchall()
        ]
    p = _row_to_profile(row)
    p["evidence"]        = evidence
    p["evidence_count"]  = len(evidence)
    p["references"]      = references
    p["reference_count"] = len(references)
    return p


_UPDATABLE = {
    "name", "aliases", "notes", "severity", "tags",
    "motivation", "origin_country", "first_seen", "last_seen", "targets",
}


def update_profile(profile_id: str, **fields) -> bool:
    bad = set(fields) - _UPDATABLE
    if bad:
        raise ValueError(f"non-updatable fields: {sorted(bad)}")
    if not fields:
        return False
    # Coerce list-shaped fields stored as JSON.
    for k in ("aliases", "tags", "targets"):
        if k in fields:
            fields[k] = json.dumps(_coerce_list(fields[k]))
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [profile_id]
    with _conn() as c:
        cur = c.execute(
            f"UPDATE actor_profiles SET {sets} WHERE id = ?", values
        )
        return cur.rowcount > 0


def delete_profile(profile_id: str) -> bool:
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM actor_profiles WHERE id = ?", (profile_id,)
        )
        return cur.rowcount > 0


# ── Evidence ──────────────────────────────────────────────────────────

_VALID_CATEGORIES = {"ioc", "ttp", "infra", "tooling",
                     "human", "news", "misc", ""}
_VALID_CONFIDENCE = {"high", "medium", "low", ""}


def attribute_evidence(profile_id: str, evidence: dict,
                       source: str = "manual",
                       source_seed: str = "",
                       category: str = "",
                       confidence: str = "",
                       tags: list | str | None = None) -> int:
    init_db()
    category = (category or "").lower().strip()
    if category not in _VALID_CATEGORIES:
        category = "misc"
    confidence = (confidence or "").lower().strip()
    if confidence not in _VALID_CONFIDENCE:
        confidence = ""
    payload = json.dumps(evidence or {}, default=str)
    now = _now()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO actor_evidence (profile_id, evidence, source, "
            "source_seed, seen_at, category, confidence, tags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (profile_id, payload, source or "manual",
             source_seed or "", now,
             category, confidence,
             json.dumps(_coerce_list(tags))),
        )
        c.execute(
            "UPDATE actor_profiles SET updated_at = ? WHERE id = ?",
            (now, profile_id),
        )
        return int(cur.lastrowid)


def detach_evidence(evidence_id: int) -> bool:
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM actor_evidence WHERE id = ?", (int(evidence_id),)
        )
        return cur.rowcount > 0


# ── References ────────────────────────────────────────────────────────

def add_reference(profile_id: str, title: str, url: str,
                  source: str = "", notes: str = "") -> int:
    if not title or not title.strip():
        raise ValueError("title is required")
    if not url or not url.strip():
        raise ValueError("url is required")
    init_db()
    now = _now()
    with _conn() as c:
        # Make sure parent profile exists so we get a clean 404 rather
        # than a foreign-key crash.
        if not c.execute(
            "SELECT 1 FROM actor_profiles WHERE id = ?", (profile_id,)
        ).fetchone():
            raise ValueError(f"profile not found: {profile_id}")
        cur = c.execute(
            "INSERT INTO actor_references (profile_id, title, url, "
            "source, notes, added_at) VALUES (?, ?, ?, ?, ?, ?)",
            (profile_id, title.strip(), url.strip(),
             (source or "").strip(), (notes or "").strip(), now),
        )
        c.execute(
            "UPDATE actor_profiles SET updated_at = ? WHERE id = ?",
            (now, profile_id),
        )
        return int(cur.lastrowid)


def list_references(profile_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM actor_references WHERE profile_id = ? "
            "ORDER BY added_at DESC",
            (profile_id,),
        ).fetchall()
    return [
        {
            "id":       int(r["id"]),
            "title":    r["title"],
            "url":      r["url"],
            "source":   r["source"],
            "notes":    r["notes"],
            "added_at": r["added_at"],
        }
        for r in rows
    ]


def delete_reference(reference_id: int) -> bool:
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM actor_references WHERE id = ?", (int(reference_id),)
        )
        return cur.rowcount > 0
