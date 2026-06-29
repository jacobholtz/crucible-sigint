"""
crucible.hunt_rules
===================

YARA-style composite rule engine for hunting new actor infrastructure
across CertStream / crt.sh polling / GTI Livehunt notifications.

A rule is a JSON document with two top-level keys: `meta` (free-form, used
for GTI Livehunt export) and `condition`. The condition is a tree of
nodes:

    {"and":  [<node>, <node>, ...]}
    {"or":   [<node>, <node>, ...]}
    {"not":  <node>}

Or a leaf predicate:

    {"field": "host",     "op": "regex",         "value": "^secure\\w+example\\."}
    {"field": "issuer",   "op": "icontains",     "value": "Let's Encrypt"}
    {"field": "registrar","op": "equals_ci",     "value": "EXAMPLE REGISTRAR"}
    {"field": "creation", "op": "after",         "value": "2026-01-01"}
    {"field": "creation", "op": "before",        "value": "2026-12-31"}
    {"field": "host",     "op": "endswith_ci",   "value": ".workers.dev"}
    {"field": "all_sans", "op": "any_regex",     "value": "phishing"}

Supported fields (set by the caller from CertStream/crt.sh/GTI payloads):
    host, all_sans (list[str]), issuer, registrar, creation, ns,
    record_type, source

Supported ops:
    regex, icontains, equals, equals_ci, startswith_ci, endswith_ci,
    in (value is list), after / before (ISO date), any_regex (against
    a list-valued field)

Evaluator returns (matched: bool, matched_evidence: dict). The evidence
captures which predicates fired and the candidate values they fired on,
so analysts can see *why* a rule matched in the Slack alert and the queue.

Schema
------
    hunt_rules
        id            INTEGER PK
        name          TEXT
        description   TEXT
        rule_json     TEXT (the full rule document)
        profile_id    TEXT  (nullable; FK by convention to actor_profiles)
        enabled       INTEGER (0/1)
        created_at    TEXT
        last_fired_at TEXT
        fire_count    INTEGER

    hunt_matches
        id            INTEGER PK
        rule_id       INTEGER FK -> hunt_rules.id (ON DELETE CASCADE)
        matched_value TEXT  (the host/domain that matched)
        evidence      TEXT  (JSON — what the evaluator captured)
        payload       TEXT  (JSON — the full CertStream/crtsh/GTI payload)
        source        TEXT  ('certstream' | 'crtsh' | 'gti_livehunt')
        seen_at       TEXT
        review_status TEXT  ('pending' | 'accepted' | 'rejected')
        reviewed_at   TEXT
        UNIQUE(rule_id, matched_value)   -- dedupe matches per rule

Public surface
--------------
    init_db()
    create_rule(name, condition, meta=None, profile_id=None, ...)
    list_rules(enabled_only=False)
    get_rule(id)
    update_rule(id, **fields)
    delete_rule(id)
    set_enabled(id, enabled)
    evaluate_rule(rule, candidate) → (matched, evidence)
    record_match(rule_id, matched_value, evidence, payload, source)
    list_matches(rule_id=None, status=None, limit=200)
    update_match_status(match_id, status)
    livehunt_yaml(rule) → str   (GTI Livehunt dnsHunt YAML)
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
    "crucible_hunts.sqlite",
)
os.makedirs(os.path.dirname(_DEFAULT_PATH), exist_ok=True)
DB_PATH = os.environ.get("CRUCIBLE_HUNTS_DB", _DEFAULT_PATH)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunt_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    rule_json     TEXT NOT NULL,
    profile_id    TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_fired_at TEXT,
    fire_count    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hunt_matches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       INTEGER NOT NULL REFERENCES hunt_rules(id) ON DELETE CASCADE,
    matched_value TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    payload       TEXT NOT NULL,
    source        TEXT NOT NULL,
    seen_at       TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'pending',
    reviewed_at   TEXT,
    UNIQUE(rule_id, matched_value)
);

CREATE INDEX IF NOT EXISTS idx_matches_status ON hunt_matches(review_status);
CREATE INDEX IF NOT EXISTS idx_matches_rule   ON hunt_matches(rule_id);
"""


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


# ── Evaluator ──────────────────────────────────────────────────────────

_VALID_OPS = {
    "regex", "icontains", "equals", "equals_ci",
    "startswith_ci", "endswith_ci", "in",
    "after", "before", "any_regex",
}
_VALID_FIELDS = {
    "host", "all_sans", "issuer", "registrar",
    "creation", "ns", "record_type", "source",
}


def validate_rule(rule: dict) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: list[str] = []
    if not isinstance(rule, dict):
        return ["rule must be a JSON object"]
    cond = rule.get("condition")
    if cond is None:
        return ["rule.condition is required"]
    errors.extend(_validate_node(cond, path="condition"))
    return errors


def _validate_node(node, path: str) -> list[str]:
    if not isinstance(node, dict):
        return [f"{path}: must be an object"]
    errs: list[str] = []
    if "and" in node:
        if not isinstance(node["and"], list) or not node["and"]:
            errs.append(f"{path}.and: must be a non-empty list")
        else:
            for i, child in enumerate(node["and"]):
                errs.extend(_validate_node(child, f"{path}.and[{i}]"))
        return errs
    if "or" in node:
        if not isinstance(node["or"], list) or not node["or"]:
            errs.append(f"{path}.or: must be a non-empty list")
        else:
            for i, child in enumerate(node["or"]):
                errs.extend(_validate_node(child, f"{path}.or[{i}]"))
        return errs
    if "not" in node:
        errs.extend(_validate_node(node["not"], f"{path}.not"))
        return errs
    # Leaf
    field = node.get("field")
    op = node.get("op")
    if field not in _VALID_FIELDS:
        errs.append(f"{path}: field must be one of {sorted(_VALID_FIELDS)}")
    if op not in _VALID_OPS:
        errs.append(f"{path}: op must be one of {sorted(_VALID_OPS)}")
    if "value" not in node:
        errs.append(f"{path}: value is required")
    if op == "regex" or op == "any_regex":
        try:
            re.compile(str(node.get("value", "")))
        except re.error as e:
            errs.append(f"{path}: invalid regex — {e}")
    if op == "in" and not isinstance(node.get("value"), list):
        errs.append(f"{path}: 'in' op requires a list value")
    if op in ("after", "before"):
        v = str(node.get("value", ""))
        try:
            _dt.date.fromisoformat(v[:10])
        except ValueError:
            errs.append(f"{path}: '{op}' op needs ISO YYYY-MM-DD value")
    return errs


def evaluate_rule(rule: dict, candidate: dict) -> tuple[bool, dict]:
    """Evaluate `rule` against the candidate observation dict and return
    (matched, evidence). The evidence dict shows which predicates fired
    and the candidate values they fired on."""
    evidence: dict = {"predicates": []}
    cond = rule.get("condition") or {}
    matched = _eval_node(cond, candidate, evidence)
    return matched, evidence


def _eval_node(node, candidate: dict, evidence: dict) -> bool:
    if "and" in node:
        return all(_eval_node(c, candidate, evidence) for c in node["and"])
    if "or" in node:
        # Short-circuit but still collect predicates that fired up to the hit.
        results = [_eval_node(c, candidate, evidence) for c in node["or"]]
        return any(results)
    if "not" in node:
        # Don't propagate predicate-fires from inside a NOT (they didn't
        # contribute to the match).
        sub_evidence: dict = {"predicates": []}
        return not _eval_node(node["not"], candidate, sub_evidence)
    return _eval_leaf(node, candidate, evidence)


def _eval_leaf(leaf, candidate: dict, evidence: dict) -> bool:
    field = leaf.get("field")
    op    = leaf.get("op")
    value = leaf.get("value")
    cand_value = candidate.get(field)
    hit = False
    try:
        if op == "regex":
            if isinstance(cand_value, str):
                hit = re.search(str(value), cand_value) is not None
        elif op == "any_regex":
            if isinstance(cand_value, list):
                hit = any(
                    re.search(str(value), str(v)) for v in cand_value
                )
        elif op == "icontains":
            if isinstance(cand_value, str):
                hit = str(value).lower() in cand_value.lower()
        elif op == "equals":
            hit = cand_value == value
        elif op == "equals_ci":
            hit = (isinstance(cand_value, str)
                   and cand_value.lower() == str(value).lower())
        elif op == "startswith_ci":
            hit = (isinstance(cand_value, str)
                   and cand_value.lower().startswith(str(value).lower()))
        elif op == "endswith_ci":
            hit = (isinstance(cand_value, str)
                   and cand_value.lower().endswith(str(value).lower()))
        elif op == "in":
            if isinstance(value, list):
                hit = cand_value in value
        elif op == "after":
            if isinstance(cand_value, str) and cand_value[:10]:
                hit = cand_value[:10] > str(value)[:10]
        elif op == "before":
            if isinstance(cand_value, str) and cand_value[:10]:
                hit = cand_value[:10] < str(value)[:10]
    except (re.error, TypeError, ValueError):
        hit = False
    if hit:
        evidence["predicates"].append({
            "field": field, "op": op, "value": value,
            "matched_against": cand_value,
        })
    return hit


# ── CRUD ───────────────────────────────────────────────────────────────

def create_rule(name: str, condition: dict, *,
                description: str = "", meta: dict | None = None,
                profile_id: str | None = None, enabled: bool = True) -> int:
    if not name or not name.strip():
        raise ValueError("name is required")
    rule_doc = {"meta": meta or {}, "condition": condition}
    errors = validate_rule(rule_doc)
    if errors:
        raise ValueError("invalid rule: " + "; ".join(errors))
    init_db()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO hunt_rules (name, description, rule_json, "
            "profile_id, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name.strip(), description or "", json.dumps(rule_doc),
             profile_id, 1 if enabled else 0, _now()),
        )
        return int(cur.lastrowid)


def _row_to_rule(row: sqlite3.Row) -> dict:
    rule = json.loads(row["rule_json"])
    return {
        "id":            int(row["id"]),
        "name":          row["name"],
        "description":   row["description"],
        "rule":          rule,
        "profile_id":    row["profile_id"],
        "enabled":       bool(row["enabled"]),
        "created_at":    row["created_at"],
        "last_fired_at": row["last_fired_at"] or "",
        "fire_count":    int(row["fire_count"]),
    }


def list_rules(enabled_only: bool = False) -> list[dict]:
    init_db()
    sql = "SELECT * FROM hunt_rules"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY created_at DESC"
    with _conn() as c:
        return [_row_to_rule(r) for r in c.execute(sql).fetchall()]


def get_rule(rule_id: int) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM hunt_rules WHERE id = ?", (int(rule_id),)
        ).fetchone()
        return _row_to_rule(row) if row else None


_RULE_UPDATABLE = {"name", "description", "rule", "profile_id", "enabled"}


def update_rule(rule_id: int, **fields) -> bool:
    bad = set(fields) - _RULE_UPDATABLE
    if bad:
        raise ValueError(f"non-updatable fields: {sorted(bad)}")
    if not fields:
        return False
    if "rule" in fields:
        errors = validate_rule(fields["rule"])
        if errors:
            raise ValueError("invalid rule: " + "; ".join(errors))
        fields["rule_json"] = json.dumps(fields.pop("rule"))
    if "enabled" in fields:
        fields["enabled"] = 1 if fields["enabled"] else 0
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [int(rule_id)]
    with _conn() as c:
        cur = c.execute(
            f"UPDATE hunt_rules SET {sets} WHERE id = ?", values
        )
        return cur.rowcount > 0


def set_enabled(rule_id: int, enabled: bool) -> bool:
    return update_rule(rule_id, enabled=bool(enabled))


def delete_rule(rule_id: int) -> bool:
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM hunt_rules WHERE id = ?", (int(rule_id),)
        )
        return cur.rowcount > 0


# ── Matches ────────────────────────────────────────────────────────────

def record_match(rule_id: int, matched_value: str, evidence: dict,
                 payload: dict, source: str) -> int | None:
    """Insert a match. Returns the new match id, or None if it was a dup
    (same rule_id + matched_value already exists). Bumps fire_count +
    last_fired_at on the rule on a successful insert."""
    init_db()
    now = _now()
    with _conn() as c:
        try:
            cur = c.execute(
                "INSERT INTO hunt_matches (rule_id, matched_value, evidence, "
                "payload, source, seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                (int(rule_id), matched_value or "",
                 json.dumps(evidence or {}, default=str),
                 json.dumps(payload or {}, default=str),
                 source, now),
            )
        except sqlite3.IntegrityError:
            return None
        c.execute(
            "UPDATE hunt_rules SET last_fired_at = ?, "
            "fire_count = fire_count + 1 WHERE id = ?",
            (now, int(rule_id)),
        )
        return int(cur.lastrowid)


def list_matches(rule_id: int | None = None, status: str | None = None,
                 limit: int = 200) -> list[dict]:
    init_db()
    where: list[str] = []
    args:  list = []
    if rule_id is not None:
        where.append("m.rule_id = ?")
        args.append(int(rule_id))
    if status:
        where.append("m.review_status = ?")
        args.append(status)
    sql = (
        "SELECT m.*, r.name AS rule_name, r.profile_id "
        "FROM hunt_matches m LEFT JOIN hunt_rules r ON r.id = m.rule_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY m.seen_at DESC LIMIT ?"
    args.append(int(limit))
    with _conn() as c:
        rows = c.execute(sql, args).fetchall()
    out: list[dict] = []
    for r in rows:
        out.append({
            "id":            int(r["id"]),
            "rule_id":       int(r["rule_id"]),
            "rule_name":     r["rule_name"] or "",
            "profile_id":    r["profile_id"] or "",
            "matched_value": r["matched_value"],
            "evidence":      json.loads(r["evidence"] or "{}"),
            "payload":       json.loads(r["payload"] or "{}"),
            "source":        r["source"],
            "seen_at":       r["seen_at"],
            "review_status": r["review_status"],
            "reviewed_at":   r["reviewed_at"] or "",
        })
    return out


def get_match(match_id: int) -> dict | None:
    rows = list_matches()
    # Simple path — match volumes are small per analyst session.
    for m in rows:
        if m["id"] == int(match_id):
            return m
    return None


def update_match_status(match_id: int, status: str) -> bool:
    if status not in ("pending", "accepted", "rejected"):
        raise ValueError("status must be pending|accepted|rejected")
    with _conn() as c:
        cur = c.execute(
            "UPDATE hunt_matches SET review_status = ?, reviewed_at = ? "
            "WHERE id = ?",
            (status, _now(), int(match_id)),
        )
        return cur.rowcount > 0


# ── GTI Livehunt YAML export ───────────────────────────────────────────

def livehunt_yaml(rule: dict) -> str:
    """Export a Crucible rule to a GTI Livehunt `dnsHunt` rule.

    Only `host` / `all_sans` / `issuer` / `registrar` / `creation` leaves
    map cleanly to dnsHunt clauses. Other fields are emitted as comments
    so the analyst can decide whether to translate them by hand.
    """
    # Accept either the stored-rule wrapper ({"id":..., "rule":{meta,condition}})
    # or the raw rule doc ({meta, condition}) directly.
    rule_doc = rule.get("rule") if isinstance(rule.get("rule"), dict) else rule
    meta = rule_doc.get("meta") or {}
    name = (meta.get("name") or "crucible_rule").replace(" ", "_")
    cond = rule_doc.get("condition") or {}

    lines: list[str] = []
    lines.append(f"rule {name} {{")
    lines.append("  meta:")
    lines.append(f'    author       = "Crucible SIGINT"')
    if meta.get("description"):
        lines.append(f'    description  = {json.dumps(meta["description"])}')
    if meta.get("actor"):
        lines.append(f'    actor        = {json.dumps(meta["actor"])}')
    lines.append("")
    lines.append("  condition:")
    body_lines = _yaml_emit_node(cond, depth=2)
    if not body_lines:
        body_lines = ["    true  // empty condition"]
    lines.extend(body_lines)
    lines.append("}")
    return "\n".join(lines) + "\n"


def _yaml_emit_node(node, depth: int) -> list[str]:
    indent = "  " * depth
    if "and" in node:
        parts = []
        for child in node["and"]:
            parts.extend(_yaml_emit_node(child, depth + 1))
        if not parts:
            return []
        return [f"{indent}(", *parts, f"{indent}) // and"]
    if "or" in node:
        parts = []
        last = len(node["or"]) - 1
        for i, child in enumerate(node["or"]):
            parts.extend(_yaml_emit_node(child, depth + 1))
            if i < last:
                parts.append(f"{indent}  or")
        return [f"{indent}(", *parts, f"{indent}) // or"]
    if "not" in node:
        inner = _yaml_emit_node(node["not"], depth + 1)
        return [f"{indent}not (", *inner, f"{indent})"]
    return [_yaml_emit_leaf(node, indent)]


def _yaml_emit_leaf(leaf, indent: str) -> str:
    field = leaf.get("field")
    op    = leaf.get("op")
    value = leaf.get("value")
    if field == "host" and op == "regex":
        return f'{indent}dns.dns_name matches /{value}/'
    if field == "host" and op == "endswith_ci":
        return f'{indent}dns.dns_name endswith "{value}"'
    if field == "all_sans" and op == "any_regex":
        return f'{indent}entity.cert.sans matches /{value}/'
    if field == "issuer" and op == "icontains":
        return f'{indent}entity.cert.issuer icontains "{value}"'
    if field == "registrar" and op in ("equals_ci", "icontains"):
        return f'{indent}entity.whois.registrar icontains "{value}"'
    if field == "creation" and op == "after":
        return f'{indent}entity.whois.creation_date > "{value}"'
    if field == "creation" and op == "before":
        return f'{indent}entity.whois.creation_date < "{value}"'
    return f'{indent}// untranslatable leaf — {json.dumps(leaf)}'
