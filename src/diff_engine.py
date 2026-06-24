"""
crucible.diff_engine
====================

Compares two scan states (typically a current run and an earlier run of the
same seed, both pulled from pdns_store) and surfaces what changed at the
infrastructure layer: new IPs, removed IPs, source-coverage changes per IP,
and elapsed time.

Inputs are the dicts returned by pdns_store.query_scan_state(scan_id) — i.e.
fully self-contained snapshots; no live network calls. The output is meant to
be human-readable enough for a log line ("S20: 2 new IPs, 1 removed since
last scan") and rich enough to drive a future UI diff panel.

Public surface
--------------
    diff_scans(prior_state, current_state)             → dict
    diff_against_history(seed, current_state)          → dict | {error}
"""

from __future__ import annotations

from typing import Optional

import pdns_store


def _index_by_ip(state: dict) -> dict:
    """ip → {'sources': set, 'observed_at': set}"""
    idx: dict = {}
    for obs in (state or {}).get("observations", []):
        ip = obs.get("ip")
        if not ip:
            continue
        e = idx.setdefault(ip, {"sources": set(), "observed_at": set(),
                                "record_types": set()})
        if obs.get("source"):
            e["sources"].add(obs["source"])
        if obs.get("observed_at"):
            e["observed_at"].add(obs["observed_at"])
        if obs.get("record_type"):
            e["record_types"].add(obs["record_type"])
    return idx


def diff_scans(prior_state: dict, current_state: dict) -> dict:
    """Return the diff between two scan_state snapshots.

    Shape:
        {
          prior_scan_id, current_scan_id, seed,
          prior_started_at, current_started_at,
          added_ips:    [ip, ...],
          removed_ips:  [ip, ...],
          stable_ips:   [ip, ...],
          source_changes: { ip: { gained: [...], lost: [...] } },
          summary: { added_count, removed_count, stable_count,
                     ips_with_source_changes },
        }
    """
    prior = _index_by_ip(prior_state)
    current = _index_by_ip(current_state)

    prior_ips = set(prior.keys())
    current_ips = set(current.keys())

    added = sorted(current_ips - prior_ips)
    removed = sorted(prior_ips - current_ips)
    stable = sorted(prior_ips & current_ips)

    source_changes: dict = {}
    for ip in stable:
        gained = sorted(current[ip]["sources"] - prior[ip]["sources"])
        lost   = sorted(prior[ip]["sources"]   - current[ip]["sources"])
        if gained or lost:
            source_changes[ip] = {"gained": gained, "lost": lost}

    return {
        "prior_scan_id":      (prior_state or {}).get("scan_id"),
        "current_scan_id":    (current_state or {}).get("scan_id"),
        "seed":               (current_state or {}).get("seed")
                              or (prior_state or {}).get("seed"),
        "prior_started_at":   (prior_state or {}).get("started_at"),
        "current_started_at": (current_state or {}).get("started_at"),
        "added_ips":          added,
        "removed_ips":        removed,
        "stable_ips":         stable,
        "source_changes":     source_changes,
        "summary": {
            "added_count":              len(added),
            "removed_count":            len(removed),
            "stable_count":             len(stable),
            "ips_with_source_changes":  len(source_changes),
        },
    }


def diff_against_history(seed: str, current_state: dict) -> dict:
    """Convenience: compare current_state to the most recent COMPLETED prior
    scan of `seed` recorded in pdns_store. Returns {error} when there's no
    earlier scan to compare against."""
    seed_lc = (seed or "").lower()
    scans = pdns_store.query_scans_for_seed(seed_lc, limit=20)
    current_id = (current_state or {}).get("scan_id")
    prior_meta: Optional[dict] = None
    for s in scans:
        if s["scan_id"] != current_id and s.get("completed_at"):
            prior_meta = s
            break
    if not prior_meta:
        return {"error": f"No prior completed scan for {seed_lc}", "seed": seed_lc}
    prior_state = pdns_store.query_scan_state(prior_meta["scan_id"])
    if not prior_state:
        return {"error": f"Prior scan {prior_meta['scan_id']} state unavailable",
                "seed": seed_lc}
    return diff_scans(prior_state, current_state)
