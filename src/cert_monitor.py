"""
crucible.cert_monitor
=====================

Background workers that monitor for new actor infrastructure and feed
matches into the hunt_matches queue. Three concurrent loops:

1. CertStream WebSocket (primary, near-real-time):
   Connects to CERTSTREAM_URL (default wss://certstream.calidog.io/) and
   evaluates every new cert against enabled rules. Reconnects with
   exponential backoff on disconnect.

2. crt.sh polling (fallback, ~5-min cadence):
   Periodically polls crt.sh for new certs touching the rule's regex
   anchor patterns. Catches issuances that CertStream missed (the public
   Calidog server has multi-day outages) and double-checks recent infra.

3. GTI Livehunt notifications poller (optional):
   When GTI_LIVEHUNT_ENABLED=1, polls /api/v3/intelligence/hunting_
   notifications for matches GTI's pipeline found against rules the
   analyst pasted into the GTI console.

A monitor "status" tracker (in-memory) lets the UI report which loop is
currently primary and when each last produced data.

Public surface
--------------
    MonitorStatus singleton (last_certstream_ts, last_crtsh_run, etc.)
    start_workers(app_state)  → schedules the three asyncio tasks
    stop_workers()
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import re
import time
from typing import Optional

import httpx
import websockets

import hunt_rules
import actor_profiles
import alerting


# ── status singleton ──────────────────────────────────────────────────

class MonitorStatus:
    """Light in-memory status for the monitor loops, surfaced via
    /api/monitor/status. Reset on server restart (intentional)."""
    certstream_connected: bool = False
    certstream_last_msg_at: str = ""
    certstream_msg_count: int = 0
    crtsh_last_run_at: str = ""
    crtsh_last_match_count: int = 0
    crtsh_run_count: int = 0
    gti_last_run_at: str = ""
    gti_last_match_count: int = 0
    gti_run_count: int = 0
    workers_started: bool = False
    primary_source: str = "(none)"   # 'certstream' | 'crtsh' | '(none)'

    @classmethod
    def snapshot(cls) -> dict:
        return {
            k: getattr(cls, k)
            for k in (
                "certstream_connected", "certstream_last_msg_at",
                "certstream_msg_count", "crtsh_last_run_at",
                "crtsh_last_match_count", "crtsh_run_count",
                "gti_last_run_at", "gti_last_match_count",
                "gti_run_count", "workers_started", "primary_source",
            )
        }


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── shared match handling ─────────────────────────────────────────────

async def _evaluate_and_record(candidate: dict, source: str) -> int:
    """Evaluate `candidate` against every enabled rule. For each match,
    insert into hunt_matches (deduped per rule_id + matched_value) and
    dispatch a Slack alert. Returns the number of matches recorded."""
    try:
        rules = hunt_rules.list_rules(enabled_only=True)
    except Exception:
        return 0

    matched_count = 0
    for rule in rules:
        try:
            ok, evidence = hunt_rules.evaluate_rule(rule["rule"], candidate)
        except Exception:
            continue
        if not ok:
            continue
        match_id = hunt_rules.record_match(
            rule_id=rule["id"],
            matched_value=candidate.get("host") or "",
            evidence=evidence,
            payload=candidate,
            source=source,
        )
        if match_id is None:
            continue   # dedupe — already recorded
        matched_count += 1

        # Resolve the profile (best-effort) for the Slack alert.
        profile = None
        if rule.get("profile_id"):
            try:
                profile = actor_profiles.get_profile(rule["profile_id"])
            except Exception:
                profile = None

        try:
            await alerting.dispatch_match_alert(
                rule=rule,
                match={
                    "id": match_id,
                    "matched_value": candidate.get("host") or "",
                    "source": source,
                    "evidence": evidence,
                },
                profile=profile,
            )
        except Exception:
            pass
    return matched_count


# ── CertStream worker ─────────────────────────────────────────────────

def _certstream_to_candidate(msg: dict) -> list[dict]:
    """CertStream messages of type `certificate_update` carry a leaf cert
    with `all_domains`, `issuer`, `not_before`. Emit one candidate per
    SAN so a rule keyed on `host` regex sees every name."""
    if msg.get("message_type") != "certificate_update":
        return []
    data = msg.get("data") or {}
    leaf = (data.get("leaf_cert") or {})
    all_sans = [d.lower() for d in (leaf.get("all_domains") or []) if d]
    if not all_sans:
        return []
    issuer = (leaf.get("issuer") or {}).get("aggregated") \
        or (leaf.get("issuer") or {}).get("O") \
        or ""
    not_before = leaf.get("not_before")
    if isinstance(not_before, (int, float)):
        try:
            creation = _dt.datetime.utcfromtimestamp(
                int(not_before)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            creation = ""
    else:
        creation = ""

    out: list[dict] = []
    for host in all_sans:
        # Strip wildcards — CT logs leak wildcard CNs that aren't useful
        # for hostname-anchored rules.
        host = host.lstrip("*.")
        out.append({
            "host":       host,
            "all_sans":   all_sans,
            "issuer":     issuer,
            "creation":   creation,
            "source":     "certstream",
        })
    return out


async def certstream_worker(stop_event: asyncio.Event) -> None:
    """Connect to CertStream and feed each new cert into the matcher.
    Reconnects with capped exponential backoff. Falls silent (and lets
    the crt.sh fallback take over) when the upstream is down."""
    url = os.environ.get("CERTSTREAM_URL",
                         "wss://certstream.calidog.io/").strip()
    if not url:
        return
    backoff = 2.0
    while not stop_event.is_set():
        try:
            async with websockets.connect(url, ping_interval=20,
                                          ping_timeout=20,
                                          max_size=2 ** 22) as ws:
                MonitorStatus.certstream_connected = True
                MonitorStatus.primary_source = "certstream"
                backoff = 2.0
                while not stop_event.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=120)
                    except asyncio.TimeoutError:
                        # No data for 2min — break out to let the connection
                        # cycle and the fallback step up.
                        break
                    try:
                        msg = json.loads(raw)
                    except (TypeError, ValueError):
                        continue
                    MonitorStatus.certstream_msg_count += 1
                    MonitorStatus.certstream_last_msg_at = _now()
                    for cand in _certstream_to_candidate(msg):
                        await _evaluate_and_record(cand, source="certstream")
        except (asyncio.CancelledError, KeyboardInterrupt):
            break
        except Exception:
            MonitorStatus.certstream_connected = False
            if MonitorStatus.primary_source == "certstream":
                MonitorStatus.primary_source = "(none)"
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 120.0)
        finally:
            MonitorStatus.certstream_connected = False


# ── crt.sh polling fallback ───────────────────────────────────────────

_RULE_HOST_REGEX_RE = re.compile(r'"field":\s*"host"\s*,\s*"op":\s*"regex"'
                                 r'\s*,\s*"value":\s*"([^"]+)"')


def _extract_host_anchors(rule_doc: dict) -> list[str]:
    """Pull plausible crt.sh query strings out of a rule. crt.sh doesn't
    support arbitrary regex, but it accepts SQL LIKE patterns via `?q=`.
    For each `host` regex predicate we extract a stable literal substring
    (letters/digits) longest-first and use that as the query."""
    cond_json = json.dumps(rule_doc.get("condition") or {})
    anchors: list[str] = []
    for m in _RULE_HOST_REGEX_RE.finditer(cond_json):
        pat = m.group(1)
        # Strip regex metachars to find the longest literal run.
        for chunk in re.split(r"[^a-zA-Z0-9.\-]+", pat):
            if len(chunk) >= 4:
                anchors.append(chunk)
    # Also use `endswith_ci` host predicates as anchors.
    for m in re.finditer(r'"field":\s*"host"\s*,\s*"op":\s*"endswith_ci"'
                         r'\s*,\s*"value":\s*"([^"]+)"', cond_json):
        v = m.group(1).lstrip(".")
        if v:
            anchors.append(v)
    # Dedupe, prefer longer anchors first.
    return sorted(set(anchors), key=lambda s: (-len(s), s))[:5]


async def _crtsh_query(client: httpx.AsyncClient,
                       anchor: str) -> list[dict]:
    """Query crt.sh with a LIKE-anchored substring. Returns a list of
    {host, issuer, creation, all_sans, source} candidates."""
    # crt.sh accepts both `q=%foo%` and `q=foo`. `output=json` returns
    # an array. The Apache server occasionally returns 502 — caller swallows.
    url = f"https://crt.sh/?q=%25{anchor}%25&output=json"
    try:
        r = await client.get(url, timeout=20.0)
    except Exception:
        return []
    if r.status_code != 200:
        return []
    try:
        rows = r.json()
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    out: list[dict] = []
    seen_hosts: set[str] = set()
    for row in rows[:500]:
        sans = []
        for line in (row.get("name_value") or "").split("\n"):
            line = line.strip().lstrip("*.").lower()
            if line:
                sans.append(line)
        for host in sans:
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            out.append({
                "host":     host,
                "all_sans": sans,
                "issuer":   row.get("issuer_name") or "",
                "creation": (row.get("not_before") or "")[:10],
                "source":   "crtsh",
            })
    return out


async def crtsh_worker(stop_event: asyncio.Event,
                       poll_seconds: int = 300) -> None:
    """Periodically poll crt.sh for new certs anchored on each rule's host
    regex literal. Cheap dedupe via hunt_matches UNIQUE constraint."""
    while not stop_event.is_set():
        try:
            rules = hunt_rules.list_rules(enabled_only=True)
        except Exception:
            rules = []
        match_total = 0
        if rules:
            async with httpx.AsyncClient(
                headers={"User-Agent": "crucible/1.0 (+hunts)"},
            ) as client:
                for rule in rules:
                    anchors = _extract_host_anchors(rule["rule"])
                    for anchor in anchors:
                        if stop_event.is_set():
                            break
                        candidates = await _crtsh_query(client, anchor)
                        for cand in candidates:
                            ok, evidence = hunt_rules.evaluate_rule(
                                rule["rule"], cand,
                            )
                            if not ok:
                                continue
                            match_id = hunt_rules.record_match(
                                rule_id=rule["id"],
                                matched_value=cand.get("host") or "",
                                evidence=evidence,
                                payload=cand,
                                source="crtsh",
                            )
                            if match_id is None:
                                continue
                            match_total += 1
                            profile = None
                            if rule.get("profile_id"):
                                try:
                                    profile = actor_profiles.get_profile(
                                        rule["profile_id"]
                                    )
                                except Exception:
                                    profile = None
                            try:
                                await alerting.dispatch_match_alert(
                                    rule=rule,
                                    match={
                                        "id": match_id,
                                        "matched_value":
                                            cand.get("host") or "",
                                        "source": "crtsh",
                                        "evidence": evidence,
                                    },
                                    profile=profile,
                                )
                            except Exception:
                                pass
        MonitorStatus.crtsh_run_count += 1
        MonitorStatus.crtsh_last_run_at = _now()
        MonitorStatus.crtsh_last_match_count = match_total
        # If CertStream has been silent for >10 min, promote crt.sh to primary.
        if MonitorStatus.certstream_last_msg_at:
            try:
                last = _dt.datetime.strptime(
                    MonitorStatus.certstream_last_msg_at,
                    "%Y-%m-%dT%H:%M:%SZ",
                ).replace(tzinfo=_dt.timezone.utc)
                if (_dt.datetime.now(_dt.timezone.utc) - last
                        ).total_seconds() > 600:
                    MonitorStatus.primary_source = "crtsh"
            except ValueError:
                pass
        elif MonitorStatus.primary_source == "(none)":
            MonitorStatus.primary_source = "crtsh"
        try:
            await asyncio.wait_for(stop_event.wait(),
                                   timeout=poll_seconds)
        except asyncio.TimeoutError:
            pass


# ── GTI Livehunt notifications poller ─────────────────────────────────

async def gti_livehunt_worker(stop_event: asyncio.Event,
                              poll_seconds: int = 600) -> None:
    """Pull notifications from the GTI hunting endpoint. Only runs when
    GTI_LIVEHUNT_ENABLED is set, since lower-tier keys 4xx on it."""
    if os.environ.get("GTI_LIVEHUNT_ENABLED", "0").lower() in ("0", "false", ""):
        return
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return

    url = ("https://www.virustotal.com/api/v3/intelligence/"
           "hunting_notifications?limit=40")
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    seen: set[str] = set()
    while not stop_event.is_set():
        match_total = 0
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(url, headers=headers)
                if r.status_code == 200:
                    items = (r.json() or {}).get("data") or []
                    for item in items:
                        nid = item.get("id") or ""
                        if not nid or nid in seen:
                            continue
                        seen.add(nid)
                        attrs = item.get("attributes") or {}
                        cand = {
                            "host":     attrs.get("rule_name") or "",
                            "all_sans": [],
                            "issuer":   "",
                            "creation": attrs.get("date") or "",
                            "source":   "gti_livehunt",
                        }
                        # We don't re-evaluate Crucible rules against GTI
                        # notifications (GTI already matched its own rule).
                        # Still: record the match so it shows up in the queue.
                        try:
                            mid = hunt_rules.record_match(
                                rule_id=0,
                                matched_value=cand["host"] or nid,
                                evidence={"gti_rule": attrs.get("rule_name")},
                                payload=item,
                                source="gti_livehunt",
                            )
                            if mid is not None:
                                match_total += 1
                        except Exception:
                            pass
        except Exception:
            pass
        MonitorStatus.gti_run_count += 1
        MonitorStatus.gti_last_run_at = _now()
        MonitorStatus.gti_last_match_count = match_total
        try:
            await asyncio.wait_for(stop_event.wait(),
                                   timeout=poll_seconds)
        except asyncio.TimeoutError:
            pass


# ── orchestration ─────────────────────────────────────────────────────

_tasks: list[asyncio.Task] = []
_stop_event: Optional[asyncio.Event] = None


def start_workers() -> None:
    """Schedule the three workers on the running event loop. Idempotent."""
    global _stop_event
    if MonitorStatus.workers_started:
        return
    _stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    _tasks.append(loop.create_task(certstream_worker(_stop_event),
                                   name="cert_monitor.certstream"))
    _tasks.append(loop.create_task(crtsh_worker(_stop_event),
                                   name="cert_monitor.crtsh"))
    _tasks.append(loop.create_task(gti_livehunt_worker(_stop_event),
                                   name="cert_monitor.gti_livehunt"))
    MonitorStatus.workers_started = True


async def stop_workers() -> None:
    if not MonitorStatus.workers_started:
        return
    if _stop_event is not None:
        _stop_event.set()
    for t in _tasks:
        t.cancel()
    for t in _tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass
    _tasks.clear()
    MonitorStatus.workers_started = False
