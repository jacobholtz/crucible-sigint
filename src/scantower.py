"""
crucible.scantower
==================

scantower.io API client — ACTIVE PROBING. Unlike the rest of Crucible
(passive OSINT only), this module triggers real HTTP/port/SSL scans
against the target. Only use on infrastructure you're authorized to
probe (your own assets, pentest scope, sanctioned IR).

Workflow (per scantower's documented REST API):
    POST /ext/scans          → register + trigger ad-hoc scan
    GET  /ext/scans/:id      → poll status until completed
    GET  /ext/reports/:id/data → structured report payload

Docs are sparse on response shapes beyond `{scan, vulnerabilities,
summary}`. extract_intel() walks the entire payload recursively for
hostnames / IPs / SAN values so anything scantower surfaces (subdomains,
detected JS hosts, cert SANs, redirect targets) gets pulled into a flat
list for downstream Crucible pivots — without depending on a fragile
schema.

Public surface
--------------
    is_configured() → bool                (SCANTOWER_API_KEY set?)
    trigger_scan(url, scan_type=..., port_scan=..., modules=...) → dict
    poll_scan(scan_id, timeout=120, interval=5) → dict (final state)
    fetch_report(scan_id) → dict          (raw report JSON from API)
    extract_intel(report, seed_domain) → dict
        {hostnames: [...], ips: [...], vulnerabilities: [...],
         security_score: int, summary: {...}}
    list_scans(limit=20) → list[dict]
    list_sites(limit=20) → list[dict]
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from typing import Any

import httpx


BASE_URL = "https://api.scantower.io/api/v1/ext"

# Reasonable per-scan ceiling. Most scans complete in <2 min; this guards
# against the UI hanging indefinitely on a stuck scan.
DEFAULT_POLL_TIMEOUT_S = 180
DEFAULT_POLL_INTERVAL_S = 5

# Hostname regex used by extract_intel() to vacuum every domain-like
# string out of arbitrary report JSON.
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)


def is_configured() -> bool:
    return bool(os.environ.get("SCANTOWER_API_KEY", "").strip())


def _key() -> str:
    return os.environ.get("SCANTOWER_API_KEY", "").strip()


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_key()}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _err(payload: Any, status: int) -> dict:
    """Normalize a non-200 response into a Crucible-style error dict."""
    if isinstance(payload, dict):
        err = payload.get("error") or {}
        if isinstance(err, dict):
            msg = err.get("message") or ""
            code = err.get("code") or ""
            if msg:
                return {"error": f"scantower HTTP {status}: "
                                 f"{msg}{f' ({code})' if code else ''}"}
    return {"error": f"scantower HTTP {status}"}


async def trigger_scan(url: str, *,
                       scan_type: str = "full",
                       port_scan: bool = True,
                       browser_scan: bool = True,
                       misconfiguration: bool = True) -> dict:
    """Trigger an ad-hoc scan. Returns the raw API response dict, with a
    `scan_id` convenience field promoted to the top when the API returns
    a recognisable id."""
    if not is_configured():
        return {"error": "SCANTOWER_API_KEY not configured"}
    valid_types = {"full", "ssl-only", "wordpress-security",
                   "malware-scanner"}
    if scan_type not in valid_types:
        return {"error": f"scan_type must be one of {sorted(valid_types)}"}

    body = {
        "url": url,
        "scanType": scan_type,
        "portScan": bool(port_scan),
        "modules": {
            "browserScan":      bool(browser_scan),
            "misconfiguration": bool(misconfiguration),
        },
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(f"{BASE_URL}/scans",
                                  headers=_headers(), json=body)
            try:
                data = r.json()
            except Exception:
                data = {}
            if r.status_code not in (200, 201, 202):
                return _err(data, r.status_code)
            # Promote scan_id from the envelope so callers don't guess.
            scan_id = (
                (data.get("data") or {}).get("id")
                or data.get("id")
                or (data.get("data") or {}).get("scanId")
                or data.get("scanId")
            )
            return {"scan_id": scan_id, "raw": data}
    except Exception as e:
        return {"error": f"scantower request failed: {e}"}


async def _get_scan(client: httpx.AsyncClient, scan_id: str) -> dict:
    r = await client.get(f"{BASE_URL}/scans/{scan_id}", headers=_headers())
    try:
        data = r.json()
    except Exception:
        data = {}
    if r.status_code != 200:
        return _err(data, r.status_code)
    return (data.get("data") if isinstance(data.get("data"), dict)
            else data)


async def poll_scan(scan_id: str, *,
                    timeout: int = DEFAULT_POLL_TIMEOUT_S,
                    interval: int = DEFAULT_POLL_INTERVAL_S) -> dict:
    """Poll GET /ext/scans/:id until status is terminal or timeout
    elapses. Returns the final scan dict (or an error dict)."""
    if not is_configured():
        return {"error": "SCANTOWER_API_KEY not configured"}
    deadline = asyncio.get_event_loop().time() + max(10, timeout)
    last: dict = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while asyncio.get_event_loop().time() < deadline:
                last = await _get_scan(client, scan_id)
                if "error" in last:
                    return last
                # Status field shape varies — accept whichever the API
                # uses, lowercased. Terminal states stop the poll.
                status = (str(last.get("status") or "").lower())
                if status in ("completed", "complete", "done",
                              "failed", "error", "errored"):
                    return last
                await asyncio.sleep(max(2, interval))
    except Exception as e:
        return {"error": f"scantower poll failed: {e}"}
    last["_timeout"] = True
    return last


async def fetch_report(scan_id: str) -> dict:
    """Fetch the structured report payload."""
    if not is_configured():
        return {"error": "SCANTOWER_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(f"{BASE_URL}/reports/{scan_id}/data",
                                 headers=_headers())
            try:
                data = r.json()
            except Exception:
                data = {}
            if r.status_code != 200:
                return _err(data, r.status_code)
            # Docs show payload nested under `data`. Unwrap for caller
            # convenience but preserve `_envelope` so anything outside
            # `data` (e.g., meta) is still inspectable.
            inner = data.get("data") if isinstance(data.get("data"), dict) else data
            return {"report": inner, "_envelope": data}
    except Exception as e:
        return {"error": f"scantower report fetch failed: {e}"}


async def list_scans(limit: int = 20) -> dict:
    if not is_configured():
        return {"error": "SCANTOWER_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(f"{BASE_URL}/scans",
                                 headers=_headers(),
                                 params={"limit": max(1, min(int(limit), 100))})
            try:
                data = r.json()
            except Exception:
                data = {}
            if r.status_code != 200:
                return _err(data, r.status_code)
            items = data.get("data") if isinstance(data.get("data"), list) else []
            return {"scans": items, "meta": data.get("meta") or {}}
    except Exception as e:
        return {"error": f"scantower list failed: {e}"}


async def list_sites(limit: int = 20) -> dict:
    if not is_configured():
        return {"error": "SCANTOWER_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(f"{BASE_URL}/sites",
                                 headers=_headers(),
                                 params={"limit": max(1, min(int(limit), 100))})
            try:
                data = r.json()
            except Exception:
                data = {}
            if r.status_code != 200:
                return _err(data, r.status_code)
            items = data.get("data") if isinstance(data.get("data"), list) else []
            return {"sites": items, "meta": data.get("meta") or {}}
    except Exception as e:
        return {"error": f"scantower list failed: {e}"}


# ── intelligence extraction ───────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved
                    or addr.is_unspecified)
    except ValueError:
        return False


def _walk_strings(obj: Any, sink: list[str]) -> None:
    """Recursively walk arbitrary JSON, appending every string value."""
    if isinstance(obj, str):
        sink.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, sink)
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, sink)


def extract_intel(report: dict, seed_domain: str = "") -> dict:
    """Normalize scantower's report payload into Crucible's pivot shape.

    Because the report schema beyond `{scan, vulnerabilities, summary}`
    isn't documented, this walks the entire payload defensively and
    collects:
      * hostnames — every domain-like string seen, deduped, optionally
                    filtered to the seed registrable
      * ips       — every public-IP string seen, deduped
      * vulnerabilities — pass-through of the documented `vulnerabilities`
                          list (capped, normalised keys)
      * security_score, summary — pass-through
    """
    if not report:
        return {"hostnames": [], "ips": [], "vulnerabilities": [],
                "security_score": None, "summary": {},
                "raw_keys": []}

    inner = report.get("report") if isinstance(report.get("report"), dict) else report

    strings: list[str] = []
    _walk_strings(inner, strings)

    seed_lc = (seed_domain or "").lower().lstrip("*.")
    hostnames: set[str] = set()
    for s in strings:
        if not s or len(s) > 253:
            continue
        for m in _HOSTNAME_RE.finditer(s):
            host = m.group(0).lower().lstrip("*.")
            # Skip obvious file extensions that the regex catches
            # ("foo.png", "x.js" — TLD-shaped but actually a filename).
            tld = host.rsplit(".", 1)[-1]
            if tld in ("png", "jpg", "jpeg", "gif", "css", "js",
                       "html", "htm", "ico", "svg", "woff", "woff2",
                       "ttf", "map", "json", "xml", "txt", "pdf"):
                continue
            hostnames.add(host)

    # IP extraction: simple v4 pass; v6 is rarer in scan output.
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips: set[str] = set()
    for s in strings:
        for m in ip_re.finditer(s):
            ip = m.group(0)
            if _is_public_ip(ip):
                ips.add(ip)

    # Optional: bias toward the seed registrable when seed_domain provided
    related: list[dict] = []
    if seed_lc:
        suffix = "." + seed_lc
        for h in sorted(hostnames):
            related.append({
                "host": h,
                "related_to_seed":
                    h == seed_lc or h.endswith(suffix),
            })
    else:
        related = [{"host": h, "related_to_seed": None}
                   for h in sorted(hostnames)]

    vulns: list[dict] = []
    for v in (inner.get("vulnerabilities") or [])[:200]:
        if not isinstance(v, dict):
            continue
        vulns.append({
            "id":          v.get("id") or "",
            "title":       v.get("title") or v.get("name") or "",
            "severity":    (v.get("severity") or "").lower(),
            "description": (v.get("description") or "")[:400],
            "evidence":    (v.get("evidence")
                            or v.get("location") or "")[:400],
            "remediation": (v.get("remediation") or "")[:400],
        })

    scan_meta = inner.get("scan") or {}

    return {
        "hostnames":       related,
        "hostname_count":  len(hostnames),
        "ips":             sorted(ips),
        "ip_count":        len(ips),
        "vulnerabilities": vulns,
        "vuln_count":      len(vulns),
        "security_score":  inner.get("securityScore")
                            or scan_meta.get("securityScore"),
        "summary":         inner.get("summary") or {},
        "scan_meta":       scan_meta,
        "raw_keys":        sorted(list(inner.keys())),
    }
