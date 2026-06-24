"""
Origin IP Discovery — find the real backend IP behind a Cloudflare / CDN-
fronted seed by combining four passive techniques. Each one surfaces
candidate IPs from a different vantage point; the aggregator dedupes by IP
and scores each candidate by how many techniques independently confirmed it.

Techniques
----------
  1. cert_search        Censys + Shodan: which IPs currently serve a TLS
                        cert with the seed in its SAN list? The CDN edges
                        do too, so we filter known CDN ranges; what remains
                        is usually the origin.
  2. pdns_historical    VirusTotal + OTX passive DNS: any IP the domain
                        resolved to *before* Cloudflare was put in front.
  3. subdomain_leak     Common admin / mail / dev subdomains that often
                        bypass the proxy and resolve directly to origin
                        (cpanel, mail, dev, staging, autodiscover, …).
  4. mx_origin          MX records → A records of mail servers. Self-hosted
                        mail is co-located with origin web more often than
                        not; flagged separately when the MX is on a known
                        managed-mail provider (Google / M365 / Proton).

The CDN filter is critical for *every* technique — without it the candidate
list is dominated by the same anycast IPs we were trying to look behind.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any

import httpx


# ════════════════════════════════════════════════════════════════════
# CDN range filter — duplicated from crucible_app._SHARED_CDN_CIDRS so
# this module stays free of a circular import on the app. Keep these
# two lists in lockstep when adding new providers / ranges.
# ════════════════════════════════════════════════════════════════════
_SHARED_CDN_CIDRS = tuple(ipaddress.ip_network(c) for c in (
    # Cloudflare — https://www.cloudflare.com/ips-v4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Akamai — major anycast ranges
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
    "23.0.0.0/12", "2.16.0.0/13",
    # Fastly — major anycast ranges
    "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16",
))


def is_shared_cdn_ip(ip_str: str) -> bool:
    """True if ``ip_str`` falls in a published CDN anycast range — used to
    filter out the proxy IPs we already knew about from every discovery
    technique's results."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _SHARED_CDN_CIDRS)


# ════════════════════════════════════════════════════════════════════
# DoH helper — Google Public DNS, matches the same surface crucible_app
# already uses elsewhere. Returns a flat list of A/AAAA answer strings.
# ════════════════════════════════════════════════════════════════════
async def _doh_resolve(client: httpx.AsyncClient, name: str, rtype: str = "A") -> list[str]:
    try:
        r = await client.get(
            "https://dns.google/resolve",
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=6.0,
        )
        if r.status_code != 200:
            return []
        data = r.json() or {}
        return [a.get("data", "").strip().rstrip(".")
                for a in (data.get("Answer") or [])
                if a.get("data")]
    except Exception:
        return []


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ════════════════════════════════════════════════════════════════════
# 1. cert_search — Censys + Shodan, "which IPs serve this cert?"
# ════════════════════════════════════════════════════════════════════
async def _cert_search_censys(seed: str, api_id: str, api_secret: str,
                              limit: int = 50) -> dict:
    """Censys v2 hosts search: every host with the seed in any leaf cert's
    SAN list. Returns the raw IP list plus a count of how many of the hits
    were in known CDN ranges (so the UI can show "filtered: 8 CF edges")."""
    if not (api_id and api_secret):
        return {"matches": [], "error": "Censys API key not configured"}
    q = (f'services.tls.certificates.leaf_data.names: "{seed}"'
         f' or services.tls.certificates.leaf_data.subject.common_name: "{seed}"')
    url = "https://search.censys.io/api/v2/hosts/search"
    try:
        async with httpx.AsyncClient(timeout=20.0,
                                     auth=httpx.BasicAuth(api_id, api_secret)) as client:
            r = await client.get(url, params={"q": q, "per_page": min(50, limit)})
            if r.status_code in (401, 403):
                return {"matches": [], "error": f"Censys {r.status_code} (auth/paid tier required)"}
            if r.status_code != 200:
                return {"matches": [], "error": f"Censys HTTP {r.status_code}"}
            data = r.json() or {}
    except Exception as e:
        return {"matches": [], "error": f"Censys query failed: {e}"}

    matches: list[dict] = []
    hits = ((data.get("result") or {}).get("hits") or [])[:limit]
    for h in hits:
        ip = (h.get("ip") or "").strip()
        if not _valid_ip(ip):
            continue
        asn = ((h.get("autonomous_system") or {}).get("name") or "").strip()
        matches.append({"ip": ip, "asn": asn})
    return {"matches": matches, "total": int((data.get("result") or {}).get("total") or 0)}


async def _cert_search_shodan(seed: str, api_key: str, limit: int = 50) -> dict:
    """Shodan search: hosts whose TLS cert CN/SAN matches the seed.
    `ssl.cert.subject.cn` is the most common cert query; SAN data is
    indexed as `ssl.cert.subject.cn` too in Shodan's flattened model."""
    if not api_key:
        return {"matches": [], "error": "Shodan API key not configured"}
    q = f'ssl.cert.subject.cn:"{seed}"'
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": q, "minify": "true"},
            )
            if r.status_code in (401, 402, 403):
                return {"matches": [], "error": f"Shodan {r.status_code} (paid /host/search required)"}
            if r.status_code != 200:
                return {"matches": [], "error": f"Shodan HTTP {r.status_code}"}
            data = r.json() or {}
    except Exception as e:
        return {"matches": [], "error": f"Shodan query failed: {e}"}

    matches: list[dict] = []
    for m in (data.get("matches") or [])[:limit]:
        ip = (m.get("ip_str") or "").strip()
        if not _valid_ip(ip):
            continue
        matches.append({"ip": ip, "asn": m.get("asn") or ""})
    return {"matches": matches, "total": int(data.get("total") or 0)}


# ════════════════════════════════════════════════════════════════════
# 2. pdns_historical — pre-CDN A-record observations
# ════════════════════════════════════════════════════════════════════
async def _pdns_historical(seed: str, vt_key: str, otx_key: str) -> dict:
    """Walk VT + OTX passive DNS for the seed, return historical non-CDN IPs
    with their last-seen dates. The intuition: a domain that's now behind
    Cloudflare often resolved directly to its origin before the proxy was
    added — and pDNS sources remember."""
    # Late import to avoid pulling intelligence_extensions at module load time
    # if a caller only wants the cert-search technique.
    from intelligence_extensions import (
        fetch_virustotal_passive_dns,
        fetch_otx_domain_passive_dns,
    )
    vt_task = fetch_virustotal_passive_dns(seed, vt_key) if vt_key else None
    otx_task = fetch_otx_domain_passive_dns(seed, otx_key) if otx_key else None

    tasks = [t for t in (vt_task, otx_task) if t is not None]
    if not tasks:
        return {"records": [], "error": "no pDNS keys configured (VT / OTX)"}
    results = await asyncio.gather(*tasks, return_exceptions=True)

    rows: dict[str, dict] = {}
    errors: list[str] = []
    # VT first (if it ran)
    idx = 0
    if vt_task is not None:
        vt_res = results[idx]; idx += 1
        if isinstance(vt_res, BaseException):
            errors.append(f"vt: {vt_res}")
        elif isinstance(vt_res, dict):
            if vt_res.get("error"):
                errors.append(f"vt: {vt_res['error']}")
            for r in vt_res.get("ip_history") or []:
                ip = (r.get("ip") or "").strip()
                if _valid_ip(ip):
                    e = rows.setdefault(ip, {"ip": ip, "sources": set(), "last_seen": None})
                    e["sources"].add("vt_pdns")
                    e["last_seen"] = max(filter(None, [e.get("last_seen"),
                                                       r.get("last_resolved")]), default=None)
    # OTX
    if otx_task is not None:
        otx_res = results[idx]
        if isinstance(otx_res, BaseException):
            errors.append(f"otx: {otx_res}")
        elif isinstance(otx_res, dict):
            if otx_res.get("error"):
                errors.append(f"otx: {otx_res['error']}")
            for r in otx_res.get("records") or []:
                ip = (r.get("ip") or "").strip()
                if _valid_ip(ip):
                    e = rows.setdefault(ip, {"ip": ip, "sources": set(), "last_seen": None})
                    e["sources"].add("otx_pdns")
                    e["last_seen"] = max(filter(None, [e.get("last_seen"),
                                                       r.get("last") or r.get("first")]),
                                          default=None)

    cleaned = []
    for ip, e in rows.items():
        if is_shared_cdn_ip(ip):
            continue
        cleaned.append({"ip": ip, "last_seen": e["last_seen"],
                        "sources": sorted(e["sources"])})
    # Oldest origin observations are most valuable for "was it ever direct?"
    # but most-recent-first lets the analyst see the most-likely-still-live
    # origin first. Sort by last_seen desc.
    cleaned.sort(key=lambda r: r.get("last_seen") or "", reverse=True)
    out = {"records": cleaned}
    if errors:
        out["error"] = " · ".join(errors)
    return out


# ════════════════════════════════════════════════════════════════════
# 3. subdomain_leak — common revealing subdomains, DoH probe
# ════════════════════════════════════════════════════════════════════
# Curated list of subdomain prefixes that, in practice, often bypass the
# proxy and resolve directly to origin infrastructure. Order doesn't matter
# (all probed in parallel) — keep the list tight; each entry is a DNS query.
_LEAK_SUBDOMAINS: tuple[str, ...] = (
    "mail", "smtp", "pop", "imap", "webmail", "mx", "mx1", "mx2",
    "cpanel", "whm", "plesk", "webdisk",
    "ftp", "sftp",
    "dev", "staging", "test", "qa", "beta", "preview",
    "admin", "api", "backend", "internal", "intranet", "vpn",
    "autodiscover",
    "direct", "origin", "real", "no-cdn",
    "ns1", "ns2",
)


async def _subdomain_leak(seed: str) -> dict:
    """Probe a curated list of revealing subdomains via DoH. For each that
    resolves, filter A records in CDN ranges; what's left is a high-value
    candidate origin IP."""
    async with httpx.AsyncClient() as client:
        async def _probe(sub: str) -> list[dict]:
            host = f"{sub}.{seed}"
            ips = await _doh_resolve(client, host, "A")
            out: list[dict] = []
            for ip in ips:
                if not _valid_ip(ip) or is_shared_cdn_ip(ip):
                    continue
                out.append({"ip": ip, "hostname": host, "subdomain": sub})
            return out

        per_sub = await asyncio.gather(*[_probe(s) for s in _LEAK_SUBDOMAINS],
                                        return_exceptions=True)

    flat: list[dict] = []
    for r in per_sub:
        if isinstance(r, BaseException):
            continue
        flat.extend(r)
    return {"hits": flat}


# ════════════════════════════════════════════════════════════════════
# 4. mx_origin — MX records + A-record resolution
# ════════════════════════════════════════════════════════════════════
# Hostnames matching any of these substrings are flagged as managed mail
# providers — their IPs aren't a usable web-origin signal even if non-CDN.
_MANAGED_MAIL_PROVIDERS: tuple[str, ...] = (
    "google.com", "googlemail.com", "outlook.com", "office365.com",
    "protonmail", "proton.me", "zoho", "mailgun", "sendgrid", "mandrill",
    "amazonses", "fastmail", "yandex", "rackspace", "icloud", "mimecast",
    "barracuda", "messagingengine.com",
)


async def _mx_origin(seed: str) -> dict:
    """Pull the seed's MX records and resolve each MX hostname's A records.
    Self-hosted mail co-located with origin web is common in small / scammy
    operations; we surface the IPs and flag known managed providers so the
    analyst doesn't chase Google's mail edges."""
    async with httpx.AsyncClient() as client:
        mx_answers = await _doh_resolve(client, seed, "MX")
        if not mx_answers:
            return {"records": []}
        # "10 mail.example.com." → "mail.example.com"
        mx_hosts: list[tuple[int, str]] = []
        for a in mx_answers:
            parts = a.split()
            if len(parts) == 2 and parts[0].isdigit():
                mx_hosts.append((int(parts[0]), parts[1].rstrip(".").lower()))
            else:
                mx_hosts.append((0, a.rstrip(".").lower()))
        mx_hosts.sort()

        async def _resolve_one(prio: int, host: str) -> dict:
            ips = await _doh_resolve(client, host, "A")
            managed = any(p in host for p in _MANAGED_MAIL_PROVIDERS)
            non_cdn_ips = [ip for ip in ips
                           if _valid_ip(ip) and not is_shared_cdn_ip(ip)]
            return {"priority": prio, "host": host, "ips": non_cdn_ips,
                    "managed": managed}

        rows = await asyncio.gather(*[_resolve_one(p, h) for p, h in mx_hosts],
                                     return_exceptions=True)
    out: list[dict] = []
    for r in rows:
        if isinstance(r, dict) and r.get("ips"):
            out.append(r)
    return {"records": out}


# ════════════════════════════════════════════════════════════════════
# Aggregator
# ════════════════════════════════════════════════════════════════════
async def discover_origin(
    seed: str,
    *,
    censys_id: str = "",
    censys_secret: str = "",
    shodan_key: str = "",
    vt_key: str = "",
    otx_key: str = "",
    ip_enricher: Any = None,
) -> dict:
    """Run all four techniques in parallel, aggregate candidates by IP, and
    score each by how many *independent* techniques surfaced it.

    ``ip_enricher`` is an optional ``async def(ip) -> dict`` that returns
    ASN / org / country for a given IP — used to flag candidate IPs that
    are themselves on another CDN (ATTACKER also using Akamai, etc.). If
    not provided, the candidates are returned without that enrichment.
    """
    cert_censys = _cert_search_censys(seed, censys_id, censys_secret)
    cert_shodan = _cert_search_shodan(seed, shodan_key)
    pdns        = _pdns_historical(seed, vt_key, otx_key)
    subleak     = _subdomain_leak(seed)
    mx          = _mx_origin(seed)
    cc, cs, pd, sl, mxr = await asyncio.gather(
        cert_censys, cert_shodan, pdns, subleak, mx, return_exceptions=True,
    )

    # Per-IP aggregation. ``agg[ip] = {ip, sources, evidence}`` so the
    # scoring loop can sort by # of distinct techniques per IP.
    agg: dict[str, dict] = {}

    def _add(ip: str, source: str, evidence: str) -> None:
        if not _valid_ip(ip) or is_shared_cdn_ip(ip):
            return
        e = agg.setdefault(ip, {"ip": ip, "sources": set(), "evidence": []})
        e["sources"].add(source)
        e["evidence"].append(evidence)

    techniques_run: list[dict] = []
    skipped: list[dict] = []

    # 1. Censys cert
    if isinstance(cc, dict):
        if cc.get("error"):
            skipped.append({"technique": "cert_censys", "reason": cc["error"]})
        for m in cc.get("matches") or []:
            _add(m["ip"], "cert_censys",
                 f"Censys: IP serves cert matching SAN {seed} (asn: {m.get('asn') or '?'})")
        techniques_run.append({"technique": "cert_censys",
                               "raw_total": cc.get("total", 0),
                               "kept": sum(1 for m in cc.get("matches") or []
                                            if not is_shared_cdn_ip(m["ip"]))})
    # 2. Shodan cert
    if isinstance(cs, dict):
        if cs.get("error"):
            skipped.append({"technique": "cert_shodan", "reason": cs["error"]})
        for m in cs.get("matches") or []:
            _add(m["ip"], "cert_shodan",
                 f"Shodan: IP serves TLS cert with CN={seed} (asn: {m.get('asn') or '?'})")
        techniques_run.append({"technique": "cert_shodan",
                               "raw_total": cs.get("total", 0),
                               "kept": sum(1 for m in cs.get("matches") or []
                                            if not is_shared_cdn_ip(m["ip"]))})
    # 3. pDNS historical
    if isinstance(pd, dict):
        if pd.get("error"):
            skipped.append({"technique": "pdns_historical", "reason": pd["error"]})
        for r in pd.get("records") or []:
            ts = r.get("last_seen") or "?"
            for src in r.get("sources") or ["pdns"]:
                _add(r["ip"], src,
                     f"Passive DNS ({src}): {seed} resolved to {r['ip']} (last seen {ts})")
        techniques_run.append({"technique": "pdns_historical",
                               "kept": len(pd.get("records") or [])})
    # 4. Subdomain leak
    if isinstance(sl, dict):
        for h in sl.get("hits") or []:
            _add(h["ip"], "subdomain_leak",
                 f"Subdomain bypass: {h['hostname']} resolves to {h['ip']}")
        techniques_run.append({"technique": "subdomain_leak",
                               "kept": len(sl.get("hits") or [])})
    # 5. MX
    if isinstance(mxr, dict):
        for r in mxr.get("records") or []:
            flag = "managed mail provider" if r.get("managed") else "self-hosted"
            for ip in r["ips"]:
                _add(ip, "mx_origin",
                     f"MX {r['host']} (prio {r['priority']}, {flag}) → {ip}")
        techniques_run.append({"technique": "mx_origin",
                               "kept": sum(len(r.get("ips") or [])
                                            for r in mxr.get("records") or [])})

    # Optional ASN enrichment in parallel
    candidates: list[dict] = list(agg.values())
    if ip_enricher and candidates:
        enrichments = await asyncio.gather(
            *[ip_enricher(c["ip"]) for c in candidates], return_exceptions=True,
        )
        for c, enr in zip(candidates, enrichments):
            if isinstance(enr, dict):
                c["asn"] = enr.get("as") or enr.get("asn") or ""
                c["isp"] = enr.get("isp") or enr.get("organization") or ""
                c["country"] = enr.get("countryCode") or enr.get("country") or ""

    # Score = # of distinct techniques that surfaced this IP. ≥2 = STRONG.
    for c in candidates:
        c["score"] = len(c["sources"])
        c["confidence"] = "strong" if c["score"] >= 2 else "lead"
        c["sources"] = sorted(c["sources"])

    candidates.sort(key=lambda c: (-c["score"], c["ip"]))

    return {
        "seed": seed,
        "candidates": candidates,
        "techniques_run": techniques_run,
        "skipped": skipped,
        "generated_at": int(time.time()),
    }
