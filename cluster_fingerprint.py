"""
Cluster Fingerprint — given N seeds believed to belong to the same campaign,
identify the single most discriminating characteristic they share so the
analyst can pivot to undiscovered infrastructure.

Pipeline:
    seeds → per-seed pipeline result (cached) → extract_features
         → rank_shared_features (prior × coverage, generic values dropped)
         → ranked list of (class, value, coverage, score, pivot_url)

This module is intentionally independent of crucible_app.py: the caller
injects an async ``pipeline_runner(seed) -> result_dict`` so this code can be
unit-tested in isolation and reused from a CLI later.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Awaitable, Callable, Iterable

import httpx

import cache_store
import pivot_intel


# ────────────────────────────────────────────────────────────────────
# Feature priors — higher = better pivot when shared across the cluster.
# Tuned for "if N seeds share this exact value, how unique to one actor
# is that?". A shared tracking ID is essentially a smoking gun; a shared
# country is almost meaningless.
# ────────────────────────────────────────────────────────────────────
FEATURE_PRIORS: dict[str, int] = {
    "tracking_id":      100,
    "body_sha256_norm":  90,
    "body_sha256":       85,
    "favicon_hash":      75,
    "jarm":              60,
    "cert_san_pattern":  55,
    "nameservers":       50,
    "cert_issuer_org":   45,
    "title":             40,
    "server_header":     30,
    "asn":               25,
    "registrar":         20,
    "country":           15,
}


# ────────────────────────────────────────────────────────────────────
# Generic-value blocklists — values so common they'd top the ranking
# at 100% coverage without telling the analyst anything useful.
# Checked case-insensitively against the trimmed value.
# ────────────────────────────────────────────────────────────────────
_GENERIC_VALUES: dict[str, set[str]] = {
    "favicon_hash": {"0", ""},
    "title":        {"", "index of /", "welcome to nginx!", "apache2 ubuntu default page",
                     "it works!", "default web site page", "test page for the apache http server",
                     "401 unauthorized", "403 forbidden", "404 not found"},
    "server_header": {"", "cloudflare", "nginx", "apache", "microsoft-iis", "litespeed",
                      "openresty", "awselb/2.0", "akamaighost"},
    "body_sha256":      {""},
    "body_sha256_norm": {""},
    "jarm":             {"", "00000000000000000000000000000000000000000000000000000000000000"},
    "cert_issuer_org":  {"", "let's encrypt", "lets encrypt", "google trust services llc",
                         "google trust services", "cloudflare, inc.", "amazon", "digicert inc",
                         "sectigo limited", "zerossl"},
    "nameservers":  {"", "cloudflare.com", "awsdns", "googledomains.com"},
    "registrar":    {"", "?", "unknown"},
    "country":      {"", "?", "unknown"},
    "asn":          {"", "?", "as13335 cloudflarenet", "as16509 amazon-02",
                     "as14618 amazon-aes", "as15169 google llc", "as8075 microsoft"},
    "tracking_id":  {""},
    "cert_san_pattern": {""},
}


# ────────────────────────────────────────────────────────────────────
# Pivot URL templates — one per feature class. {value} is URL-escaped
# by the caller path; {value_12} = first 12 chars of the value (used
# for publicwww which accepts substring searches and won't match a
# full 64-char SHA-256 reliably).
# ────────────────────────────────────────────────────────────────────
PIVOT_TEMPLATES: dict[str, str] = {
    "favicon_hash":     'https://www.shodan.io/search?query=http.favicon.hash:{value}',
    "jarm":             'https://search.censys.io/search?resource=hosts&q=services.jarm.fingerprint:"{value}"',
    "body_sha256_norm": 'https://publicwww.com/websites/"{value_12}"/',
    "body_sha256":      'https://publicwww.com/websites/"{value_12}"/',
    "tracking_id":      'https://publicwww.com/websites/"{value}"/',
    "server_header":    'https://www.shodan.io/search?query=http.headers.server:"{value}"',
    "title":            'https://www.shodan.io/search?query=http.title:"{value}"',
    "nameservers":      'https://search.censys.io/search?resource=hosts&q=names:"{value}"',
    "cert_issuer_org":  'https://crt.sh/?q={value}',
    "cert_san_pattern": 'https://crt.sh/?q={value}',
}


# ────────────────────────────────────────────────────────────────────
# Feature extraction — pull (class, value) tuples out of one pipeline
# result dict. Values are normalized (lowercased, trimmed) so the same
# string from two seeds collapses to one bucket.
# ────────────────────────────────────────────────────────────────────
def _norm(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip().lower()
    return s


def extract_features(result: dict) -> list[tuple[str, str]]:
    """Pull discriminating features from a single seed's pipeline result.

    Returns a list of (feature_class, normalized_value) tuples. A seed
    may contribute multiple values for the same class (e.g. several
    tracking IDs, several JARMs across endpoints) — each one counts
    once for that seed when ranking."""
    feats: list[tuple[str, str]] = []
    if not isinstance(result, dict):
        return feats

    fp = result.get("pivot_fingerprint") or {}
    if isinstance(fp, dict):
        for cls, key in (
            ("favicon_hash",     "favicon_hash"),
            ("body_sha256",      "body_sha256"),
            ("body_sha256_norm", "body_sha256_norm"),
            ("title",            "title"),
            ("server_header",    "server"),
        ):
            v = _norm(fp.get(key))
            if v:
                feats.append((cls, v))
        for tid in fp.get("tracking_ids") or []:
            v = _norm(tid.get("value") if isinstance(tid, dict) else tid)
            if v:
                feats.append(("tracking_id", v))

    for j in result.get("jarms") or []:
        v = _norm(j)
        if v:
            feats.append(("jarm", v))

    rdap = result.get("rdap") or {}
    if isinstance(rdap, dict):
        reg = _norm(rdap.get("registrar"))
        if reg and reg != "?":
            feats.append(("registrar", reg))
        # rdap["nameservers"] is stored as a comma-joined string
        ns_field = rdap.get("nameservers") or ""
        for ns in re.split(r"[,\s]+", ns_field):
            ns_n = _norm(ns)
            if ns_n:
                feats.append(("nameservers", ns_n))

    for asn_entry in result.get("asn_data") or []:
        if not isinstance(asn_entry, dict):
            continue
        v = _norm(asn_entry.get("as"))
        if v and v != "?":
            feats.append(("asn", v))
        c = _norm(asn_entry.get("countryCode") or asn_entry.get("country"))
        if c and c != "?":
            feats.append(("country", c))

    for cert in result.get("certs") or []:
        if not isinstance(cert, dict):
            continue
        issuer = (cert.get("issuer") or {}) if isinstance(cert.get("issuer"), dict) else {}
        iorg = _norm(issuer.get("O") or issuer.get("organization") or cert.get("issuer_org"))
        if iorg:
            feats.append(("cert_issuer_org", iorg))
        for san in cert.get("sans") or cert.get("san") or []:
            pattern = _san_to_pattern(_norm(san))
            if pattern:
                feats.append(("cert_san_pattern", pattern))

    # Deduplicate within a single seed — a seed that lists "ns1.example.com"
    # twice should still count as one for coverage purposes.
    return list(dict.fromkeys(feats))


_SAN_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def _san_to_pattern(san: str) -> str:
    """Reduce a SAN to a stable cluster pattern. ``*.actor.com`` and
    ``mail.actor.com`` both collapse to ``*.actor.com`` so two seeds in
    the same registered domain share a feature even if their concrete
    SAN strings differ."""
    if not san or "." not in san:
        return ""
    if san.startswith("*."):
        return san
    labels = san.split(".")
    if len(labels) < 2:
        return ""
    # naive eTLD+1: take the last two labels; good enough for clustering
    # within a campaign since most actors register under a single TLD.
    base = ".".join(labels[-2:])
    if not all(_SAN_LABEL_RE.match(l) for l in labels[-2:]):
        return ""
    return f"*.{base}"


# ────────────────────────────────────────────────────────────────────
# Ranking
# ────────────────────────────────────────────────────────────────────
def rank_shared_features(per_seed_features: list[list[tuple[str, str]]]) -> list[dict]:
    """Score every (class, value) by ``prior × coverage_fraction``.

    A feature is included only if (a) shared by ≥2 seeds and (b) the
    value is not in that class's generic blocklist. Singleton features
    are dropped — they don't help cluster pivoting."""
    n = len(per_seed_features)
    if n < 2:
        return []

    counts: dict[tuple[str, str], int] = {}
    for feats in per_seed_features:
        for fv in set(feats):
            counts[fv] = counts.get(fv, 0) + 1

    ranked: list[dict] = []
    for (cls, val), count in counts.items():
        if count < 2:
            continue
        blocked = _GENERIC_VALUES.get(cls, set())
        if val in blocked:
            continue
        prior = FEATURE_PRIORS.get(cls, 10)
        coverage = count / n
        ranked.append({
            "class":     cls,
            "value":     val,
            "count":     count,
            "coverage":  round(coverage, 4),
            "score":     round(prior * coverage, 2),
            "pivot_url": _pivot_url(cls, val),
        })

    ranked.sort(key=lambda r: (-r["score"], -r["count"], r["class"]))
    return ranked


def _pivot_url(cls: str, value: str) -> str | None:
    tpl = PIVOT_TEMPLATES.get(cls)
    if not tpl:
        return None
    from urllib.parse import quote
    return tpl.format(value=quote(value, safe=""), value_12=quote(value[:12], safe=""))


# ────────────────────────────────────────────────────────────────────
# Orchestrator
# ────────────────────────────────────────────────────────────────────
PipelineRunner = Callable[[str], Awaitable[dict]]


async def cluster_fingerprint(
    seeds: Iterable[str],
    pipeline_runner: PipelineRunner,
    cache_ttl_hours: float = 24.0,
    settings_hash: str = "",
    max_concurrency: int = 4,
) -> dict:
    """Run the pipeline for each seed (cached) and return ranked shared features.

    ``pipeline_runner`` is an async function the caller supplies that, given
    a domain, returns the same dict ``run_standard_pipeline`` would produce —
    typically a thin wrapper that drains the SSE generator and parses the
    terminal ``complete`` event.
    """
    seed_list = [s.strip().lower() for s in seeds if s and s.strip()]
    seed_list = list(dict.fromkeys(seed_list))  # dedupe, preserve order
    if not seed_list:
        return {"seeds": [], "ranked": [], "generated_at": int(time.time())}

    sem = asyncio.Semaphore(max(1, max_concurrency))

    async def _one(seed: str) -> tuple[str, dict, bool, int | None]:
        cached = cache_store.get_pipeline_result(seed, settings_hash, cache_ttl_hours) \
            if settings_hash else None
        if cached is not None:
            return seed, cached, True, cached.get("_cached_at")
        async with sem:
            result = await pipeline_runner(seed)
        if isinstance(result, dict) and settings_hash:
            cache_store.put_pipeline_result(seed, settings_hash, result)
        return seed, (result or {}), False, None

    pairs = await asyncio.gather(*[_one(s) for s in seed_list], return_exceptions=True)

    per_seed_features: list[list[tuple[str, str]]] = []
    seed_meta: list[dict] = []
    for item in pairs:
        if isinstance(item, BaseException):
            seed_meta.append({"seed": "?", "cache_hit": False, "cached_at": None,
                              "error": str(item), "feature_count": 0})
            continue
        seed, result, hit, cached_at = item
        feats = extract_features(result)
        per_seed_features.append(feats)
        seed_meta.append({
            "seed": seed,
            "cache_hit": hit,
            "cached_at": cached_at,
            "feature_count": len(feats),
            "error": result.get("error") if isinstance(result, dict) else None,
        })

    ranked = rank_shared_features(per_seed_features)
    return {
        "seeds": seed_meta,
        "ranked": ranked,
        "settings_hash": settings_hash or None,
        "ttl_hours": cache_ttl_hours,
        "generated_at": int(time.time()),
    }


# ════════════════════════════════════════════════════════════════════
# CLUSTER EXPANSION
# ════════════════════════════════════════════════════════════════════
#
# Take the ranked output of ``cluster_fingerprint`` and use the strongest
# shared features to query Shodan / Censys / crt.sh / HackerTarget for
# additional hosts. Each candidate is scored by how many of the top
# features it independently matches — a host that matches 2+ is a
# strong cluster member; 1 is a lead.
#
# Safety knobs that matter:
#   • ``per_feature_cap`` — if a single pivot returns more than this many
#     hosts, the feature was actually generic (CDN favicon, shared cert
#     org) and we drop it rather than poison the candidate list with
#     thousands of unrelated entries.
#   • ``max_features`` — total pivots issued, capped to control API spend.
#     Only ranked features in PIVOTABLE_CLASSES count toward this budget;
#     non-API features (body hash, tracking ID) are silently skipped.

PIVOTABLE_CLASSES: tuple[str, ...] = (
    "favicon_hash",
    "jarm",
    "cert_san_pattern",
    "nameservers",
    "tracking_id",
)


async def _shodan_jarm_pivot(jarm: str, api_key: str, limit: int = 40) -> dict:
    """Query Shodan for hosts whose TLS stack matches a JARM fingerprint.
    Shodan indexes JARM under ``ssl.jarm:<hex>``. Mirrors the shape of
    ``pivot_intel.shodan_favicon_pivot`` so the aggregator can treat them
    interchangeably."""
    if not api_key:
        return {"value": jarm, "matches": [], "error": "Shodan API key not configured"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(pivot_intel.SHODAN_SEARCH_URL,
                params={"key": api_key, "query": f"ssl.jarm:{jarm}", "minify": "true"})
            if r.status_code in (401, 402, 403):
                return {"value": jarm, "matches": [], "total": 0,
                        "error": f"Shodan: {r.status_code} (membership/key)"}
            if r.status_code != 200:
                return {"value": jarm, "matches": [], "total": 0,
                        "error": f"Shodan HTTP {r.status_code}"}
            data = r.json() or {}
            matches = []
            for m in (data.get("matches") or [])[:limit]:
                for h in (m.get("hostnames") or [])[:4]:
                    matches.append({"host": h, "ip": m.get("ip_str")})
                if not m.get("hostnames"):
                    matches.append({"host": m.get("ip_str"), "ip": m.get("ip_str")})
            return {"value": jarm, "matches": matches, "total": data.get("total", 0)}
    except Exception as e:
        return {"value": jarm, "matches": [], "total": 0, "error": f"Shodan query failed: {e}"}


async def _crtsh_san_pivot(san_pattern: str, limit: int = 200) -> dict:
    """Pivot a SAN pattern (e.g. ``*.actor.com``) to other certs/domains
    via crt.sh. crt.sh accepts SQL-LIKE wildcards via ``%`` rather than
    ``*``. The returned ``name_value`` field can contain multiple SAN
    entries separated by newlines — we expand them."""
    if not san_pattern or "." not in san_pattern:
        return {"value": san_pattern, "matches": [], "total": 0, "error": "empty pattern"}
    query = san_pattern.replace("*.", "%.").replace("*", "%")
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.get("https://crt.sh/",
                params={"q": query, "output": "json"})
            if r.status_code != 200:
                return {"value": san_pattern, "matches": [], "total": 0,
                        "error": f"crt.sh HTTP {r.status_code}"}
            rows = r.json() or []
    except Exception as e:
        return {"value": san_pattern, "matches": [], "total": 0,
                "error": f"crt.sh query failed: {e}"}

    seen: set[str] = set()
    matches: list[dict] = []
    base_root = san_pattern.replace("*.", "").lower()
    for row in rows:
        names = (row.get("name_value") or "").split("\n")
        for name in names:
            n = name.strip().lower().lstrip("*.")
            if not n or "." not in n:
                continue
            # exclude entries that are the root domain itself or an exact match
            # of the unwildcard form — we want *new* hostnames.
            if n == base_root or n in seen:
                continue
            seen.add(n)
            matches.append({"host": n, "source": "crtsh"})
            if len(matches) >= limit:
                break
        if len(matches) >= limit:
            break
    return {"value": san_pattern, "matches": matches, "total": len(seen)}


async def _favicon_pivot_combined(
    favicon_hash: str, shodan_key: str,
    censys_id: str, censys_secret: str, limit: int = 40,
) -> dict:
    """Run Shodan + Censys favicon pivots in parallel and union their hosts.
    Reports total across both, source per host so the UI can show provenance."""
    try:
        h_int = int(favicon_hash)
    except (TypeError, ValueError):
        return {"value": favicon_hash, "matches": [], "total": 0,
                "error": "favicon hash is not an integer"}

    sh_task = pivot_intel.shodan_favicon_pivot(h_int, shodan_key, limit=limit)
    cs_task = pivot_intel.censys_favicon_pivot(h_int, censys_id, censys_secret, limit=limit)
    sh, cs = await asyncio.gather(sh_task, cs_task, return_exceptions=True)

    matches: list[dict] = []
    errors: list[str] = []
    total = 0

    def _consume(res: Any, source: str) -> None:
        nonlocal total
        if isinstance(res, BaseException):
            errors.append(f"{source}: {res}")
            return
        if not isinstance(res, dict):
            return
        if res.get("error"):
            errors.append(f"{source}: {res['error']}")
        total = max(total, int(res.get("total") or 0))
        for m in res.get("matches") or []:
            for h in (m.get("hostnames") or [])[:4]:
                matches.append({"host": h, "ip": m.get("ip"), "source": source})
            if not m.get("hostnames") and m.get("ip"):
                matches.append({"host": m["ip"], "ip": m["ip"], "source": source})

    _consume(sh, "shodan")
    _consume(cs, "censys")

    out = {"value": favicon_hash, "matches": matches, "total": total}
    if errors:
        out["error"] = " · ".join(errors)
    return out


_TRACKING_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9-]+)+$")


async def _urlscan_tracking_pivot(value: str, api_key: str = "", limit: int = 200) -> dict:
    """Search urlscan.io's public scan corpus for pages whose HTML contains the
    given tracking ID (UA-xxx, G-xxx, GTM-xxx, etc.). Free without a key at
    low rate; a key raises the per-minute quota."""
    if not value:
        return {"value": value, "matches": [], "total": 0, "error": "empty value"}
    headers = {"API-Key": api_key} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            r = await client.get("https://urlscan.io/api/v1/search/",
                params={"q": f'page.html:"{value}"', "size": min(10000, limit)})
            if r.status_code == 429:
                return {"value": value, "matches": [], "total": 0,
                        "error": "urlscan: rate-limited (add API key for higher quota)"}
            if r.status_code != 200:
                return {"value": value, "matches": [], "total": 0,
                        "error": f"urlscan HTTP {r.status_code}"}
            data = r.json() or {}
    except Exception as e:
        return {"value": value, "matches": [], "total": 0,
                "error": f"urlscan query failed: {e}"}

    seen: set[str] = set()
    matches: list[dict] = []
    for hit in (data.get("results") or [])[:limit]:
        host = ((hit.get("page") or {}).get("domain") or "").strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        if not _TRACKING_HOST_RE.match(host):
            continue
        seen.add(host)
        matches.append({"host": host, "source": "urlscan"})
    return {"value": value, "matches": matches, "total": int(data.get("total") or len(matches))}


async def _spyonweb_tracking_pivot(value: str, api_key: str, limit: int = 200) -> dict:
    """SpyOnWeb reverse-lookup for an Analytics / AdSense ID. The documented
    JSON API needs a free access token; without one we surface a clear note
    rather than scraping the web UI."""
    if not value:
        return {"value": value, "matches": [], "total": 0, "error": "empty value"}
    if not api_key:
        return {"value": value, "matches": [], "total": 0,
                "error": "SpyOnWeb access token not configured — pivot skipped"}

    # SpyOnWeb routes by ID type. UA-xxx / G-xxx → /analytics; pub-xxx → /adsense.
    v = value.strip()
    lower = v.lower()
    if lower.startswith("pub-") or lower.startswith("ca-pub-"):
        path = "adsense"
    else:
        path = "analytics"
    url = f"https://api.spyonweb.com/v1/{path}/{v}"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, params={"access_token": api_key})
            if r.status_code in (401, 403):
                return {"value": v, "matches": [], "total": 0,
                        "error": "SpyOnWeb: unauthorized (bad token)"}
            if r.status_code == 429:
                return {"value": v, "matches": [], "total": 0,
                        "error": "SpyOnWeb: quota exceeded"}
            if r.status_code != 200:
                return {"value": v, "matches": [], "total": 0,
                        "error": f"SpyOnWeb HTTP {r.status_code}"}
            data = r.json() or {}
    except Exception as e:
        return {"value": v, "matches": [], "total": 0,
                "error": f"SpyOnWeb query failed: {e}"}

    if data.get("status") != "found":
        return {"value": v, "matches": [], "total": 0,
                "note": data.get("status") or "no result"}

    items = (((data.get("result") or {}).get(path) or {}).get(v) or {}).get("items") or {}
    matches: list[dict] = []
    for host in list(items.keys())[:limit]:
        h = host.strip().lower().rstrip(".")
        if h and _TRACKING_HOST_RE.match(h):
            matches.append({"host": h, "source": "spyonweb"})
    return {"value": v, "matches": matches, "total": len(items)}


async def _tracking_pivot_combined(value: str, urlscan_key: str, spyonweb_key: str,
                                   limit: int = 200) -> dict:
    """Run urlscan + SpyOnWeb in parallel and union hosts. AnalyzeID is
    intentionally not wired in: it has no documented public API, and
    scraping the web UI is brittle + ToS-risky. The manual pivot URL in the
    cluster rank table still points the analyst at it for one-off checks."""
    u_task = _urlscan_tracking_pivot(value, urlscan_key, limit=limit)
    s_task = _spyonweb_tracking_pivot(value, spyonweb_key, limit=limit)
    u, s = await asyncio.gather(u_task, s_task, return_exceptions=True)

    matches: list[dict] = []
    errors: list[str] = []
    total = 0

    def _consume(res: Any, source: str) -> None:
        nonlocal total
        if isinstance(res, BaseException):
            errors.append(f"{source}: {res}")
            return
        if not isinstance(res, dict):
            return
        if res.get("error"):
            errors.append(f"{source}: {res['error']}")
        total = max(total, int(res.get("total") or 0))
        for m in res.get("matches") or []:
            host = (m.get("host") or "").strip().lower()
            if host:
                matches.append({"host": host, "source": source})

    _consume(u, "urlscan")
    _consume(s, "spyonweb")

    out = {"value": value, "matches": matches, "total": total}
    if errors:
        out["error"] = " · ".join(errors)
    return out


async def _nameserver_pivot(ns_value: str) -> dict:
    """One nameserver → reverse-NS hosts (HackerTarget). The cluster
    ranker emits one row per NS, so we wrap one at a time and rely on the
    candidate-aggregation step to union hosts across multiple NS pivots."""
    res = await pivot_intel.fetch_reverse_ns([ns_value])
    flat = res.get("flat") or []
    matches = [{"host": r["hostname"], "source": "hackertarget"} for r in flat]
    out = {"value": ns_value, "matches": matches, "total": len(flat)}
    err_bits = [e.get("error") for e in (res.get("per_ns") or []) if e.get("error")]
    if err_bits:
        out["error"] = " · ".join(err_bits)
    return out


async def expand_cluster(
    ranked: list[dict],
    exclude_hosts: Iterable[str] = (),
    *,
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    urlscan_key: str = "",
    spyonweb_key: str = "",
    max_features: int = 5,
    per_feature_cap: int = 2000,
    matches_per_feature: int = 200,
) -> dict:
    """Auto-pivot on the top shared features to surface additional hosts.

    Returns:
        {
          candidates: [{host, score, matched_features:[class], sources:[name]}],
          pivoted_features: [{class, value, total, contributed}],
          skipped_features: [{class, value, reason}],
          generated_at: epoch_seconds,
        }
    """
    exclude = {h.strip().lower() for h in exclude_hosts if h and h.strip()}

    # Pick the highest-scoring features we know how to query, capped by
    # ``max_features``. Non-pivotable features (body hash, tracking ID, etc.)
    # are silently bypassed — they remain in the rank table with a manual
    # pivot URL for the analyst to follow by hand.
    candidates_to_pivot: list[dict] = []
    for r in ranked:
        if r.get("class") not in PIVOTABLE_CLASSES:
            continue
        candidates_to_pivot.append(r)
        if len(candidates_to_pivot) >= max_features:
            break

    pivot_tasks: list[Awaitable[dict]] = []
    for r in candidates_to_pivot:
        cls, val = r["class"], r["value"]
        if cls == "favicon_hash":
            pivot_tasks.append(_favicon_pivot_combined(
                val, shodan_key, censys_id, censys_secret, limit=matches_per_feature))
        elif cls == "jarm":
            pivot_tasks.append(_shodan_jarm_pivot(val, shodan_key, limit=matches_per_feature))
        elif cls == "cert_san_pattern":
            pivot_tasks.append(_crtsh_san_pivot(val, limit=matches_per_feature))
        elif cls == "nameservers":
            pivot_tasks.append(_nameserver_pivot(val))
        elif cls == "tracking_id":
            pivot_tasks.append(_tracking_pivot_combined(
                val, urlscan_key, spyonweb_key, limit=matches_per_feature))

    results = await asyncio.gather(*pivot_tasks, return_exceptions=True)

    # Aggregate: host → which feature-classes matched, which sources
    agg: dict[str, dict] = {}
    pivoted_meta: list[dict] = []
    skipped: list[dict] = []

    for r, res in zip(candidates_to_pivot, results):
        cls, val = r["class"], r["value"]
        if isinstance(res, BaseException):
            skipped.append({"class": cls, "value": val, "reason": f"pivot raised: {res}"})
            continue
        if not isinstance(res, dict):
            skipped.append({"class": cls, "value": val, "reason": "no result"})
            continue
        err = res.get("error")
        total = int(res.get("total") or 0)
        matches = res.get("matches") or []

        # Generic-feature explosion guard: if the upstream reports more
        # than ``per_feature_cap`` hits, the feature was not actually
        # discriminating — drop it entirely rather than spray the candidate
        # list with a CDN's tenants.
        if total > per_feature_cap:
            skipped.append({"class": cls, "value": val,
                            "reason": f"too generic ({total} upstream hits > cap {per_feature_cap})"})
            continue

        contributed = 0
        for m in matches:
            host = (m.get("host") or "").strip().lower().rstrip(".")
            if not host or host in exclude:
                continue
            src = m.get("source") or _DEFAULT_SOURCE.get(cls, cls)
            entry = agg.setdefault(host, {"host": host,
                                          "matched_features": set(),
                                          "sources": set(),
                                          "evidence": []})
            if cls not in entry["matched_features"]:
                entry["evidence"].append({"class": cls, "value": val, "source": src})
            entry["matched_features"].add(cls)
            entry["sources"].add(src)
            contributed += 1

        pivoted_meta.append({"class": cls, "value": val,
                             "total": total, "returned": len(matches),
                             "contributed": contributed,
                             "error": err})

    candidates: list[dict] = []
    for entry in agg.values():
        score = len(entry["matched_features"])
        candidates.append({
            "host": entry["host"],
            "score": score,
            "strength": "strong" if score >= 2 else "lead",
            "matched_features": sorted(entry["matched_features"]),
            "sources": sorted(entry["sources"]),
            "evidence": entry["evidence"],
        })
    # Strongest first, then alphabetical for stability
    candidates.sort(key=lambda c: (-c["score"], c["host"]))

    return {
        "candidates": candidates,
        "pivoted_features": pivoted_meta,
        "skipped_features": skipped,
        "max_features": max_features,
        "per_feature_cap": per_feature_cap,
        "generated_at": int(time.time()),
    }


_DEFAULT_SOURCE: dict[str, str] = {
    "favicon_hash":     "shodan/censys",
    "jarm":             "shodan",
    "cert_san_pattern": "crtsh",
    "nameservers":      "hackertarget",
    "tracking_id":      "urlscan/spyonweb",
}
