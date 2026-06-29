"""
crucible.alerting
=================

Slack-webhook dispatcher for hunt matches + manual attributions. Reads
SLACK_WEBHOOK_URL from the environment at call time so a webhook added to
.env mid-session is picked up on the next dispatch (no restart needed).

Empty webhook = silently disabled. Matches still queue in SQLite and
appear in the UI; only the Slack notification is suppressed.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


_SEVERITY_COLOR = {
    "critical": "#cc1f1a",
    "high":     "#f2a52b",
    "medium":   "#2eb886",
    "low":      "#7f8a99",
    "":         "#7f8a99",
}


def _webhook_url() -> str:
    return os.environ.get("SLACK_WEBHOOK_URL", "").strip()


def alerting_enabled() -> bool:
    return bool(_webhook_url())


async def _post(blocks_payload: dict[str, Any]) -> bool:
    url = _webhook_url()
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, json=blocks_payload)
            # Slack returns "ok" on success and a text error on failure.
            return r.status_code == 200 and r.text.strip() == "ok"
    except Exception:
        return False


def _trim(s: str, limit: int = 200) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


async def dispatch_match_alert(*, rule: dict, match: dict,
                               profile: dict | None,
                               base_url: str = "http://localhost:8000") -> bool:
    """Fire a Slack alert for a new hunt match. Returns True on success,
    False on either send failure or alerting disabled."""
    if not alerting_enabled():
        return False
    sev = (profile or {}).get("severity") or "medium"
    color = _SEVERITY_COLOR.get(sev, "#2eb886")
    rule_name = rule.get("name") or f"rule#{rule.get('id')}"
    profile_name = (profile or {}).get("name") or "unattributed"
    matched = match.get("matched_value") or "?"
    source = match.get("source") or "?"

    fired_predicates = (match.get("evidence") or {}).get("predicates") or []
    pred_lines = []
    for p in fired_predicates[:6]:
        pred_lines.append(
            f"• `{p.get('field')}` {p.get('op')} `{_trim(str(p.get('value')), 60)}`"
            f" → `{_trim(str(p.get('matched_against')), 60)}`"
        )
    pred_text = "\n".join(pred_lines) or "_no predicate evidence captured_"

    queue_url = f"{base_url}/#hunts-queue/{match.get('id')}"
    vt_url = (
        f"https://www.virustotal.com/gui/domain/{matched}"
        if matched and "/" not in matched else ""
    )

    payload = {
        "attachments": [{
            "color": color,
            "fallback": f"Hunt match: {rule_name} → {matched}",
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": f"🔎  Hunt match — {rule_name}"}},
                {"type": "section",
                 "fields": [
                    {"type": "mrkdwn",
                     "text": f"*Matched value*\n`{_trim(matched, 100)}`"},
                    {"type": "mrkdwn",
                     "text": f"*Profile*\n{profile_name}"},
                    {"type": "mrkdwn", "text": f"*Source*\n{source}"},
                    {"type": "mrkdwn",
                     "text": f"*Severity*\n{sev or '—'}"},
                 ]},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*Predicates fired:*\n{pred_text}"}},
                {"type": "actions", "elements": [
                    {"type": "button",
                     "text": {"type": "plain_text", "text": "Review queue"},
                     "url": queue_url},
                    *([{"type": "button",
                        "text": {"type": "plain_text", "text": "Open in VT"},
                        "url": vt_url}] if vt_url else []),
                ]},
            ],
        }],
    }
    return await _post(payload)


async def dispatch_attribution_alert(*, profile: dict, evidence: dict,
                                     source_seed: str = "",
                                     base_url: str = "http://localhost:8000",
                                     ) -> bool:
    """Fire a Slack alert when an analyst attributes evidence to a profile.
    Useful when running with a team — keeps everyone in the loop."""
    if not alerting_enabled():
        return False
    sev = profile.get("severity") or "medium"
    color = _SEVERITY_COLOR.get(sev, "#2eb886")
    headline = (evidence or {}).get("finding") \
        or (evidence or {}).get("title") \
        or "Evidence attached"
    profile_url = f"{base_url}/#actors/{profile.get('id')}"

    payload = {
        "attachments": [{
            "color": color,
            "fallback": f"Attribution: {headline}",
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": f"📎  Attribution — {profile.get('name','?')}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Finding*\n{_trim(headline, 200)}"},
                    {"type": "mrkdwn",
                     "text": f"*Seed*\n`{_trim(source_seed or '—', 100)}`"},
                    {"type": "mrkdwn",
                     "text": f"*Severity*\n{sev or '—'}"},
                ]},
                {"type": "actions", "elements": [
                    {"type": "button",
                     "text": {"type": "plain_text", "text": "Open profile"},
                     "url": profile_url},
                ]},
            ],
        }],
    }
    return await _post(payload)


async def dispatch_test_message() -> bool:
    """Send a one-line test ping to the configured webhook so the analyst
    can confirm the wiring works."""
    if not alerting_enabled():
        return False
    payload = {
        "text": ":satellite_antenna: Crucible alerting webhook test — "
                "if you see this, Slack is wired up correctly.",
    }
    return await _post(payload)
