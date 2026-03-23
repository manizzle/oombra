"""
Push notifications — Slack, PagerDuty, email.
When a webhook ingestion matches IOCs or finds gaps, notify the user
with actionable remediation intelligence.
"""
from __future__ import annotations



async def send_slack_notification(
    webhook_url: str,
    title: str,
    fields: list[dict],
    color: str = "#22c55e",
    footer: str = "nur — collective security intelligence",
) -> bool:
    """Send a Slack notification via incoming webhook."""
    import httpx

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title}
        },
        {"type": "divider"},
    ]

    for field in fields:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{field['label']}*\n{field['value']}"
            }
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": footer}]
    })

    payload = {"blocks": blocks}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            return resp.status_code == 200
    except Exception:
        return False


def build_remediation_notification(
    format_detected: str,
    items_stored: int,
    analysis: dict | None = None,
    engine_stats: dict | None = None,
) -> dict:
    """Build a notification payload from webhook ingestion results."""
    title = f"nur: {format_detected.title()} Detection Ingested"
    fields = [
        {"label": "Source", "value": format_detected},
        {"label": "Items Processed", "value": str(items_stored)},
    ]

    if analysis:
        intel = analysis.get("intelligence", {})

        # IOC matches
        shared = intel.get("shared_ioc_count", 0)
        if shared > 0:
            fields.append({
                "label": "Campaign Match",
                "value": f"{shared} IOCs match the collective — coordinated campaign detected"
            })
            ioc_dist = intel.get("ioc_type_distribution", {})
            if ioc_dist:
                dist_str = ", ".join(f"{k}: {v}" for k, v in ioc_dist.items())
                fields.append({"label": "IOC Types", "value": dist_str})

        # Detection gaps
        gaps = intel.get("detection_gaps", [])
        if gaps:
            gap_lines = []
            for g in gaps[:5]:
                gap_lines.append(f"• {g['technique_id']}: {g.get('frequency', '?')}x observed, {g.get('caught_by_count', '?')} tools detect it")
            fields.append({
                "label": f"Detection Gaps ({len(gaps)})",
                "value": "\n".join(gap_lines)
            })

        # Coverage score
        coverage = intel.get("coverage_score")
        if coverage is not None:
            pct = int(coverage * 100)
            fields.append({"label": "Coverage Score", "value": f"{pct}%"})

        # Remediation hints
        hints = intel.get("remediation_hints", {})
        if hints:
            cats = hints.get("most_effective_categories", [])
            if cats:
                best = cats[0]
                fields.append({
                    "label": "Recommended Remediation",
                    "value": f"{best['category'].title()} — {int(best['success_rate'] * 100)}% success rate across the collective"
                })

        # Actions
        actions = intel.get("actions", [])
        if actions:
            action_lines = []
            for a in actions[:3]:
                action_lines.append(f"[{a.get('priority', '?').upper()}] {a.get('action', '')}")
            fields.append({
                "label": "Recommended Actions",
                "value": "\n".join(action_lines)
            })

    if engine_stats:
        fields.append({
            "label": "Platform",
            "value": f"{engine_stats.get('total_contributions', 0)} contributions · {engine_stats.get('unique_vendors', 0)} vendors · Merkle root: {engine_stats.get('merkle_root', '?')[:16]}..."
        })

    return {"title": title, "fields": fields}
