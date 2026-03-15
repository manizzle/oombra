"""
Actionable intelligence analysis — the core value proposition.

Takes a contribution, stores it, then cross-references against the collective
intelligence DB to return prioritized actions.
"""
from __future__ import annotations

import json
from typing import Any

from .db import Database


def detect_contribution_type(data: dict[str, Any]) -> str:
    """Detect the contribution type from the payload shape."""
    if "iocs" in data:
        return "ioc_bundle"
    if "techniques" in data:
        return "attack_map"
    if "vendor" in data or data.get("data", {}).get("vendor"):
        return "eval"
    raise ValueError("Cannot detect contribution type: missing 'iocs', 'techniques', or 'vendor' key")


async def analyze_ioc_bundle(data: dict[str, Any], db: Database) -> dict:
    """Analyze an IOC bundle against collective intelligence."""
    # Store the contribution first
    cid = await db.store_ioc_bundle(data)

    # Extract submitted hashes
    iocs = data.get("iocs", [])
    hashes = [ioc.get("value_hash", "") for ioc in iocs if ioc.get("value_hash")]

    # Find matches in existing DB (exclude the contribution we just stored)
    matches = await db.get_ioc_matches(hashes, exclude_contribution_id=cid) if hashes else []

    # Deduplicate: only count IOCs from OTHER contributions (not the one we just stored)
    shared_ioc_count = len(matches)
    threat_actors = list({m["threat_actor"] for m in matches if m.get("threat_actor")})
    campaigns = list({m["campaign"] for m in matches if m.get("campaign")})

    if shared_ioc_count == 0:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "intelligence": {
                "campaign_match": False,
                "campaign_summary": (
                    "No matching IOCs found in collective intelligence. "
                    "Your contribution has been stored and will help future analyses."
                ),
                "shared_ioc_count": 0,
                "threat_actors": [],
                "actions": [],
            },
        }

    # Build campaign summary
    actor_str = ", ".join(threat_actors) if threat_actors else "unknown threat actors"
    campaign_str = ", ".join(campaigns) if campaigns else "unnamed campaigns"
    summary = (
        f"Your IOCs match {shared_ioc_count} indicators seen by other organizations. "
        f"Associated threat actors: {actor_str}. Campaigns: {campaign_str}."
    )

    # Build actions
    actions = []
    if threat_actors:
        domain_matches = sum(1 for m in matches if m.get("ioc_type") == "domain")
        ip_matches = sum(1 for m in matches if m.get("ioc_type") == "ip")
        if domain_matches > 0 or ip_matches > 0:
            actions.append({
                "priority": "critical",
                "action": "Block C2 domains/IPs at firewall and DNS",
                "detail": (
                    f"{domain_matches + ip_matches} network IOCs match known "
                    f"{actor_str} infrastructure seen across multiple orgs"
                ),
            })

    actions.append({
        "priority": "high",
        "action": "Hunt for related activity in your environment",
        "detail": (
            f"Cross-reference the {shared_ioc_count} matched IOCs with your "
            f"SIEM/EDR logs for the last 30 days"
        ),
    })

    actions.append({
        "priority": "medium",
        "action": "Share findings with your sector ISAC",
        "detail": (
            f"Campaign correlation suggests coordinated activity — "
            f"sector-level sharing accelerates collective defense"
        ),
    })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "intelligence": {
            "campaign_match": True,
            "campaign_summary": summary,
            "shared_ioc_count": shared_ioc_count,
            "threat_actors": threat_actors,
            "actions": actions,
        },
    }


async def analyze_attack_map(data: dict[str, Any], db: Database) -> dict:
    """Analyze an attack map against collective technique data."""
    # Store the contribution first
    cid = await db.store_attack_map(data)

    tools = data.get("tools_in_scope", [])
    if isinstance(tools, str):
        tools = json.loads(tools)

    # Find techniques that our tools miss (exclude current contribution)
    gaps = await db.get_techniques_for_tools(tools, exclude_contribution_id=cid) if tools else []

    # Get top techniques for context
    top_techniques = await db.get_top_techniques(50)
    top_ids = {t["technique_id"] for t in top_techniques}
    techniques_seen = [t["technique_id"] for t in top_techniques]

    if not gaps:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "intelligence": {
                "detection_gaps": [],
                "coverage_score": 1.0,
                "techniques_seen_by_others": techniques_seen,
                "actions": [
                    {
                        "priority": "info",
                        "action": "Coverage looks good",
                        "detail": (
                            "No detection gaps found for your tools based on current "
                            "collective intelligence. Continue monitoring for new threats."
                        ),
                    }
                ],
            },
        }

    # Build detection gaps
    detection_gaps = []
    seen_ids = set()
    for g in gaps:
        tid = g["technique_id"]
        if tid in seen_ids:
            continue
        seen_ids.add(tid)
        caught_by = [t for t in g.get("detected_by", []) if t.lower() not in {t2.lower() for t2 in tools}]
        detection_gaps.append({
            "technique_id": tid,
            "technique_name": g.get("technique_name", ""),
            "your_tools_miss": True,
            "caught_by": caught_by,
            "recommendation": (
                f"Add detection rule for {g.get('technique_name', tid)}. "
                f"{'Tools that catch it: ' + ', '.join(caught_by) + '.' if caught_by else 'No known tool detections — consider custom Sigma rule.'}"
            ),
        })

    # Coverage score
    coverage_score = round(
        max(0.0, 1.0 - (len(detection_gaps) / max(len(top_techniques), 1))),
        2,
    )

    # Build actions
    actions = []
    for i, gap in enumerate(detection_gaps[:5]):
        priority = "critical" if i == 0 else "high" if i < 3 else "medium"
        actions.append({
            "priority": priority,
            "action": f"Deploy {gap['technique_id']} detection",
            "detail": gap["recommendation"],
        })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "intelligence": {
            "detection_gaps": detection_gaps,
            "coverage_score": coverage_score,
            "techniques_seen_by_others": techniques_seen,
            "actions": actions,
        },
    }


async def analyze_eval_record(data: dict[str, Any], db: Database) -> dict:
    """Analyze an eval record against vendor aggregates."""
    # Store the contribution first
    cid = await db.store_eval_record(data)

    # Support both wire format and flat format
    d = data.get("data", data)
    vendor = d.get("vendor")
    category = d.get("category")
    your_score = d.get("overall_score")

    if not vendor:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "intelligence": {
                "your_vendor": None,
                "your_score": your_score,
                "category_avg": None,
                "percentile": None,
                "better_alternatives": [],
                "known_gaps": [],
                "actions": [
                    {
                        "priority": "info",
                        "action": "No vendor specified",
                        "detail": "Submit with a vendor name to get comparative analysis.",
                    }
                ],
            },
        }

    # Get aggregate data
    aggregate = await db.get_vendor_aggregate(vendor)
    category_avg = await db.get_category_average(category) if category else None
    vendor_gaps = await db.get_vendor_gaps(vendor)

    if not aggregate:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "intelligence": {
                "your_vendor": vendor,
                "your_score": your_score,
                "category_avg": category_avg,
                "percentile": None,
                "better_alternatives": [],
                "known_gaps": vendor_gaps,
                "actions": [
                    {
                        "priority": "info",
                        "action": "Baseline established",
                        "detail": (
                            f"First evaluation for {vendor}. Your contribution establishes "
                            f"the baseline. Future analyses will compare against this."
                        ),
                    }
                ],
            },
        }

    avg_score = aggregate.get("avg_score")

    # Simple percentile estimate
    if your_score is not None and avg_score is not None:
        if your_score > avg_score:
            percentile = 75
        elif your_score == avg_score:
            percentile = 50
        else:
            percentile = 25
    else:
        percentile = None

    # Build actions
    actions = []
    if vendor_gaps:
        gap_list = ", ".join(vendor_gaps[:5])
        actions.append({
            "priority": "medium",
            "action": f"Supplement {vendor} with additional detection rules",
            "detail": (
                f"{vendor} has known gaps in: {gap_list}. "
                f"Consider custom Sigma rules or a complementary tool."
            ),
        })

    if your_score is not None and avg_score is not None:
        if your_score >= avg_score:
            actions.append({
                "priority": "info",
                "action": f"{vendor} scores at or above average",
                "detail": (
                    f"Your score ({your_score}) vs category average "
                    f"({round(avg_score, 1) if avg_score else '?'}). "
                    f"{'Address known gaps to maximize value.' if vendor_gaps else 'No known gaps detected.'}"
                ),
            })
        else:
            actions.append({
                "priority": "high",
                "action": f"Investigate {vendor} underperformance",
                "detail": (
                    f"Your score ({your_score}) is below the category average "
                    f"({round(avg_score, 1)}). Review configuration and deployment."
                ),
            })

    if not actions:
        actions.append({
            "priority": "info",
            "action": "Evaluation recorded",
            "detail": f"Your {vendor} evaluation has been added to the collective intelligence.",
        })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "intelligence": {
            "your_vendor": vendor,
            "your_score": your_score,
            "category_avg": round(category_avg, 1) if category_avg is not None else None,
            "percentile": percentile,
            "better_alternatives": [],
            "known_gaps": vendor_gaps,
            "actions": actions,
        },
    }
