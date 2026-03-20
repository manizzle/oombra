"""
Intelligence endpoints — market maps, threat mapping, danger radar.

Simplified port from bakeoff's intelligence module, adapted to work
with nur's existing database (contributions, attack_techniques, aggregated_scores).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..vendors import (
    VENDOR_REGISTRY, get_vendor, list_vendors,
    weighted_score, confidence_level, SOURCE_WEIGHTS, DEFAULT_WEIGHT,
    load_capabilities, load_integrations, load_mitre_map,
)

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


# ── Helpers ──────────────────────────────────────────────────────────

def _match_techniques(threat_text: str, mitre_map: dict) -> list[tuple[str, dict, int]]:
    """Return (tech_id, tech_data, match_count) sorted by relevance."""
    threat_lower = threat_text.lower()
    threat_words = set(threat_lower.split())
    matches = []
    for tech_id, tech in mitre_map.items():
        score = 0
        if tech["name"].lower() in threat_lower:
            score += 5
        for word in tech["name"].lower().split():
            if len(word) > 2 and word in threat_words:
                score += 2
        tactic_clean = tech["tactic"].replace("-", " ")
        if tactic_clean in threat_lower:
            score += 3
        for word in tactic_clean.split():
            if len(word) > 3 and word in threat_words:
                score += 1
        for cat in tech.get("categories", []):
            if cat.lower() in threat_lower or cat.lower() in threat_words:
                score += 2
        desc_words = set(tech.get("description", "").lower().split())
        overlap = threat_words & desc_words
        meaningful = [w for w in overlap if len(w) > 4]
        score += len(meaningful)
        if score > 0:
            matches.append((tech_id, tech, score))
    return sorted(matches, key=lambda x: -x[2])[:15]


async def _vendor_score_from_db(vendor_id: str) -> dict | None:
    """Get weighted score and confidence for a vendor from nur's DB."""
    from ..app import get_db
    db = get_db()
    agg = await db.get_vendor_aggregate(vendor_id)
    if not agg:
        return None

    # Build a simple eval list for weighted_score calculation
    # Use the aggregate avg_score as a proxy
    score = agg.get("avg_score")
    count = agg.get("contribution_count", 0)
    conf = confidence_level(count, min(count, 5))

    return {
        "vendor_id": vendor_id,
        "weighted_score": round(score, 2) if score else None,
        "confidence": conf,
        "eval_count": count,
        "category": agg.get("category"),
    }


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/market/{category}")
async def market_map(category: str, request: Request):
    """Market map view — vendors tiered by score + confidence."""
    from ..app import get_db, track_query
    track_query(request, "market")

    db = get_db()
    category_lower = category.lower()

    # Get vendors from registry matching this category
    registry_vendors = list_vendors(category=category_lower)

    # Also get vendors from DB aggregated scores
    db_vendors = await db.get_category_vendors(category_lower)
    db_vendor_map = {v["vendor"]: v for v in db_vendors}

    # Merge: use registry metadata + DB scores
    all_vendor_ids = set()
    for rv in registry_vendors:
        all_vendor_ids.add(rv["id"])
    for dv in db_vendors:
        all_vendor_ids.add(dv["vendor"])

    leaders = []
    contenders = []
    emerging = []
    watch = []

    for vid in all_vendor_ids:
        registry_info = get_vendor(vid)
        db_info = db_vendor_map.get(vid)

        display = registry_info["display_name"] if registry_info else vid.replace("-", " ").title()
        cat = (registry_info or {}).get("category", category_lower)
        score = db_info["avg_score"] if db_info else None
        count = db_info["contribution_count"] if db_info else 0
        conf = confidence_level(count, min(count, 5))

        entry = {
            "vendor_id": vid,
            "display": display,
            "weighted_score": round(score, 2) if score else None,
            "confidence": conf,
            "eval_count": count,
        }

        if score is not None and score > 8 and conf == "high":
            leaders.append(entry)
        elif score is not None and 7 <= score <= 8:
            contenders.append(entry)
        elif conf == "medium":
            emerging.append(entry)
        else:
            watch.append(entry)

    for tier in (leaders, contenders, emerging, watch):
        tier.sort(key=lambda x: x.get("weighted_score") or 0, reverse=True)

    vendor_count = len(leaders) + len(contenders) + len(emerging) + len(watch)

    return {
        "category": category_lower,
        "vendor_count": vendor_count,
        "tiers": {
            "leaders": leaders,
            "contenders": contenders,
            "emerging": emerging,
            "watch": watch,
        },
    }


class ThreatMapRequest(BaseModel):
    threat: str
    current_tools: list[str] = []


@router.post("/threat-map")
async def threat_map(body: ThreatMapRequest, request: Request):
    """Map a threat description to MITRE techniques and show coverage gaps."""
    from ..app import get_db, track_query
    track_query(request, "threat_map")

    db = get_db()

    current_tools_lower = [t.lower().replace(" ", "-") for t in body.current_tools]
    mitre_data = load_mitre_map()
    matched = _match_techniques(body.threat, mitre_data)

    if not matched:
        return {
            "threat": body.threat,
            "kill_chain": [],
            "coverage_summary": {"covered": 0, "gaps": 0, "total_techniques": 0},
            "gap_recommendations": [],
        }

    kill_chain = []
    covered_count = 0
    gap_count = 0
    gap_categories: set[str] = set()

    # Sort by tactic_order if available
    matched.sort(key=lambda x: x[1].get("tactic_order", 99))

    for tech_id, tech, _score in matched:
        primary_vendors = tech.get("primary_vendors", [])

        your_coverage = None
        is_gap = True
        for tool in current_tools_lower:
            if tool in primary_vendors:
                vendor_info = get_vendor(tool)
                your_coverage = vendor_info["display_name"] if vendor_info else tool.replace("-", " ").title()
                is_gap = False
                break

        if is_gap:
            gap_count += 1
            for cat in tech.get("categories", []):
                gap_categories.add(cat)
        else:
            covered_count += 1

        recommended = []
        for vid in primary_vendors:
            if vid in current_tools_lower:
                continue
            vendor_info = get_vendor(vid)
            display = vendor_info["display_name"] if vendor_info else vid.replace("-", " ").title()
            score_data = await _vendor_score_from_db(vid)
            recommended.append({
                "vendor_id": vid,
                "vendor_display": display,
                "weighted_score": score_data["weighted_score"] if score_data else None,
            })
        recommended.sort(key=lambda r: r.get("weighted_score") or 0, reverse=True)

        kill_chain.append({
            "tactic": tech["tactic"],
            "technique_id": tech_id,
            "technique_name": tech["name"],
            "your_coverage": your_coverage,
            "gap": is_gap,
            "recommended": recommended[:3],
            "detection_approach": tech.get("detection_approach"),
            "prevention_approach": tech.get("prevention_approach"),
        })

    total = covered_count + gap_count

    gap_recommendations = []
    if "email" in gap_categories:
        gap_recommendations.append("Add email security — phishing is the #1 initial access vector")
    if "edr" in gap_categories:
        gap_recommendations.append("Add EDR — endpoint visibility is critical for detection and response")
    if "iam" in gap_categories or "pam" in gap_categories:
        gap_recommendations.append("Strengthen identity controls — credential abuse is in most attack chains")
    if "ndr" in gap_categories:
        gap_recommendations.append("Add network detection — lateral movement is invisible without NDR")
    if "siem" in gap_categories:
        gap_recommendations.append("Add SIEM — centralized logging is essential for investigation and compliance")

    return {
        "threat": body.threat,
        "kill_chain": kill_chain,
        "coverage_summary": {
            "covered": covered_count,
            "gaps": gap_count,
            "total_techniques": total,
        },
        "gap_recommendations": gap_recommendations,
    }


# ── Source group constants for danger radar ───────────────────────────

_REVIEW_SOURCES = {"g2", "capterra", "trustradius", "peerspot", "gartner-peer-insights", "gartner"}
_COMMUNITY_SOURCES = {"community", "reddit", "hackernews", "hacker-news", "stackexchange"}
_LAB_SOURCES = {"mitre-attack-evals", "av-test", "selabs", "mitre"}


@router.get("/danger-radar")
async def danger_radar():
    """Vendors with hidden risk signals — contradictions between reviews and real-world data."""
    from ..app import get_db
    db = get_db()

    results = []
    for vid, vendor_meta in VENDOR_REGISTRY.items():
        agg = await db.get_vendor_aggregate(vid)
        score = agg["avg_score"] if agg else None
        count = agg["contribution_count"] if agg else 0

        danger_signals: list[str] = []

        # Signal: documented incidents
        if vendor_meta.get("known_issues") and vendor_meta["known_issues"].strip():
            issues = vendor_meta["known_issues"]
            danger_signals.append(
                f"Has documented incidents/issues: {issues[:100]}..."
                if len(issues) > 100
                else f"Has documented incidents/issues: {issues}"
            )

        # Signal: no insurance acceptance
        carriers = vendor_meta.get("insurance_carriers", [])
        if not carriers:
            danger_signals.append("No insurance carriers accept this tool — may indicate enterprise risk concerns")

        if not danger_signals:
            continue

        danger_score = round(
            (2 if vendor_meta.get("known_issues", "").strip() else 0)
            + (1 if not carriers else 0),
            1,
        )

        results.append({
            "vendor_id": vid,
            "display_name": vendor_meta["display_name"],
            "category": vendor_meta["category"],
            "avg_score": round(score, 2) if score else None,
            "eval_count": count,
            "danger_score": danger_score,
            "danger_signals": danger_signals,
            "known_issues": vendor_meta.get("known_issues"),
            "insurance_carriers": carriers,
        })

    results.sort(key=lambda x: x["danger_score"], reverse=True)
    return {"vendors": results}


# -- Attack pattern intelligence endpoints -----------------------------------


@router.get("/patterns/{vertical}")
async def attack_patterns(vertical: str):
    """Get attack methodology patterns for an industry vertical.

    Returns aggregated attack patterns, technique frequency, tool effectiveness,
    remediation insights, and minimum viable stack recommendations.
    """
    from ..app import get_db
    from ...intelligence import extract_attack_patterns
    from ...verticals import VERTICALS

    if vertical not in VERTICALS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown vertical: {vertical!r}. Available: {', '.join(VERTICALS.keys())}",
        )

    db = get_db()
    stats = await db.get_stats()
    techniques = await db.get_top_techniques(100)

    # Get all attack_map contributions for remediation data
    from sqlalchemy import select
    from ..models import Contribution, AttackTechnique
    contributions_raw: list[dict] = []
    techniques_detailed: list[dict] = []

    async with db.session() as s:
        # Get contributions
        result = await s.execute(
            select(Contribution).where(Contribution.contrib_type == "attack_map")
        )
        for row in result.scalars().all():
            contributions_raw.append({
                "contrib_type": row.contrib_type,
                "industry": row.industry,
                "remediation_json": row.remediation_json,
                "time_to_detect": row.time_to_detect,
                "time_to_contain": row.time_to_contain,
                "time_to_recover": row.time_to_recover,
                "ransom_paid": row.ransom_paid,
                "data_exfiltrated": row.data_exfiltrated,
                "severity": row.severity,
            })

        # Get detailed technique data with detected_by/missed_by
        tech_result = await s.execute(select(AttackTechnique))
        for row in tech_result.scalars().all():
            techniques_detailed.append({
                "technique_id": row.technique_id,
                "technique_name": row.technique_name,
                "tactic": row.tactic,
                "detected_by": row.detected_by,
                "missed_by": row.missed_by,
            })

    patterns = extract_attack_patterns(
        stats, techniques_detailed, contributions_raw, vertical,
    )
    return patterns


class SimulateRequest(BaseModel):
    stack: list[str]
    vertical: str = "healthcare"
    attack_type: str | None = None


@router.post("/simulate")
async def simulate(body: SimulateRequest, request: Request):
    """Simulate an attack chain against a security stack.

    Shows exactly where your defenses break, step by step.
    """
    from ..app import track_query
    track_query(request, "simulate", body.stack)
    from ...simulator import simulate_attack
    from ...verticals import VERTICALS

    if body.vertical not in VERTICALS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown vertical: {body.vertical!r}. Available: {', '.join(VERTICALS.keys())}",
        )

    if not body.stack:
        raise HTTPException(
            status_code=400,
            detail="Stack cannot be empty. Provide at least one tool.",
        )

    result = simulate_attack(
        stack=body.stack,
        vertical=body.vertical,
        attack_type=body.attack_type,
    )
    return result
