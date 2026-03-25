"""
Enhanced search endpoints — vendor lookup with weighted scores,
category ranking, and side-by-side comparison.

Simplified port from bakeoff's search module, adapted to work
with nur's existing database and vendor registry.
"""
from __future__ import annotations


from fastapi import APIRouter, HTTPException, Query, Request

from ..vendors import (
    get_vendor, list_vendors,
    confidence_level, load_integrations,
)

router = APIRouter(prefix="/search", tags=["search"])


# ── Helpers ──────────────────────────────────────────────────────────

async def _get_vendor_detail(vendor_id: str) -> dict:
    """Build a detailed vendor profile from registry + DB."""
    from ..app import get_db
    db = get_db()

    vid = vendor_id.lower().replace(" ", "-")
    registry_info = get_vendor(vid)
    agg = await db.get_vendor_aggregate(vid)

    if not registry_info and not agg:
        raise HTTPException(404, f"Vendor not found: {vendor_id}")

    display = registry_info["display_name"] if registry_info else vid.replace("-", " ").title()
    category = (registry_info or {}).get("category")
    if not category and agg:
        category = agg.get("category")

    score = agg["avg_score"] if agg else None
    count = agg["contribution_count"] if agg else 0
    conf = confidence_level(count, min(count, 5))

    # Build source list from contributions (simplified)
    sources = []
    if count > 0:
        sources = ["community"]  # nur contributions are community-sourced

    result = {
        "vendor_display": display,
        "vendor_id": vid,
        "category": category,
        "eval_count": count,
        "avg_score": round(score, 2) if score is not None else None,
        "weighted_score": round(score, 2) if score is not None else None,
        "confidence": conf,
        "source_count": len(sources),
        "sources": sources,
    }

    if registry_info:
        result["price_range"] = registry_info.get("price_range")
        result["certifications"] = registry_info.get("certifications", [])
        result["known_issues"] = registry_info.get("known_issues")
        result["insurance_carriers"] = registry_info.get("insurance_carriers", [])
        result["compliance_frameworks"] = registry_info.get("compliance_frameworks", [])

    if agg:
        result["metrics"] = {
            "detection_rate": agg.get("avg_detection_rate"),
            "fp_rate": agg.get("avg_fp_rate"),
            "deploy_days": agg.get("avg_deploy_days"),
        }
        result["would_buy_pct"] = agg.get("would_buy_pct")

    # Strengths/friction from recent contributions
    result["strengths"] = []
    result["friction"] = []

    # Peer breakdown by industry (from contributions)
    result["peer_breakdown"] = {"by_industry": {}}

    # Integration data if available
    try:
        integrations = load_integrations()
        vendor_integrations = integrations.get(vid, {})
        if vendor_integrations:
            result["integrations"] = {
                "feeds_into": [e.get("vendor_id") for e in vendor_integrations.get("feeds_into", [])[:5]],
                "feeds_from": [e.get("vendor_id") for e in vendor_integrations.get("feeds_from", [])[:5]],
                "competes_with": vendor_integrations.get("competes_with", [])[:5],
            }
    except Exception:
        pass

    return result


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/vendor/{name}")
async def search_vendor(name: str, request: Request):
    """Enhanced vendor lookup — weighted score, confidence, source breakdown, metadata."""
    from ..app import track_query
    track_query(request, "search", [name])
    return await _get_vendor_detail(name)


@router.get("/category/{name}")
async def search_category(name: str):
    """Category ranking — vendors ranked by weighted score within a category."""
    from ..app import get_db
    db = get_db()
    category_lower = name.lower()

    # Get from DB
    db_vendors = await db.get_category_vendors(category_lower)

    # Also get from registry
    registry_vendors = list_vendors(category=category_lower)
    registry_ids = {rv["id"] for rv in registry_vendors}
    db_ids = {dv["vendor"] for dv in db_vendors}

    # Merge all vendor IDs
    all_ids = registry_ids | db_ids

    if not all_ids:
        raise HTTPException(404, f"No vendors found for category: {name}")

    db_map = {dv["vendor"]: dv for dv in db_vendors}
    out = []

    for vid in all_ids:
        registry_info = get_vendor(vid)
        db_info = db_map.get(vid)

        display = registry_info["display_name"] if registry_info else vid.replace("-", " ").title()
        score = db_info["avg_score"] if db_info else None
        count = db_info["contribution_count"] if db_info else 0
        conf = confidence_level(count, min(count, 5))

        entry = {
            "vendor_display": display,
            "vendor_id": vid,
            "eval_count": count,
            "avg_score": round(score, 2) if score is not None else None,
            "weighted_score": round(score, 2) if score is not None else None,
            "confidence": conf,
        }

        if registry_info:
            entry["price_range"] = registry_info.get("price_range")
            entry["insurance_carriers"] = registry_info.get("insurance_carriers", [])

        if db_info:
            entry["metrics"] = {
                "detection_rate": db_info.get("avg_detection_rate"),
            }
            entry["would_buy_pct"] = db_info.get("would_buy_pct")

        out.append(entry)

    # Sort by weighted_score descending (None last)
    out.sort(key=lambda x: x.get("weighted_score") or 0, reverse=True)

    return {
        "category": category_lower,
        "vendor_count": len(out),
        "vendors": out,
    }


@router.get("/compare")
async def compare_vendors(
    request: Request,
    a: str = Query(..., description="First vendor ID"),
    b: str = Query(..., description="Second vendor ID"),
):
    """Side-by-side vendor comparison."""
    from ..app import track_query
    track_query(request, "compare", [a, b])
    vendor_a = await _get_vendor_detail(a)
    vendor_b = await _get_vendor_detail(b)
    return {
        "vendor_a": vendor_a,
        "vendor_b": vendor_b,
    }
