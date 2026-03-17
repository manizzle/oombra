"""
Tier system + vendor dashboard — the revenue engine.

Three tiers:
  Free:       Contribute data → see YOUR comparative position
  Pro:        Full market maps, vendor rankings, detection matrices
  Enterprise: API access, custom verticals, compliance reports, vendor dashboards

Vendor Dashboard (B2B):
  Vendors pay to see their aggregate perception data + proofs.
  "42 healthcare orgs scored you 7.3/10. Here's what they say you miss."
  This is Glassdoor for security tools — with cryptographic proof of methodology.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel


router = APIRouter(tags=["tiers"])


# ── Tier definitions ────────────────────────────────────────────────

TIERS = {
    "community": {
        "name": "Community",
        "price": 0,
        "features": [
            "contribute_data",
            "own_percentile",
            "basic_stats",
            "receipts",
        ],
        "rate_limit": 60,
        "description": "Contribute data, see your comparative position. Free forever.",
    },
    "pro": {
        "name": "Pro",
        "price": 99,  # $/month
        "features": [
            "contribute_data",
            "own_percentile",
            "basic_stats",
            "receipts",
            "market_maps",
            "vendor_rankings",
            "threat_maps",
            "detection_matrices",
            "attack_patterns",
            "simulate",
            "vendor_compare",
        ],
        "rate_limit": 600,
        "description": "Full intelligence access. Market maps, rankings, threat analysis.",
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 499,  # $/month
        "features": [
            "contribute_data",
            "own_percentile",
            "basic_stats",
            "receipts",
            "market_maps",
            "vendor_rankings",
            "threat_maps",
            "detection_matrices",
            "attack_patterns",
            "simulate",
            "vendor_compare",
            "api_access",
            "custom_verticals",
            "compliance_reports",
            "rfp_generation",
            "vendor_dashboard",
            "export_stix",
            "priority_support",
        ],
        "rate_limit": 6000,
        "description": "Full API, custom analysis, compliance reporting, vendor dashboards.",
    },
}

# Features that require Pro or higher
PRO_FEATURES = {
    "market_maps", "vendor_rankings", "threat_maps", "detection_matrices",
    "attack_patterns", "simulate", "vendor_compare",
}

# Features that require Enterprise
ENTERPRISE_FEATURES = {
    "api_access", "custom_verticals", "compliance_reports",
    "rfp_generation", "vendor_dashboard", "export_stix", "priority_support",
}

# Map routes to required features
ROUTE_FEATURES = {
    "/intelligence/market": "market_maps",
    "/intelligence/threat-map": "threat_maps",
    "/intelligence/danger-radar": "vendor_rankings",
    "/intelligence/patterns": "attack_patterns",
    "/intelligence/simulate": "simulate",
    "/search/compare": "vendor_compare",
    "/vendor-dashboard": "vendor_dashboard",
}


def get_tier_for_key(api_key: str | None) -> str:
    """Look up tier for an API key. Returns 'community' if unknown."""
    # In production, this queries the APIKeyRecord table.
    # For now, check env var for enterprise keys.
    enterprise_keys = os.environ.get("NUR_ENTERPRISE_KEYS", "").split(",")
    pro_keys = os.environ.get("NUR_PRO_KEYS", "").split(",")
    if api_key in enterprise_keys:
        return "enterprise"
    if api_key in pro_keys:
        return "pro"
    return "community"


def check_feature_access(tier: str, feature: str) -> bool:
    """Check if a tier has access to a feature."""
    tier_data = TIERS.get(tier, TIERS["community"])
    return feature in tier_data["features"]


def require_feature(tier: str, feature: str) -> None:
    """Raise 403 if tier doesn't have the feature."""
    if not check_feature_access(tier, feature):
        tier_data = TIERS.get(tier, TIERS["community"])
        if feature in ENTERPRISE_FEATURES:
            required = "Enterprise"
        elif feature in PRO_FEATURES:
            required = "Pro"
        else:
            required = "Pro"
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Feature not available on your plan",
                "feature": feature,
                "your_tier": tier_data["name"],
                "required_tier": required,
                "upgrade_url": "/pricing",
            },
        )


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/pricing")
async def pricing():
    """Pricing tiers and features."""
    return {
        "tiers": {
            name: {
                "name": t["name"],
                "price": t["price"],
                "price_label": "Free" if t["price"] == 0 else f"${t['price']}/mo",
                "features": t["features"],
                "description": t["description"],
                "rate_limit": f"{t['rate_limit']} requests/min",
            }
            for name, t in TIERS.items()
        },
        "currency": "USD",
        "billing": "monthly",
    }


@router.get("/my-tier")
async def my_tier(request: Request):
    """Check your current tier and features."""
    api_key = request.headers.get("X-API-Key")
    tier = get_tier_for_key(api_key)
    tier_data = TIERS.get(tier, TIERS["community"])
    return {
        "tier": tier,
        "name": tier_data["name"],
        "features": tier_data["features"],
        "rate_limit": tier_data["rate_limit"],
    }


# ── Vendor Dashboard (Enterprise / B2B) ─────────────────────────────

@router.get("/vendor-dashboard/{vendor}")
async def vendor_dashboard(vendor: str, request: Request):
    """
    Vendor intelligence dashboard — how the market perceives you.

    This is the B2B product: vendors pay to see their aggregate data
    with cryptographic proof of sample size and methodology.

    Returns: aggregate scores, detection gaps, category comparison,
    and proof chain proving the data is real.
    """
    api_key = request.headers.get("X-API-Key")
    tier = get_tier_for_key(api_key)
    require_feature(tier, "vendor_dashboard")

    from ..app import get_db
    db = get_db()

    # Get vendor aggregate
    aggregate = await db.get_vendor_aggregate(vendor)
    if not aggregate:
        raise HTTPException(status_code=404, detail=f"No data for vendor: {vendor}")

    # Get detection gaps
    gaps = await db.get_vendor_gaps(vendor)

    # Get category peers for comparison
    category = aggregate.get("category")
    peers = await db.get_category_vendors(category) if category else []

    # Rank within category
    rank = 1
    for p in peers:
        if (p.get("avg_score") or 0) > (aggregate.get("avg_score") or 0):
            rank += 1

    return {
        "vendor": vendor,
        "aggregate": aggregate,
        "category_rank": rank,
        "category_total": len(peers),
        "detection_gaps": gaps[:10],
        "gap_count": len(gaps),
        "category_peers": [
            {
                "vendor": p["vendor"],
                "avg_score": p.get("avg_score"),
                "contribution_count": p.get("contribution_count", 0),
            }
            for p in peers[:10]
        ],
        "proof": {
            "methodology": "Aggregated from anonymized practitioner evaluations",
            "contributor_count": aggregate.get("contribution_count", 0),
            "data_commitment": "Pedersen commitments on all contributed values",
            "verification": "Each aggregate is Merkle-tree-bound to committed contributions",
            "note": "Individual contributions are discarded after aggregation — only commitments remain",
        },
    }


# ── Proven Stats (Free tier — what you get for contributing) ─────────

@router.get("/my-position/{vendor}")
async def my_position(vendor: str, request: Request):
    """
    Your comparative position — the free-tier value proposition.

    "You scored CrowdStrike 9.2 — that's 73rd percentile across
    42 evaluations. The category average is 8.1."

    This is what you get for contributing. Full analysis requires Pro.
    """
    from ..app import get_db
    db = get_db()

    aggregate = await db.get_vendor_aggregate(vendor)
    if not aggregate:
        return {
            "vendor": vendor,
            "message": "No aggregate data yet. Your contribution will be the first!",
        }

    avg_score = aggregate.get("avg_score")
    count = aggregate.get("contribution_count", 0)
    category = aggregate.get("category")
    category_avg = await db.get_category_average(category) if category else None

    return {
        "vendor": vendor,
        "category": category,
        "aggregate_score": round(avg_score, 1) if avg_score else None,
        "contributor_count": count,
        "category_average": round(category_avg, 1) if category_avg else None,
        "note": "Contribute your evaluation to see your percentile. Upgrade to Pro for full market analysis.",
    }
