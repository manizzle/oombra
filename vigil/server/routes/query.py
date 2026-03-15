"""
Read-side query API — all responses are aggregates.
No individual contribution is ever returned.
"""
from __future__ import annotations

import os

from fastapi import APIRouter

router = APIRouter(prefix="/query", tags=["query"])


def _min_k() -> int:
    """Read min-k at request time so env var changes take effect (e.g. in tests)."""
    return int(os.environ.get("VIGIL_MIN_K", "3"))


@router.get("/vendor/{name}")
async def query_vendor(name: str):
    """Aggregated scores across all anonymous contributors for a vendor."""
    from ..app import get_db
    db = get_db()
    result = await db.get_vendor_aggregate(name)
    if result is None:
        return {"error": "vendor not found", "vendor": name}
    min_k = _min_k()
    count = result.get("contribution_count", 0)
    if count < min_k:
        return {
            "error": "Insufficient contributors",
            "min_required": min_k,
            "current": count,
        }
    return result


@router.get("/category/{name}")
async def query_category(name: str):
    """All vendors in a category with aggregate scores."""
    from ..app import get_db
    db = get_db()
    min_k = _min_k()
    vendors = await db.get_category_vendors(name)
    filtered = [v for v in vendors if v.get("contribution_count", 0) >= min_k]
    return {"category": name, "vendors": filtered}


@router.get("/techniques")
async def query_techniques(limit: int = 20):
    """Most-seen MITRE techniques across all AttackMaps."""
    from ..app import get_db
    db = get_db()
    techniques = await db.get_top_techniques(limit=limit)
    return {"techniques": techniques}


@router.get("/ioc-stats")
async def query_ioc_stats():
    """IOC type distribution (no raw values ever)."""
    from ..app import get_db
    db = get_db()
    stats = await db.get_ioc_stats()
    return {"ioc_types": stats}
