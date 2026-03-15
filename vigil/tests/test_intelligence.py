"""
Tests for intelligence and search endpoints.
"""
from __future__ import annotations

import json
import os

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _make_app():
    """Create a fresh app with initialized in-memory database."""
    import vigil.server.app as app_mod
    from vigil.server.app import create_app
    from vigil.server.db import Database

    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.init()
    app_mod._db = db
    return app, db


async def _seed_vendor_evals(client: AsyncClient, db):
    """Seed some vendor evaluations for testing."""
    evals = [
        {
            "data": {
                "vendor": "crowdstrike",
                "category": "edr",
                "overall_score": 8.5,
                "detection_rate": 0.98,
                "fp_rate": 0.02,
                "deploy_days": 14,
                "would_buy": True,
                "top_strength": "detection",
                "top_friction": "cost",
            },
            "context": {"industry": "financial"},
        },
        {
            "data": {
                "vendor": "crowdstrike",
                "category": "edr",
                "overall_score": 9.0,
                "detection_rate": 0.97,
                "fp_rate": 0.03,
                "deploy_days": 10,
                "would_buy": True,
                "top_strength": "detection",
                "top_friction": "pricing",
            },
            "context": {"industry": "healthcare"},
        },
        {
            "data": {
                "vendor": "crowdstrike",
                "category": "edr",
                "overall_score": 8.0,
                "detection_rate": 0.96,
                "fp_rate": 0.04,
                "deploy_days": 21,
                "would_buy": True,
                "top_strength": "visibility",
                "top_friction": "complexity",
            },
            "context": {"industry": "tech"},
        },
        {
            "data": {
                "vendor": "sentinelone",
                "category": "edr",
                "overall_score": 7.5,
                "detection_rate": 0.95,
                "fp_rate": 0.03,
                "deploy_days": 7,
                "would_buy": True,
                "top_strength": "ease of use",
                "top_friction": "false positives",
            },
            "context": {"industry": "tech"},
        },
        {
            "data": {
                "vendor": "sentinelone",
                "category": "edr",
                "overall_score": 7.8,
                "detection_rate": 0.94,
                "fp_rate": 0.04,
                "deploy_days": 5,
                "would_buy": True,
                "top_strength": "automation",
                "top_friction": "console UX",
            },
            "context": {"industry": "financial"},
        },
        {
            "data": {
                "vendor": "sentinelone",
                "category": "edr",
                "overall_score": 7.2,
                "detection_rate": 0.93,
                "fp_rate": 0.05,
                "deploy_days": 8,
                "would_buy": False,
                "top_strength": "rollback",
                "top_friction": "support",
            },
            "context": {"industry": "healthcare"},
        },
        {
            "data": {
                "vendor": "splunk",
                "category": "siem",
                "overall_score": 7.0,
                "detection_rate": 0.85,
                "fp_rate": 0.10,
                "deploy_days": 30,
                "would_buy": True,
                "top_strength": "search power",
                "top_friction": "cost",
            },
            "context": {"industry": "financial"},
        },
        {
            "data": {
                "vendor": "splunk",
                "category": "siem",
                "overall_score": 6.5,
                "detection_rate": 0.82,
                "fp_rate": 0.12,
                "deploy_days": 45,
                "would_buy": False,
                "top_strength": "flexibility",
                "top_friction": "licensing",
            },
            "context": {"industry": "tech"},
        },
        {
            "data": {
                "vendor": "splunk",
                "category": "siem",
                "overall_score": 7.5,
                "detection_rate": 0.88,
                "fp_rate": 0.08,
                "deploy_days": 25,
                "would_buy": True,
                "top_strength": "ecosystem",
                "top_friction": "complexity",
            },
            "context": {"industry": "healthcare"},
        },
    ]
    for ev in evals:
        resp = await client.post("/contribute/submit", json=ev)
        assert resp.status_code == 200


# ── Market endpoint ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_market_returns_tiered_vendors():
    """Market endpoint returns vendors grouped into tiers."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _seed_vendor_evals(client, db)

        resp = await client.get("/intelligence/market/edr")
        assert resp.status_code == 200
        data = resp.json()

        assert "tiers" in data
        assert "category" in data
        assert data["category"] == "edr"
        tiers = data["tiers"]
        assert "leaders" in tiers
        assert "contenders" in tiers
        assert "emerging" in tiers
        assert "watch" in tiers

        # Should have some vendors in at least one tier
        all_vendors = (
            tiers["leaders"] + tiers["contenders"]
            + tiers["emerging"] + tiers["watch"]
        )
        assert len(all_vendors) > 0


@pytest.mark.asyncio
async def test_market_siem_category():
    """Market endpoint works for siem category."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _seed_vendor_evals(client, db)

        resp = await client.get("/intelligence/market/siem")
        assert resp.status_code == 200
        data = resp.json()
        assert data["category"] == "siem"
        assert data["vendor_count"] > 0


# ── Threat map endpoint ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_threat_map_returns_coverage_gaps():
    """Threat-map endpoint returns coverage analysis with gaps."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/intelligence/threat-map",
            json={
                "threat": "ransomware lateral movement credential theft",
                "current_tools": ["crowdstrike", "splunk"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "kill_chain" in data
        assert "coverage_summary" in data
        summary = data["coverage_summary"]
        assert "covered" in summary
        assert "gaps" in summary
        assert "total_techniques" in summary
        assert summary["total_techniques"] > 0


@pytest.mark.asyncio
async def test_threat_map_empty_threat():
    """Threat-map with unmatched threat returns empty."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/intelligence/threat-map",
            json={"threat": "xyzzy_nonexistent_threat_12345", "current_tools": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["coverage_summary"]["total_techniques"] == 0


# ── Danger radar endpoint ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_danger_radar_returns_signals():
    """Danger radar returns vendors with risk signals."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/intelligence/danger-radar")
        assert resp.status_code == 200
        data = resp.json()

        assert "vendors" in data
        # Should have some vendors with danger signals (from known_issues in registry)
        assert len(data["vendors"]) > 0
        for v in data["vendors"]:
            assert "danger_signals" in v
            assert "vendor_id" in v
            assert len(v["danger_signals"]) > 0


# ── Search vendor endpoint ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_vendor_returns_weighted_scores():
    """Search vendor returns detailed profile with weighted scores."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _seed_vendor_evals(client, db)

        resp = await client.get("/search/vendor/crowdstrike")
        assert resp.status_code == 200
        data = resp.json()

        assert data["vendor_id"] == "crowdstrike"
        assert data["vendor_display"] == "CrowdStrike"
        assert data["category"] == "edr"
        assert data["weighted_score"] is not None
        assert data["confidence"] in ("high", "medium", "low", "insufficient")
        assert data["eval_count"] > 0
        assert "price_range" in data
        assert "certifications" in data
        assert "insurance_carriers" in data


@pytest.mark.asyncio
async def test_search_vendor_not_found():
    """Search for unknown vendor returns 404."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/search/vendor/nonexistent-vendor-xyz")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_search_vendor_registry_only():
    """Search vendor that exists in registry but has no DB evals still returns metadata."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # okta is in the registry but we haven't seeded evals for it
        resp = await client.get("/search/vendor/okta")
        assert resp.status_code == 200
        data = resp.json()
        assert data["vendor_id"] == "okta"
        assert data["vendor_display"] == "Okta"
        assert data["category"] == "iam"
        assert data["eval_count"] == 0


# ── Search category endpoint ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_category_returns_ranked_list():
    """Search category returns vendors ranked by weighted score."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _seed_vendor_evals(client, db)

        resp = await client.get("/search/category/edr")
        assert resp.status_code == 200
        data = resp.json()

        assert data["category"] == "edr"
        assert len(data["vendors"]) > 0

        # Verify sorted by score descending
        scores = [v.get("weighted_score") or 0 for v in data["vendors"]]
        assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_search_category_includes_registry_vendors():
    """Search category includes vendors from registry even without DB data."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/search/category/edr")
        assert resp.status_code == 200
        data = resp.json()
        # EDR vendors from registry: crowdstrike, sentinelone, ms-defender
        vendor_ids = [v["vendor_id"] for v in data["vendors"]]
        assert "crowdstrike" in vendor_ids
        assert "sentinelone" in vendor_ids
        assert "ms-defender" in vendor_ids


# ── Search compare endpoint ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_compare():
    """Compare endpoint returns side-by-side data for two vendors."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "1"
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _seed_vendor_evals(client, db)

        resp = await client.get("/search/compare", params={"a": "crowdstrike", "b": "sentinelone"})
        assert resp.status_code == 200
        data = resp.json()

        assert "vendor_a" in data
        assert "vendor_b" in data
        assert data["vendor_a"]["vendor_id"] == "crowdstrike"
        assert data["vendor_b"]["vendor_id"] == "sentinelone"
        assert data["vendor_a"]["weighted_score"] is not None
        assert data["vendor_b"]["weighted_score"] is not None
