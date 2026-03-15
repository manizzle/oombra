"""
Tests for the /analyze endpoint — actionable intelligence analysis.
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


# ── IOC bundle analysis ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_ioc_bundle():
    """IOC bundle analysis returns campaign matches and actions."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed some IOCs
        seed_data = {
            "context": {"industry": "healthcare"},
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value_hash": "abc123",
                    "threat_actor": "LockBit",
                    "campaign": "LB3-Healthcare",
                    "detected_by": ["crowdstrike"],
                    "missed_by": [],
                },
                {
                    "ioc_type": "ip",
                    "value_hash": "def456",
                    "threat_actor": "LockBit",
                    "campaign": "LB3-Healthcare",
                    "detected_by": [],
                    "missed_by": ["sentinelone"],
                },
            ],
        }
        resp = await client.post("/contribute/ioc-bundle", json=seed_data)
        assert resp.status_code == 200

        # Analyze a bundle with overlapping IOCs
        analyze_data = {
            "context": {"industry": "healthcare"},
            "iocs": [
                {"ioc_type": "domain", "value_hash": "abc123", "detected_by": [], "missed_by": []},
                {"ioc_type": "hash", "value_hash": "xyz789", "detected_by": [], "missed_by": []},
            ],
        }
        resp = await client.post("/analyze", json=analyze_data)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"
        assert "contribution_id" in data
        assert "intelligence" in data
        intel = data["intelligence"]
        assert intel["campaign_match"] is True
        assert intel["shared_ioc_count"] >= 1
        assert "LockBit" in intel["threat_actors"]
        assert len(intel["actions"]) > 0


# ── Attack map analysis ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_attack_map():
    """Attack map analysis returns detection gaps and coverage score."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed an attack map
        seed = {
            "threat_name": "LockBit 3.0",
            "context": {"industry": "financial"},
            "techniques": [
                {
                    "technique_id": "T1490",
                    "technique_name": "Inhibit System Recovery",
                    "tactic": "impact",
                    "detected_by": ["sentinelone"],
                    "missed_by": ["crowdstrike"],
                },
                {
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "tactic": "impact",
                    "detected_by": ["crowdstrike", "sentinelone"],
                    "missed_by": [],
                },
            ],
            "tools_in_scope": ["crowdstrike", "sentinelone"],
        }
        resp = await client.post("/contribute/attack-map", json=seed)
        assert resp.status_code == 200

        # Analyze with crowdstrike as our tool
        analyze = {
            "threat_name": "Ransomware Assessment",
            "context": {"industry": "financial"},
            "techniques": [
                {
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "tactic": "impact",
                    "detected_by": ["crowdstrike"],
                    "missed_by": [],
                },
            ],
            "tools_in_scope": ["crowdstrike"],
        }
        resp = await client.post("/analyze", json=analyze)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"
        intel = data["intelligence"]
        assert "detection_gaps" in intel
        assert "coverage_score" in intel
        assert isinstance(intel["actions"], list)


# ── Eval record analysis ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_eval_record():
    """Eval record analysis returns vendor comparison."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed eval records
        for score in [8.0, 8.5, 9.0]:
            await client.post(
                "/contribute/submit",
                json={
                    "vendor": "CrowdStrike",
                    "category": "edr",
                    "overall_score": score,
                    "detection_rate": 92.0,
                    "would_buy": True,
                },
            )

        # Analyze a new eval
        analyze = {
            "vendor": "CrowdStrike",
            "category": "edr",
            "overall_score": 9.2,
            "detection_rate": 95.0,
            "would_buy": True,
        }
        resp = await client.post("/analyze", json=analyze)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"
        intel = data["intelligence"]
        assert intel["your_vendor"] == "CrowdStrike"
        assert intel["your_score"] == 9.2
        assert "category_avg" in intel
        assert "percentile" in intel
        assert isinstance(intel["actions"], list)


# ── Empty DB ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_empty_db():
    """Analysis with empty DB returns graceful responses, not errors."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # IOC bundle
        resp = await client.post("/analyze", json={
            "iocs": [{"ioc_type": "hash", "value_hash": "nope123", "detected_by": [], "missed_by": []}],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"
        assert data["intelligence"]["campaign_match"] is False
        assert data["intelligence"]["shared_ioc_count"] == 0

        # Attack map
        resp = await client.post("/analyze", json={
            "techniques": [{"technique_id": "T1566", "technique_name": "Phishing"}],
            "tools_in_scope": ["crowdstrike"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"

        # Eval record
        resp = await client.post("/analyze", json={
            "vendor": "NewVendor",
            "category": "edr",
            "overall_score": 7.5,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "analyzed"


# ── JSON format for CLI consumption ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_returns_valid_json_for_cli():
    """Response is well-structured JSON suitable for the 'vigil report --json' command."""
    os.environ.pop("VIGIL_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "vendor": "TestVendor",
            "category": "siem",
            "overall_score": 6.0,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "contribution_id" in data
        assert "intelligence" in data
        # Must be JSON-serializable
        serialized = json.dumps(data)
        assert len(serialized) > 0
