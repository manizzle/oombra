"""
Tests for Attack Pattern Intelligence, Simulator, and Privacy modules.
"""
from __future__ import annotations

import json
import os

import pytest
from httpx import AsyncClient, ASGITransport


# ── Intelligence module tests ──────────────────────────────────────────────


def test_extract_patterns_healthcare_defaults():
    """Intelligence engine returns patterns even with empty data (uses baselines)."""
    from nur.intelligence import extract_attack_patterns

    result = extract_attack_patterns(
        db_stats={"total_contributions": 0, "by_type": {}},
        techniques=[],
        contributions=[],
        vertical="healthcare",
    )

    assert result["vertical"] == "healthcare"
    assert "patterns" in result
    patterns = result["patterns"]
    assert "initial_access" in patterns
    assert "common_chains" in patterns
    assert "remediation_insights" in patterns
    assert "minimum_viable_stack" in patterns

    # Should have baseline-driven initial access patterns
    ia = patterns["initial_access"]
    assert "spearphishing" in ia
    assert ia["spearphishing"]["pct"] == 89
    assert ia["spearphishing"]["technique"] == "T1566.001"


def test_extract_patterns_financial():
    """Intelligence engine works for financial vertical."""
    from nur.intelligence import extract_attack_patterns

    result = extract_attack_patterns(
        db_stats={"total_contributions": 5, "by_type": {"attack_map": 5}},
        techniques=[],
        contributions=[],
        vertical="financial",
    )

    assert result["vertical"] == "financial"
    assert "APT28/Fancy Bear" in result["threat_actors"]

    chains = result["patterns"]["common_chains"]
    chain_names = [c["name"] for c in chains]
    assert "APT Credential Harvest" in chain_names


def test_extract_patterns_with_technique_data():
    """Intelligence engine uses real technique data when available."""
    from nur.intelligence import extract_attack_patterns

    techniques = [
        {
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic": "initial-access",
            "detected_by": json.dumps(["proofpoint", "mimecast"]),
            "missed_by": json.dumps(["crowdstrike"]),
        },
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "execution",
            "detected_by": json.dumps(["crowdstrike", "sentinelone"]),
            "missed_by": json.dumps([]),
        },
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "impact",
            "detected_by": json.dumps(["crowdstrike"]),
            "missed_by": json.dumps(["splunk"]),
        },
    ]

    result = extract_attack_patterns(
        db_stats={"total_contributions": 10, "by_type": {"attack_map": 3}},
        techniques=techniques,
        contributions=[],
        vertical="healthcare",
    )

    # Tool effectiveness should be populated
    tool_eff = result["patterns"]["tool_effectiveness"]
    assert len(tool_eff) > 0

    # Technique frequency should be populated
    tech_freq = result["patterns"]["technique_frequency"]
    assert len(tech_freq) > 0


def test_extract_patterns_all_verticals():
    """Intelligence engine works for all defined verticals."""
    from nur.intelligence import extract_attack_patterns
    from nur.verticals import VERTICALS

    for vertical in VERTICALS:
        result = extract_attack_patterns(
            db_stats={"total_contributions": 0, "by_type": {}},
            techniques=[],
            contributions=[],
            vertical=vertical,
        )
        assert result["vertical"] == vertical
        assert "patterns" in result


def test_extract_patterns_invalid_vertical():
    """Intelligence engine raises ValueError for unknown vertical."""
    from nur.intelligence import extract_attack_patterns

    with pytest.raises(ValueError, match="Unknown vertical"):
        extract_attack_patterns(
            db_stats={}, techniques=[], contributions=[], vertical="nonexistent",
        )


def test_tool_effectiveness_calculation():
    """Tool effectiveness helper calculates detection percentages correctly."""
    from nur.intelligence import _build_tool_effectiveness

    techniques = [
        {"technique_id": "T1", "detected_by": '["crowdstrike"]', "missed_by": '[]'},
        {"technique_id": "T2", "detected_by": '["crowdstrike"]', "missed_by": '["splunk"]'},
        {"technique_id": "T3", "detected_by": '[]', "missed_by": '["crowdstrike"]'},
    ]

    result = _build_tool_effectiveness(techniques)
    assert "crowdstrike" in result
    assert result["crowdstrike"]["detection_pct"] == 67  # 2/3
    assert "T3" in result["crowdstrike"]["misses"]


def test_chain_analysis():
    """Chain analysis enriches predefined chains with observed data."""
    from nur.intelligence import _build_chain_analysis
    from nur.server.vendors import load_mitre_map

    mitre_map = load_mitre_map()
    techniques = [
        {"technique_id": "T1566.001"},
        {"technique_id": "T1486"},
    ]

    chains = _build_chain_analysis(techniques, "healthcare", mitre_map)
    assert len(chains) > 0
    assert chains[0]["name"] == "Classic Ransomware"
    assert chains[0]["data_coverage_pct"] > 0


# ── Simulator tests ────────────────────────────────────────────────────────


def test_simulate_healthcare_ransomware():
    """Simulate healthcare ransomware with a typical stack."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike", "splunk", "okta"],
        vertical="healthcare",
        attack_type="ransomware",
    )

    assert result["attack_type"] == "ransomware"
    assert result["vertical"] == "healthcare"
    assert "chain" in result
    assert len(result["chain"]) > 0

    # Should have step data
    step = result["chain"][0]
    assert "technique_id" in step
    assert "technique_name" in step
    assert "result" in step
    assert step["result"] in ("BLOCKED", "DETECTED", "PASS_THROUGH")

    # Should have coverage analysis
    assert "coverage_pct" in result
    assert "recommendations" in result
    assert "cost_to_close" in result


def test_simulate_financial_apt():
    """Simulate financial APT attack."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike", "splunk"],
        vertical="financial",
        attack_type="apt",
    )

    assert result["attack_name"] == "APT Credential Harvest"
    assert len(result["chain"]) == 6  # 6-step chain


def test_simulate_energy_ics():
    """Simulate energy ICS attack."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike"],
        vertical="energy",
        attack_type="ics",
    )

    assert result["attack_name"] == "ICS/OT Pivot"
    assert len(result["chain"]) == 5


def test_simulate_government_supply_chain():
    """Simulate government supply chain attack."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike", "okta", "splunk"],
        vertical="government",
        attack_type="supply-chain",
    )

    assert result["attack_name"] == "Supply Chain Compromise"


def test_simulate_default_attack_type():
    """Simulate uses default attack type when none specified."""
    from nur.simulator import simulate_attack

    result = simulate_attack(stack=["crowdstrike"], vertical="healthcare")
    assert result["attack_type"] == "ransomware"

    result = simulate_attack(stack=["crowdstrike"], vertical="financial")
    assert result["attack_type"] == "apt"


def test_simulate_empty_stack_has_all_pass_through():
    """Empty-ish stack (unknown tool) has pass-throughs."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["unknown-tool-xyz"],
        vertical="healthcare",
        attack_type="ransomware",
    )

    pass_throughs = [s for s in result["chain"] if s["result"] == "PASS_THROUGH"]
    assert len(pass_throughs) == len(result["chain"])
    assert result["coverage_pct"] == 0


def test_simulate_full_stack_has_coverage():
    """Well-equipped stack should have good coverage."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike", "splunk", "okta", "proofpoint", "darktrace", "cyberark-pam"],
        vertical="healthcare",
        attack_type="ransomware",
    )

    assert result["coverage_pct"] > 50
    assert result["chain_breaks_at"] is not None


def test_simulate_recommendations_generated():
    """Simulator generates recommendations for gaps."""
    from nur.simulator import simulate_attack

    result = simulate_attack(
        stack=["crowdstrike"],
        vertical="healthcare",
        attack_type="ransomware",
    )

    # With only one tool, there should be gaps and recommendations
    recs = result["recommendations"]
    assert len(recs) > 0
    assert all("priority" in r for r in recs)
    assert all("action" in r for r in recs)


def test_list_attack_types():
    """List attack types returns valid data."""
    from nur.simulator import list_attack_types

    all_types = list_attack_types()
    assert "healthcare" in all_types
    assert "ransomware" in all_types["healthcare"]

    hc_types = list_attack_types("healthcare")
    assert "healthcare" in hc_types


# ── Privacy module tests ──────────────────────────────────────────────────


def test_get_privacy_level_standard():
    """Standard privacy level returns correct config."""
    from nur.privacy import get_privacy_level

    config = get_privacy_level("standard")
    assert config["ioc_hashing"] is True
    assert config["text_scrubbing"] == "standard"
    assert config["dp_noise"] is False
    assert config["min_k"] == 3


def test_get_privacy_level_maximum():
    """Maximum privacy level has strongest settings."""
    from nur.privacy import get_privacy_level

    config = get_privacy_level("maximum")
    assert config["dp_noise"] is True
    assert config["dp_epsilon"] == 1.0
    assert config["min_k"] == 10
    assert config["strip_timing"] is True


def test_get_privacy_level_research():
    """Research privacy level has most utility."""
    from nur.privacy import get_privacy_level

    config = get_privacy_level("research")
    assert config["text_scrubbing"] == "light"
    assert config["dp_noise"] is False
    assert config["min_k"] == 2


def test_get_privacy_level_invalid():
    """Invalid privacy level raises ValueError."""
    from nur.privacy import get_privacy_level

    with pytest.raises(ValueError, match="Unknown privacy level"):
        get_privacy_level("nonexistent")


def test_list_privacy_levels():
    """List privacy levels returns all three levels."""
    from nur.privacy import list_privacy_levels

    levels = list_privacy_levels()
    assert len(levels) == 3
    names = [l["name"] for l in levels]
    assert "maximum" in names
    assert "standard" in names
    assert "research" in names
    assert all("description" in l for l in levels)


def test_apply_privacy_config_standard():
    """Apply standard privacy config to a contribution."""
    from nur.privacy import apply_privacy_config

    contrib = {
        "data": {
            "vendor": "crowdstrike",
            "overall_score": 8.5,
            "notes": "Great product, tested by john@acme.com",
            "top_strength": "detection",
        },
        "iocs": [
            {"value": "192.168.1.1", "ioc_type": "ip"},
        ],
    }

    result = apply_privacy_config(contrib, "standard")

    # Should annotate with privacy level
    assert result["_privacy_level"] == "standard"
    assert result["_min_k"] == 3

    # Original should not be modified
    assert "value" in contrib["iocs"][0]


def test_apply_privacy_config_maximum_strips_timing():
    """Maximum privacy strips timing fields."""
    from nur.privacy import apply_privacy_config

    contrib = {
        "data": {"vendor": "test", "notes": "test notes"},
        "received_at": "2024-01-01T00:00:00Z",
        "timestamp": "2024-01-01",
    }

    result = apply_privacy_config(contrib, "maximum")

    assert "received_at" not in result
    assert "timestamp" not in result
    assert result["_privacy_level"] == "maximum"


def test_apply_privacy_config_preserves_original():
    """Privacy config does not mutate the original dict."""
    from nur.privacy import apply_privacy_config

    contrib = {
        "data": {"vendor": "test", "notes": "hello"},
        "iocs": [{"value": "1.2.3.4", "ioc_type": "ip"}],
    }

    result = apply_privacy_config(contrib, "standard")
    assert result is not contrib
    # Original IOC should still have value
    assert "value" in contrib["iocs"][0]


# ── Server endpoint tests ──────────────────────────────────────────────────


async def _make_app():
    """Create a fresh app with initialized in-memory database."""
    import nur.server.app as app_mod
    from nur.server.app import create_app
    from nur.server.db import Database

    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.init()
    app_mod._db = db
    return app, db


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
async def test_patterns_endpoint_healthcare():
    """Patterns endpoint returns data for healthcare vertical."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/intelligence/patterns/healthcare")
        assert resp.status_code == 200
        data = resp.json()

        assert data["vertical"] == "healthcare"
        assert "patterns" in data
        assert "initial_access" in data["patterns"]
        assert "common_chains" in data["patterns"]


@pytest.mark.asyncio
async def test_patterns_endpoint_invalid_vertical():
    """Patterns endpoint rejects invalid vertical."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/intelligence/patterns/nonexistent")
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_simulate_endpoint():
    """Simulate endpoint returns attack chain analysis."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/intelligence/simulate",
            json={
                "stack": ["crowdstrike", "splunk", "okta"],
                "vertical": "healthcare",
                "attack_type": "ransomware",
            },
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["attack_type"] == "ransomware"
        assert "chain" in data
        assert len(data["chain"]) > 0
        assert "coverage_pct" in data
        assert "recommendations" in data


@pytest.mark.asyncio
async def test_simulate_endpoint_empty_stack():
    """Simulate endpoint rejects empty stack."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/intelligence/simulate",
            json={"stack": [], "vertical": "healthcare"},
        )
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_simulate_endpoint_with_seeded_data():
    """Simulate endpoint works when the DB has seeded data."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed an attack map
        await client.post(
            "/contribute/attack-map",
            json={
                "threat_name": "LockBit 3.0",
                "techniques": [
                    {
                        "technique_id": "T1566.001",
                        "technique_name": "Spearphishing",
                        "tactic": "initial-access",
                        "detected_by": ["proofpoint"],
                        "missed_by": ["crowdstrike"],
                    },
                ],
                "tools_in_scope": ["crowdstrike", "proofpoint"],
                "context": {"industry": "healthcare"},
            },
        )

        # Now simulate
        resp = await client.post(
            "/intelligence/simulate",
            json={
                "stack": ["crowdstrike", "proofpoint"],
                "vertical": "healthcare",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["chain"]) > 0


@pytest.mark.asyncio
async def test_patterns_endpoint_all_verticals():
    """Patterns endpoint works for all defined verticals."""
    os.environ.pop("NUR_API_KEY", None)
    app, db = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for vertical in ("healthcare", "financial", "energy", "government"):
            resp = await client.get(f"/intelligence/patterns/{vertical}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["vertical"] == vertical
