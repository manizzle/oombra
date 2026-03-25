"""Tests for the /contribute web form POST handler — full submission flow."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def anyio_backend():
    return "asyncio"


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


def _valid_form(**overrides):
    """Return valid form data for POST /contribute."""
    data = {
        "vendor": "CrowdStrike",
        "category": "edr",
        "overall_score": "7.0",
        "would_buy": "yes",
        "email": "analyst@acmecorp.com",
        "support_quality": "8",
    }
    data.update(overrides)
    return data


# ── Test 1: Happy path ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_contribute_happy_path():
    """POST /contribute with valid data → 303 redirect to /contribute/thanks."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form())
    assert resp.status_code == 303
    assert "/contribute/thanks" in resp.headers["location"]


# ── Test 2: Vendor normalization ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vendor_normalization():
    """Submit 'crowdstrike' (lowercase) → stored as 'CrowdStrike' (canonical)."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(vendor="crowdstrike"))
    assert resp.status_code == 303
    # Check DB
    agg = await db.get_vendor_aggregate("CrowdStrike")
    assert agg is not None
    assert agg["vendor"] == "CrowdStrike"


# ── Test 3: Unknown vendor stored as-is ──────────────────────────────────────

@pytest.mark.asyncio
async def test_unknown_vendor_stored_as_is():
    """Submit 'MyCustomTool' (not in VENDORS list) → stored as-is."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(vendor="MyCustomTool"))
    assert resp.status_code == 303
    agg = await db.get_vendor_aggregate("MyCustomTool")
    assert agg is not None
    assert agg["vendor"] == "MyCustomTool"


# ── Test 4: Free email rejection ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_free_email_rejected():
    """Submit with gmail.com → 400 error HTML page."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(email="user@gmail.com"))
    assert resp.status_code == 400
    assert "gmail.com" in resp.text
    assert "Submission Error" in resp.text


# ── Test 5: Missing vendor ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_vendor_error():
    """Submit with empty vendor → 400 error HTML page."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(vendor=""))
    assert resp.status_code == 400
    assert "Submission Error" in resp.text


# ── Test 6: support_quality=0 accepted ───────────────────────────────────────

@pytest.mark.asyncio
async def test_support_quality_zero_accepted():
    """Submit with support_quality=0 → stored as 0.0, not dropped."""
    app, db = await _make_app()
    # We need to capture the payload passed to store_eval_record
    captured = {}
    original_store = db.store_eval_record

    async def capturing_store(data):
        captured["data"] = data
        return await original_store(data)

    db.store_eval_record = capturing_store
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(support_quality="0"))
    assert resp.status_code == 303
    assert captured["data"]["data"]["support_quality"] == 0.0


# ── Test 7: Proof failure resilience ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_proof_failure_still_redirects():
    """If proof engine throws, user still gets redirect (contribution was saved)."""
    app, db = await _make_app()
    with patch("nur.server.app.get_proof_engine") as mock_engine:
        mock_engine.return_value.commit_contribution.side_effect = RuntimeError("proof boom")
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
        ) as c:
            resp = await c.post("/contribute", data=_valid_form())
    assert resp.status_code == 303
    assert "/contribute/thanks" in resp.headers["location"]


# ── Test 8: Aggregate computation ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_aggregate_computation():
    """Submit eval with score 7.0 → aggregate avg_score == 7.0."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp = await c.post("/contribute", data=_valid_form(overall_score="7.0"))
    assert resp.status_code == 303
    agg = await db.get_vendor_aggregate("CrowdStrike")
    assert agg is not None
    assert agg["avg_score"] == 7.0


# ── Test 9: Vendor autocomplete ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vendor_autocomplete():
    """GET /api/v1/vendor-search?q=crowd → CrowdStrike in results."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        resp = await c.get("/api/v1/vendor-search?q=crowd")
    assert resp.status_code == 200
    data = resp.json()
    assert "CrowdStrike" in data["results"]


# ── Test 10: Vendor metadata ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vendor_metadata():
    """GET /api/v1/vendor-meta?vendor=CrowdStrike → has category and competitors."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        resp = await c.get("/api/v1/vendor-meta?vendor=CrowdStrike")
    assert resp.status_code == 200
    data = resp.json()
    assert data["category"] is not None
    assert "competitors" in data


# ── Test 11: Multi-submission aggregation ─────────────────────────────────────

@pytest.mark.asyncio
async def test_multi_submission_aggregation():
    """Submit 2 evals (scores 6.0 and 8.0) for same vendor → avg_score == 7.0."""
    app, db = await _make_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False,
    ) as c:
        resp1 = await c.post("/contribute", data=_valid_form(overall_score="6.0"))
        assert resp1.status_code == 303
        resp2 = await c.post("/contribute", data=_valid_form(overall_score="8.0"))
        assert resp2.status_code == 303
    agg = await db.get_vendor_aggregate("CrowdStrike")
    assert agg is not None
    assert agg["avg_score"] == 7.0
    assert agg["contribution_count"] == 2
