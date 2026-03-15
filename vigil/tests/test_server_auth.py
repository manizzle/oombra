"""
Tests for server API key auth middleware and min-k query enforcement.
"""
from __future__ import annotations

import os
import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _make_app():
    """Create a fresh app with initialized database (reads env vars at creation time)."""
    # Force re-import so env vars are picked up fresh
    import vigil.server.app as app_mod
    from vigil.server.app import create_app
    from vigil.server.db import Database

    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    # Manually init the DB since ASGITransport doesn't trigger lifespan
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.init()
    app_mod._db = db
    return app


# ── API key auth tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_upload_without_key_when_required():
    """POST to /contribute/* without API key when key is set should return 401."""
    os.environ["VIGIL_API_KEY"] = "test-secret-key"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/contribute/submit", json={"vendor": "TestVendor"})
            assert resp.status_code == 401
            assert resp.json()["error"] == "Invalid or missing API key"
    finally:
        del os.environ["VIGIL_API_KEY"]


@pytest.mark.asyncio
async def test_upload_with_correct_key():
    """POST to /contribute/* with correct API key should succeed."""
    os.environ["VIGIL_API_KEY"] = "test-secret-key"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/contribute/submit",
                json={"vendor": "TestVendor", "category": "edr", "overall_score": 8.0},
                headers={"X-API-Key": "test-secret-key"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "accepted"
    finally:
        del os.environ["VIGIL_API_KEY"]


@pytest.mark.asyncio
async def test_upload_with_wrong_key():
    """POST to /contribute/* with wrong API key should return 401."""
    os.environ["VIGIL_API_KEY"] = "test-secret-key"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/contribute/submit",
                json={"vendor": "TestVendor"},
                headers={"X-API-Key": "wrong-key"},
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "Invalid or missing API key"
    finally:
        del os.environ["VIGIL_API_KEY"]


@pytest.mark.asyncio
async def test_upload_without_key_open_mode():
    """POST to /contribute/* without API key when no key is set (open mode) should succeed."""
    os.environ.pop("VIGIL_API_KEY", None)
    app = await _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/contribute/submit",
            json={"vendor": "TestVendor", "category": "edr", "overall_score": 8.0},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"


# ── Min-k query enforcement tests ────────────────────────────────────────────


async def _seed_vendor(client: AsyncClient, vendor: str, category: str, count: int):
    """Submit `count` contributions for a vendor."""
    for i in range(count):
        await client.post(
            "/contribute/submit",
            json={
                "vendor": vendor,
                "category": category,
                "overall_score": 7.0 + i * 0.5,
                "detection_rate": 90.0,
                "fp_rate": 1.0,
                "deploy_days": 5,
                "would_buy": True,
            },
        )


@pytest.mark.asyncio
async def test_query_vendor_with_enough_contributors():
    """Vendor with k>=3 contributors should return data."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "3"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await _seed_vendor(client, "CrowdStrike", "edr", 4)
            resp = await client.get("/query/vendor/CrowdStrike")
            assert resp.status_code == 200
            data = resp.json()
            assert "error" not in data or data.get("error") != "Insufficient contributors"
            assert data.get("vendor") == "CrowdStrike"
    finally:
        os.environ.pop("VIGIL_MIN_K", None)


@pytest.mark.asyncio
async def test_query_vendor_with_few_contributors():
    """Vendor with k<3 contributors should return error message."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "3"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await _seed_vendor(client, "TinyVendor", "edr", 2)
            resp = await client.get("/query/vendor/TinyVendor")
            assert resp.status_code == 200
            data = resp.json()
            assert data["error"] == "Insufficient contributors"
            assert data["min_required"] == 3
            assert data["current"] == 2
    finally:
        os.environ.pop("VIGIL_MIN_K", None)


@pytest.mark.asyncio
async def test_query_category_filters_low_k():
    """Category query should filter out vendors with fewer than k contributors."""
    os.environ.pop("VIGIL_API_KEY", None)
    os.environ["VIGIL_MIN_K"] = "3"
    try:
        app = await _make_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Seed one vendor with 4 contribs (above k) and one with 1 (below k)
            await _seed_vendor(client, "BigVendor", "edr", 4)
            await _seed_vendor(client, "SmallVendor", "edr", 1)

            resp = await client.get("/query/category/edr")
            assert resp.status_code == 200
            data = resp.json()
            vendor_names = [v["vendor"] for v in data["vendors"]]
            assert "BigVendor" in vendor_names
            assert "SmallVendor" not in vendor_names
    finally:
        os.environ.pop("VIGIL_MIN_K", None)
