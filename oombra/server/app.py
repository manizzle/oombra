"""
FastAPI application — the oombra server.

Endpoints:
  POST /contribute/submit       — receive EvalRecord
  POST /contribute/attack-map   — receive AttackMap
  POST /contribute/ioc-bundle   — receive IOCBundle
  GET  /health                  — liveness check
  GET  /stats                   — contribution counts (anonymized)
  GET  /query/*                 — aggregated read-side queries
  POST /secagg/*                — secure aggregation coordinator
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .db import Database
from .routes.query import router as query_router
from .routes.secagg import router as secagg_router


# ── App setup ────────────────────────────────────────────────────────────────

_db: Database | None = None


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db
    db_url = app.state.db_url if hasattr(app.state, "db_url") else "sqlite+aiosqlite:///oombra.db"
    _db = Database(db_url)
    await _db.init()
    yield
    await _db.close()
    _db = None


def create_app(db_url: str = "sqlite+aiosqlite:///oombra.db") -> FastAPI:
    app = FastAPI(
        title="oombra",
        description="Privacy-preserving federated threat intelligence server",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.db_url = db_url
    app.include_router(query_router)
    app.include_router(secagg_router)

    # Conditionally include FL router
    try:
        from ..fl.server import router as fl_router
        app.include_router(fl_router)
    except ImportError:
        pass  # FL module not available (missing numpy)

    # ── Health ────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    # ── Stats ─────────────────────────────────────────────────────────

    @app.get("/stats")
    async def stats():
        db = get_db()
        return await db.get_stats()

    # ── Contribute routes ─────────────────────────────────────────────

    @app.post("/contribute/submit")
    async def contribute_eval(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_eval_record(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/attack-map")
    async def contribute_attack_map(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_attack_map(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/ioc-bundle")
    async def contribute_ioc_bundle(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_ioc_bundle(body)
        return {"status": "accepted", "contribution_id": cid}

    return app


# Default app instance for `uvicorn oombra.server.app:app`
app = create_app()
