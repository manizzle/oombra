"""
Secure aggregation coordinator routes.

The coordinator is untrusted by design — it only sees random-looking shares,
never plaintext values. Clients split their values into additive shares
before sending; the coordinator sums shares to produce aggregates.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ...secagg import SecAggSession

router = APIRouter(prefix="/secagg", tags=["secagg"])

# In-memory session store (production would use DB)
_sessions: dict[str, SecAggSession] = {}


class EnrollRequest(BaseModel):
    session_id: str
    party_id: str
    n_parties: int = 3
    field_names: list[str] = Field(default_factory=list)


class SubmitSharesRequest(BaseModel):
    session_id: str
    party_id: str
    shares: list[float]


@router.post("/enroll")
async def enroll(req: EnrollRequest):
    """Enroll a party in a secure aggregation session."""
    if req.session_id not in _sessions:
        _sessions[req.session_id] = SecAggSession(
            session_id=req.session_id,
            n_parties=req.n_parties,
            field_names=req.field_names,
        )
    session = _sessions[req.session_id]
    ready = session.enroll(req.party_id)
    return {
        "status": "enrolled",
        "session_id": req.session_id,
        "enrolled": len(session.enrolled),
        "needed": session.n_parties,
        "ready": ready,
    }


@router.post("/submit-shares")
async def submit_shares(req: SubmitSharesRequest):
    """Submit aggregated shares from a party."""
    if req.session_id not in _sessions:
        raise HTTPException(404, "Session not found")
    session = _sessions[req.session_id]
    try:
        all_received = session.submit_shares(req.party_id, req.shares)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "status": "accepted",
        "session_id": req.session_id,
        "received": len(session.shares_received),
        "needed": session.n_parties,
        "ready": all_received,
    }


@router.get("/result/{session_id}")
async def get_result(session_id: str):
    """Get the aggregated result for a completed session."""
    if session_id not in _sessions:
        raise HTTPException(404, "Session not found")
    session = _sessions[session_id]
    if not session.is_ready:
        return {
            "status": "waiting",
            "received": len(session.shares_received),
            "needed": session.n_parties,
        }
    try:
        result = session.compute_result()
    except ValueError as e:
        raise HTTPException(400, str(e))
    # Format result with field names if available
    if session.field_names and len(session.field_names) == len(result):
        named = {name: round(val, 2) for name, val in zip(session.field_names, result)}
        return {
            "status": "complete",
            "session_id": session_id,
            "n_parties": session.n_parties,
            "aggregate": named,
        }
    return {
        "status": "complete",
        "session_id": session_id,
        "n_parties": session.n_parties,
        "aggregate": [round(v, 2) for v in result],
    }


@router.get("/sessions")
async def list_sessions():
    """List active sessions (admin)."""
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "n_parties": s.n_parties,
                "enrolled": len(s.enrolled),
                "submitted": len(s.shares_received),
                "ready": s.is_ready,
            }
            for s in _sessions.values()
        ]
    }
