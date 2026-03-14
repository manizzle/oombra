"""
FL Coordinator — FastAPI routes for managing federated learning sessions.

Endpoints:
  POST /fl/create-session  — Create FL training session
  POST /fl/join            — Client joins a session
  GET  /fl/session/{id}    — Get session status + current global params
  POST /fl/submit-update   — Submit local model update
  GET  /fl/result/{id}     — Get final trained model
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .aggregator import fedavg, trimmed_mean, krum, geometric_median, detect_poisoning
from .models import MalwareClassifier, AnomalyDetector, IOCScorer
from .protocol import (
    FLSession, FLUpdate, FLRoundResult, FLRoundState,
    serialize_params, deserialize_params,
)

router = APIRouter(prefix="/fl", tags=["federated-learning"])

# In-memory session store
_sessions: dict[str, FLSession] = {}
_updates: dict[str, list[FLUpdate]] = {}  # session_id -> updates for current round
_global_params: dict[str, dict] = {}  # session_id -> serialized global params
_results: dict[str, FLRoundResult] = {}  # session_id -> latest result

_AGGREGATORS = {
    "fedavg": fedavg,
    "trimmed_mean": trimmed_mean,
    "krum": krum,
    "geometric_median": geometric_median,
}

_MODEL_FACTORIES = {
    "malware": lambda: MalwareClassifier(),
    "anomaly": lambda: AnomalyDetector(),
    "ioc_scorer": lambda: IOCScorer(),
}


# ── Request/response models ──────────────────────────────────────────────────

class CreateSessionRequest(BaseModel):
    model_type: str  # "malware", "anomaly", "ioc_scorer"
    max_rounds: int = 10
    min_clients: int = 2
    aggregation: str = "fedavg"
    epsilon: float | None = None


class JoinRequest(BaseModel):
    session_id: str
    client_id: str


class SubmitUpdateRequest(BaseModel):
    session_id: str
    client_id: str
    round_num: int
    params: dict
    metrics: dict = {}
    n_samples: int = 1


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/create-session")
async def create_session(req: CreateSessionRequest) -> dict:
    """Create a new FL training session."""
    if req.model_type not in _MODEL_FACTORIES:
        raise HTTPException(400, f"Unknown model type: {req.model_type}")
    if req.aggregation not in _AGGREGATORS:
        raise HTTPException(400, f"Unknown aggregation: {req.aggregation}")

    session_id = str(uuid.uuid4())

    # Initialize model and serialize global params
    model = _MODEL_FACTORIES[req.model_type]()
    initial_params = serialize_params(model.get_params())

    session = FLSession(
        session_id=session_id,
        model_type=req.model_type,
        max_rounds=req.max_rounds,
        min_clients=req.min_clients,
        aggregation=req.aggregation,
        epsilon=req.epsilon,
    )

    _sessions[session_id] = session
    _updates[session_id] = []
    _global_params[session_id] = initial_params

    return {
        "session_id": session_id,
        "model_type": req.model_type,
        "status": session.state.value,
    }


@router.post("/join")
async def join_session(req: JoinRequest) -> dict:
    """Client joins a session."""
    session = _sessions.get(req.session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    if req.client_id not in session.clients:
        session.clients.append(req.client_id)

    # Transition to training if enough clients
    if len(session.clients) >= session.min_clients:
        session.state = FLRoundState.TRAINING

    return {
        "session_id": req.session_id,
        "client_id": req.client_id,
        "round_num": session.round_num,
        "status": session.state.value,
        "global_params": _global_params.get(req.session_id, {}),
        "n_clients": len(session.clients),
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str) -> dict:
    """Get session status + current global params."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    return {
        "session_id": session_id,
        "model_type": session.model_type,
        "round_num": session.round_num,
        "max_rounds": session.max_rounds,
        "state": session.state.value,
        "n_clients": len(session.clients),
        "clients": session.clients,
        "aggregation": session.aggregation,
        "epsilon": session.epsilon,
        "global_params": _global_params.get(session_id, {}),
    }


@router.post("/submit-update")
async def submit_update(req: SubmitUpdateRequest) -> dict:
    """Submit local model update. Triggers aggregation when all clients have submitted."""
    session = _sessions.get(req.session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    if session.state == FLRoundState.COMPLETE:
        raise HTTPException(400, "Session is already complete")
    if req.round_num != session.round_num:
        raise HTTPException(400, f"Expected round {session.round_num}, got {req.round_num}")

    update = FLUpdate(
        session_id=req.session_id,
        client_id=req.client_id,
        round_num=req.round_num,
        params=req.params,
        metrics=req.metrics,
        n_samples=req.n_samples,
    )

    _updates[req.session_id].append(update)

    # Check if all clients have submitted
    if len(_updates[req.session_id]) >= len(session.clients):
        result = _aggregate_round(session)
        return {
            "status": "aggregated",
            "round_num": result.round_num,
            "n_contributors": result.n_contributors,
            "aggregate_metrics": result.aggregate_metrics,
            "poisoning_flags": result.poisoning_flags,
            "session_state": session.state.value,
        }

    return {
        "status": "waiting",
        "received": len(_updates[req.session_id]),
        "expected": len(session.clients),
        "round_num": session.round_num,
    }


@router.get("/result/{session_id}")
async def get_result(session_id: str) -> dict:
    """Get the latest result (or final model) for a session."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    result = _results.get(session_id)
    if not result:
        raise HTTPException(404, "No results yet — training in progress")

    return {
        "session_id": session_id,
        "round_num": result.round_num,
        "aggregation_method": result.aggregation_method,
        "n_contributors": result.n_contributors,
        "aggregate_metrics": result.aggregate_metrics,
        "poisoning_flags": result.poisoning_flags,
        "global_params": result.global_params,
        "session_complete": session.state == FLRoundState.COMPLETE,
    }


# ── Internal aggregation ─────────────────────────────────────────────────────

def _aggregate_round(session: FLSession) -> FLRoundResult:
    """Run aggregation for the current round."""
    session.state = FLRoundState.AGGREGATING

    updates = _updates[session.session_id]
    agg_fn = _AGGREGATORS[session.aggregation]

    # Deserialize updates
    param_updates = [deserialize_params(u.params) for u in updates]
    weights = [u.n_samples for u in updates]

    # Check for poisoning
    poisoning_flags = detect_poisoning(param_updates)

    # Aggregate
    if session.aggregation == "fedavg":
        aggregated = agg_fn(param_updates, weights=weights)
    elif session.aggregation == "krum":
        aggregated = agg_fn(param_updates)
    elif session.aggregation == "trimmed_mean":
        aggregated = agg_fn(param_updates)
    else:
        aggregated = agg_fn(param_updates)

    # Apply aggregated delta to global params
    current_global = deserialize_params(_global_params[session.session_id])
    new_global = {k: current_global[k] + aggregated[k] for k in current_global}
    _global_params[session.session_id] = serialize_params(new_global)

    # Aggregate metrics
    all_metrics: dict[str, list[float]] = {}
    for u in updates:
        for mk, mv in u.metrics.items():
            all_metrics.setdefault(mk, []).append(mv)
    aggregate_metrics = {k: float(sum(v) / len(v)) for k, v in all_metrics.items()}

    result = FLRoundResult(
        session_id=session.session_id,
        round_num=session.round_num,
        global_params=_global_params[session.session_id],
        aggregation_method=session.aggregation,
        n_contributors=len(updates),
        aggregate_metrics=aggregate_metrics,
        poisoning_flags=[f for f in poisoning_flags if f["flagged"]],
    )
    _results[session.session_id] = result

    # Advance round
    session.round_num += 1
    _updates[session.session_id] = []

    if session.round_num >= session.max_rounds:
        session.state = FLRoundState.COMPLETE
    else:
        session.state = FLRoundState.TRAINING

    return result
