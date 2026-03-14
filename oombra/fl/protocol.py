"""
FL round protocol — state machine, message types, and serialization.

Defines the wire format for federated learning sessions between
clients and the coordinator server.
"""
from __future__ import annotations

import base64
import io
from enum import Enum
from typing import Any

import numpy as np
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════════════
# Numpy serialization helpers
# ══════════════════════════════════════════════════════════════════════════════

def ndarray_to_b64(arr: np.ndarray) -> dict:
    """Serialize a numpy array to a JSON-safe dict with base64 data."""
    buf = io.BytesIO()
    np.save(buf, arr)
    data = base64.b64encode(buf.getvalue()).decode("ascii")
    return {"dtype": str(arr.dtype), "shape": list(arr.shape), "data": data}


def b64_to_ndarray(d: dict) -> np.ndarray:
    """Deserialize a numpy array from a base64-encoded dict."""
    raw = base64.b64decode(d["data"])
    buf = io.BytesIO(raw)
    return np.load(buf)


def serialize_params(params: dict[str, np.ndarray]) -> dict[str, dict]:
    """Serialize a parameter dict for JSON transport."""
    return {k: ndarray_to_b64(v) for k, v in params.items()}


def deserialize_params(data: dict[str, dict]) -> dict[str, np.ndarray]:
    """Deserialize a parameter dict from JSON transport."""
    return {k: b64_to_ndarray(v) for k, v in data.items()}


# ══════════════════════════════════════════════════════════════════════════════
# State machine
# ══════════════════════════════════════════════════════════════════════════════

class FLRoundState(str, Enum):
    WAITING_FOR_CLIENTS = "waiting"
    TRAINING = "training"
    AGGREGATING = "aggregating"
    COMPLETE = "complete"


# ══════════════════════════════════════════════════════════════════════════════
# Protocol messages
# ══════════════════════════════════════════════════════════════════════════════

class FLSession(BaseModel):
    """A federated learning training session."""
    session_id: str
    model_type: str  # "malware", "anomaly", "ioc_scorer"
    round_num: int = 0
    max_rounds: int = 10
    min_clients: int = 2
    aggregation: str = "fedavg"  # fedavg, trimmed_mean, krum, geometric_median
    epsilon: float | None = None
    state: FLRoundState = FLRoundState.WAITING_FOR_CLIENTS
    clients: list[str] = Field(default_factory=list)


class FLUpdate(BaseModel):
    """A client's model update for a round."""
    session_id: str
    client_id: str
    round_num: int
    params: dict  # serialized numpy arrays (base64-encoded)
    metrics: dict  # local training metrics (loss, accuracy)
    n_samples: int  # for weighted averaging


class FLRoundResult(BaseModel):
    """Result of aggregating a round's updates."""
    session_id: str
    round_num: int
    global_params: dict  # aggregated parameters (serialized)
    aggregation_method: str
    n_contributors: int
    aggregate_metrics: dict
    poisoning_flags: list[dict] = Field(default_factory=list)
