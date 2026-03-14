"""
PSI wire protocol — transport-agnostic message format.

Works over HTTP, WebSocket, or file exchange. Each message is a Pydantic
model that serializes to JSON for transmission.
"""
from __future__ import annotations

import base64
from enum import Enum
from pydantic import BaseModel, Field


class PSIRound(str, Enum):
    """PSI protocol rounds."""
    INIT = "init"           # Session setup
    BLIND = "blind"         # Round 1: blinded points
    DOUBLE_BLIND = "double_blind"  # Round 2: double-blinded points
    RESULT = "result"       # Cardinality result


class PSIMessage(BaseModel):
    """A single PSI protocol message."""
    round: PSIRound
    session_id: str
    party_id: str
    points: list[str] = Field(default_factory=list)  # base64-encoded EC points
    cardinality: int | None = None  # only in RESULT round
    error: str | None = None

    @staticmethod
    def encode_points(raw_points: list[bytes]) -> list[str]:
        """Encode raw bytes as base64 strings for JSON transmission."""
        return [base64.b64encode(p).decode() for p in raw_points]

    @staticmethod
    def decode_points(encoded: list[str]) -> list[bytes]:
        """Decode base64 strings back to raw bytes."""
        return [base64.b64decode(p) for p in encoded]


class PSISession(BaseModel):
    """Tracks the state of a PSI session between two parties."""
    session_id: str
    initiator_id: str
    responder_id: str | None = None
    round: PSIRound = PSIRound.INIT
    initiator_blinded: list[str] = Field(default_factory=list)
    responder_blinded: list[str] = Field(default_factory=list)
    initiator_double: list[str] = Field(default_factory=list)
    responder_double: list[str] = Field(default_factory=list)
    result_cardinality: int | None = None
    completed: bool = False


class SecAggMessage(BaseModel):
    """Message for the secure aggregation protocol."""
    session_id: str
    party_id: str
    round: str  # "enroll", "submit", "result"
    shares: list[float] = Field(default_factory=list)
    field_names: list[str] = Field(default_factory=list)
    n_parties: int | None = None
    error: str | None = None
