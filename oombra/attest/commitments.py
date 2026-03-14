"""
Cryptographic commitment schemes for the attestation protocol.

Current: Hash-based commitments (SHA-256, stdlib only)
Future:  Pedersen commitments for DP range proofs (Phase 6, needs EC)

A commitment scheme allows you to:
  1. COMMIT to a value without revealing it: C = Commit(v, r)
  2. Later OPEN the commitment: reveal (v, r), verifier checks C == Commit(v, r)

Properties:
  - Hiding: C reveals nothing about v
  - Binding: Can't open C to a different value v'
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Commitment:
    """A cryptographic commitment to a value."""
    commitment: str   # hex-encoded commitment hash
    randomness: str   # hex-encoded randomness (kept secret until opening)
    scheme: str = "sha256"

    def to_dict(self) -> dict:
        return {
            "commitment": self.commitment,
            "scheme": self.scheme,
        }
        # NOTE: randomness is NOT included — it's secret until opening

    def open_dict(self) -> dict:
        """Full dict including randomness (for opening phase)."""
        return {
            "commitment": self.commitment,
            "randomness": self.randomness,
            "scheme": self.scheme,
        }


def commit(value: str | float | int) -> Commitment:
    """
    Create a hash-based commitment to a value.

    C = SHA-256(value || randomness)

    The randomness ensures hiding: same value produces different
    commitments each time.
    """
    randomness = secrets.token_bytes(32)
    value_bytes = str(value).encode()
    commitment_hash = hashlib.sha256(value_bytes + randomness).hexdigest()
    return Commitment(
        commitment=commitment_hash,
        randomness=randomness.hex(),
    )


def verify_commitment(
    commitment: str,
    value: str | float | int,
    randomness: str,
) -> bool:
    """
    Verify that a commitment was made to the claimed value.

    Given (C, v, r), check that C == SHA-256(v || r).
    """
    value_bytes = str(value).encode()
    randomness_bytes = bytes.fromhex(randomness)
    expected = hashlib.sha256(value_bytes + randomness_bytes).hexdigest()
    return expected == commitment


def commit_field(field_name: str, value: float | int) -> Commitment:
    """
    Commit to a specific field value.
    Includes field name in the commitment for domain separation.
    """
    randomness = secrets.token_bytes(32)
    data = f"{field_name}:{value}".encode()
    commitment_hash = hashlib.sha256(data + randomness).hexdigest()
    return Commitment(
        commitment=commitment_hash,
        randomness=randomness.hex(),
    )


def verify_field_commitment(
    commitment: str,
    field_name: str,
    value: float | int,
    randomness: str,
) -> bool:
    """Verify a field-specific commitment."""
    data = f"{field_name}:{value}".encode()
    randomness_bytes = bytes.fromhex(randomness)
    expected = hashlib.sha256(data + randomness_bytes).hexdigest()
    return expected == commitment


# ══════════════════════════════════════════════════════════════════════════════
# Batch commitments (for committing to multiple fields at once)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CommitmentBatch:
    """A batch of commitments to multiple fields."""
    commitments: dict[str, Commitment]
    batch_hash: str  # Merkle-like: hash of all individual commitments

    def to_dict(self) -> dict:
        return {
            "batch_hash": self.batch_hash,
            "commitments": {
                k: v.to_dict() for k, v in self.commitments.items()
            },
        }

    def open_dict(self) -> dict:
        return {
            "batch_hash": self.batch_hash,
            "commitments": {
                k: v.open_dict() for k, v in self.commitments.items()
            },
        }


def commit_batch(fields: dict[str, float | int]) -> CommitmentBatch:
    """
    Commit to multiple field values at once.
    Produces individual commitments + a batch hash binding them together.
    """
    commitments = {}
    for name, value in fields.items():
        commitments[name] = commit_field(name, value)

    # Batch hash: SHA-256 of sorted individual commitments
    combined = "|".join(
        f"{k}:{commitments[k].commitment}"
        for k in sorted(commitments.keys())
    )
    batch_hash = hashlib.sha256(combined.encode()).hexdigest()

    return CommitmentBatch(
        commitments=commitments,
        batch_hash=batch_hash,
    )


def verify_batch(
    batch: CommitmentBatch,
    fields: dict[str, float | int],
) -> bool:
    """
    Verify all commitments in a batch.
    Returns True only if ALL individual commitments verify.
    """
    for name, value in fields.items():
        if name not in batch.commitments:
            return False
        c = batch.commitments[name]
        if not verify_field_commitment(c.commitment, name, value, c.randomness):
            return False

    # Verify batch hash
    combined = "|".join(
        f"{k}:{batch.commitments[k].commitment}"
        for k in sorted(batch.commitments.keys())
    )
    expected_batch = hashlib.sha256(combined.encode()).hexdigest()
    return expected_batch == batch.batch_hash
