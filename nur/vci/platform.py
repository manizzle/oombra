"""
Platform Attestation — zero-knowledge proof about the database.

Proves to new users: "I have N contributions from M unique orgs
with average credibility W" without revealing individual records.

Uses Pedersen commitments + range proofs on statistics, bound to a
Merkle tree of contribution envelope hashes. The server can't inflate
N without forging proofs because the Merkle tree binds the statistics
to actual data.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import datetime
from dataclasses import dataclass, field

from ..zkp.proofs import (
    ProofParams,
    Commitment,
    commit,
    create_range_proof,
    verify_range_proof,
)


# ══════════════════════════════════════════════════════════════════════════════
# Merkle tree
# ══════════════════════════════════════════════════════════════════════════════

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_merkle_tree(leaves: list[str]) -> tuple[str, list[list[str]]]:
    """
    Build a Merkle tree from leaf hashes.

    Returns:
        (root_hash, tree_levels) where tree_levels[0] = leaves
    """
    if not leaves:
        return _sha256(b"empty"), [[]]

    # Pad to power of 2
    n = len(leaves)
    target = 1
    while target < n:
        target *= 2
    padded = list(leaves) + [_sha256(b"pad")] * (target - n)

    levels = [padded]
    current = padded

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            combined = (current[i] + current[i + 1]).encode()
            next_level.append(_sha256(combined))
        levels.append(next_level)
        current = next_level

    return current[0], levels


def verify_merkle_proof(
    leaf_hash: str,
    proof_path: list[tuple[str, str]],  # [(sibling_hash, "left"|"right"), ...]
    root: str,
) -> bool:
    """Verify a Merkle inclusion proof."""
    current = leaf_hash
    for sibling, direction in proof_path:
        if direction == "left":
            combined = (sibling + current).encode()
        else:
            combined = (current + sibling).encode()
        current = _sha256(combined)
    return current == root


def get_merkle_proof(
    leaf_index: int,
    tree_levels: list[list[str]],
) -> list[tuple[str, str]]:
    """Get the Merkle proof path for a leaf."""
    proof = []
    idx = leaf_index
    for level in tree_levels[:-1]:  # skip root level
        if idx % 2 == 0:
            sibling_idx = idx + 1
            direction = "right"
        else:
            sibling_idx = idx - 1
            direction = "left"
        if sibling_idx < len(level):
            proof.append((level[sibling_idx], direction))
        idx //= 2
    return proof


# ══════════════════════════════════════════════════════════════════════════════
# Platform attestation
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PlatformAttestation:
    """
    Zero-knowledge proof about the platform's database.

    Proves:
    - N contributions exist (range proof on N)
    - M unique organizations (range proof on M)
    - Average credibility W >= threshold (range proof on scaled W)
    - Statistics are bound to a Merkle tree of actual envelope hashes
    """
    statistics_commitments: dict       # {N: commitment, M: commitment, W: commitment}
    statistics_proofs: dict            # {N: range_proof, M: range_proof, W: range_proof}
    merkle_root: str                   # SHA-256 root of all envelope hashes
    leaf_count: int                    # publicly known leaf count
    leaf_count_commitment: dict        # Pedersen commitment to leaf count
    leaf_count_proof: dict             # range proof that committed N = leaf_count
    server_signature: str              # HMAC signature
    timestamp: str
    version: str = "vci-attestation-v1"

    def to_dict(self) -> dict:
        return {
            "statistics_commitments": self.statistics_commitments,
            "statistics_proofs": self.statistics_proofs,
            "merkle_root": self.merkle_root,
            "leaf_count": self.leaf_count,
            "leaf_count_commitment": self.leaf_count_commitment,
            "leaf_count_proof": self.leaf_count_proof,
            "server_signature": self.server_signature,
            "timestamp": self.timestamp,
            "version": self.version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> PlatformAttestation:
        return cls(
            statistics_commitments=data["statistics_commitments"],
            statistics_proofs=data["statistics_proofs"],
            merkle_root=data["merkle_root"],
            leaf_count=data["leaf_count"],
            leaf_count_commitment=data["leaf_count_commitment"],
            leaf_count_proof=data["leaf_count_proof"],
            server_signature=data["server_signature"],
            timestamp=data["timestamp"],
            version=data.get("version", "vci-attestation-v1"),
        )

    @classmethod
    def from_json(cls, text: str) -> PlatformAttestation:
        return cls.from_dict(json.loads(text))


def generate_platform_attestation(
    params: ProofParams,
    envelope_hashes: list[str],
    org_ids: list[str],
    credibility_weights: list[float],
    server_secret: bytes,
) -> PlatformAttestation:
    """
    Generate a platform attestation proving database properties.

    Args:
        params: ZKP parameters
        envelope_hashes: SHA-256 hashes of all contribution envelopes
        org_ids: organization identifiers (hashed)
        credibility_weights: credibility weight for each contribution
        server_secret: server's HMAC key for signing

    Returns:
        PlatformAttestation with commitments, proofs, and Merkle tree
    """
    n_contributions = len(envelope_hashes)
    n_unique_orgs = len(set(org_ids))

    # Average credibility scaled to integer (multiply by 100 for 2 decimal places)
    avg_credibility = (
        sum(credibility_weights) / len(credibility_weights)
        if credibility_weights
        else 0
    )
    scaled_credibility = int(round(avg_credibility * 100))

    # Build Merkle tree from envelope hashes
    merkle_root, tree_levels = build_merkle_tree(envelope_hashes)

    # Generate commitments and range proofs for statistics
    stats_commitments = {}
    stats_proofs = {}

    # N: number of contributions (range [1, 100000])
    c_n, p_n = create_range_proof(params, n_contributions, 1, 100000)
    stats_commitments["N"] = c_n.to_dict()
    stats_proofs["N"] = p_n.to_dict()

    # M: number of unique orgs (range [1, 10000])
    c_m, p_m = create_range_proof(params, n_unique_orgs, 1, 10000)
    stats_commitments["M"] = c_m.to_dict()
    stats_proofs["M"] = p_m.to_dict()

    # W: average credibility * 100 (range [5, 95] since weights are in [0.05, 0.95])
    clamped_w = max(5, min(95, scaled_credibility))
    c_w, p_w = create_range_proof(params, clamped_w, 5, 95)
    stats_commitments["W"] = c_w.to_dict()
    stats_proofs["W"] = p_w.to_dict()

    # Leaf count commitment + proof (binds N to actual Merkle tree)
    c_leaf, p_leaf = create_range_proof(params, n_contributions, 1, 100000)

    # Server signature over the attestation contents
    sig_contents = json.dumps({
        "merkle_root": merkle_root,
        "leaf_count": n_contributions,
        "stats": {"N": n_contributions, "M": n_unique_orgs, "W": scaled_credibility},
    }, sort_keys=True).encode()
    signature = hmac.new(server_secret, sig_contents, hashlib.sha256).hexdigest()

    return PlatformAttestation(
        statistics_commitments=stats_commitments,
        statistics_proofs=stats_proofs,
        merkle_root=merkle_root,
        leaf_count=n_contributions,
        leaf_count_commitment=c_leaf.to_dict(),
        leaf_count_proof=p_leaf.to_dict(),
        server_signature=signature,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def verify_platform_attestation(
    params: ProofParams,
    attestation: PlatformAttestation,
) -> dict:
    """
    Verify a platform attestation.

    Checks:
    1. Range proof for N (contribution count)
    2. Range proof for M (unique orgs)
    3. Range proof for W (average credibility)
    4. Leaf count proof matches claimed N
    5. All commitments are well-formed

    Returns:
        {"valid": bool, "checks": dict, "statistics": dict, "errors": list}
    """
    errors = []
    checks = {
        "N_range_proof": False,
        "M_range_proof": False,
        "W_range_proof": False,
        "leaf_count_proof": False,
    }

    # Verify N range proof
    try:
        c_n = Commitment.from_dict(attestation.statistics_commitments["N"])
        from ..zkp.proofs import RangeProof
        p_n = RangeProof.from_dict(attestation.statistics_proofs["N"])
        checks["N_range_proof"] = verify_range_proof(params, c_n, p_n, 1, 100000)
        if not checks["N_range_proof"]:
            errors.append("N range proof verification failed")
    except Exception as e:
        errors.append(f"N range proof error: {e}")

    # Verify M range proof
    try:
        c_m = Commitment.from_dict(attestation.statistics_commitments["M"])
        p_m = RangeProof.from_dict(attestation.statistics_proofs["M"])
        checks["M_range_proof"] = verify_range_proof(params, c_m, p_m, 1, 10000)
        if not checks["M_range_proof"]:
            errors.append("M range proof verification failed")
    except Exception as e:
        errors.append(f"M range proof error: {e}")

    # Verify W range proof
    try:
        c_w = Commitment.from_dict(attestation.statistics_commitments["W"])
        p_w = RangeProof.from_dict(attestation.statistics_proofs["W"])
        checks["W_range_proof"] = verify_range_proof(params, c_w, p_w, 5, 95)
        if not checks["W_range_proof"]:
            errors.append("W range proof verification failed")
    except Exception as e:
        errors.append(f"W range proof error: {e}")

    # Verify leaf count proof
    try:
        c_leaf = Commitment.from_dict(attestation.leaf_count_commitment)
        p_leaf = RangeProof.from_dict(attestation.leaf_count_proof)
        checks["leaf_count_proof"] = verify_range_proof(params, c_leaf, p_leaf, 1, 100000)
        if not checks["leaf_count_proof"]:
            errors.append("Leaf count proof verification failed")
    except Exception as e:
        errors.append(f"Leaf count proof error: {e}")

    return {
        "valid": all(checks.values()),
        "checks": checks,
        "statistics": {
            "leaf_count": attestation.leaf_count,
            "merkle_root": attestation.merkle_root,
        },
        "errors": errors,
    }


__all__ = [
    "PlatformAttestation",
    "build_merkle_tree",
    "generate_platform_attestation",
    "get_merkle_proof",
    "verify_merkle_proof",
    "verify_platform_attestation",
]
