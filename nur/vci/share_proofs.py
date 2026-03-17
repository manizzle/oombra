"""
Shamir-Pedersen Binding — prove that Shamir shares reconstruct
to the same value committed in a Pedersen commitment.

Key math:
  Given original commitment C = g^v * h^r and Shamir shares (x_i, s_i)
  where v = sum(lambda_i * s_i) via Lagrange interpolation:

  1. Commit to each share: C_i = g^{s_i} * h^{r_i}
  2. Reconstruct from commitments:
     R = prod(C_i^{lambda_i}) = g^v * h^{sum(lambda_i * r_i)}
  3. Proof is delta = sum(lambda_i * r_i) - r mod q
  4. Verifier checks: prod(C_i^{lambda_i}) == C * h^delta
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from ..zkp.proofs import (
    ProofParams,
    Commitment,
    _mod_inverse,
    _random_scalar,
    commit,
)


# ══════════════════════════════════════════════════════════════════════════════
# VCI-specific Shamir over Z_q (matches ZKP params field)
# ══════════════════════════════════════════════════════════════════════════════

def vci_shamir_split(
    secret: int,
    n_parties: int,
    threshold: int,
    q: int,
) -> list[tuple[int, int]]:
    """Split secret into Shamir shares over Z_q (ZKP-compatible field)."""
    if threshold > n_parties:
        raise ValueError("threshold cannot exceed n_parties")
    if threshold < 2:
        raise ValueError("threshold must be at least 2")

    coeffs = [secret % q]
    for _ in range(threshold - 1):
        coeffs.append(secrets.randbelow(q))

    shares = []
    for i in range(1, n_parties + 1):
        y = sum(c * pow(i, power, q) for power, c in enumerate(coeffs)) % q
        shares.append((i, y))
    return shares


def vci_shamir_reconstruct(shares: list[tuple[int, int]], q: int) -> int:
    """Reconstruct secret from Shamir shares over Z_q."""
    if not shares:
        raise ValueError("Need at least one share")
    xs = [x for x, _ in shares]
    lambdas = lagrange_coefficients(xs, q)
    return sum(lam * y for lam, (_, y) in zip(lambdas, shares)) % q


def lagrange_coefficients(xs: list[int], q: int) -> list[int]:
    """Compute Lagrange coefficients for interpolation at x=0 over Z_q."""
    lambdas = []
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for j, xj in enumerate(xs):
            if i != j:
                num = (num * (-xj)) % q
                den = (den * (xi - xj)) % q
        lambdas.append((num * pow(den, q - 2, q)) % q)
    return lambdas


# ══════════════════════════════════════════════════════════════════════════════
# Share commitments and consistency proofs
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ShareConsistencyProof:
    """Proves Shamir shares reconstruct to the same value as a Pedersen commitment."""
    share_commitments: list[dict]       # Pedersen commitment to each share
    blinding_delta: int                 # sum(lambda_i * r_i) - r_original mod q
    share_xs: list[int]                 # x-coordinates of shares

    def to_dict(self) -> dict:
        return {
            "share_commitments": self.share_commitments,
            "blinding_delta": self.blinding_delta,
            "share_xs": self.share_xs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ShareConsistencyProof:
        return cls(
            share_commitments=[c for c in data["share_commitments"]],
            blinding_delta=int(data["blinding_delta"]),
            share_xs=[int(x) for x in data["share_xs"]],
        )


def commit_and_prove_shares(
    params: ProofParams,
    original_commitment: Commitment,
    shares: list[tuple[int, int]],
) -> ShareConsistencyProof:
    """
    Commit to each Shamir share and prove consistency with the original commitment.

    Args:
        params: ZKP parameters
        original_commitment: C = g^v * h^r (the commitment from the ZKP bundle)
        shares: list of (x_i, s_i) Shamir shares

    Returns:
        ShareConsistencyProof binding the shares to the original commitment
    """
    xs = [x for x, _ in shares]
    lambdas = lagrange_coefficients(xs, params.q)

    share_commitments = []
    share_randomnesses = []

    for _, s_i in shares:
        r_i = _random_scalar(params.q)
        c_i = commit(params, s_i, randomness=r_i)
        share_commitments.append(c_i)
        share_randomnesses.append(r_i)

    # Compute blinding delta: sum(lambda_i * r_i) - r_original mod q
    weighted_r_sum = sum(
        (lam * r_i) % params.q
        for lam, r_i in zip(lambdas, share_randomnesses)
    ) % params.q

    delta = (weighted_r_sum - original_commitment.randomness) % params.q

    return ShareConsistencyProof(
        share_commitments=[c.to_dict() for c in share_commitments],
        blinding_delta=delta,
        share_xs=xs,
    )


def verify_share_consistency(
    params: ProofParams,
    original_commitment: Commitment,
    proof: ShareConsistencyProof,
) -> bool:
    """
    Verify that committed shares reconstruct to the original committed value.

    Checks: prod(C_i^{lambda_i}) == C * h^delta

    Where C_i are the share commitments, lambda_i are Lagrange coefficients,
    C is the original commitment, and delta is the blinding factor difference.
    """
    if not proof.share_commitments or not proof.share_xs:
        return False
    if len(proof.share_commitments) != len(proof.share_xs):
        return False

    lambdas = lagrange_coefficients(proof.share_xs, params.q)
    share_coms = [Commitment.from_dict(c) for c in proof.share_commitments]

    # LHS: prod(C_i^{lambda_i}) mod p
    reconstructed = 1
    for c_i, lam in zip(share_coms, lambdas):
        reconstructed = (reconstructed * pow(c_i.value_commitment, lam, params.p)) % params.p

    # RHS: C * h^delta mod p
    expected = (
        original_commitment.value_commitment
        * pow(params.h, proof.blinding_delta, params.p)
    ) % params.p

    return reconstructed == expected


__all__ = [
    "ShareConsistencyProof",
    "commit_and_prove_shares",
    "lagrange_coefficients",
    "vci_shamir_reconstruct",
    "vci_shamir_split",
    "verify_share_consistency",
]
