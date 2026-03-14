"""
Secure Aggregation — multiple orgs contribute vendor evaluations;
a coordinator computes the average without seeing any individual score.

Uses additive secret sharing with optional Shamir's threshold scheme
for dropout tolerance. Composes with DP from dp.py: noise BEFORE splitting.
"""
from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field
from typing import Sequence


# ══════════════════════════════════════════════════════════════════════════════
# Additive secret sharing
# ══════════════════════════════════════════════════════════════════════════════

def split(value: float, n_parties: int) -> list[float]:
    """
    Split a value into n additive shares that sum to the original.
    Each individual share reveals nothing about the value.
    """
    if n_parties < 2:
        raise ValueError("Need at least 2 parties")
    # Generate n-1 random shares, compute the last as value - sum(others)
    shares = [random.uniform(-1e6, 1e6) for _ in range(n_parties - 1)]
    shares.append(value - sum(shares))
    return shares


def aggregate(all_shares: list[list[float]]) -> list[float]:
    """
    Sum shares from all parties to recover aggregate values.

    Args:
        all_shares: list of share vectors, one per party.
                    Each vector has the same length (one share per field).
    Returns:
        Summed values (one per field).
    """
    if not all_shares:
        return []
    n_fields = len(all_shares[0])
    return [sum(shares[i] for shares in all_shares) for i in range(n_fields)]


# ══════════════════════════════════════════════════════════════════════════════
# Shamir's Secret Sharing (threshold scheme for dropout tolerance)
# ══════════════════════════════════════════════════════════════════════════════

# Use a large prime for the finite field
_PRIME = 2**127 - 1  # Mersenne prime M127


def _mod_inverse(a: int, p: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % p
    g, x, _ = _extended_gcd(a, p)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % p


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def shamir_split(
    secret: int,
    n_parties: int,
    threshold: int,
) -> list[tuple[int, int]]:
    """
    Split secret into n shares where any threshold shares can reconstruct.

    Returns list of (x, y) points on the polynomial.
    """
    if threshold > n_parties:
        raise ValueError("threshold cannot exceed n_parties")
    if threshold < 2:
        raise ValueError("threshold must be at least 2")

    # Random polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    coeffs = [secret % _PRIME]
    for _ in range(threshold - 1):
        coeffs.append(secrets.randbelow(_PRIME))

    shares = []
    for i in range(1, n_parties + 1):
        y = sum(c * pow(i, power, _PRIME) for power, c in enumerate(coeffs)) % _PRIME
        shares.append((i, y))
    return shares


def shamir_reconstruct(shares: list[tuple[int, int]]) -> int:
    """
    Reconstruct the secret from threshold or more shares.
    Uses Lagrange interpolation at x=0.
    """
    if not shares:
        raise ValueError("Need at least one share")

    secret = 0
    for i, (xi, yi) in enumerate(shares):
        # Lagrange basis polynomial evaluated at x=0
        num = 1
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = (num * (-xj)) % _PRIME
                den = (den * (xi - xj)) % _PRIME
        lagrange = (yi * num * _mod_inverse(den, _PRIME)) % _PRIME
        secret = (secret + lagrange) % _PRIME
    return secret


# ══════════════════════════════════════════════════════════════════════════════
# Session management
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecAggSession:
    """
    Manages a single secure aggregation round.

    Flow:
      1. Coordinator creates session with expected n_parties
      2. Each party enrolls
      3. Each party splits their values into n_parties shares
      4. Each party sends share_i to party_i (via coordinator)
      5. Coordinator sums received shares per party → aggregate
    """
    session_id: str
    n_parties: int
    threshold: int | None = None  # None = all parties required (additive)
    field_names: list[str] = field(default_factory=list)

    # State
    enrolled: list[str] = field(default_factory=list)  # party IDs
    shares_received: dict[str, list[float]] = field(default_factory=dict)  # party_id -> shares
    _result: list[float] | None = field(default=None, repr=False)

    def enroll(self, party_id: str) -> bool:
        """Enroll a party. Returns True if enrollment is now complete."""
        if party_id in self.enrolled:
            return len(self.enrolled) >= self.n_parties
        self.enrolled.append(party_id)
        return len(self.enrolled) >= self.n_parties

    def submit_shares(self, party_id: str, shares: list[float]) -> bool:
        """
        Submit aggregated shares from a party.
        Returns True if all shares have been received.
        """
        if party_id not in self.enrolled:
            raise ValueError(f"Party {party_id} not enrolled")
        self.shares_received[party_id] = shares
        return len(self.shares_received) >= self.n_parties

    def compute_result(self) -> list[float]:
        """Compute the aggregate from all received shares."""
        if len(self.shares_received) < self.n_parties:
            raise ValueError(
                f"Need {self.n_parties} submissions, have {len(self.shares_received)}"
            )
        all_shares = list(self.shares_received.values())
        self._result = aggregate(all_shares)
        return self._result

    @property
    def result(self) -> list[float] | None:
        return self._result

    @property
    def is_ready(self) -> bool:
        return len(self.shares_received) >= self.n_parties


def prepare_shares(
    values: list[float],
    n_parties: int,
) -> list[list[float]]:
    """
    Split each value into n_parties additive shares.

    Returns: list of n_parties share vectors.
    share_vectors[i] should be sent to party i.
    """
    n_fields = len(values)
    # For each field, split into n shares
    all_splits = [split(v, n_parties) for v in values]
    # Transpose: share_vectors[party_i] = [field_0_share_i, field_1_share_i, ...]
    return [
        [all_splits[f][p] for f in range(n_fields)]
        for p in range(n_parties)
    ]
