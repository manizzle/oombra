"""Pedersen commitments and Schnorr-style proofs for Oombra."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


def _sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def _fs_encode(value) -> bytes:
    if isinstance(value, int):
        return f"i:{value};".encode()
    if isinstance(value, str):
        return f"s:{len(value)}:{value};".encode()
    if isinstance(value, list):
        encoded = [f"l:{len(value)}:[".encode()]
        for item in value:
            encoded.append(_fs_encode(item))
        encoded.append(b"]")
        return b"".join(encoded)
    if isinstance(value, tuple):
        return _fs_encode(list(value))
    raise TypeError(f"Unsupported Fiat-Shamir value: {type(value)!r}")


def _challenge(params, *parts) -> int:
    payload = b"".join(_fs_encode(part) for part in parts)
    return _sha256_int(payload) % params.q


def _mod_inverse(value: int, modulus: int) -> int:
    return pow(value % modulus, modulus - 2, modulus)


def _random_scalar(q: int) -> int:
    return secrets.randbelow(q)


def _hash_to_group(p: int, q: int, label: str, disallow: int | None = None) -> int:
    counter = 0
    while True:
        seed = _sha256_int(f"{label}:{counter}".encode()) % p
        if seed in (0, 1, p - 1):
            counter += 1
            continue
        candidate = pow(seed, 2, p)
        if candidate != 1 and pow(candidate, q, p) == 1 and candidate != disallow:
            return candidate
        counter += 1


def _in_subgroup(params, element: int) -> bool:
    return 0 < element < params.p and pow(element, params.q, params.p) == 1


def _encode_value(params, value) -> int:
    if isinstance(value, str):
        return _sha256_int(value.encode()) % params.q
    if isinstance(value, int):
        return value % params.q
    raise TypeError("Values must be ints or strings.")


def _normalize_allowed_values(params, allowed_values) -> list[int]:
    encoded = sorted({_encode_value(params, value) for value in allowed_values})
    if not encoded:
        raise ValueError("allowed_set must not be empty.")
    return encoded


def _bit_decompose(value: int, bit_length: int) -> list[int]:
    bits = []
    for index in range(bit_length):
        bits.append((value >> index) & 1)
    return bits


def _weighted_randomness_shares(params, target_randomness: int, bit_length: int) -> list[int]:
    if bit_length < 1:
        raise ValueError("bit_length must be at least 1.")
    if bit_length == 1:
        return [target_randomness % params.q]

    shares = []
    accumulator = 0
    for index in range(bit_length - 1):
        share = _random_scalar(params.q)
        shares.append(share)
        accumulator = (accumulator + ((1 << index) * share)) % params.q

    coefficient = pow(2, bit_length - 1, params.q)
    final_share = ((target_randomness - accumulator) % params.q) * _mod_inverse(
        coefficient, params.q
    )
    shares.append(final_share % params.q)
    return shares


def _weighted_commitment_product(params, commitments: list[int]) -> int:
    product = 1
    for index, commitment in enumerate(commitments):
        product = (product * pow(commitment, 1 << index, params.p)) % params.p
    return product


def _opening_statements(params, commitment_value: int, allowed_values: list[int]) -> list[int]:
    statements = []
    for allowed in allowed_values:
        value_factor = pow(params.g, allowed, params.p)
        statements.append((commitment_value * _mod_inverse(value_factor, params.p)) % params.p)
    return statements


def _create_opening_or_proof(
    params,
    commitment_value: int,
    opening_randomness: int,
    actual_value: int,
    allowed_values: list[int],
    domain: str,
) -> "MembershipProof":
    if actual_value not in allowed_values:
        raise ValueError("Committed value is not in the allowed set.")

    statements = _opening_statements(params, commitment_value, allowed_values)
    witness_index = allowed_values.index(actual_value)
    announcements = []
    challenges = []
    responses = []
    real_nonce = _random_scalar(params.q)

    for index, statement in enumerate(statements):
        if not _in_subgroup(params, statement):
            raise ValueError("Invalid subgroup statement.")
        if index == witness_index:
            announcements.append(pow(params.h, real_nonce, params.p))
            challenges.append(0)
            responses.append(0)
            continue

        challenge = _random_scalar(params.q)
        response = _random_scalar(params.q)
        announcement = pow(params.h, response, params.p)
        announcement = (announcement * pow(_mod_inverse(statement, params.p), challenge, params.p)) % params.p
        announcements.append(announcement)
        challenges.append(challenge)
        responses.append(response)

    master_challenge = _challenge(params, domain, commitment_value, allowed_values, announcements)
    real_challenge = (master_challenge - sum(challenges)) % params.q
    real_response = (real_nonce + real_challenge * opening_randomness) % params.q

    challenges[witness_index] = real_challenge
    responses[witness_index] = real_response
    return MembershipProof(
        announcements=announcements,
        challenges=challenges,
        responses=responses,
        relation=domain,
    )


def _verify_opening_or_proof(
    params,
    commitment_value: int,
    proof: "MembershipProof",
    allowed_values: list[int],
    domain: str,
) -> bool:
    if proof.relation != domain:
        return False
    if not _in_subgroup(params, commitment_value):
        return False
    if len(proof.announcements) != len(allowed_values):
        return False
    if len(proof.challenges) != len(allowed_values):
        return False
    if len(proof.responses) != len(allowed_values):
        return False

    statements = _opening_statements(params, commitment_value, allowed_values)
    for index, statement in enumerate(statements):
        announcement = proof.announcements[index]
        challenge = proof.challenges[index] % params.q
        response = proof.responses[index] % params.q
        if not _in_subgroup(params, statement):
            return False
        if not _in_subgroup(params, announcement):
            return False
        lhs = pow(params.h, response, params.p)
        rhs = (announcement * pow(statement, challenge, params.p)) % params.p
        if lhs != rhs:
            return False

    master_challenge = _challenge(params, domain, commitment_value, allowed_values, proof.announcements)
    return sum(proof.challenges) % params.q == master_challenge


def _require_int(name: str, value) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an int.")
    return value


@dataclass(frozen=True)
class ProofParams:
    p: int = 76910954774514048114308037844818328980132981626852410033832376445786461872543
    g: int = 4
    q: int = 38455477387257024057154018922409164490066490813426205016916188222893230936271
    h: int = field(default=0)

    def __post_init__(self) -> None:
        if self.p != (2 * self.q) + 1:
            raise ValueError("p must be a safe prime with q = (p - 1) / 2.")
        if self.h == 0:
            object.__setattr__(self, "h", _hash_to_group(self.p, self.q, "vigil_h", self.g))
        if not _in_subgroup(self, self.g):
            raise ValueError("g must be in the order-q subgroup.")
        if self.g == 1:
            raise ValueError("g must not be the identity.")
        if not _in_subgroup(self, self.h):
            raise ValueError("h must be in the order-q subgroup.")
        if self.h in (1, self.g):
            raise ValueError("h must be independent from g.")

    def to_dict(self) -> dict:
        return {"p": self.p, "g": self.g, "q": self.q, "h": self.h}

    @classmethod
    def from_dict(cls, data: dict) -> "ProofParams":
        return cls(p=int(data["p"]), g=int(data["g"]), q=int(data["q"]), h=int(data["h"]))


@dataclass(frozen=True)
class Commitment:
    value_commitment: int
    randomness: int

    @classmethod
    def commit(cls, params: ProofParams, value, randomness: int | None = None) -> "Commitment":
        scalar = _encode_value(params, value)
        blinding = _random_scalar(params.q) if randomness is None else randomness % params.q
        commitment_value = pow(params.g, scalar, params.p)
        commitment_value = (commitment_value * pow(params.h, blinding, params.p)) % params.p
        return cls(value_commitment=commitment_value, randomness=blinding)

    def to_dict(self) -> dict:
        return {
            "value_commitment": self.value_commitment,
            "randomness": self.randomness,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Commitment":
        return cls(
            value_commitment=int(data["value_commitment"]),
            randomness=int(data["randomness"]),
        )


def commit(params: ProofParams, value, randomness: int | None = None) -> Commitment:
    return Commitment.commit(params, value, randomness=randomness)


@dataclass(frozen=True)
class MembershipProof:
    announcements: list[int]
    challenges: list[int]
    responses: list[int]
    relation: str = "membership"

    def to_dict(self) -> dict:
        return {
            "announcements": list(self.announcements),
            "challenges": list(self.challenges),
            "responses": list(self.responses),
            "relation": self.relation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MembershipProof":
        return cls(
            announcements=[int(value) for value in data["announcements"]],
            challenges=[int(value) for value in data["challenges"]],
            responses=[int(value) for value in data["responses"]],
            relation=data.get("relation", "membership"),
        )


@dataclass(frozen=True)
class RangeProof:
    lower_bit_commitments: list[int]
    lower_bit_proofs: list[MembershipProof]
    upper_bit_commitments: list[int]
    upper_bit_proofs: list[MembershipProof]
    bit_length: int
    relation: str = "range"

    def to_dict(self) -> dict:
        return {
            "lower_bit_commitments": list(self.lower_bit_commitments),
            "lower_bit_proofs": [proof.to_dict() for proof in self.lower_bit_proofs],
            "upper_bit_commitments": list(self.upper_bit_commitments),
            "upper_bit_proofs": [proof.to_dict() for proof in self.upper_bit_proofs],
            "bit_length": self.bit_length,
            "relation": self.relation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RangeProof":
        return cls(
            lower_bit_commitments=[int(value) for value in data["lower_bit_commitments"]],
            lower_bit_proofs=[
                MembershipProof.from_dict(proof) for proof in data["lower_bit_proofs"]
            ],
            upper_bit_commitments=[int(value) for value in data["upper_bit_commitments"]],
            upper_bit_proofs=[
                MembershipProof.from_dict(proof) for proof in data["upper_bit_proofs"]
            ],
            bit_length=int(data["bit_length"]),
            relation=data.get("relation", "range"),
        )


@dataclass(frozen=True)
class ConsistencyProof:
    announcement: int
    challenge: int
    response: int
    relation: str = "equal"

    def to_dict(self) -> dict:
        return {
            "announcement": self.announcement,
            "challenge": self.challenge,
            "response": self.response,
            "relation": self.relation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConsistencyProof":
        return cls(
            announcement=int(data["announcement"]),
            challenge=int(data["challenge"]),
            response=int(data["response"]),
            relation=data.get("relation", "equal"),
        )


@dataclass(frozen=True)
class NonZeroProof:
    opening_randomness: int
    announcement: int
    challenge: int
    response: int
    relation: str = "nonzero"

    def to_dict(self) -> dict:
        return {
            "opening_randomness": self.opening_randomness,
            "announcement": self.announcement,
            "challenge": self.challenge,
            "response": self.response,
            "relation": self.relation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NonZeroProof":
        return cls(
            opening_randomness=int(data["opening_randomness"]),
            announcement=int(data["announcement"]),
            challenge=int(data["challenge"]),
            response=int(data["response"]),
            relation=data.get("relation", "nonzero"),
        )


def create_range_proof(
    params: ProofParams,
    value: int,
    lo: int,
    hi: int,
    randomness: int | None = None,
) -> tuple[Commitment, RangeProof]:
    value = _require_int("value", value)
    lo = _require_int("lo", lo)
    hi = _require_int("hi", hi)
    if lo > hi:
        raise ValueError("lo must be <= hi.")
    if value < lo or value > hi:
        raise ValueError("value must lie in [lo, hi].")
    if hi - lo >= params.q:
        raise ValueError("Public range width must be smaller than q.")

    commitment = commit(params, value, randomness=randomness)
    bit_length = max(1, (hi - lo).bit_length())
    lower_value = value - lo
    upper_value = hi - value
    lower_bits = _bit_decompose(lower_value, bit_length)
    upper_bits = _bit_decompose(upper_value, bit_length)

    lower_randomness = _weighted_randomness_shares(params, commitment.randomness, bit_length)
    upper_randomness = _weighted_randomness_shares(
        params, (-commitment.randomness) % params.q, bit_length
    )

    lower_bit_commitments = []
    lower_bit_proofs = []
    for bit, share in zip(lower_bits, lower_randomness):
        bit_commitment = commit(params, bit, randomness=share)
        lower_bit_commitments.append(bit_commitment.value_commitment)
        lower_bit_proofs.append(
            _create_opening_or_proof(
                params=params,
                commitment_value=bit_commitment.value_commitment,
                opening_randomness=bit_commitment.randomness,
                actual_value=bit,
                allowed_values=[0, 1],
                domain="range_bit",
            )
        )

    upper_bit_commitments = []
    upper_bit_proofs = []
    for bit, share in zip(upper_bits, upper_randomness):
        bit_commitment = commit(params, bit, randomness=share)
        upper_bit_commitments.append(bit_commitment.value_commitment)
        upper_bit_proofs.append(
            _create_opening_or_proof(
                params=params,
                commitment_value=bit_commitment.value_commitment,
                opening_randomness=bit_commitment.randomness,
                actual_value=bit,
                allowed_values=[0, 1],
                domain="range_bit",
            )
        )

    proof = RangeProof(
        lower_bit_commitments=lower_bit_commitments,
        lower_bit_proofs=lower_bit_proofs,
        upper_bit_commitments=upper_bit_commitments,
        upper_bit_proofs=upper_bit_proofs,
        bit_length=bit_length,
    )
    return commitment, proof


def verify_range_proof(
    params: ProofParams,
    commitment: Commitment,
    proof: RangeProof,
    lo: int,
    hi: int,
) -> bool:
    try:
        lo = _require_int("lo", lo)
        hi = _require_int("hi", hi)
    except TypeError:
        return False
    if proof.relation != "range":
        return False
    if lo > hi:
        return False
    if hi - lo >= params.q:
        return False
    expected_bit_length = max(1, (hi - lo).bit_length())
    if proof.bit_length != expected_bit_length:
        return False
    if len(proof.lower_bit_commitments) != proof.bit_length:
        return False
    if len(proof.upper_bit_commitments) != proof.bit_length:
        return False
    if len(proof.lower_bit_proofs) != proof.bit_length:
        return False
    if len(proof.upper_bit_proofs) != proof.bit_length:
        return False
    if not _in_subgroup(params, commitment.value_commitment):
        return False

    for bit_commitment, bit_proof in zip(proof.lower_bit_commitments, proof.lower_bit_proofs):
        if not _verify_opening_or_proof(params, bit_commitment, bit_proof, [0, 1], "range_bit"):
            return False
    for bit_commitment, bit_proof in zip(proof.upper_bit_commitments, proof.upper_bit_proofs):
        if not _verify_opening_or_proof(params, bit_commitment, bit_proof, [0, 1], "range_bit"):
            return False

    lower_target = (
        commitment.value_commitment * _mod_inverse(pow(params.g, lo % params.q, params.p), params.p)
    ) % params.p
    if _weighted_commitment_product(params, proof.lower_bit_commitments) != lower_target:
        return False

    upper_target = (
        pow(params.g, hi % params.q, params.p)
        * _mod_inverse(commitment.value_commitment, params.p)
    ) % params.p
    if _weighted_commitment_product(params, proof.upper_bit_commitments) != upper_target:
        return False

    return True


def create_membership_proof(
    params: ProofParams,
    value,
    allowed_set,
    randomness: int | None = None,
) -> tuple[Commitment, MembershipProof]:
    encoded_value = _encode_value(params, value)
    allowed_values = _normalize_allowed_values(params, allowed_set)
    if encoded_value not in allowed_values:
        raise ValueError("value must be in allowed_set.")

    commitment = commit(params, encoded_value, randomness=randomness)
    proof = _create_opening_or_proof(
        params=params,
        commitment_value=commitment.value_commitment,
        opening_randomness=commitment.randomness,
        actual_value=encoded_value,
        allowed_values=allowed_values,
        domain="membership",
    )
    return commitment, proof


def verify_membership_proof(
    params: ProofParams,
    commitment: Commitment,
    proof: MembershipProof,
    allowed_set,
) -> bool:
    try:
        allowed_values = _normalize_allowed_values(params, allowed_set)
    except (TypeError, ValueError):
        return False
    return _verify_opening_or_proof(
        params=params,
        commitment_value=commitment.value_commitment,
        proof=proof,
        allowed_values=allowed_values,
        domain="membership",
    )


def create_consistency_proof(
    params: ProofParams,
    left: Commitment,
    right: Commitment,
) -> ConsistencyProof:
    quotient = (left.value_commitment * _mod_inverse(right.value_commitment, params.p)) % params.p
    if not _in_subgroup(params, quotient):
        raise ValueError("Commitments must be subgroup elements.")

    witness = (left.randomness - right.randomness) % params.q
    nonce = _random_scalar(params.q)
    announcement = pow(params.h, nonce, params.p)
    challenge = _challenge(
        params,
        "consistency",
        left.value_commitment,
        right.value_commitment,
        announcement,
    )
    response = (nonce + challenge * witness) % params.q
    return ConsistencyProof(
        announcement=announcement,
        challenge=challenge,
        response=response,
        relation="equal",
    )


def verify_consistency_proof(
    params: ProofParams,
    left: Commitment,
    right: Commitment,
    proof: ConsistencyProof,
) -> bool:
    if proof.relation != "equal":
        return False
    if not _in_subgroup(params, left.value_commitment):
        return False
    if not _in_subgroup(params, right.value_commitment):
        return False
    if not _in_subgroup(params, proof.announcement):
        return False

    quotient = (left.value_commitment * _mod_inverse(right.value_commitment, params.p)) % params.p
    if not _in_subgroup(params, quotient):
        return False

    expected_challenge = _challenge(
        params,
        "consistency",
        left.value_commitment,
        right.value_commitment,
        proof.announcement,
    )
    if proof.challenge % params.q != expected_challenge:
        return False

    lhs = pow(params.h, proof.response % params.q, params.p)
    rhs = (proof.announcement * pow(quotient, proof.challenge % params.q, params.p)) % params.p
    return lhs == rhs


def create_nonzero_proof(
    params: ProofParams,
    commitment: Commitment,
    value: int,
) -> NonZeroProof:
    value = _require_int("value", value) % params.q
    if value == 0:
        raise ValueError("Committed value must be non-zero modulo q.")
    if not _in_subgroup(params, commitment.value_commitment):
        raise ValueError("Commitment must be a subgroup element.")

    unblinded = (
        commitment.value_commitment
        * _mod_inverse(pow(params.h, commitment.randomness, params.p), params.p)
    ) % params.p
    inverse_value = _mod_inverse(value, params.q)
    nonce = _random_scalar(params.q)
    announcement = pow(unblinded, nonce, params.p)
    challenge = _challenge(
        params,
        "nonzero",
        commitment.value_commitment,
        commitment.randomness,
        unblinded,
        announcement,
    )
    response = (nonce + challenge * inverse_value) % params.q
    return NonZeroProof(
        opening_randomness=commitment.randomness,
        announcement=announcement,
        challenge=challenge,
        response=response,
    )


def verify_nonzero_proof(
    params: ProofParams,
    commitment: Commitment,
    proof: NonZeroProof,
) -> bool:
    if proof.relation != "nonzero":
        return False
    if not _in_subgroup(params, commitment.value_commitment):
        return False
    if not _in_subgroup(params, proof.announcement):
        return False

    unblinded = (
        commitment.value_commitment
        * _mod_inverse(pow(params.h, proof.opening_randomness % params.q, params.p), params.p)
    ) % params.p
    if unblinded == 1 or not _in_subgroup(params, unblinded):
        return False

    expected_challenge = _challenge(
        params,
        "nonzero",
        commitment.value_commitment,
        proof.opening_randomness % params.q,
        unblinded,
        proof.announcement,
    )
    if proof.challenge % params.q != expected_challenge:
        return False

    lhs = pow(unblinded, proof.response % params.q, params.p)
    rhs = (proof.announcement * pow(params.g, proof.challenge % params.q, params.p)) % params.p
    return lhs == rhs


__all__ = [
    "Commitment",
    "ConsistencyProof",
    "MembershipProof",
    "NonZeroProof",
    "ProofParams",
    "RangeProof",
    "commit",
    "create_consistency_proof",
    "create_membership_proof",
    "create_nonzero_proof",
    "create_range_proof",
    "verify_consistency_proof",
    "verify_membership_proof",
    "verify_nonzero_proof",
    "verify_range_proof",
]
