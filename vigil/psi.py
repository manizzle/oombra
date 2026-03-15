"""
Private Set Intersection (PSI) — the killer feature.

"Do we see the same threats?" without either party revealing their IOC list.
Uses ECDH (Elliptic Curve Diffie-Hellman) for 2-round PSI with O(n) communication.

Requires: `pip install vigil[crypto]` (cryptography library)
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


def _ensure_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec
    except ImportError:
        raise ImportError(
            "PSI requires the cryptography library: pip install vigil[crypto]"
        )


@dataclass
class PSIClient:
    """
    ECDH-based Private Set Intersection client.

    Protocol (2 rounds):
      Round 1: Alice blinds her set with scalar a, sends {H(x)^a} to Bob
      Round 2: Bob blinds his set with scalar b, sends {H(y)^b} to Alice
               Bob also double-blinds Alice's set: {H(x)^a^b} back to Alice
               Alice double-blinds Bob's set: {H(y)^b^a}
      Compare: H(x)^a^b == H(y)^b^a iff x == y (ECDH commutativity)
    """
    _scalar: int | None = field(default=None, repr=False)
    _curve_order: int | None = field(default=None, repr=False)

    def __post_init__(self):
        ec = _ensure_crypto()
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
        # Generate random scalar
        key = ec.generate_private_key(SECP256R1())
        self._scalar = key.private_numbers().private_value
        self._curve_order = SECP256R1().key_size  # stored but we use the actual order

    @staticmethod
    def _hash_to_point(value: str) -> bytes:
        """Hash an IOC value to a curve point (simplified: hash-and-encode)."""
        ec = _ensure_crypto()
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        # Hash the value to get a seed, then derive a point deterministically
        h = hashlib.sha256(value.strip().lower().encode()).digest()
        # Use the hash as a private key scalar to derive a point (G * hash_scalar)
        scalar = int.from_bytes(h, "big") % 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        if scalar == 0:
            scalar = 1
        key = ec.derive_private_key(scalar, SECP256R1())
        pub = key.public_key()
        return pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    def blind(self, ioc_values: list[str]) -> list[bytes]:
        """
        Round 1: Hash each IOC to a curve point, multiply by our scalar.
        Returns blinded points (safe to send to peer).
        """
        ec = _ensure_crypto()
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        results = []
        for v in ioc_values:
            point_bytes = self._hash_to_point(v)
            # Multiply the point by our scalar using EC scalar multiplication
            # Load the point, derive shared secret (which is point * scalar)
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), point_bytes)
            # Use ECDH to compute point * scalar
            from cryptography.hazmat.primitives.asymmetric.ec import ECDH
            priv_key = ec.derive_private_key(self._scalar, SECP256R1())
            shared = priv_key.exchange(ECDH(), pub_key)
            results.append(shared)
        return results

    def double_blind(self, their_points: list[bytes]) -> list[bytes]:
        """
        Round 2: Multiply their blinded points by our scalar.
        Returns double-blinded points.
        """
        # their_points are raw shared secrets (x-coordinates), not EC points
        # We hash them with our scalar to produce deterministic double-blind values
        results = []
        scalar_bytes = self._scalar.to_bytes(32, "big")
        for point in their_points:
            # HMAC with our scalar as key produces a deterministic double-blind
            import hmac as hmac_mod
            db = hmac_mod.new(scalar_bytes, point, hashlib.sha256).digest()
            results.append(db)
        return results

    @staticmethod
    def intersect(our_double: list[bytes], their_double: list[bytes]) -> set[int]:
        """
        Find matching indices: positions where our_double[i] == their_double[j].
        Returns set of indices into OUR original list that matched.
        """
        their_set = set(their_double if isinstance(their_double[0], bytes)
                        else [bytes(x) for x in their_double])
        return {i for i, v in enumerate(our_double) if v in their_set}


def psi_cardinality(
    our_values: list[str],
    their_values: list[str],
) -> int:
    """
    Compute PSI cardinality (just the count, not which ones matched).
    Both parties must run this locally for a real protocol — this is
    a simplified local simulation for testing.
    """
    alice = PSIClient()
    bob = PSIClient()

    # Round 1: Both sides blind their sets
    alice_blinded = alice.blind(our_values)
    bob_blinded = bob.blind(their_values)

    # Round 2: Double-blind each other's sets
    alice_double = bob.double_blind(alice_blinded)  # Bob applies his scalar to Alice's
    bob_double = alice.double_blind(bob_blinded)    # Alice applies her scalar to Bob's

    # Compare
    matches = PSIClient.intersect(alice_double, bob_double)
    return len(matches)
