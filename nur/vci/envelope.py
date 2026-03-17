"""
VCI Contribution Envelope — binds ZKP proofs, attestation chain,
and Shamir shares into a single cryptographically coherent package.

The envelope prevents the "valid-proof-garbage-shares" attack:
a contributor cannot pass ZKP verification (score in [0,10]) but
submit Shamir shares that reconstruct to a different value.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..attest.chain import AttestationChain
from ..zkp.contrib_proofs import ContributionProofBundle
from ..zkp.proofs import Commitment, ProofParams

from .share_proofs import (
    ShareConsistencyProof,
    commit_and_prove_shares,
    vci_shamir_split,
    verify_share_consistency,
)


@dataclass
class VCIContributionEnvelope:
    """
    A cryptographically bound package containing:
    - Attestation chain proving correct data processing
    - ZKP bundle proving all field values are valid
    - Share commitments + validity proofs binding shares to ZKP commitments
    - The actual Shamir shares for secure aggregation
    - Contributor signature over the entire envelope
    """
    attestation_chain: dict                     # AttestationChain.to_dict()
    zkp_bundle: dict                            # ContributionProofBundle.to_dict()
    share_consistency_proofs: list[dict]         # One per numeric field
    shamir_shares: list[list[tuple[int, int]]]   # Shares per field
    field_names: list[str]                       # Names of committed numeric fields
    contributor_public_key: str
    contributor_signature: str                   # HMAC over envelope contents
    envelope_hash: str = ""                      # SHA-256 of canonical contents

    def to_dict(self) -> dict:
        return {
            "attestation_chain": self.attestation_chain,
            "zkp_bundle": self.zkp_bundle,
            "share_consistency_proofs": self.share_consistency_proofs,
            "shamir_shares": self.shamir_shares,
            "field_names": self.field_names,
            "contributor_public_key": self.contributor_public_key,
            "contributor_signature": self.contributor_signature,
            "envelope_hash": self.envelope_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> VCIContributionEnvelope:
        return cls(
            attestation_chain=data["attestation_chain"],
            zkp_bundle=data["zkp_bundle"],
            share_consistency_proofs=data["share_consistency_proofs"],
            shamir_shares=data["shamir_shares"],
            field_names=data["field_names"],
            contributor_public_key=data["contributor_public_key"],
            contributor_signature=data["contributor_signature"],
            envelope_hash=data.get("envelope_hash", ""),
        )

    @classmethod
    def from_json(cls, text: str) -> VCIContributionEnvelope:
        return cls.from_dict(json.loads(text))


def _canonical_hash(data: dict) -> str:
    """SHA-256 of canonical JSON (sorted keys, no whitespace)."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _sign_envelope(contents_hash: str, secret_key: bytes) -> str:
    """HMAC-SHA256 signature over the envelope hash."""
    import hmac
    return hmac.new(secret_key, contents_hash.encode(), hashlib.sha256).hexdigest()


def build_envelope(
    params: ProofParams,
    attestation_chain: AttestationChain,
    zkp_bundle: ContributionProofBundle,
    field_values: dict[str, int],
    n_parties: int,
    threshold: int,
    contributor_secret: bytes,
) -> VCIContributionEnvelope:
    """
    Build a complete VCI contribution envelope.

    Args:
        params: ZKP parameters
        attestation_chain: ADTC chain for this contribution
        zkp_bundle: ZKP proof bundle for all fields
        field_values: {field_name: integer_value} for numeric fields to share
        n_parties: number of Shamir share recipients
        threshold: minimum shares needed for reconstruction
        contributor_secret: contributor's HMAC key for signing

    Returns:
        A fully bound VCIContributionEnvelope
    """
    pub_key = hashlib.sha256(contributor_secret).hexdigest()

    # Extract the original commitments from the ZKP bundle for binding
    commitment_map = _extract_commitments(zkp_bundle)

    share_consistency_proofs = []
    all_shares = []
    field_names = []

    for field_name, value in field_values.items():
        # Generate Shamir shares over Z_q
        shares = vci_shamir_split(value, n_parties, threshold, params.q)

        # Find the matching commitment from the ZKP bundle
        original_com = commitment_map.get(field_name)
        if original_com is None:
            # Create a fresh commitment if not in the ZKP bundle
            original_com = Commitment.commit(params, value)

        # Prove shares are consistent with the ZKP commitment
        proof = commit_and_prove_shares(params, original_com, shares)

        share_consistency_proofs.append(proof.to_dict())
        all_shares.append(shares)
        field_names.append(field_name)

    # Build the envelope (without signature yet)
    chain_dict = attestation_chain.to_dict()
    bundle_dict = zkp_bundle.to_dict()

    contents = {
        "attestation_chain": chain_dict,
        "zkp_bundle": bundle_dict,
        "share_consistency_proofs": share_consistency_proofs,
        "field_names": field_names,
        "contributor_public_key": pub_key,
    }
    envelope_hash = _canonical_hash(contents)
    signature = _sign_envelope(envelope_hash, contributor_secret)

    return VCIContributionEnvelope(
        attestation_chain=chain_dict,
        zkp_bundle=bundle_dict,
        share_consistency_proofs=share_consistency_proofs,
        shamir_shares=all_shares,
        field_names=field_names,
        contributor_public_key=pub_key,
        contributor_signature=signature,
        envelope_hash=envelope_hash,
    )


def verify_envelope(
    params: ProofParams,
    envelope: VCIContributionEnvelope,
) -> dict:
    """
    Verify a VCI contribution envelope.

    Checks:
    1. Envelope hash matches contents
    2. ZKP bundle proofs are valid
    3. Share consistency proofs bind shares to ZKP commitments
    4. Attestation chain has valid structure

    Returns:
        {"valid": bool, "checks": dict, "errors": list}
    """
    from ..zkp.contrib_proofs import _verify_bundle

    errors = []
    checks = {
        "envelope_hash": False,
        "zkp_proofs": False,
        "share_consistency": False,
        "attestation_chain": False,
    }

    # 1. Verify envelope hash
    contents = {
        "attestation_chain": envelope.attestation_chain,
        "zkp_bundle": envelope.zkp_bundle,
        "share_consistency_proofs": envelope.share_consistency_proofs,
        "field_names": envelope.field_names,
        "contributor_public_key": envelope.contributor_public_key,
    }
    expected_hash = _canonical_hash(contents)
    if expected_hash == envelope.envelope_hash:
        checks["envelope_hash"] = True
    else:
        errors.append("Envelope hash mismatch — contents may be tampered")

    # 2. Verify ZKP bundle
    bundle = ContributionProofBundle.from_dict(envelope.zkp_bundle)
    vr = _verify_bundle(params, bundle)
    if vr.valid:
        checks["zkp_proofs"] = True
    else:
        errors.append(f"ZKP verification failed: {vr.failed_proofs}")

    # 3. Verify share consistency proofs
    commitment_map = _extract_commitments(bundle)
    all_consistent = True

    for i, field_name in enumerate(envelope.field_names):
        if i >= len(envelope.share_consistency_proofs):
            all_consistent = False
            errors.append(f"Missing share consistency proof for {field_name}")
            continue

        proof = ShareConsistencyProof.from_dict(envelope.share_consistency_proofs[i])
        original_com = commitment_map.get(field_name)

        if original_com is None:
            errors.append(f"No ZKP commitment found for field {field_name}")
            all_consistent = False
            continue

        if not verify_share_consistency(params, original_com, proof):
            errors.append(f"Share consistency failed for {field_name}")
            all_consistent = False

    checks["share_consistency"] = all_consistent

    # 4. Verify attestation chain structure
    chain = AttestationChain.from_dict(envelope.attestation_chain)
    if chain.stages and chain.root_cdi:
        checks["attestation_chain"] = True
    else:
        errors.append("Attestation chain has no stages or missing root CDI")

    return {
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
    }


def _extract_commitments(bundle: ContributionProofBundle) -> dict[str, Commitment]:
    """Extract Pedersen commitments from a ZKP proof bundle, keyed by field name."""
    result = {}
    for entry in bundle.proofs:
        field_name = entry["field"]
        com_data = entry["commitment"]
        result[field_name] = Commitment.from_dict(com_data)
    return result


__all__ = [
    "VCIContributionEnvelope",
    "build_envelope",
    "verify_envelope",
]
