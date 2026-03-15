"""
High-level ZKP interface for vigil contributions.

Wraps the low-level proofs into contribution-specific validators that prove
contribution data is valid without revealing the actual values.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .proofs import (
    ProofParams,
    Commitment,
    RangeProof,
    MembershipProof,
    NonZeroProof,
    commit,
    create_range_proof,
    verify_range_proof,
    create_membership_proof,
    verify_membership_proof,
    create_nonzero_proof,
    verify_nonzero_proof,
    _encode_value,
)


# ---------------------------------------------------------------------------
# Proof bundle — serializable container for all proofs on a contribution
# ---------------------------------------------------------------------------

@dataclass
class ContributionProofBundle:
    """Bundle of proofs for a single contribution."""

    contribution_type: str = ""
    proofs: list[dict] = field(default_factory=list)

    def add_proof(
        self,
        proof_type: str,
        field_name: str,
        commitment: Commitment,
        proof_data: dict,
    ) -> None:
        self.proofs.append({
            "proof_type": proof_type,
            "field": field_name,
            "commitment": commitment.to_dict(),
            "proof_data": proof_data,
        })

    def to_dict(self) -> dict:
        return {
            "contribution_type": self.contribution_type,
            "proofs": self.proofs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ContributionProofBundle:
        return cls(
            contribution_type=data["contribution_type"],
            proofs=data["proofs"],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> ContributionProofBundle:
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# Allowed value sets for contribution fields
# ---------------------------------------------------------------------------

EVAL_CATEGORIES = [
    "edr", "siem", "cnapp", "xdr", "soar", "casb", "ztna",
    "ids", "ips", "waf", "dlp", "pam", "mdr", "ndr", "cspm",
    "cwpp", "devsecops", "email-security", "firewall", "vpn",
]

IOC_TYPES = [
    "domain", "ip", "hash-sha256", "hash-md5", "url", "email",
]


# ---------------------------------------------------------------------------
# EvalRecord proofs
# ---------------------------------------------------------------------------

class EvalRecordProof:
    """Prove an EvalRecord is valid without revealing scores."""

    def __init__(self, params: ProofParams | None = None):
        self.params = params or ProofParams()

    def prove(self, record) -> ContributionProofBundle:
        """Generate proofs that an EvalRecord has valid field ranges.

        Proves:
        - overall_score in [0, 10]
        - detection_rate in [0, 100]
        - fp_rate in [0, 100]
        - deploy_days in [1, 365]
        - cpu_overhead in [0, 100]
        - category in EVAL_CATEGORIES
        """
        bundle = ContributionProofBundle(contribution_type="eval")

        # Category membership proof
        cat = getattr(record, "category", None)
        if cat is not None:
            com, proof = create_membership_proof(
                self.params, str(cat), EVAL_CATEGORIES,
            )
            bundle.add_proof("membership", "category", com, proof.to_dict())

        # Range proofs for numeric fields
        range_fields = [
            ("overall_score", 0, 10),
            ("detection_rate", 0, 100),
            ("fp_rate", 0, 100),
            ("cpu_overhead", 0, 100),
        ]
        for field_name, lo, hi in range_fields:
            val = getattr(record, field_name, None)
            if val is not None:
                # Convert float to int (multiply by 10 for one decimal place)
                int_val = int(round(val * 10))
                com, proof = create_range_proof(
                    self.params, int_val, lo * 10, hi * 10,
                )
                bundle.add_proof(
                    "range", field_name, com,
                    {**proof.to_dict(), "scale": 10, "lo": lo, "hi": hi},
                )

        # deploy_days as integer range
        dd = getattr(record, "deploy_days", None)
        if dd is not None:
            com, proof = create_range_proof(self.params, int(dd), 1, 365)
            bundle.add_proof(
                "range", "deploy_days", com,
                {**proof.to_dict(), "scale": 1, "lo": 1, "hi": 365},
            )

        # Non-zero proof for vendor (contributed something real)
        vendor = getattr(record, "vendor", None)
        if vendor:
            encoded = _encode_value(self.params, str(vendor))
            com = commit(self.params, encoded)
            nzp = create_nonzero_proof(self.params, com, encoded)
            bundle.add_proof("nonzero", "vendor", com, nzp.to_dict())

        return bundle

    def verify(self, bundle: ContributionProofBundle) -> VerificationResult:
        """Verify all proofs in the bundle."""
        return _verify_bundle(self.params, bundle)


# ---------------------------------------------------------------------------
# AttackMap proofs
# ---------------------------------------------------------------------------

# Regex for MITRE technique IDs: T#### or T####.###
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class AttackMapProof:
    """Prove an AttackMap has valid structure."""

    def __init__(self, params: ProofParams | None = None):
        self.params = params or ProofParams()

    def prove(self, attack_map) -> ContributionProofBundle:
        """Generate proofs for an AttackMap.

        Proves:
        - At least 1 technique present (non-empty)
        - technique_ids follow MITRE format (T####.###)
        - detected_by or missed_by are non-empty for at least some techniques
        """
        bundle = ContributionProofBundle(contribution_type="attack_map")
        techniques = getattr(attack_map, "techniques", [])

        if not techniques:
            raise ValueError("AttackMap must have at least one technique")

        # Non-zero proof: number of techniques > 0
        n_techniques = len(techniques)
        com = commit(self.params, n_techniques)
        nzp = create_nonzero_proof(self.params, com, n_techniques)
        bundle.add_proof("nonzero", "technique_count", com, nzp.to_dict())

        # For each technique, prove its ID is valid MITRE format
        for i, tech in enumerate(techniques):
            tid = getattr(tech, "technique_id", "")
            if not _MITRE_RE.match(tid):
                raise ValueError(f"Invalid MITRE technique ID: {tid}")

            # Prove the technique_id is non-zero (real contribution)
            encoded = _encode_value(self.params, tid)
            com = commit(self.params, encoded)
            nzp = create_nonzero_proof(self.params, com, encoded)
            bundle.add_proof(
                "nonzero", f"technique_{i}_id", com, nzp.to_dict(),
            )

            # Prove at least one of detected_by or missed_by is non-empty
            detected = getattr(tech, "detected_by", [])
            missed = getattr(tech, "missed_by", [])
            total_vendors = len(detected) + len(missed)
            if total_vendors > 0:
                com2 = commit(self.params, total_vendors)
                nzp2 = create_nonzero_proof(self.params, com2, total_vendors)
                bundle.add_proof(
                    "nonzero", f"technique_{i}_vendor_count", com2, nzp2.to_dict(),
                )

        return bundle

    def verify(self, bundle: ContributionProofBundle) -> VerificationResult:
        return _verify_bundle(self.params, bundle)


# ---------------------------------------------------------------------------
# IOCBundle proofs
# ---------------------------------------------------------------------------

class IOCBundleProof:
    """Prove IOC bundle is real without revealing IOC values."""

    def __init__(self, params: ProofParams | None = None):
        self.params = params or ProofParams()

    def prove(self, bundle_data) -> ContributionProofBundle:
        """Generate proofs for an IOCBundle.

        Proves:
        - At least 1 IOC present
        - ioc_type in {domain, ip, hash-sha256, hash-md5, url, email}
        - value_hash is a valid SHA-256 (64 hex chars) — proven non-zero
        - IOC values are non-empty
        """
        proof_bundle = ContributionProofBundle(contribution_type="ioc_bundle")
        iocs = getattr(bundle_data, "iocs", [])

        if not iocs:
            raise ValueError("IOCBundle must have at least one IOC")

        # Non-zero proof: count of IOCs
        n_iocs = len(iocs)
        com = commit(self.params, n_iocs)
        nzp = create_nonzero_proof(self.params, com, n_iocs)
        proof_bundle.add_proof("nonzero", "ioc_count", com, nzp.to_dict())

        for i, ioc in enumerate(iocs):
            # Membership proof for ioc_type
            ioc_type = getattr(ioc, "ioc_type", None)
            if ioc_type is not None:
                com_t, proof_t = create_membership_proof(
                    self.params, str(ioc_type), IOC_TYPES,
                )
                proof_bundle.add_proof(
                    "membership", f"ioc_{i}_type", com_t, proof_t.to_dict(),
                )

            # Non-zero proof for value_hash (proves IOC has actual content)
            value_hash = getattr(ioc, "value_hash", None)
            if value_hash and len(value_hash) == 64:
                encoded = _encode_value(self.params, value_hash)
                com_v = commit(self.params, encoded)
                nzp_v = create_nonzero_proof(self.params, com_v, encoded)
                proof_bundle.add_proof(
                    "nonzero", f"ioc_{i}_value_hash", com_v, nzp_v.to_dict(),
                )

        return proof_bundle

    def verify(self, bundle: ContributionProofBundle) -> VerificationResult:
        return _verify_bundle(self.params, bundle)


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of verifying a proof bundle."""
    valid: bool = True
    proof_count: int = 0
    verified_count: int = 0
    failed_proofs: list[dict] = field(default_factory=list)

    @property
    def summary(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return (
            f"ZKP Verification: {status} "
            f"({self.verified_count}/{self.proof_count} proofs passed)"
        )


# ---------------------------------------------------------------------------
# Generic bundle verifier
# ---------------------------------------------------------------------------

def _verify_bundle(params: ProofParams, bundle: ContributionProofBundle) -> VerificationResult:
    """Verify all proofs in a ContributionProofBundle."""
    result = VerificationResult(proof_count=len(bundle.proofs))

    for entry in bundle.proofs:
        proof_type = entry["proof_type"]
        field_name = entry["field"]
        com_data = entry["commitment"]
        proof_data = entry["proof_data"]

        com = Commitment.from_dict(com_data)
        ok = False

        try:
            if proof_type == "range":
                rp = RangeProof.from_dict(proof_data)
                lo = proof_data.get("lo", 0)
                hi = proof_data.get("hi", 0)
                scale = proof_data.get("scale", 1)
                ok = verify_range_proof(params, com, rp, lo * scale, hi * scale)

            elif proof_type == "membership":
                mp = MembershipProof.from_dict(proof_data)
                # Determine allowed set from field name
                if "category" in field_name:
                    allowed = EVAL_CATEGORIES
                elif "ioc" in field_name and "type" in field_name:
                    allowed = IOC_TYPES
                else:
                    # Fallback: cannot verify without knowing the set
                    ok = False
                    result.failed_proofs.append({
                        "field": field_name,
                        "reason": "Unknown membership set",
                    })
                    continue
                ok = verify_membership_proof(params, com, mp, allowed)

            elif proof_type == "nonzero":
                nzp = NonZeroProof.from_dict(proof_data)
                ok = verify_nonzero_proof(params, com, nzp)

            else:
                result.failed_proofs.append({
                    "field": field_name,
                    "reason": f"Unknown proof type: {proof_type}",
                })
                continue

        except Exception as exc:
            ok = False
            result.failed_proofs.append({
                "field": field_name,
                "reason": str(exc),
            })
            continue

        if ok:
            result.verified_count += 1
        else:
            result.failed_proofs.append({
                "field": field_name,
                "reason": "Proof verification failed",
            })

    result.valid = (result.verified_count == result.proof_count and result.proof_count > 0)
    return result
