"""
Zero-knowledge proof primitives for vigil contributions.

Proves contribution validity without revealing content:
  - Range proofs: "my score is between 0-10"
  - Membership proofs: "my IOC type is one of {domain, ip, hash}"
  - Consistency proofs: "my data hasn't been tampered with"
  - Non-zero proofs: "I contributed real data, not empty/garbage"
"""
from .proofs import (
    ProofParams,
    Commitment,
    RangeProof,
    MembershipProof,
    ConsistencyProof,
    NonZeroProof,
    commit,
    create_range_proof,
    verify_range_proof,
    create_membership_proof,
    verify_membership_proof,
    create_consistency_proof,
    verify_consistency_proof,
    create_nonzero_proof,
    verify_nonzero_proof,
)
from .contrib_proofs import (
    EvalRecordProof,
    AttackMapProof,
    IOCBundleProof,
    ContributionProofBundle,
    VerificationResult,
)
from .verify import ZKPVerifier, ZKPVerificationResult

__all__ = [
    "ProofParams",
    "Commitment",
    "RangeProof",
    "MembershipProof",
    "ConsistencyProof",
    "NonZeroProof",
    "commit",
    "create_range_proof",
    "verify_range_proof",
    "create_membership_proof",
    "verify_membership_proof",
    "create_consistency_proof",
    "verify_consistency_proof",
    "create_nonzero_proof",
    "verify_nonzero_proof",
    "EvalRecordProof",
    "AttackMapProof",
    "IOCBundleProof",
    "ContributionProofBundle",
    "VerificationResult",
    "ZKPVerifier",
    "ZKPVerificationResult",
]
