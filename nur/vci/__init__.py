"""
Verified Collective Intelligence (VCI) Protocol.

Combines ZKPs, MPC (SecAgg), and BDP into a unified protocol that:
1. Lets contributors prove data is real without revealing it (ZKP envelopes)
2. Lets the server aggregate without seeing individual values (SecAgg + BDP weights)
3. Lets new users verify the platform has real data (platform attestation)
4. Makes data poisoning mathematically bounded (formal poisoning bounds)

4 independent patentable claims:
  1. Share-Committed Secure Aggregation with ZKP Validity
  2. Behavioral-Credibility-Weighted Secure Aggregation with Formal Poisoning Bound
  3. Zero-Knowledge Platform Attestation via Commitment-Bound Merkle Trees
  4. PSI-Driven Trust Feedback with Credibility Reinforcement
"""

from .share_proofs import (
    ShareConsistencyProof,
    commit_and_prove_shares,
    lagrange_coefficients,
    vci_shamir_reconstruct,
    vci_shamir_split,
    verify_share_consistency,
)
from .envelope import (
    VCIContributionEnvelope,
    build_envelope,
    verify_envelope,
)
from .aggregation import (
    VCIAggSession,
    vci_aggregate_with_bound,
    weighted_aggregate_values,
)
from .platform import (
    PlatformAttestation,
    build_merkle_tree,
    generate_platform_attestation,
    get_merkle_proof,
    verify_merkle_proof,
    verify_platform_attestation,
)
from .trust_graph import (
    TrustEdge,
    TrustGraph,
    apply_trust_feedback,
    compute_credibility_delta,
    compute_ioc_rarity,
    process_psi_result,
)
from .bounds import (
    PoisoningBound,
    compute_collective_bound,
    compute_poisoning_bound,
)
from .histograms import (
    HistogramEncoder,
    SecureHistogramSession,
    build_technique_vector,
    build_vendor_detection_vector,
    compute_detection_rate,
    TECHNIQUE_TABLE,
    VENDOR_TABLE,
)

__all__ = [
    # Share proofs
    "ShareConsistencyProof",
    "commit_and_prove_shares",
    "lagrange_coefficients",
    "vci_shamir_reconstruct",
    "vci_shamir_split",
    "verify_share_consistency",
    # Envelope
    "VCIContributionEnvelope",
    "build_envelope",
    "verify_envelope",
    # Aggregation
    "VCIAggSession",
    "vci_aggregate_with_bound",
    "weighted_aggregate_values",
    # Platform
    "PlatformAttestation",
    "build_merkle_tree",
    "generate_platform_attestation",
    "get_merkle_proof",
    "verify_merkle_proof",
    "verify_platform_attestation",
    # Trust graph
    "TrustEdge",
    "TrustGraph",
    "apply_trust_feedback",
    "compute_credibility_delta",
    "compute_ioc_rarity",
    "process_psi_result",
    # Bounds
    "PoisoningBound",
    "compute_collective_bound",
    "compute_poisoning_bound",
    # Histograms
    "HistogramEncoder",
    "SecureHistogramSession",
    "build_technique_vector",
    "build_vendor_detection_vector",
    "compute_detection_rate",
    "TECHNIQUE_TABLE",
    "VENDOR_TABLE",
]
